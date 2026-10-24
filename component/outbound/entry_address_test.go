// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"fmt"
	"net"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/miekg/dns"
)

// entryAddressDNS answers A queries for any name with 127.0.0.1 and further
// loopback addresses, and AAAA queries with no data.
func entryAddressDNS(t testing.TB, records int, ttl uint32) (string, *atomic.Int64) {
	t.Helper()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	queries := new(atomic.Int64)
	server := &dns.Server{PacketConn: udp, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		queries.Add(1)
		response := new(dns.Msg).SetReply(request)
		response.RecursionAvailable = true
		q := request.Question[0]
		if q.Qtype == dns.TypeA {
			for i := range records {
				response.Answer = append(response.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: net.IPv4(127, 0, 0, byte(1+i))})
			}
		} else {
			response.Ns = []dns.RR{&dns.SOA{Hdr: dns.RR_Header{Name: "test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl}, Ns: "ns.test.", Mbox: "hostmaster.test.", Minttl: ttl}}
		}
		_ = w.WriteMsg(response)
	})}
	ready := make(chan struct{})
	server.NotifyStartedFunc = func() { close(ready) }
	go func() { _ = server.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() { _ = server.Shutdown() })
	return udp.LocalAddr().String(), queries
}

// entryAddressListener accepts plain TCP only, unlike Go's default listener.
func entryAddressListener(t testing.TB) string {
	t.Helper()
	var config net.ListenConfig
	config.SetMultipathTCP(false)
	listener, err := config.Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	return port
}

func TestEntryAddressesOutliveRuntimesUntilRelearn(t *testing.T) {
	server, queries := entryAddressDNS(t, 1, 300)
	port := entryAddressListener(t)
	global := &config.Global{DNSResolver: server}
	option := dialer.NewGlobalOption(global)
	spec := &PathSpec{Nodes: []*NodeInfo{{Property: &dialer.Property{Name: "entry", Address: "entry.test.:" + port}}}, IPVersion: 4}
	resources := new(Resources)
	dial := func(base netproxy.Dialer, network string, want int64) {
		t.Helper()
		conn, err := base.DialContext(t.Context(), network, "entry.test.:"+port)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
		if queries.Load() != want {
			t.Fatalf("%s dial: %d DNS queries, want %d", network, queries.Load(), want)
		}
	}
	// Each dormant wake builds a new entry dialer with a new resolver.
	first, err := spec.entryDialer(option, &resources.Paths)
	if err != nil {
		t.Fatal(err)
	}
	dial(first, "tcp", 1)
	woken, err := spec.entryDialer(option, &resources.Paths)
	if err != nil {
		t.Fatal(err)
	}
	dial(woken, "tcp", 1)
	dial(woken, "udp", 1)
	// A rebuilt configuration, as for a resource refresh, keeps them.
	set, err := NewDialerSet(nil)
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := NewGroupCompiler(set, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	NewGroupMaterializer(compiler, resources, global)
	rebuilt, err := spec.entryDialer(option, &resources.Paths)
	if err != nil {
		t.Fatal(err)
	}
	dial(rebuilt, "tcp", 1)
	// Relearn drops them for every path; a woken runtime's cold resolver
	// shows it on the wire.
	resources.Paths.Relearn()
	woken, err = spec.entryDialer(option, &resources.Paths)
	if err != nil {
		t.Fatal(err)
	}
	dial(woken, "tcp", 2)
	dial(first, "tcp", 2)
}

func cpuNanoseconds() int64 {
	var usage syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &usage)
	return usage.Utime.Nano() + usage.Stime.Nano()
}

// BenchmarkEntryDial measures a TCP entry dial to a node name whose DNS
// answer is cached on the wire (uncached) or as addresses (cached), against a
// literal address. cpu-ns/op includes the local accept side.
func BenchmarkEntryDial(b *testing.B) {
	for _, records := range []int{1, 4} {
		for _, cached := range []bool{false, true} {
			b.Run(fmt.Sprintf("records=%d/cached=%t", records, cached), func(b *testing.B) {
				server, _ := entryAddressDNS(b, records, 600)
				benchmarkEntryDial(b, &dialer.GlobalOption{DNSResolver: server}, "entry.test.", cached)
			})
		}
	}
	b.Run("literal", func(b *testing.B) {
		benchmarkEntryDial(b, new(dialer.GlobalOption), "127.0.0.1", false)
	})
}

func benchmarkEntryDial(b *testing.B, option *dialer.GlobalOption, host string, cached bool) {
	var pool *PathPool
	if cached {
		pool = new(PathPool)
	}
	port := entryAddressListener(b)
	base, err := (&PathSpec{IPVersion: 4}).entryDialer(option, pool)
	if err != nil {
		b.Fatal(err)
	}
	address := net.JoinHostPort(host, port)
	b.ReportAllocs()
	cpu := cpuNanoseconds()
	for b.Loop() {
		conn, err := base.DialContext(b.Context(), "tcp", address)
		if err != nil {
			b.Fatal(err)
		}
		// Avoid TIME_WAIT buildup skewing later runs.
		_ = conn.(*net.TCPConn).SetLinger(0)
		_ = conn.Close()
	}
	b.ReportMetric(float64(cpuNanoseconds()-cpu)/float64(b.N), "cpu-ns/op")
}
