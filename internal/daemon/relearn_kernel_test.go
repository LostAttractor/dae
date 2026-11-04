// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/settings"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/miekg/dns"
	"golang.org/x/sys/unix"
)

// relearnListener accepts plain TCP on address and counts connections.
func relearnListener(t *testing.T, address string) (*atomic.Int64, int) {
	t.Helper()
	var config net.ListenConfig
	config.SetMultipathTCP(false)
	listener, err := config.Listen(t.Context(), "tcp4", address)
	if err != nil {
		t.Fatal(err)
	}
	accepted := new(atomic.Int64)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
	return accepted, listener.Addr().(*net.TCPAddr).Port
}

// mptcpSYNs counts SYNs with MP_CAPABLE the network namespace sent, or
// returns -1 without MPTCP.
func mptcpSYNs(t *testing.T) int64 {
	t.Helper()
	netstat, err := os.ReadFile("/proc/net/netstat")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(netstat), "\n")
	for i := 0; i+1 < len(lines); i++ {
		if !strings.HasPrefix(lines[i], "MPTcpExt:") {
			continue
		}
		keys, values := strings.Fields(lines[i]), strings.Fields(lines[i+1])
		for j, key := range keys {
			if key == "MPCapableSYNTX" && j < len(values) {
				count, err := strconv.ParseInt(values[j], 10, 64)
				if err != nil {
					t.Fatal(err)
				}
				return count
			}
		}
	}
	return -1
}

// Run alone in a fresh process and in fresh network and private mount
// namespaces with writable bpffs: the test mounts its own /etc/hosts.
func TestDaemonReloadRelearnsNodesKernel(t *testing.T) {
	if os.Getenv("DAE_TEST_ISOLATED") != "1" {
		t.Skip("requires isolated network/mount namespaces and BPF privileges")
	}
	if mounts, err := os.ReadFile("/proc/self/mountinfo"); err != nil || bytes.Contains(mounts, []byte(" shared:")) {
		t.Skip("requires a private mount namespace")
	}
	dir := t.TempDir()
	t.Setenv("DAE_LOCATION_CACHE", dir)
	// Go rereads a nonempty hosts file at most every five seconds.
	hosts := filepath.Join(dir, "hosts")
	if err := os.WriteFile(hosts, []byte("127.0.0.9 other.test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(hosts, "/etc/hosts", "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Unmount("/etc/hosts", 0) })
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{PacketConn: udp, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg).SetReply(request)
		if q := request.Question[0]; q.Qtype == dns.TypeA {
			response.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600}, A: net.IPv4(127, 0, 0, 1)}}
		}
		_ = w.WriteMsg(response)
	})}
	ready := make(chan struct{})
	server.NotifyStartedFunc = func() { close(ready) }
	go func() { _ = server.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() { _ = server.Shutdown() })
	// The node answers nothing, so its checks fail and retry every second.
	resolved, port := relearnListener(t, "127.0.0.1:0")
	edited, _ := relearnListener(t, fmt.Sprintf("127.0.0.2:%d", port))
	path := filepath.Join(dir, "config.dae")
	text := fmt.Sprintf(`global { disable_waiting_network:true dns_resolver:'%s' check_interval_max:1s mptcp:true }
node { n: 'http://node.test:%d' }
group { proxy { policy: fixed(0) } }
routing { fallback: proxy }`, udp.LocalAddr(), port)
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	conf, _, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := InstallDefaultResolver(conf.Global.SoMarkFromDae, conf.Global.DNSResolver)
	if err != nil {
		t.Fatal(err)
	}
	store, err := settings.Open(filepath.Join(dir, "runtime.json"))
	if err != nil {
		t.Fatal(err)
	}
	datapath := control.NewRuntime()
	app := &application{options: Options{ConfigFile: path}, conf: conf, datapath: datapath, resolver: resolver, settings: store, operations: newOperations()}
	t.Cleanup(func() { resolver.SetRoute(nil); _ = datapath.Close(); _ = cleanupKernelResources() })
	app.inputs, err = loadControlInputs(t.Context(), conf, false, nil, path, nil)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := app.preparePlane(t.Context(), conf, app.inputs, nil)
	if err != nil {
		t.Fatal(err)
	}
	serveKernelTestIngress(t, datapath, conf.Global.TproxyPort)
	if err := app.publishPlane(candidate, false); err != nil {
		t.Fatal(err)
	}
	dialed := func(counter *atomic.Int64, after int64) {
		t.Helper()
		for deadline := time.Now().Add(20 * time.Second); counter.Load() <= after; time.Sleep(50 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("no node dial after %d", after)
			}
		}
	}
	dialed(resolved, 0)
	// The node does not negotiate MPTCP: after one probe, its dials use plain
	// TCP until the user reloads.
	dialed(resolved, resolved.Load()+1)
	if probes := mptcpSYNs(t); probes < 1 {
		t.Logf("MPTCP unavailable: %d SYNs", probes)
	} else {
		dialed(resolved, resolved.Load()+1)
		if again := mptcpSYNs(t); again != probes {
			t.Fatalf("node without MPTCP probed again: %d SYNs, then %d", probes, again)
		}
		if result, err := app.reload(t.Context(), false, false); err != nil || result != "No changes" {
			t.Fatalf("unchanged reload: %s, %v", result, err)
		}
		for deadline := time.Now().Add(20 * time.Second); mptcpSYNs(t) == probes; time.Sleep(50 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatal("reload did not probe MPTCP again")
			}
		}
	}
	// Edit hosts right after Go read it and reload at once: the first node
	// lookups after the reload may still miss the edit, yet it applies.
	if _, err := (&net.Resolver{PreferGo: true}).LookupNetIP(t.Context(), "ip4", "other.test"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hosts, []byte("127.0.0.9 other.test\n127.0.0.2 node.test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if result, err := app.reload(t.Context(), false, false); err != nil || result != "No changes" {
		t.Fatalf("unchanged reload: %s, %v", result, err)
	}
	dialed(edited, 0)
}
