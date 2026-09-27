//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/miekg/dns"
	"golang.org/x/sys/unix"
)

func entryTestDNS(t testing.TB, mask *atomic.Uint32) (string, *atomic.Int32) {
	t.Helper()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	queries := new(atomic.Int32)
	server := &dns.Server{PacketConn: udp, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		queries.Add(1)
		response := new(dns.Msg).SetReply(request)
		response.RecursionAvailable = true
		q := request.Question[0]
		hdr := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: 1}
		if q.Qtype == dns.TypeA && mask.Load()&uint32(family4) != 0 {
			response.Answer = []dns.RR{&dns.A{Hdr: hdr, A: net.ParseIP("127.0.0.1")}}
		}
		if q.Qtype == dns.TypeAAAA && mask.Load()&uint32(family6) != 0 {
			response.Answer = []dns.RR{&dns.AAAA{Hdr: hdr, AAAA: net.ParseIP("::1")}}
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

func TestEntrySockets(t *testing.T) {
	mask := new(atomic.Uint32)
	mask.Store(uint32(allFamilies))
	server, _ := entryTestDNS(t, mask)
	for _, family := range []int{4, 6} {
		t.Run(fmt.Sprint(family), func(t *testing.T) {
			host := "127.0.0.1"
			if family == 6 {
				host = "::1"
			}
			listener, err := net.Listen(fmt.Sprintf("tcp%d", family), net.JoinHostPort(host, "0"))
			if err != nil {
				t.Skipf("local IPv%d unavailable: %v", family, err)
			}
			defer listener.Close()
			_, port, _ := net.SplitHostPort(listener.Addr().String())
			for _, mark := range []*uint32{nil, new(uint32(0)), new(uint32(0x20)), new(uint32(0x80000000))} {
				wantMark := uint32(0x100)
				if mark != nil {
					wantMark = *mark
				}
				t.Run(fmt.Sprintf("mark-%x", wantMark), func(t *testing.T) {
					spec := &PathSpec{
						Nodes: []*NodeInfo{{Property: &dialer.Property{Name: "entry", Address: "entry.test.:" + port}}},
						Entry: EntryOptions{Mark: mark, Interface: "lo"}, IPVersion: family,
					}
					created, err := new(DialerSet).BuildPath(spec, &dialer.GlobalOption{DNSResolver: server, SoMarkFromDae: 0x100}, t.Name())
					if err != nil {
						t.Fatal(err)
					}
					defer created.Close()
					probe, err := created.ListenPacket(t.Context(), "")
					if errors.Is(err, unix.EPERM) {
						t.Skipf("socket options require privileges: %v", err)
					}
					if err != nil {
						t.Fatal(err)
					}
					_ = probe.Close()
					for _, network := range []string{"tcp", "udp", "packet"} {
						t.Run(network, func(t *testing.T) {
							ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
							defer cancel()
							var socket interface {
								Close() error
							}
							var err error
							if network == "packet" {
								socket, err = created.ListenPacket(ctx, "entry.test.:"+port)
							} else {
								socket, err = created.DialContext(ctx, network, "entry.test.:"+port)
							}
							if errors.Is(err, unix.EPERM) {
								t.Skipf("SO_MARK requires privileges: %v", err)
							}
							if err != nil {
								t.Fatal(err)
							}
							defer socket.Close()
							raw, err := socket.(syscall.Conn).SyscallConn()
							if err != nil {
								t.Fatal(err)
							}
							if err := raw.Control(func(fd uintptr) {
								mark, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK)
								if err != nil || uint32(mark) != wantMark {
									t.Errorf("SO_MARK = %#x, %v; want %#x", mark, err, wantMark)
								}
								device, err := unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
								if err != nil || device != "lo" {
									t.Errorf("SO_BINDTODEVICE = %q, %v", device, err)
								}
								domain, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_DOMAIN)
								wantDomain := unix.AF_INET
								if family == 6 {
									wantDomain = unix.AF_INET6
								}
								if err != nil || domain != wantDomain {
									t.Errorf("socket family = %d, %v; want %d", domain, err, wantDomain)
								}
							}); err != nil {
								t.Fatal(err)
							}
						})
					}
				})
			}
		})
	}
}

func TestEntryDNSBindingAndFamilyRecovery(t *testing.T) {
	mask := new(atomic.Uint32)
	mask.Store(uint32(family4))
	server, queries := entryTestDNS(t, mask)
	option := &dialer.GlobalOption{DNSResolver: server}
	spec := &PathSpec{Entry: EntryOptions{Interface: "lo"}, IPVersion: 6}
	base, err := spec.entryDialer(option)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if addr, err := netproxy.ResolveUDPAddr(ctx, base, "entry.test.:443"); err == nil {
		t.Fatalf("IPv6 entry fell back to IPv4: %v", addr)
	}
	mask.Store(uint32(allFamilies))
	if addr, err := netproxy.ResolveUDPAddr(ctx, base, "entry.test.:443"); err != nil || !addr.IP.Equal(net.ParseIP("::1")) {
		t.Fatalf("IPv6 DNS recovery failed: %v, %v", addr, err)
	}
	for _, network := range []string{"tcp", "udp"} {
		if conn, err := base.DialContext(ctx, network, "127.0.0.1:443"); err == nil {
			conn.Close()
			t.Fatalf("IPv6 entry accepted an IPv4 %s destination", network)
		}
	}
	packet, err := base.ListenPacket(ctx, "entry.test.:443")
	if err == nil {
		defer packet.Close()
		if _, err := packet.WriteTo([]byte("x"), &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443}); err == nil {
			t.Fatal("IPv6 packet socket accepted an IPv4 destination")
		}
	}
	count := queries.Load()
	spec.Entry.Interface = "dae-no-such-if"
	// External DNS must fail closed when the interface cannot be bound. A local
	// stub intentionally uses loopback independently of the proxy interface.
	option.DNSResolver = "192.0.2.53:53"
	base, err = spec.entryDialer(option)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := netproxy.ResolveUDPAddr(ctx, base, "entry.test.:443"); err == nil || !strings.Contains(err.Error(), "bind to interface") {
		t.Fatalf("bootstrap DNS escaped the bound interface: %v", err)
	}
	if queries.Load() != count {
		t.Fatal("DNS used another interface after binding failed")
	}
}

type entryResolverProbe struct {
	err     error
	calls   int
	address string
}

func (p *entryResolverProbe) ResolveUDPAddr(_ context.Context, address string) (*net.UDPAddr, error) {
	p.calls++
	p.address = address
	return nil, p.err
}
func (p *entryResolverProbe) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("dial before resolving entry")
}
func (p *entryResolverProbe) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("listen before resolving entry")
}

func TestQUICProtocolsUseEntryResolverOnReconnect(t *testing.T) {
	for _, link := range []string{
		"tuic://00000000-0000-0000-0000-000000000001:pass@entry.test:443",
		"juicity://00000000-0000-0000-0000-000000000001:pass@entry.test:443",
		"hysteria2://pass@entry.test:443",
		"hysteria2://pass@entry.test:443-445",
		"hysteria2://pass@entry.test",
		"hysteria2://pass@[::1]",
	} {
		t.Run(link, func(t *testing.T) {
			builder, _, err := parseNodeLink(link)
			if err != nil {
				t.Fatal(err)
			}
			probe := &entryResolverProbe{err: errors.New("entry DNS unavailable")}
			layer, err := builder.Build(&D.ExtraOption{}, D.NewUpstream(probe))
			if err != nil {
				t.Fatalf("construction must not resolve DNS: %v", err)
			}
			defer layer.Close()
			for range 2 {
				if err := layer.Sessions[0].Connect(t.Context()); !errors.Is(err, probe.err) {
					t.Fatalf("protocol bypassed entry resolver: %v", err)
				}
			}
			if probe.calls != 2 {
				t.Fatalf("reconnect performed %d lookups, want 2", probe.calls)
			}
			if host, _, err := net.SplitHostPort(probe.address); err != nil || host != "entry.test" && host != "::1" {
				t.Fatalf("invalid proxy resolver address: %s", probe.address)
			}
		})
	}
}
