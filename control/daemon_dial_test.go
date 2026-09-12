// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/outbound"
	"golang.org/x/sys/unix"
)

func TestInternalDNSRoutesTransportWithDaemonIdentity(t *testing.T) {
	identity := daemonProcessIdentity()
	process := strings.TrimRight(string(identity.Pname[:]), "\x00")
	for _, network := range []string{"udp", "tcp"} {
		for _, port := range []string{"53", "1053", "1054"} {
			t.Run(network+"/"+port, func(t *testing.T) {
				selected := ""
				group := func(name string) *outbound.DialerGroup {
					return downloadTestGroup(t, name, func(_ context.Context, gotNetwork, address string) (net.Conn, error) {
						selected = name
						if gotNetwork != network || address != "192.0.2.53:"+port {
							t.Errorf("transport changed: %s %s", gotNetwork, address)
						}
						conn, peer := net.Pipe()
						_ = peer.Close()
						return conn, nil
					})
				}
				c := downloadTestPlane(t, "dip(192.0.2.53) && dport(1053) -> block\n"+
					"pname('"+process+"') && sip(0.0.0.0) && dip(192.0.2.53) && dport(53) && l4proto("+network+") -> proxy(mark:91)",
					group("direct"), group("block"), group("proxy"))
				g, _ := newTestRegistry(8, time.Hour)
				c.core.domainRegistry = g
				conn, err := c.DNSResolverDialer()(context.Background(), network, netip.MustParseAddrPort("192.0.2.53:"+port))
				if port == "1053" {
					if err == nil || selected != "" || !strings.Contains(err.Error(), "blocked by routing") {
						t.Fatalf("block = %v, selected=%s", err, selected)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				_ = conn.Close()
				want := "direct"
				if port == "53" {
					want = "proxy"
				}
				if selected != want || g.Size() != 0 {
					t.Fatalf("outbound=%s want=%s, evidence=%d", selected, want, g.Size())
				}
			})
		}
	}
}

func TestInternalDNSDirectMark(t *testing.T) {
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	group := downloadTestGroup(t, "direct", func(context.Context, string, string) (net.Conn, error) {
		t.Error("route mark did not select the marked direct dialer")
		return nil, net.ErrClosed
	})
	c := downloadTestPlane(t, "dip(127.0.0.1) -> direct(mark:9029)", group)
	c.soMarkFromDae = 0x100
	conn, err := c.DNSResolverDialer()(context.Background(), "udp", netip.MustParseAddrPort(server.LocalAddr().String()))
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("SO_MARK needs privileges: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	socket := conn.(*dnsUpstreamConn).Conn.(*mitmUpstreamConn).Conn.(syscall.Conn)
	raw, err := socket.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var mark int
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		mark, sockErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK)
	}); err != nil {
		t.Fatal(err)
	}
	if sockErr != nil || mark != 9029 {
		t.Fatalf("DNS socket mark=%d, error=%v", mark, sockErr)
	}
}

func TestInternalDNSDestinationControls(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		calls := 0
		proxy := downloadTestGroup(t, "proxy", func(_ context.Context, gotNetwork, address string) (net.Conn, error) {
			calls++
			if gotNetwork != network || address != "198.51.100.53:1053" {
				t.Errorf("DNAT dial: %s %s", gotNetwork, address)
			}
			conn, peer := net.Pipe()
			_ = peer.Close()
			return conn, nil
		})
		unexpected := func(context.Context, string, string) (net.Conn, error) {
			t.Error("DNS destination controls chose the wrong outbound")
			return nil, net.ErrClosed
		}
		prepared := prepareFlowRulesForTest(t,
			"dip(192.0.2.53) && dport(53) -> dnat('198.51.100.53:1053')\ndip(198.51.100.53) -> must",
			"dip(198.51.100.53) && dport(1053) -> proxy(mark:91)")
		matcher, _ := routingMatcherForTest(t, prepared)
		c := &ControlPlane{core: &controlPlaneCore{}, routingMatcher: matcher, outbounds: []*outbound.DialerGroup{
			downloadTestGroup(t, "direct", unexpected), downloadTestGroup(t, "block", unexpected), proxy,
		}}
		conn, err := c.DNSResolverDialer()(context.Background(), network, netip.MustParseAddrPort("192.0.2.53:53"))
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
		if calls != 1 {
			t.Fatalf("rewritten DNS dials = %d", calls)
		}
	}
}
