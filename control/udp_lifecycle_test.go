package control

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"golang.org/x/sys/unix"
)

type udpLifecyclePacket struct {
	*testPacketConn
	lease  *netproxy.Lease
	writes chan netip.AddrPort
}

func (p *udpLifecyclePacket) DependencyLease() *netproxy.Lease { return p.lease }
func (p *udpLifecyclePacket) WriteTo(data []byte, dst net.Addr) (int, error) {
	p.writes <- addrPortOf(dst)
	return p.testPacketConn.WriteTo(data, dst)
}

type udpLifecycleDialer struct{ opened chan *udpLifecyclePacket }

func (d *udpLifecycleDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}
func (d *udpLifecycleDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	p := &udpLifecyclePacket{testPacketConn: newTestPacketConn(false), lease: netproxy.NewLease(netproxy.NewResourceRef()), writes: make(chan netip.AddrPort, 8)}
	d.opened <- p
	return p, nil
}

func TestUDPSourceKeepsRouteUntilFailureAndReusesPort(t *testing.T) {
	for _, device := range []bool{false, true} {
		t.Run(map[bool]string{false: "resource", true: "device"}[device], func(t *testing.T) {

			mapOf := func(name string, valueSize uint32) *ebpf.Map {
				m, err := ebpf.NewMap(&ebpf.MapSpec{Name: name, Type: ebpf.Hash,
					KeySize: uint32(unsafe.Sizeof(bpfUdpRoutingCacheKey{})), ValueSize: valueSize, MaxEntries: 16})
				if errors.Is(err, unix.EPERM) {
					t.Skip("creating a BPF map requires privileges")
				}
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = m.Close() })
				return m
			}
			bindings := mapOf("udp_bind_test", uint32(unsafe.Sizeof(uint64(0))))
			decisions := mapOf("udp_route_test", uint32(unsafe.Sizeof(bpfUdpRoutingCacheValue{})))
			newGroup := func(name string) (*outbound.DialerGroup, *udpLifecycleDialer) {
				data := &udpLifecycleDialer{opened: make(chan *udpLifecyclePacket, 8)}
				option := new(dialer.GlobalOption)
				d := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: data}), option, &dialer.Property{Name: name}, false, name)
				g := outbound.NewDialerGroup(option, name, outbound.GroupKindSingleAlwaysAlive,
					[]*dialer.Dialer{d}, []*dialer.Annotation{{}}, dialer.DialerSelectionPolicy{}, nil)
				t.Cleanup(func() { _ = g.Close() })
				return g, data
			}
			a, dataA := newGroup("a")
			b, dataB := newGroup("b")
			p := new(UdpEndpointPool)
			t.Cleanup(p.closeAll)
			c := &ControlPlane{deviceRoutes: newTestDeviceRoutes(t), udpEndpoints: p, outbounds: []*outbound.DialerGroup{nil, nil, a, b},
				core: &controlPlaneCore{bpf: &BPFState{bpfObjects: &bpfObjects{bpfMaps: bpfMaps{UdpBindingsMap: bindings, UdpRoutingCacheMap: decisions}}}}}
			src := netip.MustParseAddrPort("192.0.2.2:30000")
			first := netip.MustParseAddrPort("192.0.2.3:443")
			second := netip.MustParseAddrPort("192.0.2.4:8443")
			mac := [6]byte{2, 0, 0, 0, 0, 10}
			var epoch uint64
			send := func(dst netip.AddrPort, group uint8) {
				t.Helper()
				if err := c.handlePkt(context.Background(), []byte("datagram"), src, dst, &routingResult{Outbound: group, Mac: mac, RouteEpoch: epoch}); err != nil {
					t.Fatal(err)
				}
			}
			send(first, 2)
			connA := <-dataA.opened
			if got := <-connA.writes; got != first {
				t.Fatalf("first destination = %v", got)
			}
			// Readiness only controls new selections. It does not invalidate a working association.
			_ = a.Close()
			send(second, 3)
			if got := <-connA.writes; got != second {
				t.Fatalf("second destination = %v", got)
			}
			if len(dataB.opened) != 0 {
				t.Fatal("existing source silently changed nodes")
			}

			if device {
				if err := c.deviceRoutes.change(map[[6]byte]bool{mac: true}, func(commit func() error) error { return commit() }); err != nil {
					t.Fatal(err)
				}
				epoch++
			} else {
				connA.lease.Abort(netproxy.WrapFailure(errors.New("transport lost"), netproxy.Failure{Scope: netproxy.ScopeSharedResource}))
			}
			deadline := time.Now().Add(5 * time.Second)
			for {
				if _, exists := p.pool.Load(src); !exists {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("failed source was not released")
				}
				time.Sleep(time.Millisecond)
			}
			// Removal and re-publication use the same source lock, including BPF cleanup.
			send(second, 3)
			connB := <-dataB.opened
			if got := <-connB.writes; got != second {
				t.Fatalf("new lifetime destination = %v", got)
			}
			var bound uint64
			key := udpSourceKey(src)
			if err := bindings.Lookup(&key, &bound); err != nil {
				t.Fatalf("new source binding missing: %v", err)
			}

		})
	}
}

func TestUDPErrorsKeepOnlyRecoverableDatagrams(t *testing.T) {
	for _, tc := range []struct {
		name      string
		err       error
		temporary bool
	}{
		{"deadline", context.DeadlineExceeded, true},
		{"target capacity", netproxy.WrapFailure(errors.New("target limit"), netproxy.Failure{Scope: netproxy.ScopeOperation, Layer: netproxy.LayerUDP, Reason: netproxy.ReasonCapacity}), true},
		{"shared capacity", netproxy.WrapFailure(errors.New("resource limit"), netproxy.Failure{Scope: netproxy.ScopeSharedResource, Reason: netproxy.ReasonCapacity}), false},
		{"target unreachable", netproxy.WrapFailure(&net.OpError{Net: "udp", Err: unix.EHOSTUNREACH}, netproxy.Failure{Origin: netproxy.OriginTarget}), true},
		{"upstream unreachable", &net.OpError{Net: "udp", Err: unix.EHOSTUNREACH}, false},
		{"oversized packet", unix.EMSGSIZE, true},
		{"closed socket", net.ErrClosed, false},
		{"shared timeout", netproxy.WrapFailure(context.DeadlineExceeded, netproxy.Failure{Scope: netproxy.ScopeSharedResource}), false},
		{"joined terminal error", errors.Join(context.DeadlineExceeded, net.ErrClosed), false},
		{"TCP transport", &net.OpError{Net: "tcp", Err: unix.EHOSTUNREACH}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := temporaryUDPError(tc.err); got != tc.temporary {
				t.Fatalf("temporary = %v", got)
			}
		})
	}
}

func TestUDPDirectFallbackRetainsOriginalGroupPolicy(t *testing.T) {
	option := new(dialer.GlobalOption)
	makeGroup := func(name string, checked bool, kind outbound.GroupKind) *outbound.DialerGroup {
		d := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: dnsPathDialer{}}), option, &dialer.Property{Name: name}, checked, name)
		g := outbound.NewDialerGroup(option, name, kind, []*dialer.Dialer{d}, []*dialer.Annotation{{}}, dialer.DialerSelectionPolicy{}, nil)
		t.Cleanup(func() { _ = g.Close() })
		return g
	}
	direct := makeGroup("direct", false, outbound.GroupKindSingleAlwaysAlive)
	block := makeGroup("block", false, outbound.GroupKindInvisible)
	original := makeGroup("original", true, outbound.GroupKindSelector)
	original.SetConnectionPolicy(false, true)
	c := &ControlPlane{outbounds: []*outbound.DialerGroup{direct, block, original}, noConnectivityOutbound: consts.OutboundDirect}
	network := *common.NetworkUDP4.NetworkType()
	route, err := c.RouteDialOption(context.Background(), &RouteParam{routingResult: &routingResult{Outbound: 2}, networkType: network, Dest: netip.MustParseAddrPort("192.0.2.1:443")})
	if err != nil {
		t.Fatal(err)
	}
	if !route.Direct || route.OriginalOutbound != original || route.PolicyLease == nil {
		t.Fatalf("fallback lost group ownership: %+v", route)
	}
	originalSelection, err := original.SelectConnection(network, true)
	if !errors.Is(err, outbound.ErrNoAliveDialer) || originalSelection.Lease != route.PolicyLease {
		t.Fatalf("fallback policy is not owned by original group")
	}
	c.noConnectivityOutbound = consts.OutboundBlock
	route, err = c.RouteDialOption(context.Background(), &RouteParam{routingResult: &routingResult{Outbound: 2}, networkType: network, Dest: netip.MustParseAddrPort("192.0.2.1:443")})
	if err != nil || route.Outbound != block {
		t.Fatalf("block fallback = %+v, %v", route, err)
	}
}
