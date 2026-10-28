/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	dnsmessage "github.com/miekg/dns"
)

// Only a proxy receives the sniffed name. A direct connection, including the
// no-connectivity fallback of a proxy group, dials the client's address.
func TestDialTargetOverrideAppliesOnlyToProxies(t *testing.T) {
	unused := downloadTestDialer(func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed })
	global := &dialer.GlobalOption{}
	unavailable := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: unused}), global, &dialer.Property{Name: "unavailable"}, true, "")
	dead := outbound.NewDialerGroup(global, "dead", outbound.GroupKindSelector, []*dialer.Dialer{unavailable}, []*dialer.Annotation{{}}, dialer.DialerSelectionPolicy{})
	t.Cleanup(func() { dead.Close() })
	plane := &ControlPlane{noConnectivityOutbound: consts.OutboundDirect, outbounds: []*outbound.DialerGroup{
		downloadTestGroup(t, "direct", unused), downloadTestGroup(t, "block", unused), downloadTestGroup(t, "proxy", unused), dead,
	}}
	destination := netip.MustParseAddrPort("192.0.2.2:443")
	for _, test := range []struct {
		outbound consts.OutboundIndex
		network  *common.NetworkType
		want     string
	}{
		{consts.OutboundDirect, common.NetworkTCP4.NetworkType(), destination.String()},
		{2, common.NetworkTCP4.NetworkType(), "example.com:443"},
		{2, common.NetworkUDP4.NetworkType(), destination.String()},
		{3, common.NetworkTCP4.NetworkType(), destination.String()},
	} {
		p := &RouteParam{Src: netip.MustParseAddrPort("192.0.2.1:12345"), Dest: destination, Domain: "example.com", networkType: *test.network, routingResult: &routingResult{}}
		option, err := plane.selectDialOption(t.Context(), p, test.outbound, 0, true, nil)
		if err != nil {
			t.Fatal(err)
		}
		if option.DialTarget != test.want || (test.outbound == 3) != (option.OriginalOutbound == dead) {
			t.Fatalf("%s via %s: dial target %s, want %s", test.network, plane.outbounds[test.outbound].Name, option.DialTarget, test.want)
		}
	}
}

func TestDirectDialerForMarkCachesOverrides(t *testing.T) {
	c := &ControlPlane{soMarkFromDae: 7}
	if got := c.directDialerForMark(consts.OutboundUserDefinedMin, 8); got != nil {
		t.Fatal("non-direct outbound received a marked direct dialer")
	}
	if got := c.directDialerForMark(consts.OutboundDirect, 7); got != nil {
		t.Fatal("global mark unnecessarily replaced the configured direct dialer")
	}
	first := c.directDialerForMark(consts.OutboundDirect, 8)
	second := c.directDialerForMark(consts.OutboundDirect, 8)
	if first == nil || first != second {
		t.Fatal("marked direct dialer was not cached")
	}
}

func TestRoutingLogFieldsOmitUnavailableMetadata(t *testing.T) {
	if fields := routingLogFields(new(routingResult), ""); len(fields) != 0 {
		t.Fatalf("zero routing metadata = %#v, want empty", fields)
	}

	result := &routingResult{
		Pid:  42,
		Dscp: 4,
		Mac:  [6]uint8{0x02, 0x42, 0xac, 0x11, 0x00, 0x02},
	}
	copy(result.Pname[:], "curl")
	fields := routeLogFields(result, "lan0", "tcp4", "192.0.2.1:1234", "example.com:443")
	if len(fields) != 9 || fields["pid"] != uint32(42) || fields["pname"] != "curl" ||
		fields["interface"] != "lan0" || fields["dscp"] != uint8(4) || fields["mac"] != "02:42:ac:11:00:02" {
		t.Fatalf("routing metadata = %#v", fields)
	}
	if fields["action"] != "forward" || fields["network"] != "tcp4" ||
		fields["source"] != "192.0.2.1:1234" || fields["destination"] != "example.com:443" {
		t.Fatalf("route fields = %#v", fields)
	}
	if _, ok := fields["ifindex"]; ok {
		t.Fatal("routing metadata exposed a numeric ifindex")
	}
}

// checkedTransport answers DNS over TCP, including connectivity checks.
// ipv6Only rejects IPv4 targets, so only the tcp6 capability is confirmed.
type checkedTransport struct {
	delay    time.Duration
	offline  bool
	ipv6Only bool
	dials    sync.Map // Address to *atomic.Int32.
}

func (d *checkedTransport) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" || d.ipv6Only && !strings.HasPrefix(address, "[") {
		return nil, netproxy.UnsupportedTunnelTypeError
	}
	count, _ := d.dials.LoadOrStore(address, new(atomic.Int32))
	count.(*atomic.Int32).Add(1)
	select {
	case <-time.After(d.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if d.offline {
		return nil, errors.New("proxy unavailable")
	}
	client, peer := net.Pipe()
	go func() {
		defer peer.Close()
		conn := &dnsmessage.Conn{Conn: peer}
		for {
			query, err := conn.ReadMsg()
			if err != nil {
				return
			}
			response := new(dnsmessage.Msg).SetReply(query)
			response.Answer = []dnsmessage.RR{&dnsmessage.A{
				Hdr: dnsmessage.RR_Header{Name: query.Question[0].Name, Rrtype: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
				A:   net.IPv4(192, 0, 2, 1),
			}}
			if conn.WriteMsg(response) != nil {
				return
			}
		}
	}()
	return client, nil
}

func (*checkedTransport) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, netproxy.UnsupportedTunnelTypeError
}

// checkedPlane routes outbound index 2 to an automatic group of one node per
// transport.
func checkedPlane(t *testing.T, policy consts.DialerSelectionPolicy, transports ...*checkedTransport) (*ControlPlane, *outbound.DialerGroup) {
	t.Helper()
	option := &dialer.GlobalOption{CheckInterval: time.Hour, CheckIntervalMax: time.Hour,
		CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{"dns.test:53", "127.0.0.1", "::1"}}}
	var nodes []*dialer.Dialer
	var annotations []*dialer.Annotation
	for i, transport := range transports {
		name := fmt.Sprint("node", i)
		nodes = append(nodes, dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: transport}), option, &dialer.Property{Name: name, Link: "test://" + t.Name() + "/" + name}, true, ""))
		annotations = append(annotations, &dialer.Annotation{})
	}
	group := outbound.NewDialerGroup(option, "proxy", outbound.GroupKindSelector, nodes, annotations,
		dialer.DialerSelectionPolicy{Policy: policy, SelectionTimeout: time.Second})
	t.Cleanup(func() { group.Close() })
	unused := downloadTestDialer(func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed })
	plane := &ControlPlane{noConnectivityOutbound: consts.OutboundDirect, outbounds: []*outbound.DialerGroup{
		downloadTestGroup(t, "direct", unused), downloadTestGroup(t, "block", unused), group,
	}}
	start := make(chan struct{})
	if _, err := group.StartConnectivityChecks(start); err != nil {
		t.Fatal(err)
	}
	close(start)
	return plane, group
}

func TestFailedElectionDegradesWithoutQueueing(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		plane, group := checkedPlane(t, consts.DialerSelectionPolicy_Failover, &checkedTransport{delay: 20 * time.Millisecond, offline: true})
		p := &RouteParam{Src: netip.MustParseAddrPort("192.0.2.1:12345"), Dest: netip.MustParseAddrPort("192.0.2.2:443"),
			networkType: *common.NetworkTCP4.NetworkType(), routingResult: &routingResult{}}
		began := time.Now()
		option, err := plane.selectDialOption(t.Context(), p, 2, 0, false, nil)
		if err != nil || option.OriginalOutbound != group || !option.Direct || time.Since(began) == 0 || time.Since(began) >= time.Second {
			t.Fatalf("startup election did not degrade after its result: %+v, %v after %v", option, err, time.Since(began))
		}
		began = time.Now()
		option, err = plane.selectDialOption(t.Context(), p, 2, 0, false, nil)
		if err != nil || option.OriginalOutbound != group || time.Since(began) != 0 {
			t.Fatalf("election backoff queued a request: %v after %v", err, time.Since(began))
		}
	})
}

func TestRewrittenDestinationSelectsByItsFamily(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		plane, group := checkedPlane(t, consts.DialerSelectionPolicy_MinLastLatency, &checkedTransport{ipv6Only: true})
		time.Sleep(time.Second)
		synctest.Wait()
		if group.Available(*common.NetworkTCP4.NetworkType()) || !group.Available(*common.NetworkTCP6.NetworkType()) {
			t.Fatal("fixture did not publish an IPv6-only group")
		}
		p := &RouteParam{Src: netip.MustParseAddrPort("192.0.2.1:12345"), Dest: netip.MustParseAddrPort("192.0.2.2:443"),
			destination: netip.MustParseAddrPort("[2001:db8::2]:443"), networkType: *common.NetworkTCP4.NetworkType(), routingResult: &routingResult{}}
		option, err := plane.selectDialOption(t.Context(), p, 2, 0, false, nil)
		if err != nil || option.OriginalOutbound != nil || option.Outbound != group || option.NetworkType.IpVersion != consts.IpVersionStr_6 {
			t.Fatalf("IPv4 ingress rewritten to IPv6 degraded: %+v, %v", option, err)
		}
	})
}

func TestEndedRequestDoesNotDegrade(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		plane, _ := checkedPlane(t, consts.DialerSelectionPolicy_Failover, &checkedTransport{delay: time.Hour})
		p := &RouteParam{Src: netip.MustParseAddrPort("192.0.2.1:12345"), Dest: netip.MustParseAddrPort("192.0.2.2:443"),
			networkType: *common.NetworkTCP4.NetworkType(), routingResult: &routingResult{}}
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
		defer cancel()
		began := time.Now()
		if _, err := plane.selectDialOption(ctx, p, 2, 0, false, nil); !errors.Is(err, context.DeadlineExceeded) || time.Since(began) != 10*time.Millisecond {
			t.Fatalf("ended request: %v after %v", err, time.Since(began))
		}
	})
}
