// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/miekg/dns"
)

type sharedCheckTransport struct{ queries atomic.Int32 }

func (d *sharedCheckTransport) DialContext(_ context.Context, network, _ string) (net.Conn, error) {
	if network != "tcp" {
		return nil, netproxy.UnsupportedTunnelTypeError
	}
	d.queries.Add(1)
	client, peer := net.Pipe()
	go func() {
		defer peer.Close()
		conn := &dns.Conn{Conn: peer}
		query, err := conn.ReadMsg()
		if err != nil {
			return
		}
		response := new(dns.Msg).SetReply(query)
		response.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET},
			A:   net.IPv4(192, 0, 2, 1),
		}}
		_ = conn.WriteMsg(response)
	}()
	return client, nil
}

func (*sharedCheckTransport) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, netproxy.UnsupportedTunnelTypeError
}

func TestSharedRuntimeAcrossAutomaticAndManualGroups(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		option := &dialer.GlobalOption{
			CheckInterval: time.Hour, CheckIntervalMax: time.Hour,
			CheckDnsOptionRaw: dialer.CheckDnsOptionRaw{Raw: []string{"dns.test:53", "127.0.0.1", "::1"}},
		}
		transport := new(sharedCheckTransport)
		first := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: transport}), option, &dialer.Property{Name: "shared", Link: "shared"}, true, "automatic")
		second, ok := first.Share(first.Property, "manual")
		if !ok {
			t.Fatal("share failed")
		}
		alternative := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: new(sharedCheckTransport)}), option, &dialer.Property{Name: "alternative", Link: "alternative"}, true, "manual")
		automatic := NewDialerGroup(option, "automatic", GroupKindSelector, []*dialer.Dialer{first}, emptyAnnotations(1), dialer.DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_MinMovingAverageLatencies, EmaAlpha: 0.5,
		}, nil)
		manual := NewDialerGroup(option, "manual", GroupKindSelector, []*dialer.Dialer{second, alternative}, emptyAnnotations(2), dialer.DialerSelectionPolicy{
			Policy: consts.DialerSelectionPolicy_Selector, EmaAlpha: 0.25,
		}, nil)
		defer automatic.Close()
		defer manual.Close()
		start := make(chan struct{})
		for _, group := range []*DialerGroup{automatic, manual} {
			if _, err := group.StartConnectivityChecks(start); err != nil {
				t.Fatal(err)
			}
		}
		close(start)
		synctest.Wait()
		for _, group := range []*DialerGroup{automatic, manual} {
			select {
			case <-group.startupReady:
			default:
				t.Fatal("shared initial check did not release both startup barriers")
			}
			if state, _ := group.Connectivity(); state != api.GroupStateAvailable {
				t.Fatalf("%s state=%s", group.Name, state)
			}
		}
		if transport.queries.Load() != 2 {
			t.Fatalf("shared TCP4/TCP6 initial probes ran %d times, want 2", transport.queries.Load())
		}
		network := common.NetworkTCP4.NetworkType()
		if automatic.SelectedDialer(network) != first || manual.SelectedDialer(network) != second {
			t.Fatal("groups lost their own selected members")
		}

		late, ok := first.Share(first.Property, "late-plugin-group")
		if !ok {
			t.Fatal("late share failed")
		}
		lateGroup := NewDialerGroup(option, "late", GroupKindSelector, []*dialer.Dialer{late}, emptyAnnotations(1), dialer.DialerSelectionPolicy{}, nil)
		defer lateGroup.Close()
		ready, err := lateGroup.StartConnectivityChecks(make(chan struct{}))
		if err != nil {
			t.Fatal(err)
		}
		select {
		case <-ready:
		default:
			t.Fatal("late group did not reuse established health")
		}
		_ = lateGroup.Close()
		if err := manual.SetSelection(alternative.StatsID()); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if automatic.SelectedDialer(network) != first || manual.SelectedDialer(network) != alternative || !first.RuntimeStatus().CheckEnabled || second.RuntimeStatus().CheckEnabled {
			t.Fatal("manual selection changed the automatic group's choice or tracking")
		}
		_ = automatic.Close()
		before := transport.queries.Load()
		if err := manual.SetSelection(second.StatsID()); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if manual.SelectedDialer(network) != second || !second.RuntimeStatus().Healthy {
			t.Fatal("closing the automatic group retired the manual group's runtime")
		}
		if transport.queries.Load() <= before {
			t.Fatal("reselecting the shared path did not resume connectivity checks")
		}
	})
}
