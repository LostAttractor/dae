// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/settings"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"golang.org/x/sys/unix"
)

func TestUserspacePreparationCompilesStaticPlanBeforeInstances(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = io.WriteString(w, "module")
	}))
	defer server.Close()
	conf := outboundUsageConfig(t, `global {}
routing { pname(logical-prep) -> direct
fallback: block }`)
	conf.Global.SoMarkFromDae = 0 // Loopback-only fixture has no interception hooks.
	rules, err := PrepareRules(t.Context(), &conf.Routing, nil)
	if err != nil {
		t.Fatal(err)
	}
	built := 0
	load := func(client *http.Client) (PreparedMITM, error) {
		response, err := client.Get(server.URL)
		if err != nil {
			return PreparedMITM{}, err
		}
		_, err = io.Copy(io.Discard, response.Body)
		err = errors.Join(err, response.Body.Close())
		if err != nil {
			return PreparedMITM{}, err
		}
		prepared, err := PrepareMITMPlan(t.Context(), plugin.Plan{
			EarlyRoutes: planRulesForTest(t, "dip(127.0.0.1) -> block"),
		}, nil)
		prepared.BuildHost = func(context.Context) (*mitm.Host, error) {
			built++
			return nil, nil
		}
		return prepared, err
	}
	plane, err := NewUserspaceControlPlane(t.Context(), UserspaceResources{
		ProcessIdentity: &ProcessIdentity{PID: 123, Name: "logical-prep"},
	}, rules, nil, conf, new(settings.Store), load)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = plane.Close() })
	if built != 0 || plane.MITMHost() != nil || plane.core.bpf != nil || plane.Runtime() != nil || plane.routingState.bpf != nil || plane.udpEndpoints != nil || plane.tcpConnections != nil {
		t.Fatal("input preparation constructed live services or kernel resources")
	}
	if plane.core.domainRegistry.kernel.max != 0 || plane.core.domainRegistry.workerDone != nil {
		t.Fatal("preparation started kernel projection or persistence work")
	}
	client, closeClient := plane.NewPreparationClient()
	response, err := client.Get(server.URL)
	if response != nil {
		_ = response.Body.Close()
	}
	closeClient()
	if err == nil || requests.Load() != 1 {
		t.Fatalf("static plan did not replace base routing: requests=%d, error=%v", requests.Load(), err)
	}
	if err := plane.PrepareKernel(); err == nil {
		t.Fatal("unbound plane accepted kernel publication")
	}
	for range 2 {
		if err := plane.BuildServices(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if built != 1 {
		t.Fatalf("instances constructed %d times", built)
	}
	for range 2 {
		if err := plane.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := plane.BindKernel(nil); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed preparation accepted a binding: %v", err)
	}
}

func TestPreparationConnectivityProjectsOriginalFallbackLease(t *testing.T) {
	live := newFallbackTokenTestMap(t, 4)
	tokens := newFallbackTokens(live, newFallbackTokenTestSequence(t))
	connectivity, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 3, ValueSize: 8, MaxEntries: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer connectivity.Close()
	core := &controlPlaneCore{closed: t.Context()}
	lease := netproxy.NewLease(netproxy.NewResourceRef())
	id := uint8(consts.OutboundUserDefinedMin)
	callback := core.outboundAliveChangeCallback(id, "proxy", false, false, consts.OutboundDirect)
	if err := callback(outbound.Connectivity{Network: common.NetworkTCP4.NetworkType(), Fallback: lease}); err != nil {
		t.Fatal(err)
	}
	key := bpfOutboundConnectivityQuery{Outbound: id, L4proto: unix.IPPROTO_TCP, Ipversion: 4}
	if pending := core.outboundConnectivityValues[key]; pending.lease != lease || pending.Fallback != 0 {
		t.Fatal("unbound connectivity discarded its lease or issued a token")
	}
	core.bpf = &BPFState{Runtime: &Runtime{fallbacks: tokens}, bpfObjects: &bpfObjects{bpfMaps: bpfMaps{OutboundConnectivityMap: connectivity}}}
	if err := core.publishOutboundConnectivity(); err != nil {
		t.Fatal(err)
	}
	var value bpfOutboundConnectivity
	if err := connectivity.Lookup(key, &value); err != nil {
		t.Fatal(err)
	}
	if value.State != outboundConnectivityNoAliveDirect || value.Fallback == 0 || value.Fallback != tokens.token(lease) {
		t.Fatalf("binding lost the original fallback policy: %+v", value)
	}
	synctest.Test(t, func(t *testing.T) {
		lease.Abort(errors.New("test finished"))
		synctest.Wait()
	})
}
