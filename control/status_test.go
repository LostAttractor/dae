/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/prometheus/client_golang/prometheus"
)

type statusTestDialer struct{}

func (statusTestDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, fmt.Errorf("not implemented")
}
func (statusTestDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, fmt.Errorf("not implemented")
}

func TestStatusServerReturnsUnavailableWithoutPublishedPlane(t *testing.T) {
	server := &StatusServer{version: "test"}
	response := httptest.NewRecorder()
	server.handleStatus(response, httptest.NewRequest(http.MethodGet, "/status", nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status code = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
}

func TestStartStatusServerPreservesLiveSocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "status.sock")
	server, err := StartStatusServer(socketPath, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	second, err := StartStatusServer(socketPath, "test")
	if second != nil {
		defer second.Close()
	}
	if err == nil {
		t.Fatal("starting a second status server unexpectedly succeeded")
	}

	conn, err := net.DialTimeout("unix", socketPath, time.Second)
	if err != nil {
		t.Fatalf("original status socket became unreachable: %v", err)
	}
	_ = conn.Close()
}

func TestStartStatusServerReplacesStaleSocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "status.sock")
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	if err = stale.Close(); err != nil {
		t.Fatal(err)
	}

	server, err := StartStatusServer(socketPath, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	conn, err := net.DialTimeout("unix", socketPath, time.Second)
	if err != nil {
		t.Fatalf("replacement status socket is unreachable: %v", err)
	}
	_ = conn.Close()
}

func TestStartStatusServerPreservesNonSocketPath(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "status.sock")
	want := []byte("do not remove")
	if err := os.WriteFile(socketPath, want, 0600); err != nil {
		t.Fatal(err)
	}

	server, err := StartStatusServer(socketPath, "test")
	if server != nil {
		defer server.Close()
	}
	if err == nil {
		t.Fatal("starting on a non-socket path unexpectedly succeeded")
	}
	got, readErr := os.ReadFile(socketPath)
	if readErr != nil {
		t.Fatalf("occupied path was removed: %v", readErr)
	}
	if string(got) != string(want) {
		t.Fatalf("occupied path contents = %q, want %q", got, want)
	}
}

func TestCollectConnCountsKeepsSameNamedNodesSeparate(t *testing.T) {
	registry := prometheus.NewRegistry()
	common.InitPrometheus(registry)
	group := t.Name()
	network := common.IndexToNetworkType(0).String()
	labelsA := prometheus.Labels{
		"id": "node-a-id", "outbound": group, "subtag": "sub", "dialer": "same-name", "network": network,
	}
	labelsB := prometheus.Labels{
		"id": "node-b-id", "outbound": group, "subtag": "sub", "dialer": "same-name", "network": network,
	}
	defer common.ActiveConnections.Delete(labelsA)
	defer common.ActiveConnections.Delete(labelsB)
	defer common.TotalConnections.Delete(labelsA)
	defer common.TotalConnections.Delete(labelsB)

	common.ActiveConnections.With(labelsA).Set(2)
	common.ActiveConnections.With(labelsB).Set(5)
	common.TotalConnections.With(labelsA).Add(3)
	common.TotalConnections.With(labelsB).Add(7)

	counts := (&ControlPlane{PrometheusRegistry: registry}).collectConnCounts()
	if got := counts.byGroupNode[groupNodeKey{group: group, id: "node-a-id", subtag: "sub", name: "same-name"}]; got != (connValues{active: 2, total: 3}) {
		t.Fatalf("node A counts = %+v", got)
	}
	if got := counts.byGroupNode[groupNodeKey{group: group, id: "node-b-id", subtag: "sub", name: "same-name"}]; got != (connValues{active: 5, total: 7}) {
		t.Fatalf("node B counts = %+v", got)
	}
	if got := counts.byGroupNetwork[groupNetworkKey{group: group, network: 0}]; got != (connValues{active: 7, total: 10}) {
		t.Fatalf("group/network counts = %+v", got)
	}
}

func TestConnCountsKeepsAliasesSeparate(t *testing.T) {
	counts := newConnCounts()
	counts.add("group", "shared-id", "sub", "alias-a", 0, true, 2)
	counts.add("group", "shared-id", "sub", "alias-b", 0, true, 5)
	if got := counts.byGroupNode[groupNodeKey{group: "group", id: "shared-id", subtag: "sub", name: "alias-a"}]; got.active != 2 {
		t.Fatalf("alias A active connections = %d, want 2", got.active)
	}
	if got := counts.byGroupNode[groupNodeKey{group: "group", id: "shared-id", subtag: "sub", name: "alias-b"}]; got.active != 5 {
		t.Fatalf("alias B active connections = %d, want 5", got.active)
	}
	if got := counts.byGroupNodeID[groupNodeIDKey{group: "group", id: "shared-id"}]; got.active != 7 {
		t.Fatalf("stable ID active connections = %d, want 7", got.active)
	}
}

func TestGroupHealth(t *testing.T) {
	tests := []struct {
		name     string
		group    GroupStatus
		critical bool
		want     HealthStatus
	}{
		{
			name:     "available group",
			group:    GroupStatus{Connectivity: &GroupConnectivityStatus{Available: true}},
			critical: true,
			want:     HealthHealthy,
		},
		{
			name:     "critical group is unavailable",
			group:    GroupStatus{Connectivity: &GroupConnectivityStatus{}},
			critical: true,
			want:     HealthDegraded,
		},
		{
			name:  "non-critical group is unavailable",
			group: GroupStatus{Connectivity: &GroupConnectivityStatus{}},
			want:  HealthWarning,
		},
		{
			name:     "no-check group",
			critical: true,
			want:     HealthHealthy,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := groupHealth(tt.group, tt.critical); got != tt.want {
				t.Fatalf("groupHealth() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCombineHealth(t *testing.T) {
	health := combineHealth(HealthHealthy, HealthWarning)
	health = combineHealth(health, HealthDegraded)
	health = combineHealth(health, HealthHealthy)
	if health != HealthDegraded {
		t.Fatalf("combined health = %q, want %q", health, HealthDegraded)
	}
}

func TestStatusSnapshotReportsDomainHistory(t *testing.T) {
	prometheusRegistry := prometheus.NewRegistry()
	common.InitPrometheus(prometheusRegistry)
	domainRegistry, _ := newTestRegistry(16, 32, 0)
	now := time.Now()
	domainRegistry.Upsert(
		queryInfo{qname: "live.example.", qtype: 1},
		netip.MustParseAddr("1.1.1.1"),
		testBitmap(),
		60,
		now,
	)
	domainRegistry.Upsert(
		queryInfo{qname: "retained.example.", qtype: 1},
		netip.MustParseAddr("2.2.2.2"),
		testBitmap(),
		1,
		now.Add(-time.Minute),
	)

	plane := &ControlPlane{
		core:               &controlPlaneCore{domainRegistry: domainRegistry},
		PrometheusRegistry: prometheusRegistry,
	}
	tables := plane.StatusSnapshot("test").Tables
	if len(tables) != 2 {
		t.Fatalf("table count = %d, want 2", len(tables))
	}
	history := tables[len(tables)-1]
	if history.Name != "domain-history" || history.Used != 2 || history.Breakdown == nil {
		t.Fatalf("domain history table = %+v", history)
	}
	if history.Breakdown.LimitGC != 0 {
		t.Fatalf("domain history GC state = %+v", history)
	}
	if history.Breakdown.Live != 1 || history.Breakdown.Retained != 1 {
		t.Fatalf("domain history breakdown = %+v, want 1 live and 1 retained", history.Breakdown)
	}
}

func TestStatusSnapshotAggregatesGroupHealth(t *testing.T) {
	registry := prometheus.NewRegistry()
	common.InitPrometheus(registry)
	option := &dialer.GlobalOption{}
	policy := dialer.DialerSelectionPolicy{
		Policy:     consts.DialerSelectionPolicy_Fixed,
		FixedIndex: 0,
	}
	callback := func(bool, *common.NetworkType) error { return nil }
	directDialer := dialer.NewDialer(netproxy.NewRuntime(statusTestDialer{}), option, &dialer.Property{Property: D.Property{
		Name: "direct",
		Link: "direct://",
	}}, dialer.InitialCheckDisabled)
	blockDialer := dialer.NewDialer(netproxy.NewRuntime(statusTestDialer{}), option, &dialer.Property{Property: D.Property{
		Name: "block",
		Link: "block://",
	}}, dialer.InitialCheckDisabled)
	direct := outbound.NewDialerGroup(option, "direct", outbound.GroupKindSingleAlwaysAlive,
		[]*dialer.Dialer{directDialer}, []*dialer.Annotation{{}}, dialer.DialerSelectionPolicy{}, callback)
	block := outbound.NewDialerGroup(option, "block", outbound.GroupKindInvisible,
		[]*dialer.Dialer{blockDialer}, []*dialer.Annotation{{}}, dialer.DialerSelectionPolicy{}, callback)
	t.Cleanup(func() {
		_ = direct.Close()
		_ = block.Close()
	})

	node := dialer.NewDialer(netproxy.NewRuntime(statusTestDialer{}), option, &dialer.Property{Property: D.Property{
		Name: t.Name(),
		Link: "test://" + t.Name(),
	}}, dialer.InitialCheckBlocking)
	group := outbound.NewDialerGroup(
		option,
		t.Name(),
		outbound.GroupKindSelector,
		[]*dialer.Dialer{node},
		[]*dialer.Annotation{{}},
		policy,
		callback,
	)
	defer group.Close()

	plane := &ControlPlane{
		outbounds:          []*outbound.DialerGroup{direct, block, group},
		criticalOutbounds:  []bool{false, false, true},
		PrometheusRegistry: registry,
	}
	snapshot := plane.StatusSnapshot("test")
	if directStatus := snapshot.Groups[0]; directStatus.Connectivity != nil || directStatus.Policy != "" {
		t.Fatalf("direct status = %+v, want singleton without connectivity or policy", directStatus)
	}
	if snapshot.Health != HealthDegraded || snapshot.Groups[1].Health != HealthDegraded {
		t.Fatalf("health = %q/%q, want degraded", snapshot.Health, snapshot.Groups[1].Health)
	}
	if snapshot.Groups[1].Connectivity == nil || snapshot.Groups[1].Connectivity.Available || snapshot.Groups[1].Networks[0].SupportState != "unknown" {
		t.Fatalf("group/tcp4 status = %+v/%+v, want unavailable and unknown", snapshot.Groups[1], snapshot.Groups[1].Networks[0])
	}
	if got := snapshot.Groups[1].Nodes[0].Networks[0].SupportState; got != "unknown" {
		t.Fatalf("tcp4 support state = %q, want unknown", got)
	}

	plane.criticalOutbounds[2] = false
	snapshot = plane.StatusSnapshot("test")
	if snapshot.Health != HealthWarning || snapshot.Groups[1].Health != HealthWarning {
		t.Fatalf("health = %q/%q, want warning", snapshot.Health, snapshot.Groups[1].Health)
	}
}

func TestStatusSnapshotDoesNotSelectUnknownNetwork(t *testing.T) {
	registry := prometheus.NewRegistry()
	common.InitPrometheus(registry)
	option := &dialer.GlobalOption{}
	policy := dialer.DialerSelectionPolicy{
		Policy:     consts.DialerSelectionPolicy_Fixed,
		FixedIndex: 0,
	}
	node := dialer.NewDialer(netproxy.NewRuntime(statusTestDialer{}), option, &dialer.Property{Property: D.Property{
		Name: t.Name(),
		Link: "test://" + t.Name(),
	}}, dialer.InitialCheckBlocking)
	group := outbound.NewDialerGroup(
		option,
		t.Name(),
		outbound.GroupKindSelector,
		[]*dialer.Dialer{node},
		[]*dialer.Annotation{{}},
		policy,
		func(bool, *common.NetworkType) error { return nil },
	)
	defer group.Close()

	plane := &ControlPlane{
		outbounds:          []*outbound.DialerGroup{group},
		criticalOutbounds:  []bool{true},
		PrometheusRegistry: registry,
	}
	snapshot := plane.StatusSnapshot("test")
	status := snapshot.Groups[0].Networks[2]
	if status.SupportState != "unknown" {
		t.Fatalf("udp4 status = %+v, want unknown and not advertised as supported", status)
	}
	if status.Selected != nil {
		t.Fatalf("unknown capability exposed tentative selection %+v", status.Selected)
	}
	if snapshot.Groups[0].Nodes[0].Networks[2].SupportState != "unknown" {
		t.Fatal("unknown node capability was advertised as supported")
	}
	if snapshot.Groups[0].Connectivity == nil || snapshot.Groups[0].Connectivity.Available {
		t.Fatal("unknown network capability made the group available")
	}
}

func TestStatusSnapshotReportsSingletonNodeMetadata(t *testing.T) {
	registry := prometheus.NewRegistry()
	common.InitPrometheus(registry)
	option := &dialer.GlobalOption{}
	property := &dialer.Property{
		Property: D.Property{Name: "entry -> exit", Protocol: "socks -> ss", Address: "entry -> exit", Link: "path"},
		Hops: []dialer.Hop{
			{ID: "entry-id", Name: "entry", Subtag: "a", Protocol: "socks", Address: "entry.example:1080"},
			{ID: "exit-id", Name: "exit", Subtag: "b", Protocol: "ss", Address: "exit.example:443"},
		},
	}
	node := dialer.NewDialerRuntimeWithStatsScope(netproxy.NewRuntime(statusTestDialer{}), option, property, dialer.InitialCheckAsync, "")
	group := outbound.NewDialerGroup(
		option,
		"direct node target",
		outbound.GroupKindSelector,
		[]*dialer.Dialer{node},
		[]*dialer.Annotation{{
			AddLatency: 30 * time.Millisecond,
			Priority:   2,
			PriorityTerms: []*dialer.PriorityTerm{{
				Default:     2,
				Conditional: []*dialer.Priority{{Pri: 4, Low: 100 * time.Millisecond}},
			}},
		}},
		dialer.DialerSelectionPolicy{},
		func(bool, *common.NetworkType) error { return nil },
	).SetTargetMetadata(outbound.TargetKindNode)
	t.Cleanup(func() {
		_ = group.Close()
	})
	plane := &ControlPlane{outbounds: []*outbound.DialerGroup{group}, PrometheusRegistry: registry}
	status := plane.StatusSnapshot("test").Groups[0]
	if status.TargetKind != "node" || status.Policy != "" {
		t.Fatalf("target metadata = kind %q, policy %q", status.TargetKind, status.Policy)
	}
	if got := status.Nodes[0].Hops; len(got) != 2 || got[0].Name != "entry" || got[1].Name != "exit" {
		t.Fatalf("structured hops = %+v", got)
	}
	annotation := status.Nodes[0].Annotation
	if annotation == nil || annotation.AddLatency != "30ms" || annotation.Priority == nil || *annotation.Priority != 2 || !annotation.PriorityConditional || !status.Nodes[0].CheckAsync {
		t.Fatalf("node annotation = %+v", annotation)
	}
}
