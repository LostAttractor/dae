/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"encoding/json"
	"errors"
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

type statusTestSession struct{ state *netproxy.StateBroadcaster }

func newStatusTestSession(state netproxy.SessionState) *statusTestSession {
	return &statusTestSession{state: netproxy.NewStateBroadcaster(state)}
}
func (s *statusTestSession) Connect(context.Context) error {
	s.state.Transition(netproxy.SessionConnected, nil)
	return nil
}
func (s *statusTestSession) Snapshot() netproxy.StateEvent { return s.state.Snapshot() }
func (s *statusTestSession) WatchState(ctx context.Context) <-chan netproxy.StateEvent {
	return s.state.WatchState(ctx)
}
func (s *statusTestSession) Close() error {
	s.state.Transition(netproxy.SessionClosed, nil)
	return nil
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
	if got := counts.byGroupNode[groupNodeKey{group: group, id: "node-a-id"}]; got != (connValues{active: 2, total: 3}) {
		t.Fatalf("node A counts = %+v", got)
	}
	if got := counts.byGroupNode[groupNodeKey{group: group, id: "node-b-id"}]; got != (connValues{active: 5, total: 7}) {
		t.Fatalf("node B counts = %+v", got)
	}
	if got := counts.byGroupNetwork[groupNetworkKey{group: group, network: 0}]; got != (connValues{active: 7, total: 10}) {
		t.Fatalf("group/network counts = %+v", got)
	}
}

func TestFailureEpisodeJSONFields(t *testing.T) {
	startedAt := time.Date(2026, time.August, 9, 12, 0, 0, 0, time.UTC)
	payload := struct {
		Group GroupStatus `json:"group"`
		Node  NodeStatus  `json:"node"`
	}{
		Group: GroupStatus{
			LastFailureStartedAt: &startedAt,
			LastFailureDuration:  17 * time.Minute,
		},
		Node: NodeStatus{
			LastFailureStartedAt: &startedAt,
			LastFailureDuration:  17 * time.Minute,
		},
	}

	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Group map[string]json.RawMessage `json:"group"`
		Node  map[string]json.RawMessage `json:"node"`
	}
	if err = json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	for name, fields := range map[string]map[string]json.RawMessage{"group": got.Group, "node": got.Node} {
		if _, ok := fields["last_failure_started_at"]; !ok {
			t.Errorf("%s status omitted last_failure_started_at: %s", name, b)
		}
		var duration time.Duration
		if err = json.Unmarshal(fields["last_failure_duration"], &duration); err != nil {
			t.Errorf("decode %s failure duration: %v", name, err)
		} else if duration != 17*time.Minute {
			t.Errorf("%s failure duration = %v, want 17m", name, duration)
		}
		if _, ok := fields["last_fail_at"]; ok {
			t.Errorf("%s status still exposes last_fail_at", name)
		}
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
			group:    GroupStatus{Available: true},
			critical: true,
			want:     HealthHealthy,
		},
		{
			name:     "critical group is unavailable",
			critical: true,
			want:     HealthDegraded,
		},
		{
			name: "non-critical group is unavailable",
			want: HealthWarning,
		},
		{
			name:     "no-check group",
			group:    GroupStatus{NoCheck: true},
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
	callback := func(bool) error { return nil }
	direct := outbound.NewDialerGroup(option, "direct", outbound.GroupKindAlwaysAlive, nil, nil, policy, callback)
	block := outbound.NewDialerGroup(option, "block", outbound.GroupKindInvisible, nil, nil, policy, callback)

	node := dialer.NewDialer(statusTestDialer{}, option, &dialer.Property{Property: D.Property{
		Name: t.Name(),
		Link: "test://" + t.Name(),
	}}, true)
	group := outbound.NewDialerGroup(
		option,
		t.Name(),
		outbound.GroupKindNormal,
		[]*dialer.Dialer{node},
		[]*dialer.Annotation{{}},
		policy,
		callback,
	)
	defer group.Close()

	tcp4 := common.IndexToNetworkType(0)
	tcp6 := common.IndexToNetworkType(1)
	node.SetSupported(tcp4, true)
	node.SetSupported(tcp6, false)
	node.SetSupported(common.IndexToNetworkType(2), false)
	node.SetSupported(common.IndexToNetworkType(3), false)
	node.Update(true, time.Millisecond, tcp4, nil)
	node.NotifyStatusChange()

	plane := &ControlPlane{
		outbounds:          []*outbound.DialerGroup{direct, block, group},
		criticalOutbounds:  []bool{false, false, true},
		PrometheusRegistry: registry,
	}
	snapshot := plane.StatusSnapshot("test")
	if snapshot.Health != HealthHealthy || snapshot.Groups[1].Health != HealthHealthy {
		t.Fatalf("health = %q/%q, want healthy", snapshot.Health, snapshot.Groups[1].Health)
	}
	if !snapshot.Groups[1].Available || snapshot.Groups[1].Networks[0].SupportState != "confirmed" || !snapshot.Groups[1].Networks[0].Alive {
		t.Fatalf("group/tcp4 status = %+v/%+v, want available and supported", snapshot.Groups[1], snapshot.Groups[1].Networks[0])
	}
	if snapshot.Groups[1].Networks[1].SupportState != "unsupported" || snapshot.Groups[1].Networks[1].Alive {
		t.Fatalf("tcp6 status = %+v, want unsupported", snapshot.Groups[1].Networks[1])
	}
	if got := snapshot.Groups[1].Nodes[0].SupportState[0]; got != "confirmed" {
		t.Fatalf("tcp4 support state = %q, want confirmed", got)
	}
	if got := snapshot.Groups[1].Nodes[0].SupportState[1]; got != "unsupported" {
		t.Fatalf("tcp6 support state = %q, want unsupported", got)
	}

	node.Update(false, 0, tcp4, fmt.Errorf("unavailable"))
	node.NotifyStatusChange()
	snapshot = plane.StatusSnapshot("test")
	if snapshot.Health != HealthDegraded || snapshot.Groups[1].Health != HealthDegraded {
		t.Fatalf("health = %q/%q, want degraded", snapshot.Health, snapshot.Groups[1].Health)
	}

	plane.criticalOutbounds[2] = false
	snapshot = plane.StatusSnapshot("test")
	if snapshot.Health != HealthWarning || snapshot.Groups[1].Health != HealthWarning {
		t.Fatalf("health = %q/%q, want warning", snapshot.Health, snapshot.Groups[1].Health)
	}
}

func TestStatusSnapshotDoesNotReportUnknownNetworkAlive(t *testing.T) {
	registry := prometheus.NewRegistry()
	common.InitPrometheus(registry)
	option := &dialer.GlobalOption{}
	policy := dialer.DialerSelectionPolicy{
		Policy:     consts.DialerSelectionPolicy_Fixed,
		FixedIndex: 0,
	}
	node := dialer.NewDialer(statusTestDialer{}, option, &dialer.Property{Property: D.Property{
		Name: t.Name(),
		Link: "test://" + t.Name(),
	}}, true)
	group := outbound.NewDialerGroup(
		option,
		t.Name(),
		outbound.GroupKindNormal,
		[]*dialer.Dialer{node},
		[]*dialer.Annotation{{}},
		policy,
		func(bool) error { return nil },
	)
	defer group.Close()
	node.Update(true, time.Millisecond, nil, nil)
	node.NotifyStatusChange()

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
	if status.Selected != "" {
		t.Fatalf("unknown capability exposed tentative selection %q", status.Selected)
	}
	if snapshot.Groups[0].Nodes[0].SupportState[2] != "unknown" {
		t.Fatal("unknown node capability was advertised as supported")
	}
	if snapshot.Groups[0].Nodes[0].Selected[2] {
		t.Fatal("unknown node capability exposed tentative selection")
	}
	if !snapshot.Groups[0].Available {
		t.Fatal("global node health did not make the group available")
	}
}

func TestNodeStatusSeparatesSessionHealthAndUsability(t *testing.T) {
	registry := prometheus.NewRegistry()
	common.InitPrometheus(registry)
	option := &dialer.GlobalOption{}
	session := newStatusTestSession(netproxy.SessionConnected)
	transport := netproxy.WithSession(statusTestDialer{}, session)
	node := dialer.NewDialer(transport, option, &dialer.Property{Property: D.Property{
		Name: t.Name(),
		Link: "test://" + t.Name(),
	}}, true)
	group := outbound.NewDialerGroup(
		option,
		t.Name(),
		outbound.GroupKindNormal,
		[]*dialer.Dialer{node},
		[]*dialer.Annotation{{}},
		dialer.DialerSelectionPolicy{Policy: consts.DialerSelectionPolicy_Fixed},
		func(bool) error { return nil },
	)
	t.Cleanup(func() {
		_ = group.Close()
		_ = node.CloseTransport()
	})
	tcp4 := common.IndexToNetworkType(0)
	node.SetSupported(tcp4, true)
	node.Update(true, time.Millisecond, tcp4, nil)
	node.NotifyStatusChange()

	status := nodeStatus(group, node, newConnCounts())
	if status.DialerKind != "stateful" || status.SessionState != "connected" || status.HealthState != "healthy" {
		t.Fatalf("connected node status = %+v", status)
	}
	if status.SupportState[0] != "confirmed" {
		t.Fatalf("connected node support = %+v", status.SupportState)
	}

	session.state.Transition(netproxy.SessionDisconnected, errors.New("transport lost"))
	deadline := time.Now().Add(time.Second)
	for node.RuntimeStatus(group).Healthy && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	status = nodeStatus(group, node, newConnCounts())
	if status.SessionState != "disconnected" || status.SessionError != "transport lost" || status.HealthState != "unhealthy" {
		t.Fatalf("disconnected node status = %+v", status)
	}
	if status.SupportState[0] != "confirmed" {
		t.Fatalf("disconnect changed support: %+v", status.SupportState)
	}
}
