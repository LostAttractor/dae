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
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

func mustStatusSnapshot(t *testing.T, plane *ControlPlane) *StatusSnapshot {
	t.Helper()
	snapshot, err := plane.statusSnapshot("test")
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

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

func TestPathStatsAggregateByNetworkGroupAndNode(t *testing.T) {
	snapshot := map[stats.Path]stats.PathStats{
		{NodeID: "shared-id", Outbound: "group", Subtag: "sub", Dialer: "alias-a", Network: common.NetworkTCP4}: {
			ActiveConnections: 2, TotalConnections: 3,
			TrafficCounters: stats.TrafficCounters{UploadBytes: 1000, DownloadBytes: 2000},
			TrafficRate:     stats.TrafficRate{UploadBytesPerSecond: 100, DownloadBytesPerSecond: 200},
		},
		{NodeID: "alias-b-id", Outbound: "group", Subtag: "sub", Dialer: "alias-b", Network: common.NetworkUDP4}: {
			ActiveConnections: 5, TotalConnections: 7,
			TrafficCounters: stats.TrafficCounters{UploadBytes: 3000, DownloadBytes: 4000},
			TrafficRate:     stats.TrafficRate{UploadBytesPerSecond: 300, DownloadBytesPerSecond: 400},
		},
		{NodeID: "shared-id", Outbound: "other", Dialer: "node", Network: common.NetworkTCP6}: {
			ActiveConnections: 1, TotalConnections: 2,
			TrafficCounters: stats.TrafficCounters{UploadBytes: 5000, DownloadBytes: 6000},
			TrafficRate:     stats.TrafficRate{UploadBytesPerSecond: 500, DownloadBytesPerSecond: 600},
		},
		{NodeID: "ignored-id", Outbound: "group", Dialer: "ignored", Network: common.NetworkIndex(-1)}: {
			ActiveConnections: 11, TotalConnections: 11,
		},
	}
	index := indexPathStats(snapshot)

	if got := index.total; got != (stats.PathStats{
		ActiveConnections: 8, TotalConnections: 12,
		TrafficCounters: stats.TrafficCounters{UploadBytes: 9000, DownloadBytes: 12000},
		TrafficRate:     stats.TrafficRate{UploadBytesPerSecond: 900, DownloadBytesPerSecond: 1200},
	}) {
		t.Fatalf("global path stats = %+v", got)
	}
	if got := index.groups["group"].total; got != (stats.PathStats{
		ActiveConnections: 7, TotalConnections: 10,
		TrafficCounters: stats.TrafficCounters{UploadBytes: 4000, DownloadBytes: 6000},
		TrafficRate:     stats.TrafficRate{UploadBytesPerSecond: 400, DownloadBytesPerSecond: 600},
	}) {
		t.Fatalf("group path stats = %+v", got)
	}
	if got := index.nodes[groupNodeKey{group: "group", nodeID: "shared-id"}]; got.ActiveConnections != 2 || got.UploadBytes != 1000 {
		t.Fatalf("alias A path stats = %+v", got)
	}
	if got := index.nodes[groupNodeKey{group: "group", nodeID: "alias-b-id"}]; got.ActiveConnections != 5 || got.UploadBytes != 3000 {
		t.Fatalf("alias B path stats = %+v", got)
	}
	if got := index.nodes[groupNodeKey{group: "other", nodeID: "shared-id"}]; got.ActiveConnections != 1 || got.UploadBytes != 5000 {
		t.Fatalf("same node ID in other group stats = %+v", got)
	}
}

func TestStatusSnapshotReportsExternalCounterFailure(t *testing.T) {
	connection := stats.DefaultStore.OpenConnection(stats.Path{
		NodeID:   t.Name(),
		Outbound: t.Name(),
		Network:  common.NetworkTCP4,
	})
	if err := connection.AttachExternalCounters(func() (stats.TrafficCounters, error) {
		return stats.TrafficCounters{}, fmt.Errorf("counter source failed")
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = connection.Close()
	})

	if _, err := new(ControlPlane).statusSnapshot("test"); err == nil {
		t.Fatal("status snapshot accepted a failed external counter read")
	}
}

func TestStatusSnapshotReportsDomainHistory(t *testing.T) {
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
		core: &controlPlaneCore{domainRegistry: domainRegistry},
	}
	tables := mustStatusSnapshot(t, plane).Tables
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
	option := &dialer.GlobalOption{}
	policy := dialer.DialerSelectionPolicy{
		Policy:     consts.DialerSelectionPolicy_Fixed,
		FixedIndex: 0,
	}
	callback := func(bool, *common.NetworkType) error { return nil }
	directDialer := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: statusTestDialer{}}), option, &dialer.Property{Property: D.Property{
		Name: "direct",
		Link: "direct://",
	}}, dialer.InitialCheckDisabled, "")
	blockDialer := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: statusTestDialer{}}), option, &dialer.Property{Property: D.Property{
		Name: "block",
		Link: "block://",
	}}, dialer.InitialCheckDisabled, "")
	direct := outbound.NewDialerGroup(option, "direct", outbound.GroupKindSingleAlwaysAlive,
		[]*dialer.Dialer{directDialer}, []*dialer.Annotation{{}}, dialer.DialerSelectionPolicy{}, callback)
	block := outbound.NewDialerGroup(option, "block", outbound.GroupKindInvisible,
		[]*dialer.Dialer{blockDialer}, []*dialer.Annotation{{}}, dialer.DialerSelectionPolicy{}, callback)
	t.Cleanup(func() {
		_ = direct.Close()
		_ = block.Close()
	})

	node := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: statusTestDialer{}}), option, &dialer.Property{Property: D.Property{
		Name: t.Name(),
		Link: "test://" + t.Name(),
	}}, dialer.InitialCheckBlocking, "")
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
		outbounds:         []*outbound.DialerGroup{direct, block, group},
		criticalOutbounds: []bool{false, false, true},
	}
	snapshot := mustStatusSnapshot(t, plane)
	if directStatus := snapshot.Groups[0]; directStatus.ChecksConnectivity || directStatus.Policy != "" {
		t.Fatalf("direct status = %+v, want singleton without connectivity or policy", directStatus)
	}
	if groupStatus := snapshot.Groups[1]; !groupStatus.Critical || !groupStatus.ChecksConnectivity || groupStatus.Connectivity != stats.GroupStateChecking {
		t.Fatalf("checked group status = %+v, want critical and checking", groupStatus)
	}
	availability := snapshot.Groups[1].Availability
	if len(availability.Recent.States) != stats.GroupStateBucketCount {
		t.Fatalf("recent group availability = %+v, want ten buckets", availability)
	}
	if availability.Seen {
		t.Fatalf("unobserved group has availability: %+v", availability)
	}
	if got := snapshot.Groups[1].Nodes[0].Support[0]; got != dialer.NetworkSupportUnknown {
		t.Fatalf("tcp4 support state = %q, want unknown", got)
	}

	plane.criticalOutbounds[2] = false
	snapshot = mustStatusSnapshot(t, plane)
	if snapshot.Groups[1].Critical {
		t.Fatal("non-critical group remained critical")
	}
}

func TestStatusSnapshotDoesNotSelectUnknownNetwork(t *testing.T) {
	option := &dialer.GlobalOption{}
	policy := dialer.DialerSelectionPolicy{
		Policy:     consts.DialerSelectionPolicy_Fixed,
		FixedIndex: 0,
	}
	node := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: statusTestDialer{}}), option, &dialer.Property{Property: D.Property{
		Name: t.Name(),
		Link: "test://" + t.Name(),
	}}, dialer.InitialCheckBlocking, "")
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
		outbounds:         []*outbound.DialerGroup{group},
		criticalOutbounds: []bool{true},
	}
	snapshot := mustStatusSnapshot(t, plane)
	status := snapshot.Groups[0]
	if status.Nodes[0].Support[common.NetworkUDP4] != dialer.NetworkSupportUnknown {
		t.Fatalf("udp4 status = %+v, want unknown and not advertised as supported", status.Nodes[0].Support)
	}
	if status.SelectedNodeIDs[common.NetworkUDP4] != "" {
		t.Fatalf("unknown capability exposed tentative selection %q", status.SelectedNodeIDs[common.NetworkUDP4])
	}
	if status.Connectivity == stats.GroupStateAvailable {
		t.Fatal("unknown network capability made the group available")
	}
}

func TestStatusSnapshotReportsSingletonNodeMetadata(t *testing.T) {
	option := &dialer.GlobalOption{}
	property := &dialer.Property{
		Property: D.Property{Name: "entry -> exit", Protocol: "socks -> ss", Address: "entry -> exit", Link: "path"},
		Hops: []dialer.Hop{
			{ID: "entry-id", Name: "entry", Subtag: "a", Protocol: "socks", Address: "entry.example:1080"},
			{ID: "exit-id", Name: "exit", Subtag: "b", Protocol: "ss", Address: "exit.example:443"},
		},
	}
	node := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: statusTestDialer{}}), option, property, dialer.InitialCheckAsync, "")
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
	plane := &ControlPlane{outbounds: []*outbound.DialerGroup{group}}
	status := mustStatusSnapshot(t, plane).Groups[0]
	if status.TargetKind != "node" || status.Policy != "" {
		t.Fatalf("target metadata = kind %q, policy %q", status.TargetKind, status.Policy)
	}
	annotation := status.Nodes[0].Annotation
	if annotation == nil || annotation.AddLatency != "30ms" || annotation.Priority == nil || *annotation.Priority != 2 || !annotation.PriorityConditional || !status.Nodes[0].CheckAsync {
		t.Fatalf("node annotation = %+v", annotation)
	}
}
