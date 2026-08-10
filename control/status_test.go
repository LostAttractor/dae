/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/prometheus/client_golang/prometheus"
)

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
		Network NetworkStatus `json:"network"`
		Node    NodeStatus    `json:"node"`
	}{
		Network: NetworkStatus{
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
		Network map[string]json.RawMessage `json:"network"`
		Node    map[string]json.RawMessage `json:"node"`
	}
	if err = json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	for name, fields := range map[string]map[string]json.RawMessage{"network": got.Network, "node": got.Node} {
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
