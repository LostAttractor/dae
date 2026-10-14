// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/stats"
)

func TestTCPIdleTimeoutParsing(t *testing.T) {
	const fallback = time.Minute
	for _, value := range []string{"", "0", "-1", "oops", "9223372036854775807", "18446744073709551616"} {
		if got := parseTCPTimeout(value, fallback); got != fallback {
			t.Fatalf("%q: %v", value, got)
		}
	}
	for _, value := range []string{"7440", " 7440\n"} {
		if got := parseTCPTimeout(value, fallback); got != 7440*time.Second {
			t.Fatalf("%q: %v", value, got)
		}
	}
	if got := parseTCPTimeout("432000", fallback); got != 5*24*time.Hour {
		t.Fatal(got)
	}
}

func monitorTestProgress(t *testing.T, activity func()) (*tcpRelayMonitor, *tcpRelayProgress, stats.Path) {
	t.Helper()
	path := stats.Path{Dialer: t.Name(), NodeID: time.Now().String()}
	traffic := stats.DefaultStore.OpenDeviceConnection(path, false, [6]byte{2, 1})
	p := newTCPRelayProgress(traffic)
	p.activity = activity
	m := new(tcpRelayMonitor)
	m.setTimeouts(tcpIdleTimeouts{established: time.Second, halfClosed: time.Second})
	if !m.register(p) {
		t.Fatal("register")
	}
	t.Cleanup(func() { m.remove(p); m.close(); _ = traffic.Close() })
	return m, p, path
}

func TestTCPMonitorProgressFailureAndSettlement(t *testing.T) {
	observed := 0
	m, p, path := monitorTestProgress(t, func() { observed++ })
	var count uint64 = 100
	var readErr error
	p.directions[0].read = func() (uint64, error) { return count, readErr }
	m.sample()
	if got := stats.DefaultStore.Snapshot()[path].UploadBytes; got != 100 {
		t.Fatal(got)
	}
	count = 90 // ACK raced the queue read: retain the high watermark.
	m.sample()
	if observed != 1 {
		t.Fatal("counter regression renewed activity")
	}
	p.touch(time.Now().Add(-2 * time.Second))
	readErr = errors.New("sampling failed")
	m.sample()
	select {
	case <-p.idle:
		t.Fatal("failed sample treated as idle")
	default:
	}
	if m.confirmIdle(p) {
		t.Fatal("failed sample confirmed idle")
	}
	readErr = nil
	m.sample()
	select {
	case <-p.idle:
	default:
		t.Fatal("idle not detected")
	}
	// New payload after the notification prevents a stale timeout close.
	count = 110
	if m.confirmIdle(p) {
		t.Fatal("stale idle notification closed active relay")
	}
	p.complete(0, 120)
	count = 121 // FIN must never enter payload totals.
	m.sample()
	if got := stats.DefaultStore.Snapshot()[path].UploadBytes; got != 120 {
		t.Fatal(got)
	}
	device, _ := stats.DefaultStore.DeviceSnapshot([6]byte{2, 1})
	if device[path].UploadBytes != 120 {
		t.Fatal("device counters diverged")
	}
	if observed != 3 {
		t.Fatalf("observations = %d", observed)
	}
}

func TestTCPMonitorTimeoutUpdatesExistingRelays(t *testing.T) {
	m, p, _ := monitorTestProgress(t, nil)
	p.touch(time.Now().Add(-2 * time.Second))
	m.sample()
	m.setTimeouts(tcpIdleTimeouts{established: time.Hour, halfClosed: time.Hour})
	if m.confirmIdle(p) {
		t.Fatal("old timeout survived successful update")
	}
	m.setTimeouts(tcpIdleTimeouts{established: time.Second, halfClosed: time.Hour})
	if !m.confirmIdle(p) {
		t.Fatal("new timeout not applied to existing relay")
	}
}

func TestTCPMonitorHalfClosedTimeout(t *testing.T) {
	m, p, _ := monitorTestProgress(t, nil)
	m.setTimeouts(tcpIdleTimeouts{established: time.Hour, halfClosed: time.Second})
	p.touch(time.Now().Add(-2 * time.Second))
	if m.confirmIdle(p) {
		t.Fatal("established relay used the half-closed timeout")
	}
	p.halfClose()
	if m.confirmIdle(p) {
		t.Fatal("half-close did not count as progress")
	}
	p.touch(time.Now().Add(-2 * time.Second))
	if !m.confirmIdle(p) {
		t.Fatal("half-closed relay ignored its timeout")
	}
}

func TestRuntimeRefreshTCPIdleTimeoutsUpdatesAllRelays(t *testing.T) {
	r := NewRuntime()
	defer r.Close()
	r.tcpMonitor.setTimeouts(tcpIdleTimeouts{established: time.Nanosecond, halfClosed: time.Nanosecond})
	existing := newTCPRelayProgress(stats.DefaultStore.OpenConnection(stats.Path{Dialer: t.Name() + "-existing"}, false))
	if !r.tcpMonitor.register(existing) {
		t.Fatal("register existing relay")
	}
	defer func() { r.tcpMonitor.remove(existing); _ = existing.traffic.Close() }()
	want := tcpIdleTimeouts{
		established: readTCPTimeout("nf_conntrack_tcp_timeout_established", defaultTCPIdleTimeouts.established),
		halfClosed:  readTCPTimeout("nf_conntrack_tcp_timeout_close_wait", defaultTCPIdleTimeouts.halfClosed),
	}
	r.RefreshTCPIdleTimeouts()
	if got := r.tcpMonitor.currentTimeouts(); got != want {
		t.Fatalf("timeouts = %+v, want startup namespace values %+v", got, want)
	}
	fresh := newTCPRelayProgress(stats.DefaultStore.OpenConnection(stats.Path{Dialer: t.Name() + "-new"}, false))
	if !r.tcpMonitor.register(fresh) {
		t.Fatal("register new relay")
	}
	defer func() { r.tcpMonitor.remove(fresh); _ = fresh.traffic.Close() }()
	for _, p := range []*tcpRelayProgress{existing, fresh} {
		p.touch(time.Now().Add(-want.established / 2))
		if r.tcpMonitor.confirmIdle(p) {
			t.Fatal("relay retained the previous timeout after refresh")
		}
	}
}
