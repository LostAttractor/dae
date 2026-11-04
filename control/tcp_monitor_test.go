// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

func TestTCPMonitorReportsUnansweredPayloadOnce(t *testing.T) {
	for _, tc := range []struct {
		name             string
		upload, download bool
		reports          int
	}{
		{"unanswered", true, false, 1},
		{"answered", true, true, 0},
		{"caller silent", false, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			traffic := stats.DefaultStore.OpenConnection(stats.Path{Dialer: t.Name()}, false)
			t.Cleanup(func() { _ = traffic.Close() })
			p := newTCPRelayProgress(traffic)
			reports := 0
			p.unanswered = func() { reports++ }
			m := new(tcpRelayMonitor)
			if !m.register(p) {
				t.Fatal("register")
			}
			t.Cleanup(func() { m.remove(p); m.close() })
			if tc.upload {
				p.record(0, 1)
			}
			if tc.download {
				p.record(1, 1)
			}
			m.sample()
			if reports != 0 {
				t.Fatal("reported within the probe timeout")
			}
			if tc.upload {
				p.firstUpload.Store(time.Now().Add(-consts.DefaultDialTimeout).UnixNano())
			}
			m.sample()
			m.sample()
			if reports != tc.reports {
				t.Fatalf("reports = %d, want %d", reports, tc.reports)
			}
		})
	}
}

// Only a proxied relay can blame its outbound path for an unanswered payload.
func TestTCPCopyPairReportsUnansweredOnlyForProxies(t *testing.T) {
	d := dialer.NewDialer(netproxy.NewRuntime(netproxy.Layer{Data: statusTestDialer{}}),
		&dialer.GlobalOption{CheckInterval: time.Hour, CheckIntervalMax: time.Hour}, &dialer.Property{Name: t.Name()}, true, "")
	t.Cleanup(func() { _ = d.Close() })
	traffic := stats.DefaultStore.OpenConnection(stats.Path{Dialer: t.Name()}, false)
	t.Cleanup(func() { _ = traffic.Close() })
	for _, tc := range []struct {
		name    string
		relay   tcpRelay
		reports bool
	}{
		{"proxied", tcpRelay{dialer: d}, true},
		{"direct", tcpRelay{dialer: d, direct: true}, false},
		{"without dialer", tcpRelay{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			left, right := net.Pipe()
			t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
			tc.relay.lConn, tc.relay.rConn = left, right
			if got := newTCPCopyPair(&tc.relay, traffic).progress.unanswered != nil; got != tc.reports {
				t.Fatalf("reports unanswered payload = %v, want %v", got, tc.reports)
			}
		})
	}
}

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
