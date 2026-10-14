// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common/stats"
)

// tcpMonitorInterval bounds how late native relays report payload progress.
const tcpMonitorInterval = api.TrafficHistoryInterval

// tcpIdleTimeouts follow the startup namespace's conntrack policy. Kernel
// keepalive detects unreachable peers; these limits reclaim relays whose peers
// stay reachable but never finish, such as proxied streams behind a silent
// remote or a half-closed peer that never closes its side.
type tcpIdleTimeouts struct {
	established time.Duration // nf_conntrack_tcp_timeout_established
	halfClosed  time.Duration // nf_conntrack_tcp_timeout_close_wait
}

// Fallbacks are RFC 5382's established timeout and the kernel's CLOSE_WAIT default.
var defaultTCPIdleTimeouts = tcpIdleTimeouts{established: 7440 * time.Second, halfClosed: 60 * time.Second}

// RefreshTCPIdleTimeouts adopts the startup namespace's current conntrack
// timeouts for existing and new relays. The daemon calls it only after
// accepting startup or reload.
func (r *Runtime) RefreshTCPIdleTimeouts() {
	r.tcpMonitor.setTimeouts(tcpIdleTimeouts{
		established: readTCPTimeout("nf_conntrack_tcp_timeout_established", defaultTCPIdleTimeouts.established),
		halfClosed:  readTCPTimeout("nf_conntrack_tcp_timeout_close_wait", defaultTCPIdleTimeouts.halfClosed),
	})
}

func readTCPTimeout(name string, fallback time.Duration) time.Duration {
	data, err := os.ReadFile("/proc/sys/net/netfilter/" + name)
	if err != nil {
		return fallback
	}
	return parseTCPTimeout(string(data), fallback)
}

func parseTCPTimeout(value string, fallback time.Duration) time.Duration {
	seconds, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
	if err != nil || seconds == 0 || seconds > uint64((1<<63-1)/time.Second) {
		return fallback
	}
	return time.Duration(seconds) * time.Second
}

type tcpProgressDirection struct {
	read  func() (uint64, error)
	total uint64
}

// tcpRelayProgress tracks payload progress for one relay. Buffered copies record
// exact writes; native copies are sampled from kernel counters, and a completed
// copy retires its reader before FIN and settles the exact accepted-write count.
type tcpRelayProgress struct {
	traffic      *stats.Connection
	lastProgress atomic.Int64 // UnixNano of the latest payload or half-close
	halfClosed   atomic.Bool
	idle         chan struct{}

	mu         sync.Mutex
	directions [2]tcpProgressDirection // native only: upload, download
	activity   func()                  // native only; buffered copies report through the sniffer
	stopped    bool
}

func newTCPRelayProgress(traffic *stats.Connection) *tcpRelayProgress {
	p := &tcpRelayProgress{traffic: traffic, idle: make(chan struct{}, 1)}
	p.touch(time.Now())
	return p
}

func (p *tcpRelayProgress) touch(now time.Time) { p.lastProgress.Store(now.UnixNano()) }

// record accounts one buffered write.
func (p *tcpRelayProgress) record(index int, n uint64) {
	if index == 0 {
		p.traffic.RecordUpload(n)
	} else {
		p.traffic.RecordDownload(n)
	}
	p.touch(time.Now())
}

// halfClose starts the half-closed timeout, like a FIN does for conntrack.
func (p *tcpRelayProgress) halfClose() {
	p.halfClosed.Store(true)
	p.touch(time.Now())
}

func (p *tcpRelayProgress) publishLocked(now time.Time, changed bool, err error) {
	if changed {
		p.touch(now)
		if p.activity != nil {
			p.activity()
		}
	}
	_ = p.traffic.UpdateCounters(api.TrafficCounters{
		UploadBytes: p.directions[0].total, DownloadBytes: p.directions[1].total,
	}, err)
}

func (p *tcpRelayProgress) complete(index int, total uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	d := &p.directions[index]
	d.read = nil // No future sample can include the FIN sequence number.
	changed := total > d.total
	d.total = max(d.total, total)
	p.publishLocked(time.Now(), changed, nil)
}

// sampleLocked treats a failed read as unknown activity, never as idleness.
// Reading ACKs before the output queue may undercount transiently; retain the
// high watermark until the copy result supplies the exact terminal total.
func (p *tcpRelayProgress) sampleLocked(now time.Time) bool {
	var sampleErr error
	native, changed := false, false
	for i := range p.directions {
		d := &p.directions[i]
		if d.read == nil {
			continue
		}
		native = true
		n, err := d.read()
		sampleErr = errors.Join(sampleErr, err)
		if err == nil && n > d.total {
			d.total = n
			changed = true
		}
	}
	if native {
		p.publishLocked(now, changed, sampleErr)
	}
	return sampleErr == nil
}

func (p *tcpRelayProgress) idleLocked(now time.Time, timeouts tcpIdleTimeouts) bool {
	if p.stopped || !p.sampleLocked(now) {
		return false
	}
	timeout := timeouts.established
	if p.halfClosed.Load() {
		timeout = timeouts.halfClosed
	}
	return now.UnixNano()-p.lastProgress.Load() >= int64(timeout)
}

// Runtime owns one monitor across configuration generations. Registration starts
// it lazily; there are no additional per-connection goroutines or timers.
type tcpRelayMonitor struct {
	mu          sync.Mutex
	connections map[*tcpRelayProgress]struct{}
	timeouts    tcpIdleTimeouts
	done        chan struct{}
	worker      sync.WaitGroup
	closed      bool
}

func (m *tcpRelayMonitor) setTimeouts(timeouts tcpIdleTimeouts) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.timeouts = timeouts
}

func (m *tcpRelayMonitor) currentTimeouts() tcpIdleTimeouts {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.timeouts == (tcpIdleTimeouts{}) {
		return defaultTCPIdleTimeouts
	}
	return m.timeouts
}

func (m *tcpRelayMonitor) register(p *tcpRelayProgress) bool {
	if m == nil {
		return true
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return false
	}
	if m.connections == nil {
		m.connections = make(map[*tcpRelayProgress]struct{})
		m.done = make(chan struct{})
		m.worker.Go(func() {
			ticker := time.NewTicker(tcpMonitorInterval)
			defer ticker.Stop()
			for {
				select {
				case <-m.done:
					return
				case <-ticker.C:
					m.sample()
				}
			}
		})
	}
	m.connections[p] = struct{}{}
	return true
}

func (m *tcpRelayMonitor) remove(p *tcpRelayProgress) {
	if m != nil {
		m.mu.Lock()
		delete(m.connections, p)
		m.mu.Unlock()
	}
	p.mu.Lock()
	p.stopped = true
	p.mu.Unlock()
}

func (m *tcpRelayMonitor) sample() {
	timeouts := m.currentTimeouts()
	m.mu.Lock()
	connections := make([]*tcpRelayProgress, 0, len(m.connections))
	for p := range m.connections {
		connections = append(connections, p)
	}
	m.mu.Unlock()
	for _, p := range connections {
		p.mu.Lock()
		idle := p.idleLocked(time.Now(), timeouts)
		p.mu.Unlock()
		if idle {
			select {
			case p.idle <- struct{}{}:
			default:
			}
		}
	}
}

// The coordinator confirms fresh counters and the current timeouts before
// acting on a possibly stale notification. Only it closes FDs.
func (m *tcpRelayMonitor) confirmIdle(p *tcpRelayProgress) bool {
	timeouts := m.currentTimeouts()
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.idleLocked(time.Now(), timeouts) {
		return false
	}
	p.stopped = true
	return true
}

func (m *tcpRelayMonitor) close() {
	m.mu.Lock()
	if !m.closed {
		m.closed = true
		if m.done != nil {
			close(m.done)
		}
	}
	m.mu.Unlock()
	m.worker.Wait()
}
