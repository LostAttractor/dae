//go:build linux && surge_nodejs

// SPDX-License-Identifier: AGPL-3.0-only

package nodejs

import (
	"errors"
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/containerd/cgroups/v3/cgroup2"
)

// Stats combines live pool counts with cached process memory samples. Counters
// persist for this pool's lifetime; preflight uses a separate disposable pool.
type Stats struct {
	Active, Idle, Limit                                              int
	Started, Reused, StartFailures                                   uint64
	IdleReaped, Discarded                                            uint64
	RSSBytes, PSSBytes                                               uint64
	MemorySampledWorkers                                             int
	MemorySampledAt                                                  time.Time
	IdleTimeout                                                      time.Duration
	CgroupMemoryBytes, CgroupMemoryPeakBytes, CgroupMemoryLimitBytes uint64
	CgroupOOMKills                                                   uint64
	CgroupSampledAt                                                  time.Time
}

type memorySample struct {
	rss, pss uint64
	at       time.Time
}

// Stats performs no I/O and never sends commands to a worker.
func (p *Pool) Stats() Stats {
	p.mu.Lock()
	defer p.mu.Unlock()
	stats := p.stats
	if p.closed && p.group != nil && p.group.Deleted() {
		stats.CgroupMemoryBytes = 0
	}
	if stats.CgroupSampledAt.IsZero() {
		stats.CgroupMemoryLimitBytes = uint64(p.poolMemory)
	}
	stats.Active, stats.Idle, stats.Limit = len(p.workers)-len(p.idle), len(p.idle), cap(p.slots)
	stats.IdleTimeout = p.idleTimeout
	for w := range p.workers {
		if w.retiring {
			stats.Active--
		}
		if w.memory.at.IsZero() {
			continue
		}
		stats.RSSBytes += w.memory.rss
		stats.PSSBytes += w.memory.pss
		stats.MemorySampledWorkers++
		if stats.MemorySampledAt.IsZero() || w.memory.at.Before(stats.MemorySampledAt) {
			stats.MemorySampledAt = w.memory.at
		}
	}
	return stats
}

// Maintenance starts with the first worker, including the prewarmed one.
// Close joins it after terminating children and releasing the pool lock.
func (p *Pool) monitor() {
	defer close(p.monitorDone)
	ticks := time.Tick(p.sampleInterval)
	p.maintain(time.Now())
	for {
		select {
		case <-p.done:
			return
		case now := <-ticks:
			p.maintain(now)
		}
	}
}

func (p *Pool) maintain(now time.Time) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	// Keep the most recently returned idle worker warm. Active leases never
	// appear in this list, including while their scripts wait for host I/O.
	var retiring []*worker
	for i := 0; i < len(p.idle)-1; {
		w := p.idle[i]
		if now.Sub(w.idleSince) < p.idleTimeout {
			i++
			continue
		}
		p.idle = slices.Delete(p.idle, i, i+1)
		w.retiring = true
		retiring = append(retiring, w)
	}
	p.mu.Unlock()
	for _, w := range retiring {
		p.closeWorker(w)
		p.mu.Lock()
		delete(p.workers, w)
		p.stats.IdleReaped++
		p.notifyLocked()
		p.mu.Unlock()
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.sampleCgroupLocked()
	workers := slices.Collect(maps.Keys(p.workers))
	p.mu.Unlock()
	for _, w := range workers {
		data, err := os.ReadFile("/proc/" + strconv.Itoa(w.Cmd.Process.Pid) + "/smaps_rollup")
		var sample memorySample
		if err == nil {
			sample, _ = parseMemorySample(string(data))
		}
		p.mu.Lock()
		if _, live := p.workers[w]; live {
			w.memory = sample
		}
		p.mu.Unlock()
	}
}

func parseMemorySample(data string) (memorySample, error) {
	var sample memorySample
	var found int
	for line := range strings.SplitSeq(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[0] != "Rss:" && fields[0] != "Pss:" {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil || fields[2] != "kB" {
			return memorySample{}, errors.New("invalid process memory sample")
		}
		if fields[0] == "Rss:" {
			sample.rss = value * 1024
			found |= 1
		} else {
			sample.pss = value * 1024
			found |= 2
		}
	}
	if found != 3 {
		return memorySample{}, errors.New("incomplete process memory sample")
	}
	sample.at = time.Now()
	return sample, nil
}

// Called under the pool lock; API and metrics readers consume only this cache.
func (p *Pool) sampleCgroupLocked() {
	if p.group == nil || p.group.Manager == nil {
		return
	}
	stats, err := p.group.StatFiltered(cgroup2.StatMemory | cgroup2.StatMemoryEvents)
	if err != nil || stats.MemoryEvents == nil {
		return
	}
	p.stats.CgroupMemoryBytes = stats.Memory.Usage
	p.stats.CgroupMemoryPeakBytes = stats.Memory.MaxUsage
	p.stats.CgroupMemoryLimitBytes = stats.Memory.UsageLimit
	p.stats.CgroupOOMKills = stats.MemoryEvents.OomKill
	p.stats.CgroupSampledAt = time.Now()
}
