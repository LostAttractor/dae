// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	domainDirectRecordSize = 32
	domainDirectRingBatch  = 128
	domainDirectScanBatch  = 512
	domainDirectScanMax    = 4096
	domainDirectScanSteps  = 8
	domainDirectPoll       = 100 * time.Millisecond
)

type domainDirectObservation struct {
	ip    netip.Addr
	token uint64
	stamp uint64
	at    time.Time
}

type domainDirectSlot struct {
	Token, LastSeen uint64
}

// BPF and Go elapsed times use CLOCK_MONOTONIC, not boottime.
type domainDirectClock struct {
	at time.Time
	ns int64
}

// Preserve the monotonic mapping but use a recent wall clock for persisted
// deadlines after suspend or an NTP step. Deduplication uses the raw stamp.
func (c domainDirectClock) anchored(now time.Time) domainDirectClock {
	return domainDirectClock{at: now, ns: c.ns + now.Sub(c.at).Nanoseconds()}
}

func (c domainDirectClock) observation(key [16]byte, value domainDirectSlot) domainDirectObservation {
	if value.Token == 0 || value.LastSeen == 0 || value.LastSeen > math.MaxInt64 {
		return domainDirectObservation{}
	}
	return domainDirectObservation{
		ip: netip.AddrFrom16(key).Unmap(), token: value.Token, stamp: value.LastSeen,
		at: c.at.Add(time.Duration(int64(value.LastSeen) - c.ns)),
	}
}

func (c domainDirectClock) decode(raw []byte) domainDirectObservation {
	if len(raw) != domainDirectRecordSize {
		return domainDirectObservation{}
	}
	return c.observation([16]byte(raw[:16]), domainDirectSlot{
		Token: binary.NativeEndian.Uint64(raw[16:24]), LastSeen: binary.NativeEndian.Uint64(raw[24:]),
	})
}

type domainDirectFeed struct {
	slots, events, losses *ebpf.Map
	clock                 domainDirectClock
	mu                    sync.Mutex // reader lifetime, never held by a callback
	reader                *domainDirectReader
	recovery              domainDirectRecovery // used by one running reader at a time
}

type domainDirectReader struct {
	ring *ringbuf.Reader
	done chan struct{}
}

func newDomainDirectFeed(slots, events, losses *ebpf.Map) (*domainDirectFeed, error) {
	if slots == nil || events == nil || losses == nil {
		return nil, errors.New("domain direct activity maps unavailable")
	}
	if slots.Type() != ebpf.Hash || slots.KeySize() != 16 || slots.ValueSize() != 16 ||
		events.Type() != ebpf.RingBuf || losses.Type() != ebpf.Array || losses.KeySize() != 4 ||
		losses.ValueSize() != 8 || losses.MaxEntries() != 1 {
		return nil, errors.New("domain direct activity map ABI mismatch")
	}
	before := time.Now()
	var mono unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &mono); err != nil {
		return nil, fmt.Errorf("read domain activity clock: %w", err)
	}
	return &domainDirectFeed{slots: slots, events: events, losses: losses,
		clock: domainDirectClock{at: before.Add(time.Since(before) / 2), ns: mono.Nano()}}, nil
}

// Install only a new token (or changed membership). Updating an unchanged
// slot would reset the kernel's last observation and notification throttle.
func (f *domainDirectFeed) setSlot(ip netip.Addr, token uint64) error {
	return f.slots.Update(ip.As16(), domainDirectSlot{Token: token}, ebpf.UpdateAny)
}

// A failed batch may already have installed some slots; callers retry with
// the same tokens to converge on the intended state.
func (f *domainDirectFeed) setSlots(keys [][16]byte, values []domainDirectSlot) error {
	n, err := f.slots.BatchUpdate(keys, values, &ebpf.BatchOptions{ElemFlags: uint64(ebpf.UpdateAny)})
	if err == nil && n != len(keys) {
		return fmt.Errorf("updated %d of %d domain direct activity slots", n, len(keys))
	}
	return err
}

func (f *domainDirectFeed) removeSlot(ip netip.Addr) error {
	err := f.slots.Delete(ip.As16())
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

// The callback owns no transport lock and must consume the borrowed batch
// before returning. The owner stops outside of any lock acquired by observe.
func (f *domainDirectFeed) start(observe func([]domainDirectObservation)) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.reader != nil {
		select {
		case <-f.reader.done:
		default:
			return nil
		}
	}
	ring, err := ringbuf.NewReader(f.events)
	if err != nil {
		return fmt.Errorf("open domain direct activity ring: %w", err)
	}
	run := &domainDirectReader{ring: ring, done: make(chan struct{})}
	f.reader = run
	go f.read(run, observe)
	return nil
}

func (f *domainDirectFeed) stop() {
	f.mu.Lock()
	run := f.reader
	f.mu.Unlock()
	if run == nil {
		return
	}
	_ = run.ring.Close() // Interrupt ReadInto even if the ring is idle.
	<-run.done
	f.mu.Lock()
	if f.reader == run {
		f.reader = nil
	}
	f.mu.Unlock()
}

func (f *domainDirectFeed) read(run *domainDirectReader, observe func([]domainDirectObservation)) {
	defer close(run.done)
	defer run.ring.Close()
	var record ringbuf.Record
	var batch [domainDirectRingBatch]domainDirectObservation
	length, readCount := 0, 0
	emit := func() {
		if length != 0 {
			observe(batch[:length])
			length = 0
		}
		readCount = 0
	}
	clock := f.clock.anchored(time.Now())
	nextPoll := clock.at.Add(domainDirectPoll)
	run.ring.SetDeadline(nextPoll)
	var warnedAt time.Time
	for {
		err := run.ring.ReadInto(&record)
		if err == nil {
			if o := clock.decode(record.RawSample); o.token != 0 {
				batch[length] = o
				length++
			}
			readCount++
			if readCount == len(batch) {
				emit()
			}
		} else if !errors.Is(err, os.ErrDeadlineExceeded) {
			emit()
			if !errors.Is(err, os.ErrClosed) {
				log.WithError(err).Warn("Read domain direct activity ring; leaving traffic forwarding unchanged")
				f.recovery.force = true
			}
			return
		}

		if now := time.Now(); !now.Before(nextPoll) {
			emit()
			clock = f.clock.anchored(now)
			if err := f.recovery.poll(f.lossEpoch, f.slots, clock, observe); err != nil &&
				(warnedAt.IsZero() || now.Sub(warnedAt) >= time.Minute) {
				log.WithError(err).Warn("Recover dropped domain direct activity; leaving traffic forwarding unchanged")
				warnedAt = now
			}
			nextPoll = time.Now().Add(domainDirectPoll)
			run.ring.SetDeadline(nextPoll)
		}
	}
}

func (f *domainDirectFeed) lossEpoch() (uint64, error) {
	var epoch uint64
	err := f.losses.Lookup(uint32(0), &epoch)
	return epoch, err
}

type domainDirectScanMap interface {
	BatchLookup(*ebpf.MapBatchCursor, any, any, *ebpf.BatchOptions) (int, error)
	NextKey(any, any) error
	Lookup(any, any) error
	MaxEntries() uint32
}

type domainDirectRecovery struct {
	scanning, force    bool
	completed, started uint64
	cursor             ebpf.MapBatchCursor
	keys               [][16]byte
	values             []domainDirectSlot
	observations       []domainDirectObservation
	scalar             bool
	scalarKey          [16]byte
	scalarSteps        uint32
}

func (r *domainDirectRecovery) poll(readLoss func() (uint64, error), slots domainDirectScanMap, clock domainDirectClock, observe func([]domainDirectObservation)) error {
	if !r.scanning {
		epoch, err := readLoss()
		if err != nil {
			return err
		}
		if epoch == r.completed && !r.force {
			return nil
		}
		r.scanning, r.force, r.started = true, false, epoch
		r.cursor = ebpf.MapBatchCursor{}
		r.scalar, r.scalarSteps = false, 0
	}
	if len(r.keys) == 0 {
		r.resize(domainDirectScanBatch)
	}
	for range domainDirectScanSteps {
		var n int
		var err error
		if r.scalar {
			n, err = r.scanScalar(slots)
		} else {
			n, err = slots.BatchLookup(&r.cursor, r.keys, r.values, nil)
			if errors.Is(err, unix.ENOSPC) {
				// Hash buckets are returned whole. Handle fragmentation without
				// letting one unusually large bucket allocate an unbounded buffer.
				r.cursor = ebpf.MapBatchCursor{}
				if len(r.keys) < domainDirectScanMax {
					r.resize(2 * len(r.keys))
				} else {
					r.scalar, r.scalarSteps = true, 0
				}
				return nil
			}
		}
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			r.scanning, r.force = false, true
			return err
		}
		r.observations = r.observations[:0]
		for i := range n {
			if o := clock.observation(r.keys[i], r.values[i]); o.token != 0 {
				r.observations = append(r.observations, o)
			}
		}
		if len(r.observations) != 0 {
			observe(r.observations)
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			r.scanning = false
			epoch, err := readLoss()
			if err == nil && epoch == r.started {
				r.completed = epoch
			} else {
				r.force = true // A loss may have happened before or after its slot was scanned.
			}
			return err
		}
	}
	return nil
}

func (r *domainDirectRecovery) resize(n int) {
	r.keys = make([][16]byte, n)
	r.values = make([]domainDirectSlot, n)
	r.observations = make([]domainDirectObservation, 0, n)
}

func (r *domainDirectRecovery) scanScalar(slots domainDirectScanMap) (n int, err error) {
	for range domainDirectRingBatch {
		var previous any
		if r.scalarSteps != 0 {
			previous = &r.scalarKey
		}
		var next [16]byte
		if err := slots.NextKey(previous, &next); err != nil {
			return n, err
		}
		if r.scalarSteps >= slots.MaxEntries() {
			return n, ebpf.ErrIterationAborted // A concurrent deletion restarted the walk.
		}
		r.scalarKey, r.scalarSteps = next, r.scalarSteps+1
		var value domainDirectSlot
		if err := slots.Lookup(next, &value); errors.Is(err, ebpf.ErrKeyNotExist) {
			continue
		} else if err != nil {
			return n, err
		}
		r.keys[n], r.values[n] = next, value
		n++
	}
	return n, nil
}
