// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

type testDomainDirect struct {
	slots   map[netip.Addr]uint64
	err     error
	running atomic.Bool
}

func (f *testDomainDirect) setSlot(ip netip.Addr, token uint64) error {
	if f.err == nil {
		if f.slots == nil {
			f.slots = make(map[netip.Addr]uint64)
		}
		f.slots[ip] = token
	}
	return f.err
}

func (f *testDomainDirect) setSlots(keys [][16]byte, values []domainDirectSlot) error {
	for i, key := range keys {
		if err := f.setSlot(netip.AddrFrom16(key).Unmap(), values[i].Token); err != nil {
			return err
		}
	}
	return nil
}

func (f *testDomainDirect) removeSlot(ip netip.Addr) error {
	if f.err == nil {
		delete(f.slots, ip)
	}
	return f.err
}

func (f *testDomainDirect) start(func([]domainDirectObservation)) error {
	f.running.Store(true)
	return nil
}

func (f *testDomainDirect) stop() { f.running.Store(false) }

func TestDomainDirectRenewalLeavesPendingToTimer(t *testing.T) {
	g, kernel := newTestRegistry(2, time.Minute)
	f := new(testDomainDirect)
	g.direct = f
	now := time.Now()
	live := netip.MustParseAddr("192.0.2.1")
	pending := netip.MustParseAddr("192.0.2.2")
	g.Upsert("live.", live, testBitmap(0), 1, now)
	g.kernel.update = func(netip.Addr, []uint32, []uint32) error { return errors.New("map unavailable") }
	g.Upsert("pending.", pending, testBitmap(0), 1, now)
	g.kernel.update = kernel.update

	at := now.Add(time.Second)
	g.observeDirect([]domainDirectObservation{{live, f.slots[live], 1, at}})
	if got := g.retention("live.", live); !got.Equal(at.Add(g.window)) {
		t.Fatalf("direct deadline = %v", got)
	}
	if kernel.has(pending) || len(g.kernel.pending) != 1 {
		t.Fatal("direct renewal retried unrelated publication")
	}
	g.retryProjection(at)
	if !kernel.has(pending) || len(g.kernel.pending) != 0 {
		t.Fatal("retry timer did not publish the pending IP")
	}
}

func BenchmarkDomainDirectRenewalPending(b *testing.B) {
	for _, count := range []int{0, 16000} {
		label := "empty"
		if count != 0 {
			label = "16000"
		}
		b.Run(label, func(b *testing.B) {
			g, _ := newTestRegistry(count+1, time.Hour)
			f := new(testDomainDirect)
			g.direct = f
			now := time.Now()
			live := netip.MustParseAddr("192.0.2.1")
			g.Upsert("live.", live, testBitmap(0), 1, now)
			for i := range count {
				var ip [4]byte
				binary.BigEndian.PutUint32(ip[:], uint32(i+1))
				g.kernel.pending[netip.AddrFrom4(ip)] = domainPublication{due: now.Add(time.Hour)}
			}
			batch := []domainDirectObservation{{live, f.slots[live], 0, now}}
			b.ReportAllocs()
			for b.Loop() {
				batch[0].stamp++
				batch[0].at = batch[0].at.Add(time.Nanosecond)
				g.observeDirect(batch)
			}
		})
	}
}

func TestDomainDirectMembership(t *testing.T) {
	g, kernel := newTestRegistry(1, time.Minute)
	f := new(testDomainDirect)
	g.direct = f
	now := time.Now()
	ip := netip.MustParseAddr("192.0.2.1")
	emit := func(token, stamp uint64, seconds int) {
		g.observeDirect([]domainDirectObservation{{ip, token, stamp, now.Add(time.Duration(seconds) * time.Second)}})
	}
	g.Upsert("unmatched.", ip, testBitmap(), 1, now)
	if len(f.slots) != 0 {
		t.Fatal("a zero-only IP received a direct slot")
	}
	g.Upsert("a.", ip, testBitmap(0), 1, now)
	first := f.slots[ip]
	g.Upsert("b.", ip, testBitmap(0), 1, now) // Same AND/OR, different membership.
	current := f.slots[ip]
	if current == 0 || first == 0 || current == first {
		t.Fatal("unchanged bitmaps masked a membership change")
	}
	emit(first, 8, 50)
	if got := g.retention("b.", ip); got != now.Add(g.window) {
		t.Fatal("old membership renewed a new pair", got)
	}
	emit(current, 10, 2)
	emit(current, 10, 15)
	emit(current, 9, 22)
	until := now.Add(2*time.Second + g.window)
	for _, name := range []string{"a.", "b.", "unmatched."} {
		if got := g.retention(name, ip); got != until {
			t.Fatal("duplicate/older stamp changed an anonymous renewal", name, got)
		}
	}
	f.err = errors.New("slot map unavailable")
	g.Upsert("c.", ip, testBitmap(0), 1, now)
	emit(current, 11, 30)
	if g.retention("c.", ip) != now.Add(g.window) || len(g.directRetry) != 1 {
		t.Fatal("failed token rotation accepted a stale observation")
	}
	f.err = nil
	g.retryProjection(now.Add(time.Second))
	latest := f.slots[ip]
	if latest == current || len(g.directRetry) != 0 {
		t.Fatal("qualification retry did not recover")
	}
	g.memoryLimit = g.memoryUsed
	f.err = errors.New("delete failed")
	g.Upsert("missing.", ip, nil, 1, now)
	emit(latest, 12, 45)
	if kernel.has(ip) || g.retention("b.", ip) != until || g.directRetry[ip] != 0 {
		t.Fatal("failed slot removal renewed an isolated IP")
	}
	f.err = nil
	g.retryProjection(now.Add(2 * time.Second))
	if len(f.slots) != 0 || len(g.directRetry) != 0 {
		t.Fatal("stale slot survived recovery")
	}
}

func TestDomainDirectWaitsForPublication(t *testing.T) {
	g, kernel := newTestRegistry(1, time.Minute)
	f := new(testDomainDirect)
	g.direct = f
	ip := netip.MustParseAddr("192.0.2.1")
	now := time.Now()
	g.Upsert("a.", ip, testBitmap(0), 1, now)
	old := f.slots[ip]
	g.kernel.update = func(netip.Addr, []uint32, []uint32) error { return errors.New("map unavailable") }
	g.Upsert("b.", ip, testBitmap(1), 1, now)
	stale := []domainDirectObservation{{ip, old, 1, now.Add(time.Second)}}
	g.observeDirect(stale)
	if f.slots[ip] != old || g.retention("b.", ip) != now.Add(g.window) {
		t.Fatal("pending publication activated a new token or consumed an old one")
	}
	g.kernel.update = kernel.update
	g.retryProjection(now.Add(time.Second))
	g.observeDirect(stale)
	if f.slots[ip] == old || g.retention("b.", ip) != now.Add(g.window) {
		t.Fatal("late delivery of a pre-publication event renewed a new member")
	}
}
