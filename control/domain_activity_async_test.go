// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDomainActivityBatchBeforeCollectionAndSave(t *testing.T) {
	for _, boundary := range []string{"worker", "sweep", "dns", "save", "close"} {
		t.Run(boundary, func(t *testing.T) {
			g, fake := newTestRegistry(4, 10*time.Second)
			now := time.Now()
			ip := netip.MustParseAddr("192.0.2.1")
			name := "a.example."
			g.Upsert(name, ip, testBitmap(0), 10, now)
			g.Upsert("other.example.", ip, testBitmap(), 100, now)
			before := g.generation
			key := newDomainActivityKey(ip, "A.EXAMPLE")
			for _, seconds := range []int{9, 8, 12, 11, 12, 8} {
				g.activity.enqueue(key, now.Add(time.Duration(seconds)*time.Second))
			}
			// Status/verification are read-only and expose applied evidence.
			if !g.Verify(name, ip).Paired || g.Usage().GC != 0 || g.generation != before || !g.retention(name, ip).Equal(now.Add(10*time.Second)) {
				t.Fatal("queue admission or read-only status applied activity")
			}
			path := filepath.Join(t.TempDir(), "registry.json.gz")
			switch boundary {
			case "worker":
				g.flushActivity()
			case "sweep":
				g.Sweep(now.Add(15 * time.Second))
			case "dns":
				g.ObserveDNS(nil, now.Add(15*time.Second))
			case "save":
				if err := g.Save(path); err != nil {
					t.Fatal(err)
				}
			case "close":
				g.EnablePersistence(path)
				if err := g.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if !g.retention(name, ip).Equal(now.Add(22*time.Second)) || g.generation != before+1 || g.Usage().GC != 0 {
				t.Fatal("pending activity was lost, repeatedly applied, or used consumer time")
			}
			if !g.retention("other.example.", ip).Equal(now.Add(100 * time.Second)) {
				t.Fatal("named batch refreshed unrelated shared-IP evidence")
			}
			if boundary == "save" || boundary == "close" {
				restored, _ := newTestRegistry(4, 10*time.Second)
				if err := restored.Restore(path, func(string) []uint32 { return testBitmap(0) }, now.Add(15*time.Second)); err != nil {
					t.Fatal(err)
				}
				if !restored.retention(name, ip).Equal(now.Add(22 * time.Second)) {
					t.Fatal("snapshot omitted already accepted I/O")
				}
			}
			checkInvariants(t, g, fake)
		})
	}
}

func TestDomainActivityUnknownCannotRefreshLaterDNS(t *testing.T) {
	for _, domain := range []string{"a.example.", ""} {
		t.Run("domain="+domain, func(t *testing.T) {
			g, fake := newTestRegistry(4, 10*time.Second)
			now := time.Now()
			ip := netip.MustParseAddr("192.0.2.1")
			key := newDomainActivityKey(ip, domain)
			g.activity.enqueue(key, now.Add(20*time.Second))
			// A delayed DNS delivery has enough TTL to be admitted at the newer
			// watermark. Earlier unknown activity must not renew this new pair.
			g.Upsert("a.example.", ip, testBitmap(0), 15, now.Add(10*time.Second))
			g.flushActivity()
			if !g.retention("a.example.", ip).Equal(now.Add(25 * time.Second)) {
				t.Fatal("unknown activity was applied to later evidence")
			}
			g.Sweep(now.Add(25 * time.Second))
			g.activity.enqueue(key, now.Add(24*time.Second))
			g.Upsert("a.example.", ip, testBitmap(1), 11, now.Add(22*time.Second))
			g.flushActivity()
			if !g.retention("a.example.", ip).Equal(now.Add(33*time.Second)) || !bitmapHas(fake.routing[ip], 1) {
				t.Fatal("old activity reached a recreated pair")
			}
			checkInvariants(t, g, fake)
		})
	}
}

func TestDomainActivityQueueDoesNotWaitForKernelPublication(t *testing.T) {
	g, fake := newTestRegistry(1, 10*time.Second)
	now := time.Now()
	a, b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	g.Upsert("a.example.", a, testBitmap(0), 20, now)
	g.Upsert("b.example.", b, testBitmap(1), 10, now)
	entered, release, flushed := make(chan struct{}), make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	g.kernel.update = func(ip netip.Addr, bump, routing []uint32) {
		if ip == b {
			close(entered)
			<-release
		}
		fake.update(ip, bump, routing)
	}
	g.activity.enqueue(newDomainActivityKey(b, "b.example."), now.Add(15*time.Second))
	go func() { g.flushActivity(); close(flushed) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("batch did not reach kernel publication")
	}
	queued := make(chan struct{})
	go func() {
		for i := range 64 {
			ip := netip.AddrFrom4([4]byte{198, 51, 100, byte(i + 1)})
			g.activity.enqueue(newDomainActivityKey(ip, "unknown.example."), now.Add(16*time.Second))
		}
		g.activity.enqueue(newDomainActivityKey(a, "a.example."), now.Add(16*time.Second))
		close(queued)
	}()
	select {
	case <-queued:
	case <-time.After(time.Second):
		t.Fatal("I/O waited for the registry's kernel publication")
	}
	unblock()
	<-flushed
	g.flushActivity()
	if !fake.has(a) || fake.has(b) || !g.retention("a.example.", a).Equal(now.Add(26*time.Second)) {
		t.Fatal("enqueue during a drain was lost or not promoted in the next batch")
	}
	checkInvariants(t, g, fake)
}

func TestDomainActivityCloseSeparatesReloadWindows(t *testing.T) {
	now := time.Now()
	ip := netip.MustParseAddr("192.0.2.1")
	key := newDomainActivityKey(ip, "a.example.")
	old, fake := newTestRegistry(1, 10*time.Second)
	old.Upsert(key.domain, ip, testBitmap(0), 10, now)
	activity := old.activity
	activity.enqueue(key, now.Add(9*time.Second))
	activity.prepareHandoff()
	path := filepath.Join(t.TempDir(), "registry.json.gz")
	old.EnablePersistence(path)
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	activity.enqueue(key, now.Add(15*time.Second))
	// Saving a retired instance cannot consume the successor's queue.
	if err := old.Save(path); err != nil {
		t.Fatal(err)
	}
	if !old.retention(key.domain, ip).Equal(now.Add(19 * time.Second)) {
		t.Fatal("pre-close activity used the successor window")
	}
	next, _ := newTestRegistry(1, 30*time.Second)
	next.kernel.update, next.kernel.remove = fake.update, fake.remove
	next.AdoptFrom(old, func(string) []uint32 { return testBitmap(1) }, now.Add(20*time.Second))
	if !next.retention(key.domain, ip).Equal(now.Add(45*time.Second)) || !bitmapHas(fake.routing[ip], 1) {
		t.Fatal("handoff activity was collected or used the retired window")
	}
	activity.enqueue(key, now.Add(21*time.Second))
	old.flushActivity()
	next.flushActivity()
	if !next.retention(key.domain, ip).Equal(now.Add(51*time.Second)) || !old.retention(key.domain, ip).Equal(now.Add(19*time.Second)) {
		t.Fatal("surviving handle or retired flush consumed the wrong batch")
	}
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
	if activity.enqueue(key, now.Add(time.Hour)) != nil {
		t.Fatal("ordinary shutdown kept accepting I/O")
	}
}

func TestDomainActivityManyTargetsAcrossBatchAndReload(t *testing.T) {
	now := time.Now()
	old, fake := newTestRegistry(64, 10*time.Second)
	keys := make([]domainActivityKey, 64)
	for i := range keys {
		ip := netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)})
		if i%2 != 0 {
			ip = netip.AddrFrom16([16]byte{0x20, 1, 0x0d, 0xb8, 15: byte(i + 1)})
		}
		name := fmt.Sprintf("d%d.example.", i)
		keys[i] = newDomainActivityKey(ip, name)
		old.Upsert(name, ip, testBitmap(0), 10, now)
	}
	for _, key := range keys {
		old.activity.enqueue(key, now.Add(12*time.Second))
	}
	old.Sweep(now.Add(15 * time.Second))
	for _, key := range keys {
		if !old.retention(key.domain, key.ip).Equal(now.Add(22 * time.Second)) {
			t.Fatal("collection overtook another target's already queued activity")
		}
		old.activity.enqueue(key, now.Add(21*time.Second))
	}
	old.activity.prepareHandoff()
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		old.activity.enqueue(key, now.Add(22*time.Second))
	}
	next, _ := newTestRegistry(64, 30*time.Second)
	next.kernel.update, next.kernel.remove = fake.update, fake.remove
	next.AdoptFrom(old, func(string) []uint32 { return testBitmap(1) }, now.Add(40*time.Second))
	for _, key := range keys {
		if !old.retention(key.domain, key.ip).Equal(now.Add(31*time.Second)) || !next.retention(key.domain, key.ip).Equal(now.Add(52*time.Second)) {
			t.Fatal("batch/reload did not use one observation boundary for all targets")
		}
	}
	checkInvariants(t, next, fake)
}

func TestDomainActivityConcurrentTargetsDuringReload(t *testing.T) {
	now := time.Now()
	old, fake := newTestRegistry(32, time.Minute)
	keys := make([]domainActivityKey, 32)
	for i := range keys {
		keys[i] = newDomainActivityKey(netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}), fmt.Sprintf("d%d.example.", i))
		old.Upsert(keys[i].domain, keys[i].ip, testBitmap(0), 1, now)
	}
	activity := old.activity
	activity.prepareHandoff()
	var workers sync.WaitGroup
	for _, key := range keys {
		workers.Go(func() {
			for i := range 512 {
				activity.enqueue(key, now.Add(time.Duration(i+1)*time.Nanosecond))
				if i%64 == 0 {
					old.flushActivity()
				}
			}
		})
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	next, _ := newTestRegistry(32, time.Minute)
	next.kernel.update, next.kernel.remove = fake.update, fake.remove
	next.AdoptFrom(old, func(string) []uint32 { return testBitmap(1) }, now)
	workers.Wait()
	next.flushActivity()
	for _, key := range keys {
		if !next.retention(key.domain, key.ip).Equal(now.Add(time.Minute + 512*time.Nanosecond)) {
			t.Fatal("concurrent retirement lost a target's final observation")
		}
	}
	checkInvariants(t, next, fake)
}

func TestDomainActivityConcurrentReloadAndDrains(t *testing.T) {
	now := time.Now()
	old, fake := newTestRegistry(1, time.Minute)
	ip := netip.MustParseAddr("192.0.2.1")
	key := newDomainActivityKey(ip, "a.example.")
	old.Upsert(key.domain, ip, testBitmap(0), 1, now)
	activity := old.activity
	activity.prepareHandoff()
	var sequence atomic.Uint64
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 512 {
				i := sequence.Add(1)
				activity.enqueue(key, now.Add(time.Duration(i)))
				if i%64 == 0 {
					old.flushActivity()
				}
			}
		})
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	next, _ := newTestRegistry(1, time.Minute)
	next.kernel.update, next.kernel.remove = fake.update, fake.remove
	next.AdoptFrom(old, func(string) []uint32 { return testBitmap(1) }, now)
	workers.Wait()
	next.flushActivity()
	if !next.retention(key.domain, ip).Equal(now.Add(time.Minute + time.Duration(sequence.Load()))) {
		t.Fatal("concurrent queue swap/reload lost the latest accepted observation")
	}
	checkInvariants(t, next, fake)
}

func TestDomainActivityWorkerPublishesAndIdleDoesNotRenew(t *testing.T) {
	g, fake := newTestRegistry(1, time.Minute)
	now := time.Now().Add(-30 * time.Second)
	a, b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	g.Upsert("a.example.", a, testBitmap(0), 70, now)
	g.Upsert("b.example.", b, testBitmap(1), 60, now)
	updated := make(chan struct{}, 1)
	g.kernel.update = func(ip netip.Addr, bump, routing []uint32) {
		fake.update(ip, bump, routing)
		updated <- struct{}{}
	}
	g.Start()
	t.Cleanup(func() { _ = g.Close() })
	g.activity.connection(b, "b.example")()
	select {
	case <-updated:
	case <-time.After(5 * time.Second):
		t.Fatal("background worker did not publish accumulated I/O")
	}
	deadline := g.retention("b.example.", b)
	g.flushActivity()
	if !g.retention("b.example.", b).Equal(deadline) {
		t.Fatal("an empty batch renewed an idle connection")
	}
	checkInvariants(t, g, fake)
}
