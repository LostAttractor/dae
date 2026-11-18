// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestDomainCapacityGuardPersistence(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "new-state")
	path := filepath.Join(dir, domainCapacityFile)
	now := time.Now()
	g, _ := newTestRegistry(16, time.Hour)
	g.EnablePersistence(dir)
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unused guard: stat returned %v", err)
	}
	bucket := domainCapacityBucket(netip.MustParseAddr("192.0.2.7"))
	set := func(until time.Time) {
		g.mu.Lock()
		defer g.mu.Unlock()
		g.incomplete[bucket] = until
		g.persistCapacity(bucket, until)
		if g.capacityPending && !g.persistActiveCapacity() {
			t.Fatal("capacity guard was not written")
		}
	}
	set(now.Add(time.Hour))
	set(now.Add(time.Hour + time.Minute))
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("capacity guard must be private: %v (%v)", info, err)
	}
	// Restore without waiting for a registry window, worker, or clean Close.
	const reserve = time.Hour + domainRenewInterval
	for _, at := range []time.Time{now, now.Add(-time.Hour)} {
		restored, _ := newTestRegistry(16, time.Hour)
		if err := restored.Restore(dir, testCapacityBitmap, at); err != nil {
			t.Fatal(err)
		}
		if got := restored.incomplete[bucket]; !got.Equal(now.Add(reserve)) {
			t.Fatalf("restore at %v: durable horizon %v, want %v", at, got, now.Add(reserve))
		}
	}
	set(now.Add(reserve + time.Minute))
	durable, _, err := readDomainCapacity(path)
	if err != nil || !durable[bucket].Equal(now.Add(reserve+time.Minute+domainRenewInterval)) {
		t.Fatalf("extended horizon %v: %v", durable[bucket], err)
	}
	restored, _ := newTestRegistry(16, time.Hour)
	if err := restored.Restore(dir, testCapacityBitmap, now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if !restored.incomplete[bucket].IsZero() {
		t.Fatal("expired durable guard isolated a bucket")
	}
}

func TestDomainCapacityGuardRetriesDirectoryChain(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	l := newDomainLog(dir, time.Now(), time.Hour)
	syncFailure := errors.New("parent directory sync failed")
	attempts := 0
	syncDirTree := func(path string, mode os.FileMode) error {
		attempts++
		if err := os.MkdirAll(path, mode); err != nil {
			return err
		}
		if attempts == 1 {
			return syncFailure
		}
		return nil
	}
	if err := l.writeDomainCapacity([]byte("guard"), syncDirTree); !errors.Is(err, syncFailure) || l.capacityDirSynced {
		t.Fatalf("unconfirmed directory chain: synced=%t, err=%v", l.capacityDirSynced, err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(l.capacityPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("guard published before directory chain was durable: %v", err)
	}
	for range 2 {
		if err := l.writeDomainCapacity([]byte("guard"), syncDirTree); err != nil {
			t.Fatal(err)
		}
	}
	if attempts != 2 || !l.capacityDirSynced {
		t.Fatalf("directory chain sync attempts=%d, synced=%t", attempts, l.capacityDirSynced)
	}
}

func TestDomainCapacityRestoreUsesBudgetAcrossPartialBuckets(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	ips := []netip.Addr{netip.MustParseAddr("192.0.2.3"), netip.MustParseAddr("192.0.2.4"), netip.MustParseAddr("192.0.2.5")}
	seen := make(map[int]bool)
	var entries []domainLogEntry
	for i, ip := range ips {
		bucket := domainCapacityBucket(ip)
		if seen[bucket] {
			t.Fatal("fixture requires distinct buckets")
		}
		seen[bucket] = true
		if i > 0 {
			entries = append(entries, domainLogEntry{name: fmt.Sprintf("heavy-%d.example.", i), ip: ip, deadline: now.Add(time.Hour).UnixNano()})
		}
	}
	const shared = "shared.example."
	for _, ip := range ips {
		entries = append(entries, domainLogEntry{name: shared, ip: ip, deadline: now.Add(time.Hour).UnixNano()})
	}
	if err := os.WriteFile(filepath.Join(dir, domainBaseFile), encodeDomainBase(1, entries), 0600); err != nil {
		t.Fatal(err)
	}
	g, _ := newTestRegistry(16, time.Hour)
	g.memoryLimit = 3*(domainPairMemory+domainIPMemory) + domainNameMemory(shared, nil)
	if err := g.Restore(dir, func(name string) []uint32 {
		if name == shared {
			return nil
		}
		return testBitmap(0)
	}, now); err != nil {
		t.Fatal(err)
	}
	if usage := g.Usage(); usage.UserUsed != 3 || usage.MemoryUsed != g.memoryLimit || usage.IncompleteBuckets != 2 {
		t.Fatalf("restored usage %+v", usage)
	}
	for _, ip := range ips {
		if !g.Verify(shared, ip).Paired {
			t.Fatalf("shared name missing at %s: %v", ip, g.evidence())
		}
	}
}

func testCapacityBitmap(name string) []uint32 {
	if name == "matched.example." {
		return testBitmap(0)
	}
	return testBitmap()
}

func TestDomainCapacityRestoreLimitsBeforeProjection(t *testing.T) {
	for _, blockCapacityWrite := range []bool{false, true} {
		label := "durable-before-compaction"
		if blockCapacityWrite {
			label = "failed-guard-preserves-baseline"
		}
		t.Run(label, func(t *testing.T) {
			dir := t.TempDir()
			now := time.Now()
			ip := netip.MustParseAddr("192.0.2.7")
			basePath := filepath.Join(dir, domainBaseFile)
			base := encodeDomainBase(1, []domainLogEntry{
				{name: "matched.example.", ip: ip, deadline: now.Add(time.Hour).UnixNano()},
				{name: "other.example.", ip: ip, deadline: now.Add(time.Hour).UnixNano()},
			})
			if err := os.WriteFile(basePath, base, 0600); err != nil {
				t.Fatal(err)
			}
			g, _ := newTestRegistry(16, time.Hour)
			g.memoryLimit = domainPairMemory + domainIPMemory + domainNameMemory("matched.example.", testBitmap(0)) + domainIPBitmapMemory()
			if err := g.Restore(dir, testCapacityBitmap, now); err != nil {
				t.Fatal(err)
			}
			bucket := domainCapacityBucket(ip)
			if usage := g.Usage(); usage.UserUsed != 1 || usage.MemoryUsed != g.memoryLimit || usage.KernelUsed != 0 || !g.incomplete[bucket].Equal(now.Add(time.Hour)) {
				t.Fatalf("restored usage %+v, bucket deadline %v", usage, g.incomplete[bucket])
			}
			if _, err := os.Stat(filepath.Join(dir, domainCapacityFile)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("restore wrote a guard before activation: %v", err)
			}
			if blockCapacityWrite {
				if err := os.Mkdir(filepath.Join(dir, domainCapacityFile), 0700); err != nil {
					t.Fatal(err)
				}
			}
			g.EnablePersistence(dir)
			g.writeRenewals(now)
			if g.persist.rebuild != blockCapacityWrite {
				t.Fatalf("baseline rebuild remains pending: %t", g.persist.rebuild)
			}
			recovered, _, err := recoverDomainEvidence(dir)
			want := 1
			if blockCapacityWrite {
				want = 2
			}
			if err != nil || len(recovered.ordinals) != want {
				t.Fatalf("recovered %v, err %v, want %d ordinals", recovered, err, want)
			}
		})
	}
}

func TestDomainCapacityRestoreKeepsCompleteBuckets(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	ips := []netip.Addr{netip.MustParseAddr("192.0.2.3"), netip.MustParseAddr("192.0.2.4"), netip.MustParseAddr("192.0.2.5")}
	slices.SortFunc(ips, func(a, b netip.Addr) int { return domainCapacityBucket(a) - domainCapacityBucket(b) })
	for i := 1; i < len(ips); i++ {
		if domainCapacityBucket(ips[i-1]) == domainCapacityBucket(ips[i]) {
			t.Fatal("fixture requires distinct buckets")
		}
	}
	dirty, whole, boundary := ips[0], ips[1], ips[2]
	seed, _ := newTestRegistry(16, time.Hour)
	seed.EnablePersistence(dir)
	seed.mu.Lock()
	seed.extendIncomplete(domainCapacityBucket(dirty), now.Add(time.Hour))
	durable := seed.persistActiveCapacity()
	seed.mu.Unlock()
	if !durable {
		t.Fatal("initial isolation was not written")
	}
	var entries []domainLogEntry
	for _, name := range []string{"first.example.", "second.example."} {
		for _, ip := range ips {
			entries = append(entries, domainLogEntry{name: name, ip: ip, deadline: now.Add(time.Hour).UnixNano()})
		}
	}
	if err := os.WriteFile(filepath.Join(dir, domainBaseFile), encodeDomainBase(1, entries), 0600); err != nil {
		t.Fatal(err)
	}
	for range 10 {
		g, _ := newTestRegistry(16, time.Hour)
		bitmap := testBitmap(0)
		g.memoryLimit = 3*domainPairMemory + 2*(domainIPMemory+domainIPBitmapMemory()) +
			domainNameMemory("first.example.", bitmap) + domainNameMemory("second.example.", bitmap)
		if err := g.Restore(dir, func(string) []uint32 { return testBitmap(0) }, now); err != nil {
			t.Fatal(err)
		}
		if usage := g.Usage(); usage.UserUsed != 3 || usage.MemoryUsed != g.memoryLimit || usage.KernelUsed != 1 || usage.IncompleteBuckets != 2 {
			t.Fatalf("restored usage %+v", usage)
		}
		if !g.Verify("first.example.", whole).Paired || !g.Verify("second.example.", whole).Paired ||
			!g.Verify("first.example.", boundary).Paired || g.Verify("second.example.", boundary).Paired ||
			g.Verify("first.example.", dirty).Paired || g.Verify("second.example.", dirty).Paired {
			t.Fatalf("unstable retained evidence: %v", g.evidence())
		}
		if _, ok := g.kernel.resident[whole]; !ok {
			t.Fatal("a complete bucket lost its projection")
		}
	}
}

func TestDomainCapacityRestoreBoundarySkipsExpensivePair(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	whole, boundary := netip.MustParseAddr("192.0.2.3"), netip.MustParseAddr("192.0.2.4")
	if domainCapacityBucket(whole) == domainCapacityBucket(boundary) {
		t.Fatal("fixture requires distinct buckets")
	}
	const cheap = "other.example."
	deadline := now.Add(time.Hour).UnixNano()
	entries := []domainLogEntry{
		{name: "matched.example.", ip: boundary, deadline: deadline},
		{name: cheap, ip: whole, deadline: deadline},
		{name: cheap, ip: boundary, deadline: deadline},
	}
	if err := os.WriteFile(filepath.Join(dir, domainBaseFile), encodeDomainBase(1, entries), 0600); err != nil {
		t.Fatal(err)
	}
	g, _ := newTestRegistry(16, time.Hour)
	g.memoryLimit = 2*(domainPairMemory+domainIPMemory) + domainNameMemory(cheap, nil)
	calls := 0
	if err := g.Restore(dir, func(name string) []uint32 {
		calls++
		return testCapacityBitmap(name)
	}, now); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || !g.Verify(cheap, whole).Paired || !g.Verify(cheap, boundary).Paired || g.Verify("matched.example.", boundary).Paired {
		t.Fatalf("match calls=%d, retained evidence=%v", calls, g.evidence())
	}
	if usage := g.Usage(); usage.MemoryUsed != g.memoryLimit || usage.IncompleteBuckets != 1 {
		t.Fatalf("restored usage %+v", usage)
	}
}

func TestDomainCapacityBadGuardPreservesIsolation(t *testing.T) {
	for _, unreadable := range []bool{false, true} {
		label := "corrupt"
		if unreadable {
			label = "not-regular"
		}
		t.Run(label, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, domainCapacityFile)
			if unreadable {
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path, make([]byte, domainCapacityFileSize), 0600); err != nil {
				t.Fatal(err)
			}
			g, _ := newTestRegistry(16, time.Hour)
			if err := g.Restore(dir, testCapacityBitmap, time.Now()); err == nil {
				t.Fatal("accepted an invalid capacity file")
			}
			g.EnablePersistence(dir)
			for _, until := range g.incomplete {
				if !until.Equal(domainCapacityMaxTime) {
					t.Fatalf("capacity uncertainty cleared: %v", until)
				}
			}
			if g.persist.enabled == unreadable {
				t.Fatalf("persistence enabled=%t, unreadable=%t", g.persist.enabled, unreadable)
			}
		})
	}
}

func TestDomainCapacityGuardCloseRetries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, domainCapacityFile)
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	g, _ := newTestRegistry(16, time.Hour)
	g.EnablePersistence(dir)
	now := time.Now()
	bucket := domainCapacityBucket(netip.MustParseAddr("192.0.2.7"))
	g.mu.Lock()
	g.incomplete[bucket] = now.Add(time.Hour)
	g.persistCapacity(bucket, g.incomplete[bucket])
	durable := g.persistActiveCapacity()
	g.mu.Unlock()
	if durable || !g.capacityPending {
		t.Fatal("a failed write must leave the active guard pending")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	onDisk, _, err := readDomainCapacity(path)
	if err != nil || !onDisk[bucket].Equal(now.Add(time.Hour+domainRenewInterval)) {
		t.Fatalf("close left guard %v: %v", onDisk[bucket], err)
	}
}
