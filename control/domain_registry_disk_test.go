// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"maps"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/network"
)

// persistTestRegistry enables persistence in dir and writes the first baseline.
func persistTestRegistry(t *testing.T, g *DomainRegistry, dir string, now time.Time) {
	t.Helper()
	g.EnablePersistence(dir)
	g.writeRenewals(now)
	if g.persist.rebuild {
		t.Fatal("baseline was not written")
	}
}

func restoreTestRegistry(t *testing.T, dir string, window time.Duration, now time.Time) *DomainRegistry {
	t.Helper()
	g, fake := newTestRegistry(16, window)
	if err := g.Restore(dir, func(string) []uint32 { return testBitmap() }, now); err != nil {
		t.Fatal(err)
	}
	checkInvariants(t, g, fake)
	return g
}

// diskEvidence lists deadlines as persisted, without monotonic readings.
func diskEvidence(g *DomainRegistry) map[string]int64 {
	evidence := make(map[string]int64)
	for name, addresses := range g.evidence() {
		for ip, deadline := range addresses {
			evidence[name+" "+ip.String()] = deadline.UnixNano()
		}
	}
	return evidence
}

func requireDiskEvidence(t *testing.T, got, want map[string]int64) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("recovered %v, want %v", got, want)
	}
	for key, deadline := range want {
		if got[key] != deadline {
			t.Fatalf("recovered %s at %v, want %v", key, time.Unix(0, got[key]), time.Unix(0, deadline))
		}
	}
}

func copyDomainStore(t *testing.T, from string) string {
	t.Helper()
	to := t.TempDir()
	entries, err := os.ReadDir(from)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(from, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(to, entry.Name()), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return to
}

func TestDomainRegistryDiskRoundTrip(t *testing.T) {
	now := time.Now()
	g, _ := newTestRegistry(2, time.Second)
	ip4, ip6 := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")
	live, stale := "live.example.", "stale.example."
	g.Upsert(live, ip4, testBitmap(0), 3600, now)
	g.Upsert(live, ip6, testBitmap(0), 7200, now)
	g.Upsert(stale, ip4, testBitmap(), 60, now)
	dir := filepath.Join(t.TempDir(), "state")
	persistTestRegistry(t, g, dir, now)
	for _, name := range []string{domainBaseFile, domainJournalFile} {
		if info, err := os.Stat(filepath.Join(dir, name)); err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("private %s: %v %v", name, info, err)
		}
	}
	restored, fake := newTestRegistry(2, 7*24*time.Hour)
	activity := restored.activity
	if err := restored.Restore(dir, func(name string) []uint32 {
		if name == stale {
			t.Fatal("evaluated expired domain during restore")
		}
		return testBitmap(3)
	}, now.Add(30*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if restored.activity != activity {
		t.Fatal("disk restore replaced the registry's activity handle")
	}
	checkInvariants(t, restored, fake)
	if restored.Size() != 2 || restored.Usage().GC != 1 || restored.Verify(stale, ip4).Paired {
		t.Fatal("restoration lost a pair or restored stale evidence")
	}
	for ip, deadline := range map[netip.Addr]time.Time{ip4: now.Add(time.Hour), ip6: now.Add(2 * time.Hour)} {
		if !restored.Verify(live, ip).Paired || !kernelCurrent(restored, ip) || !restored.retention(live, ip).Equal(deadline) ||
			!bitmapHas(fake.routing[ip], 3) || bitmapHas(fake.bump[ip], 0) {
			t.Fatal("restoration changed the original deadline or current bitmap")
		}
	}
	restored.Sweep(now.Add(time.Hour))
	if restored.Verify(live, ip4).Registered || !restored.Verify(live, ip6).Paired {
		t.Fatal("round trip changed address-family verification or retention")
	}
	// Collection writes nothing; restore collects expired records itself.
	again, _ := newTestRegistry(2, time.Second)
	if err := again.Restore(dir, func(string) []uint32 { t.Fatal("expired evidence evaluated a domain"); return nil }, now.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if again.Size() != 0 || again.Usage().GC != 3 {
		t.Fatal("expired evidence survived restore")
	}
}

// journalScenario leaves a baseline and a journal with every frame kind,
// written by the returned registry with a one-hour window.
func journalScenario(t *testing.T, dir string, now time.Time) *DomainRegistry {
	t.Helper()
	g, _ := newTestRegistry(16, time.Hour)
	a, b, c := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("2001:db8::3")
	g.Upsert("base.example.", a, testBitmap(), 60, now)
	g.Upsert("late.example.", a, testBitmap(), 60, now)
	persistTestRegistry(t, g, dir, now)
	g.ObserveDNS([]domainObservation{{name: "new.example.", ips: []netip.Addr{b, c}, bitmap: testBitmap(), ttl: 60}}, now.Add(time.Minute))
	g.activity.observe(a, "base.example.", now.Add(2*time.Minute))
	// A TTL beyond the window is not rounded down to the window bound.
	g.Upsert("new.example.", b, testBitmap(), 7200, now.Add(3*time.Minute))
	g.writeRenewals(now.Add(domainRenewInterval))
	// Activity applied after its window closed is not rounded up by more
	// than one interval either.
	g.activity.observe(a, "late.example.", now.Add(domainRenewInterval-time.Second))
	g.Upsert("new.example.", netip.MustParseAddr("192.0.2.4"), testBitmap(), 60, now.Add(11*time.Minute))
	g.writeRenewals(now.Add(2 * domainRenewInterval))
	return g
}

func TestDomainRegistryJournalRecovery(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	g, _ := newTestRegistry(16, time.Hour)
	a, b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	g.Upsert("base.example.", a, testBitmap(), 60, now)
	persistTestRegistry(t, g, dir, now)
	// The observation itself appends the new pair.
	g.Upsert("new.example.", b, testBitmap(), 60, now.Add(time.Minute))
	g.activity.observe(a, "base.example.", now.Add(2*time.Minute))
	// A crash before the window closes keeps new pairs, not the renewal.
	requireDiskEvidence(t, diskEvidence(restoreTestRegistry(t, dir, time.Hour, now)), map[string]int64{
		"base.example. 192.0.2.1": now.Add(time.Hour).UnixNano(),
		"new.example. 192.0.2.2":  now.Add(time.Minute + time.Hour).UnixNano(),
	})

	dir = t.TempDir()
	g = journalScenario(t, dir, now)
	want := map[string]int64{
		// Renewed at +2m in the window opened at 0: rounded up to its bound.
		"base.example. 192.0.2.1":  now.Add(domainRenewInterval + time.Hour).UnixNano(),
		"late.example. 192.0.2.1":  now.Add(domainRenewInterval - time.Second + time.Hour).UnixNano(),
		"new.example. 192.0.2.2":   now.Add(3*time.Minute + 2*time.Hour).UnixNano(),
		"new.example. 2001:db8::3": now.Add(time.Minute + time.Hour).UnixNano(),
		"new.example. 192.0.2.4":   now.Add(11*time.Minute + time.Hour).UnixNano(),
	}
	restored := restoreTestRegistry(t, dir, time.Hour, now.Add(20*time.Minute))
	requireDiskEvidence(t, diskEvidence(restored), want)
	for key, deadline := range diskEvidence(g) {
		if want[key] < deadline || want[key] > deadline+int64(domainRenewInterval) {
			t.Fatalf("%s recovered %v from %v, beyond one renewal interval", key, time.Unix(0, want[key]), time.Unix(0, deadline))
		}
	}
	// The restored registry continues the journal with consistent ordinals.
	restored.EnablePersistence(dir)
	restored.activity.observe(netip.MustParseAddr("192.0.2.4"), "new.example.", now.Add(25*time.Minute))
	restored.writeRenewals(now.Add(30 * time.Minute))
	want["new.example. 192.0.2.4"] = now.Add(30*time.Minute + time.Hour).UnixNano()
	requireDiskEvidence(t, diskEvidence(restoreTestRegistry(t, dir, time.Hour, now.Add(20*time.Minute))), want)
}

func TestDomainRegistryJournalTruncation(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	journalScenario(t, dir, now)
	journal, err := os.ReadFile(filepath.Join(dir, domainJournalFile))
	if err != nil {
		t.Fatal(err)
	}
	// Frames are followed by the zero-filled rest of the chunk.
	boundaries := []int{domainHeaderSize}
	for offset := domainHeaderSize; binary.LittleEndian.Uint32(journal[offset:]) != 0; {
		offset += int(binary.LittleEndian.Uint32(journal[offset:])) + 8
		boundaries = append(boundaries, offset)
	}
	if len(boundaries) != 5 || len(journal) != domainJournalChunk || !bytes.Equal(journal[boundaries[4]:], make([]byte, len(journal)-boundaries[4])) {
		t.Fatalf("unexpected frames ending at %v in %d bytes", boundaries, len(journal))
	}
	journal = journal[:boundaries[4]]
	recoverAt := func(size int) (*DomainRegistry, map[string]int64) {
		torn := copyDomainStore(t, dir)
		if err := os.Truncate(filepath.Join(torn, domainJournalFile), int64(size)); err != nil {
			t.Fatal(err)
		}
		g := restoreTestRegistry(t, torn, time.Hour, now)
		return g, diskEvidence(g)
	}
	complete := make(map[int]map[string]int64)
	for _, boundary := range boundaries {
		_, complete[boundary] = recoverAt(boundary)
	}
	for size := range len(journal) {
		g, evidence := recoverAt(size)
		if size < domainHeaderSize {
			if !g.persist.rebuild {
				t.Fatalf("journal header torn at %d was not replaced", size)
			}
			requireDiskEvidence(t, evidence, complete[domainHeaderSize])
			continue
		}
		last := domainHeaderSize
		for _, boundary := range boundaries {
			if boundary <= size {
				last = boundary
			}
		}
		if g.persist.rebuild || g.persist.disk.size != int64(last) {
			t.Fatalf("torn at %d: rebuild %v, valid end %d, want %d", size, g.persist.rebuild, g.persist.disk.size, last)
		}
		requireDiskEvidence(t, evidence, complete[last])
	}
	// Frames written after a torn tail replace it and stay reachable.
	torn := copyDomainStore(t, dir)
	if err := os.Truncate(filepath.Join(torn, domainJournalFile), int64(len(journal)-3)); err != nil {
		t.Fatal(err)
	}
	g := restoreTestRegistry(t, torn, time.Hour, now)
	g.EnablePersistence(torn)
	g.Upsert("after.example.", netip.MustParseAddr("192.0.2.9"), testBitmap(), 60, now.Add(21*time.Minute))
	g.writeRenewals(now.Add(30 * time.Minute))
	want := complete[boundaries[len(boundaries)-2]]
	want["after.example. 192.0.2.9"] = now.Add(21*time.Minute + time.Hour).UnixNano()
	requireDiskEvidence(t, diskEvidence(restoreTestRegistry(t, torn, time.Hour, now)), want)
	// Replay never resumes past a corrupt frame, even when a new frame of the
	// same length realigns the valid frames behind it.
	corrupt := copyDomainStore(t, dir)
	damaged := bytes.Clone(journal)
	damaged[boundaries[1]-1] ^= 0xff
	if err := os.WriteFile(filepath.Join(corrupt, domainJournalFile), damaged, 0600); err != nil {
		t.Fatal(err)
	}
	g = restoreTestRegistry(t, corrupt, time.Hour, now)
	g.EnablePersistence(corrupt)
	b, c := netip.MustParseAddr("192.0.2.7"), netip.MustParseAddr("2001:db8::8")
	g.ObserveDNS([]domainObservation{{name: "new.example.", ips: []netip.Addr{b, c}, bitmap: testBitmap(), ttl: 60}}, now.Add(time.Minute))
	want = complete[domainHeaderSize]
	want["new.example. 192.0.2.7"] = now.Add(time.Minute + time.Hour).UnixNano()
	want["new.example. 2001:db8::8"] = now.Add(time.Minute + time.Hour).UnixNano()
	requireDiskEvidence(t, diskEvidence(restoreTestRegistry(t, corrupt, time.Hour, now)), want)
}

// A damaged length of 2^31 or more must stop replay on 32-bit targets too.
func TestDomainRegistryJournalHugeFrameLength(t *testing.T) {
	rec := &domainRecovery{epoch: 7}
	journal := binary.LittleEndian.AppendUint32(domainHeader(domainJournalMagic, rec.epoch), 0x80000010)
	rec.replay(append(journal, make([]byte, 32)...))
	if rec.journal != domainHeaderSize {
		t.Fatalf("replay ended at %d, want %d", rec.journal, domainHeaderSize)
	}
}

func TestDomainRegistryJournalEpochMismatch(t *testing.T) {
	now := time.Now()
	first, second := t.TempDir(), t.TempDir()
	journalScenario(t, first, now)
	journalScenario(t, second, now)
	baseOnly := copyDomainStore(t, first)
	if err := os.Remove(filepath.Join(baseOnly, domainJournalFile)); err != nil {
		t.Fatal(err)
	}
	g := restoreTestRegistry(t, baseOnly, time.Hour, now)
	if !g.persist.rebuild {
		t.Fatal("a missing journal was not replaced")
	}
	want := diskEvidence(g)
	foreign, err := os.ReadFile(filepath.Join(second, domainJournalFile))
	if err != nil {
		t.Fatal(err)
	}
	own, err := os.ReadFile(filepath.Join(first, domainJournalFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		journal []byte
		rebuild bool
	}{
		{"foreign journal", foreign, true},
		// The header matches, but each frame's checksum binds another epoch.
		{"foreign frames", append(own[:domainHeaderSize:domainHeaderSize], foreign[domainHeaderSize:]...), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := copyDomainStore(t, first)
			if err := os.WriteFile(filepath.Join(dir, domainJournalFile), test.journal, 0600); err != nil {
				t.Fatal(err)
			}
			g := restoreTestRegistry(t, dir, time.Hour, now)
			requireDiskEvidence(t, diskEvidence(g), want)
			if g.persist.rebuild != test.rebuild || !test.rebuild && g.persist.disk.size != domainHeaderSize {
				t.Fatalf("rebuild %v, valid end %d", g.persist.rebuild, g.persist.disk.size)
			}
		})
	}
}

func TestDomainRegistryCompactionInterrupted(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	g := journalScenario(t, dir, now)
	old := diskEvidence(restoreTestRegistry(t, dir, time.Hour, now))
	memory := diskEvidence(g)
	var entries []domainLogEntry
	for name, record := range g.byName {
		for ip, pair := range record.addresses {
			entries = append(entries, domainLogEntry{name, ip, pair.retainUntil.UnixNano()})
		}
	}
	const epoch = 7
	base := encodeDomainBase(epoch, entries)
	steps := len(domainCompaction(dir, base, epoch))
	for done := range steps + 1 {
		for _, lost := range []bool{false, true} {
			// Only the complete temporary file can replace a lost baseline.
			if lost && done != 2 {
				continue
			}
			t.Run(fmt.Sprintf("steps=%d lost=%v", done, lost), func(t *testing.T) {
				dir := copyDomainStore(t, dir)
				for _, step := range domainCompaction(dir, base, epoch)[:done] {
					if err := step(); err != nil {
						t.Fatal(err)
					}
				}
				if lost {
					// A rolled-back rename can expose a published baseline whose
					// blocks were discarded, next to the complete temporary file.
					if err := os.WriteFile(filepath.Join(dir, domainBaseFile), make([]byte, len(base)), 0600); err != nil {
						t.Fatal(err)
					}
				}
				g := restoreTestRegistry(t, dir, time.Hour, now)
				want, rebuild := old, false
				if done >= 3 || lost {
					want, rebuild = memory, done < steps
				}
				requireDiskEvidence(t, diskEvidence(g), want)
				if g.persist.rebuild != rebuild {
					t.Fatalf("rebuild = %v, want %v", g.persist.rebuild, rebuild)
				}
				if _, err := os.Stat(filepath.Join(dir, domainBaseFile+domainTempSuffix)); lost && err == nil {
					t.Fatal("adopted temporary baseline was not published")
				}
				// Whatever was recovered persists again.
				g.EnablePersistence(dir)
				g.writeRenewals(now)
				requireDiskEvidence(t, diskEvidence(restoreTestRegistry(t, dir, time.Hour, now)), want)
			})
		}
	}
}

// Random histories with reloads, rejected reloads and crashes at random points
// recover every pair at or above the deadline last made durable for it, and
// within one renewal interval above the latest deadline it had in memory.
func TestDomainRegistryJournalRandomHistory(t *testing.T) {
	for seed := range uint64(16) {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			rng := rand.New(rand.NewPCG(seed, 1))
			const window = 30 * time.Minute
			g, _ := newTestRegistry(64, window)
			dir := t.TempDir()
			now := time.Now()
			persistTestRegistry(t, g, dir, now)
			durable, latest := make(map[string]int64), make(map[string]int64)
			raise := func(to, from map[string]int64) {
				for key, deadline := range from {
					to[key] = max(to[key], deadline)
				}
			}
			check := func(step int, restored map[string]int64) {
				t.Helper()
				for key, deadline := range durable {
					if got, ok := restored[key]; deadline > now.UnixNano() && (!ok || got < deadline) {
						t.Fatalf("step %d: %s durable until %v, recovered %v (%v)", step, key, time.Unix(0, deadline), time.Unix(0, got), ok)
					}
				}
				for key, got := range restored {
					if got > latest[key]+int64(domainRenewInterval) {
						t.Fatalf("step %d: %s recovered %v, latest in memory %v", step, key, time.Unix(0, got), time.Unix(0, latest[key]))
					}
				}
			}
			for step := range 400 {
				now = now.Add(time.Duration(rng.IntN(90)) * time.Second)
				name := fmt.Sprintf("d%d.example.", rng.IntN(12))
				ip := netip.AddrFrom4([4]byte{192, 0, 2, byte(rng.IntN(16))})
				before := diskEvidence(g)
				switch rng.IntN(13) {
				case 0, 1, 2:
					// The observation appends new pairs before it returns.
					g.Upsert(name, ip, testBitmap(), []int{60, 7200}[rng.IntN(2)], now)
					for key, deadline := range diskEvidence(g) {
						if _, ok := before[key]; !ok {
							durable[key] = max(durable[key], deadline)
						}
					}
				case 3, 4, 5:
					g.activity.observe(ip, []string{name, ""}[rng.IntN(2)], now.Add(-time.Duration(rng.IntN(10))*time.Second))
				case 6:
					g.Sweep(now)
				case 7:
					g.writeRenewals(now)
					raise(durable, before)
				case 8:
					g.mu.Lock()
					g.persist.rebuild = true
					g.mu.Unlock()
					g.writeRenewals(now)
					raise(durable, before)
				case 9:
					next, _ := newTestRegistry(64, window)
					if err := next.ForkFrom(g, func(string) []uint32 { return testBitmap() }, now); err != nil {
						t.Fatal(err)
					}
					if err := g.Close(); err != nil {
						t.Fatal(err)
					}
					g = next
				case 10:
					// A rejected reload hands the files and window back.
					rejected := newDomainRegistry(64, window, func(netip.Addr, []uint32, []uint32) error { return errors.New("injected") }, func(netip.Addr) error { return nil })
					if rejected.ForkFrom(g, func(string) []uint32 { return testBitmap(0) }, now) == nil {
						// Nothing needed a kernel write, so the reload was admitted.
						if err := g.Close(); err != nil {
							t.Fatal(err)
						}
						g = rejected
					}
				case 11, 12:
					// A crash leaves the files as they are.
					check(step, diskEvidence(restoreTestRegistry(t, copyDomainStore(t, dir), window, now)))
				}
				raise(latest, diskEvidence(g))
			}
			g.Sweep(now)
			raise(durable, diskEvidence(g))
			if err := g.Close(); err != nil {
				t.Fatal(err)
			}
			restored := diskEvidence(restoreTestRegistry(t, dir, window, now))
			check(-1, restored)
			for key := range diskEvidence(g) {
				if _, ok := restored[key]; !ok {
					t.Fatalf("live pair %s was not recovered", key)
				}
			}
		})
	}
}

// Concurrent observations and activity across reloads, with compactions on the
// worker, never lose a pair or a renewal that a clean close writes.
func TestDomainRegistryConcurrentWritersAndReloads(t *testing.T) {
	const window = time.Hour
	dir := t.TempDir()
	start := time.Now()
	g, _ := newTestRegistry(64, window)
	g.Start()
	g.EnablePersistence(dir)
	var current sync.Mutex
	serving := g
	get := func() *DomainRegistry {
		current.Lock()
		defer current.Unlock()
		return serving
	}
	stop := make(chan struct{})
	var producers sync.WaitGroup
	for worker := range 4 {
		producers.Go(func() {
			rng := rand.New(rand.NewPCG(uint64(worker), 3))
			for {
				select {
				case <-stop:
					return
				default:
				}
				g := get()
				name := fmt.Sprintf("d%d.example.", rng.IntN(50))
				ip := netip.AddrFrom4([4]byte{198, 51, 100, byte(rng.IntN(200))})
				if rng.IntN(2) == 0 {
					g.Upsert(name, ip, testBitmap(), 60, time.Now())
				} else {
					g.activity.observe(ip, name, time.Now())
				}
			}
		})
	}
	for i := range 20 {
		time.Sleep(2 * time.Millisecond)
		old := get()
		if i%4 == 0 {
			old.mu.Lock()
			old.persist.rebuild = true
			old.mu.Unlock()
			old.wakePersistence()
			time.Sleep(time.Millisecond)
		}
		next, _ := newTestRegistry(64, window)
		next.Start()
		current.Lock()
		err := next.ForkFrom(old, func(string) []uint32 { return testBitmap() }, time.Now())
		serving = next
		current.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		if err := old.Close(); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	producers.Wait()
	last := get()
	if err := last.Close(); err != nil {
		t.Fatal(err)
	}
	memory := diskEvidence(last)
	restored := diskEvidence(restoreTestRegistry(t, dir, window, start))
	for key, deadline := range memory {
		if got, ok := restored[key]; !ok || got < deadline || got > deadline+int64(domainRenewInterval) {
			t.Fatalf("%s: memory %v, recovered %v (%v)", key, time.Unix(0, deadline), time.Unix(0, got), ok)
		}
	}
}

// New pairs never wait for a compaction; the worker appends them after it.
func TestDomainRegistryNewPairsDuringCompaction(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	g, _ := newTestRegistry(4, time.Hour)
	persistTestRegistry(t, g, dir, now)
	<-g.persistWake
	l := g.persist
	l.io.Lock()
	g.Upsert("a.example.", netip.MustParseAddr("192.0.2.1"), testBitmap(), 60, now)
	select {
	case <-g.persistWake:
	default:
		t.Fatal("the worker was not asked to append the queued pair")
	}
	if len(l.fresh) != 1 {
		t.Fatalf("%d queued pairs, want 1", len(l.fresh))
	}
	l.io.Unlock()
	g.writeNew(now)
	requireDiskEvidence(t, diskEvidence(restoreTestRegistry(t, dir, time.Hour, now)), map[string]int64{
		"a.example. 192.0.2.1": now.Add(time.Hour).UnixNano(),
	})
}

// A window closed late lists each renewed pair once, with its final deadline.
func TestDomainRegistryLateWindowListsPairOnce(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	g, _ := newTestRegistry(4, time.Hour)
	ip := netip.MustParseAddr("192.0.2.1")
	g.Upsert("a.example.", ip, testBitmap(), 60, now)
	persistTestRegistry(t, g, dir, now)
	for i := range 1800 {
		g.activity.observe(ip, "a.example.", now.Add(domainRenewInterval+time.Duration(i)*time.Second))
	}
	if len(g.persist.renewed) != 1 {
		t.Fatalf("%d listings for one pair", len(g.persist.renewed))
	}
	g.writeRenewals(now.Add(domainRenewInterval + 30*time.Minute))
	requireDiskEvidence(t, diskEvidence(restoreTestRegistry(t, dir, time.Hour, now)), map[string]int64{
		"a.example. 192.0.2.1": now.Add(domainRenewInterval + 1799*time.Second + time.Hour).UnixNano(),
	})
}

// A clean close writes even within the retry delay of a failed compaction.
func TestDomainRegistryCloseRetriesFailedCompaction(t *testing.T) {
	now := time.Now()
	blocked := filepath.Join(t.TempDir(), "cache")
	if err := os.WriteFile(blocked, nil, 0600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(blocked, "state")
	g, _ := newTestRegistry(4, time.Hour)
	g.Upsert("a.example.", netip.MustParseAddr("192.0.2.1"), testBitmap(), 60, now)
	g.EnablePersistence(dir)
	g.writeNew(now)
	if !g.persist.rebuild {
		t.Fatal("compaction into a blocked directory succeeded")
	}
	if err := os.Remove(blocked); err != nil {
		t.Fatal(err)
	}
	g.writeNew(now)
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("compaction retried before its retry time: %v", err)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	requireDiskEvidence(t, diskEvidence(restoreTestRegistry(t, dir, time.Hour, now)), map[string]int64{
		"a.example. 192.0.2.1": now.Add(time.Hour).UnixNano(),
	})
}

func TestDomainRegistryForkHandsOffPersistence(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	old, _ := newTestRegistry(4, time.Hour)
	a, b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	old.Upsert("a.example.", a, testBitmap(), 60, now)
	persistTestRegistry(t, old, dir, now)
	next, _ := newTestRegistry(4, time.Hour)
	if err := next.ForkFrom(old, func(string) []uint32 { return testBitmap() }, now); err != nil {
		t.Fatal(err)
	}
	// The window opened before the reload ends on its own schedule.
	if next.renewalDue(now.Add(domainRenewInterval-time.Second)) || !next.renewalDue(now.Add(domainRenewInterval)) {
		t.Fatal("reload moved the end of the open renewal window")
	}
	next.Upsert("b.example.", b, testBitmap(), 60, now.Add(time.Minute))
	// The retired predecessor still observes DNS but writes nothing.
	old.Upsert("old-only.example.", b, testBitmap(), 60, now.Add(time.Minute))
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	next.activity.observe(a, "a.example.", now.Add(2*time.Minute))
	next.writeRenewals(now.Add(domainRenewInterval))
	requireDiskEvidence(t, diskEvidence(restoreTestRegistry(t, dir, time.Hour, now)), map[string]int64{
		"a.example. 192.0.2.1": now.Add(domainRenewInterval + time.Hour).UnixNano(),
		"b.example. 192.0.2.2": now.Add(time.Minute + time.Hour).UnixNano(),
	})
}

// A rejected reload hands the open window back with the predecessor's pairs,
// so their later renewals are still written.
func TestDomainRegistryRejectedForkKeepsWindow(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	old, _ := newTestRegistry(4, time.Hour)
	ip := netip.MustParseAddr("192.0.2.1")
	old.Upsert("a.example.", ip, testBitmap(), 60, now)
	persistTestRegistry(t, old, dir, now)
	old.activity.observe(ip, "a.example.", now.Add(time.Minute))
	rejected := newDomainRegistry(4, time.Hour, func(netip.Addr, []uint32, []uint32) error { return errors.New("injected") }, func(netip.Addr) error { return nil })
	if rejected.ForkFrom(old, func(string) []uint32 { return testBitmap(0) }, now.Add(time.Minute)) == nil {
		t.Fatal("candidate with failing kernel writes was admitted")
	}
	if err := rejected.Close(); err != nil {
		t.Fatal(err)
	}
	// Beyond the window bound, so only the pair's own final deadline covers it.
	old.Upsert("a.example.", ip, testBitmap(), 7200, now.Add(2*time.Minute))
	old.writeRenewals(now.Add(domainRenewInterval))
	requireDiskEvidence(t, diskEvidence(restoreTestRegistry(t, dir, time.Hour, now)), map[string]int64{
		"a.example. 192.0.2.1": now.Add(2*time.Minute + 2*time.Hour).UnixNano(),
	})
}

// A file that exists but cannot be read may be intact, so the run restores
// nothing and writes no file, also after a reload. A directory stands in for a
// file failing with an I/O error.
func TestDomainRegistryUnreadableFilesStayUntouched(t *testing.T) {
	now := time.Now()
	scenario := t.TempDir()
	journalScenario(t, scenario, now)
	files := func(dir string) map[string]string {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		files := make(map[string]string)
		for _, entry := range entries {
			data, _ := os.ReadFile(filepath.Join(dir, entry.Name()))
			files[entry.Name()] = string(data)
		}
		return files
	}
	for _, unreadable := range []string{domainBaseFile, domainJournalFile, domainBaseFile + domainTempSuffix} {
		t.Run(unreadable, func(t *testing.T) {
			dir := copyDomainStore(t, scenario)
			_ = os.Remove(filepath.Join(dir, unreadable))
			if unreadable == domainBaseFile+domainTempSuffix {
				// Only a missing or corrupt baseline consults the temporary one.
				if err := os.Remove(filepath.Join(dir, domainBaseFile)); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Mkdir(filepath.Join(dir, unreadable), 0700); err != nil {
				t.Fatal(err)
			}
			before := files(dir)
			g, _ := newTestRegistry(16, time.Hour)
			if err := g.Restore(dir, func(string) []uint32 { return testBitmap() }, now); err == nil || g.Size() != 0 {
				t.Fatalf("restored %d pairs from unreadable files: %v", g.Size(), err)
			}
			ip := netip.MustParseAddr("192.0.2.9")
			g.EnablePersistence(dir)
			g.Upsert("a.example.", ip, testBitmap(), 60, now)
			g.writeNew(now)
			g.writeRenewals(now.Add(domainRenewInterval))
			next, _ := newTestRegistry(16, time.Hour)
			if err := next.ForkFrom(g, func(string) []uint32 { return testBitmap() }, now); err != nil {
				t.Fatal(err)
			}
			if err := g.Close(); err != nil {
				t.Fatal(err)
			}
			next.EnablePersistence(dir)
			next.Upsert("b.example.", ip, testBitmap(), 60, now)
			next.writeNew(now)
			if err := next.Close(); err != nil {
				t.Fatal(err)
			}
			if after := files(dir); !maps.Equal(after, before) {
				t.Fatalf("files changed from %d to %d entries", len(before), len(after))
			}
		})
	}
}

func TestDomainRegistryDiscardsLegacySnapshot(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "domain-registry.json.gz")
	if err := os.WriteFile(legacy, []byte("legacy"), 0600); err != nil {
		t.Fatal(err)
	}
	g := restoreTestRegistry(t, dir, time.Hour, time.Now())
	if _, err := os.Stat(legacy); !os.IsNotExist(err) || g.Size() != 0 || !g.persist.rebuild {
		t.Fatalf("legacy snapshot was imported or kept: %v", err)
	}
}

func testDomainBaseline(body []byte) []byte {
	b := append(domainHeader(domainBaseMagic, 1), body...)
	return binary.LittleEndian.AppendUint32(b, crc32.Checksum(b, domainCRC))
}

func testDomainGroup(name string, addresses ...[]byte) []byte {
	b := binary.AppendUvarint(appendDomainName(nil, name), uint64(len(addresses)))
	for _, address := range addresses {
		b = binary.AppendVarint(append(append(b, byte(len(address))), address...), time.Now().Add(time.Hour).UnixNano())
	}
	return b
}

func TestDomainRegistryBaselineRejectsInvalidEntries(t *testing.T) {
	ip := func(s string) []byte { return netip.MustParseAddr(s).AsSlice() }
	first := testDomainGroup("first.example.", ip("192.0.2.1"))
	valid := testDomainBaseline(first)
	for _, test := range []struct {
		name string
		file []byte
	}{
		{"duplicate domain", testDomainBaseline(append(bytes.Clone(first), first...))},
		{"duplicate IP", testDomainBaseline(testDomainGroup("second.example.", ip("192.0.2.2"), ip("192.0.2.2")))},
		{"invalid name", testDomainBaseline(testDomainGroup("UPPER.example.", ip("192.0.2.2")))},
		{"unspecified IP", testDomainBaseline(testDomainGroup("second.example.", ip("0.0.0.0")))},
		{"mapped IP", testDomainBaseline(testDomainGroup("second.example.", ip("::ffff:192.0.2.2")))},
		{"invalid address length", testDomainBaseline(testDomainGroup("second.example.", []byte{192, 0, 2, 1, 1}))},
		{"empty domain group", testDomainBaseline(binary.AppendUvarint(appendDomainName(nil, "second.example."), 0))},
		{"truncated group", testDomainBaseline(binary.AppendUvarint(appendDomainName(nil, "second.example."), 2))},
		{"checksum mismatch", append(valid[:len(valid)-1:len(valid)-1], valid[len(valid)-1]^0xff)},
		{"trailing data", append(bytes.Clone(valid), 0)},
		{"wrong magic", append(domainJournalMagic[:], valid[8:]...)},
		{"truncated header", valid[:domainHeaderSize]},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, domainBaseFile), test.file, 0600); err != nil {
				t.Fatal(err)
			}
			g, fake := newTestRegistry(2, time.Hour)
			if err := g.Restore(dir, func(string) []uint32 { t.Fatal("published invalid baseline"); return nil }, time.Now()); err == nil {
				t.Fatal("accepted invalid baseline")
			}
			if g.Size() != 0 || !g.persist.rebuild {
				t.Fatal("partially published invalid baseline")
			}
			checkInvariants(t, g, fake)
		})
	}
}

func TestDomainRegistryDiskEscapedNames(t *testing.T) {
	g, _ := newTestRegistry(16, time.Second)
	now := time.Now()
	ip := netip.MustParseAddr("192.0.2.1")
	for i := range 16 {
		name := fmt.Sprint(i) + "." + strings.Repeat(strings.Repeat(`\001`, 60)+".", 4)
		g.Upsert(name, ip, make([]uint32, domainBitmapWords()), 60, now)
	}
	dir := t.TempDir()
	persistTestRegistry(t, g, dir, now)
	if restoreTestRegistry(t, dir, time.Second, now).Size() != 16 {
		t.Fatal("escaped-name observations lost")
	}
}

// A baseline is one coherent copy even while observations change every pair.
func TestDomainRegistryCompactionConcurrentUpdates(t *testing.T) {
	g, _ := newTestRegistry(16, time.Second)
	now := time.Now()
	observations := make([]domainObservation, 64)
	for i := range observations {
		observations[i] = domainObservation{
			name: fmt.Sprintf("d%d.example.", i), bitmap: testBitmap(), ttl: 60,
			ips: []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")},
		}
	}
	g.ObserveDNS(observations, now)
	dir := t.TempDir()
	persistTestRegistry(t, g, dir, now)
	var writers sync.WaitGroup
	writers.Go(func() {
		for i := range 128 {
			g.ObserveDNS(observations, now.Add(time.Duration(i)*time.Second))
		}
	})
	defer writers.Wait()
	for range 8 {
		g.mu.Lock()
		g.persist.rebuild = true
		g.mu.Unlock()
		g.writeRenewals(now)
		// Renewals since the compaction are not written yet.
		evidence := diskEvidence(restoreTestRegistry(t, dir, time.Second, now))
		if len(evidence) != 2*len(observations) {
			t.Fatalf("saved %d pairs, want %d", len(evidence), 2*len(observations))
		}
		var deadline int64
		for _, got := range evidence {
			if deadline != 0 && got != deadline {
				t.Fatal("baseline mixed concurrent updates")
			}
			deadline = got
		}
	}
}

func TestDomainRegistryConcurrentCloseFinalSave(t *testing.T) {
	g, _ := newTestRegistry(16, time.Second)
	dir := t.TempDir()
	g.Start()
	g.EnablePersistence(dir)
	now := time.Now()
	ip := netip.MustParseAddr("192.0.2.1")
	name := "final.example."
	g.Upsert(name, ip, make([]uint32, domainBitmapWords()), 60, now)
	var closers sync.WaitGroup
	for range 8 {
		closers.Go(func() {
			if err := g.Close(); err != nil {
				t.Error(err)
				return
			}
			restored, _ := newTestRegistry(16, time.Second)
			if err := restored.Restore(dir, func(string) []uint32 { return make([]uint32, domainBitmapWords()) }, now); err != nil {
				t.Error(err)
				return
			}
			if !restored.Verify(name, ip).Paired {
				t.Error("Close returned before the final write")
			}
		})
	}
	closers.Wait()
	g.Upsert("late.example.", ip, make([]uint32, domainBitmapWords()), 60, now)
	if g.Usage().UserUsed != 1 {
		t.Fatal("closed registry accepted late observation")
	}
}

func TestDomainRegistrySaveFailureDoesNotPreventRetirement(t *testing.T) {
	hook := mitmClientLogHook(t)
	g, _ := newTestRegistry(4, time.Hour)
	path := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	g.Start()
	g.EnablePersistence(filepath.Join(path, "state"))
	now, ip := time.Now(), netip.MustParseAddr("192.0.2.1")
	g.Upsert("retained.example.", ip, testBitmap(0), 60, now)
	activity := g.activity
	interfaceSource, err := network.NewInterfaceManager()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = interfaceSource.Close() })
	ifmgr := interfaceSource.NewScope()
	closed, cancel := context.WithCancel(t.Context())
	core := &controlPlaneCore{closed: closed, close: cancel, ifmgr: ifmgr, domainRegistry: g}
	core.addCleanup(g.Close)
	old := newLifecycleTestControlPlane(t, new(UdpEndpointPool))
	old.core = core
	if err := old.Close(); err != nil || !old.closedDone.Load() {
		t.Fatalf("persistence failure prevented safe retirement: %v", err)
	}
	logged := false
	for _, entry := range hook.AllEntries() {
		logged = logged || strings.HasPrefix(entry.Message, "Persist domain registry") && entry.Data["error"] != nil
	}
	if !logged {
		t.Fatal("persistence failure was not reported")
	}
	activity.observe(ip, "retained.example.", now.Add(time.Minute))
	successor, _ := newTestRegistry(4, time.Hour)
	defer successor.Close()
	matcher, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t, "", ""))
	successor.ForkFrom(old.core.domainRegistry, matcher.domainMatcher.MatchDomainBitmap, time.Now())
	activity.observe(ip, "retained.example.", now.Add(time.Minute))
	if !successor.retention("retained.example.", ip).Equal(now.Add(61 * time.Minute)) {
		t.Fatal("persistence failure lost in-memory evidence or queued activity")
	}
	activity.observe(ip, "retained.example.", now.Add(2*time.Minute))
	if !successor.retention("retained.example.", ip).Equal(now.Add(62 * time.Minute)) {
		t.Fatal("retained activity handle did not reach successor")
	}
}
