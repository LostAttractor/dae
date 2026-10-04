// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/network"
)

func gzipDomainSnapshot(t *testing.T, wire []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	w := gzip.NewWriter(&buffer)
	if _, err := w.Write(wire); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func readGzipDomainSnapshot(t *testing.T, path string) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	wire, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestDomainRegistryDiskRoundTrip(t *testing.T) {
	now := time.Now().UTC()
	g, _ := newTestRegistry(2, time.Second)
	ip4, ip6 := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")
	live := "live.example."
	stale := "stale.example."
	g.Upsert(live, ip4, testBitmap(0), 3600, now)
	g.Upsert(live, ip6, testBitmap(0), 7200, now)
	g.Upsert(stale, ip4, testBitmap(), 60, now)
	path := filepath.Join(t.TempDir(), "state", "domain-registry.json.gz")
	if err := g.Save(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private snapshot: %v %v", info, err)
	}
	saved := readGzipDomainSnapshot(t, path)
	var entries map[string]map[string]time.Time
	if err := json.Unmarshal(saved, &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || len(entries[live]) != 2 || len(entries[stale]) != 1 {
		t.Fatalf("incorrect snapshot records: %s", saved)
	}
	if !entries[live][ip4.String()].Equal(now.Add(time.Hour)) ||
		!entries[live][ip6.String()].Equal(now.Add(2*time.Hour)) ||
		!entries[stale][ip4.String()].Equal(now.Add(time.Minute)) {
		t.Fatalf("grouping changed pair deadlines: %s", saved)
	}
	restored, fake := newTestRegistry(2, 7*24*time.Hour)
	activity := restored.activity
	if err := restored.Restore(path, func(string) []uint32 { return testBitmap(3) }, now.Add(30*time.Minute)); err != nil {
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
		if !restored.Verify(live, ip).KernelCovered || !restored.retention(live, ip).Equal(deadline) ||
			!bitmapHas(fake.routing[ip], 3) || bitmapHas(fake.bump[ip], 0) {
			t.Fatal("restoration changed the original deadline or current bitmap")
		}
	}
	restored.Sweep(now.Add(time.Hour))
	if restored.Verify(live, ip4).Registered || !restored.Verify(live, ip6).Paired {
		t.Fatal("round trip changed address-family verification or retention")
	}
	restored.Sweep(now.Add(2 * time.Hour))
	if restored.Size() != 0 || len(fake.bump) != 0 {
		t.Fatal("expired snapshot evidence still in kernel")
	}
	if err := restored.Save(path); err != nil {
		t.Fatal(err)
	}
	if saved := readGzipDomainSnapshot(t, path); string(saved) != "{}" {
		t.Fatalf("empty snapshot = %s, want an empty object", saved)
	}
	if err := restored.Restore(path, func(string) []uint32 { t.Fatal("empty snapshot evaluated a domain"); return nil }, now); err != nil {
		t.Fatal(err)
	}
}

func TestDomainRegistrySnapshotRejectsInvalidEntries(t *testing.T) {
	now := time.Now().UTC()
	deadline := now.Add(time.Hour).Format(time.RFC3339Nano)
	for _, test := range []struct {
		name  string
		entry string
	}{
		{"duplicate domain", fmt.Sprintf(`"first.example.":{"192.0.2.2":%q}`, deadline)},
		{"duplicate IP", fmt.Sprintf(`"second.example.":{"192.0.2.2":%q,"192.0.2.2":%q}`, deadline, deadline)},
		{"duplicate IPv6 spelling", fmt.Sprintf(`"second.example.":{"2001:db8::1":%q,"2001:0db8::1":%q}`, deadline, deadline)},
		{"null deadline", `"second.example.":{"192.0.2.2":null}`},
		{"zero deadline", `"second.example.":{"192.0.2.2":"0001-01-01T00:00:00Z"}`},
		{"invalid name", fmt.Sprintf(`"UPPER.example.":{"192.0.2.2":%q}`, deadline)},
		{"unspecified IP", fmt.Sprintf(`"second.example.":{"0.0.0.0":%q}`, deadline)},
		{"mapped IP", fmt.Sprintf(`"second.example.":{"::ffff:192.0.2.2":%q}`, deadline)},
		{"zoned IP", fmt.Sprintf(`"second.example.":{"fe80::1%%eth0":%q}`, deadline)},
		{"invalid IP", fmt.Sprintf(`"second.example.":{"not-an-ip":%q}`, deadline)},
		{"empty domain group", `"second.example.":{}`},
		{"null domain group", `"second.example.":null`},
	} {
		t.Run(test.name, func(t *testing.T) {
			wire := []byte(fmt.Sprintf(`{"first.example.":{"192.0.2.1":%q},%s}`, deadline, test.entry))
			path := filepath.Join(t.TempDir(), "registry.json.gz")
			if err := os.WriteFile(path, gzipDomainSnapshot(t, wire), 0600); err != nil {
				t.Fatal(err)
			}
			g, fake := newTestRegistry(2, time.Hour)
			if err := g.Restore(path, func(string) []uint32 { t.Fatal("published invalid snapshot"); return nil }, now); err == nil {
				t.Fatalf("accepted invalid snapshot: %s", wire)
			}
			if g.generation != 0 || g.Size() != 0 {
				t.Fatal("partially published invalid snapshot")
			}
			checkInvariants(t, g, fake)
		})
	}
}

func TestDomainRegistrySnapshotRejectsInvalidJSON(t *testing.T) {
	for _, test := range []struct {
		name string
		wire string
	}{
		{"null", "null"},
		{"array", "[]"},
		{"truncated object", "{"},
		{"trailing data", "{}" + strings.Repeat(" ", 4096) + `{"unexpected":true}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "registry.json.gz")
			if err := os.WriteFile(path, gzipDomainSnapshot(t, []byte(test.wire)), 0600); err != nil {
				t.Fatal(err)
			}
			g, fake := newTestRegistry(1, time.Hour)
			if err := g.Restore(path, func(string) []uint32 { t.Fatal("published invalid snapshot"); return nil }, time.Now()); err == nil {
				t.Fatalf("accepted invalid snapshot: %s", test.wire)
			}
			if g.generation != 0 || g.Size() != 0 {
				t.Fatal("partially published invalid snapshot")
			}
			checkInvariants(t, g, fake)
		})
	}
}

func TestDomainRegistrySnapshotRejectsCorruptGzip(t *testing.T) {
	now := time.Now().UTC()
	wire := []byte(fmt.Sprintf(`{"live.example.":{"192.0.2.1":%q}}`, now.Add(time.Hour).Format(time.RFC3339Nano)))
	compressed := gzipDomainSnapshot(t, wire)
	for _, test := range []struct {
		name   string
		mutate func([]byte) []byte
		want   error
	}{
		{"uncompressed", func([]byte) []byte { return wire }, gzip.ErrHeader},
		{"truncated header", func(b []byte) []byte { return b[:5] }, io.ErrUnexpectedEOF},
		{"truncated trailer", func(b []byte) []byte { return b[:len(b)-1] }, io.ErrUnexpectedEOF},
		{"checksum mismatch", func(b []byte) []byte { b[len(b)-8] ^= 0xff; return b }, gzip.ErrChecksum},
		{"size mismatch", func(b []byte) []byte { b[len(b)-4] ^= 0xff; return b }, gzip.ErrChecksum},
		{"trailing raw data", func(b []byte) []byte { return append(b, []byte("unexpected trailing data")...) }, gzip.ErrHeader},
		{"trailing JSON", func([]byte) []byte {
			return gzipDomainSnapshot(t, append(bytes.Clone(wire), []byte(` {"unexpected":true}`)...))
		}, nil},
		{"second gzip JSON", func(b []byte) []byte { return append(b, gzipDomainSnapshot(t, []byte(`{"unexpected":true}`))...) }, nil},
		{"corrupt second gzip", func(b []byte) []byte {
			extra := gzipDomainSnapshot(t, []byte("\n"))
			extra[len(extra)-8] ^= 0xff
			return append(b, extra...)
		}, gzip.ErrChecksum},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "registry.json.gz")
			if err := os.WriteFile(path, test.mutate(bytes.Clone(compressed)), 0600); err != nil {
				t.Fatal(err)
			}
			g, fake := newTestRegistry(1, time.Hour)
			err := g.Restore(path, func(string) []uint32 { t.Fatal("published corrupt gzip snapshot"); return nil }, now)
			if err == nil || test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("restore error = %v, want %v", err, test.want)
			}
			if g.generation != 0 || g.Size() != 0 {
				t.Fatal("partially published corrupt snapshot")
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
	path := filepath.Join(t.TempDir(), "registry.json.gz")
	if err := g.Save(path); err != nil {
		t.Fatal(err)
	}
	restored, _ := newTestRegistry(16, time.Second)
	if err := restored.Restore(path, func(string) []uint32 { return make([]uint32, domainBitmapWords()) }, now); err != nil {
		t.Fatal(err)
	}
	if restored.Usage().UserUsed != 16 {
		t.Fatal("escaped-name observations lost")
	}
}

func TestDomainRegistryConcurrentCloseFinalSave(t *testing.T) {
	g, _ := newTestRegistry(16, time.Second)
	path := filepath.Join(t.TempDir(), "registry.json.gz")
	g.Start()
	g.EnablePersistence(path)
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
			if err := restored.Restore(path, func(string) []uint32 { return make([]uint32, domainBitmapWords()) }, now); err != nil {
				t.Error(err)
				return
			}
			if !restored.Verify(name, ip).Paired {
				t.Error("Close returned before final save")
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
	g.EnablePersistence(filepath.Join(path, "state.json.gz"))
	now, ip := time.Now(), netip.MustParseAddr("192.0.2.1")
	g.Upsert("retained.example.", ip, testBitmap(0), 60, now)
	activity := g.activity
	ifmgr, err := network.NewInterfaceManager()
	if err != nil {
		t.Fatal(err)
	}
	closed, cancel := context.WithCancel(t.Context())
	core := &controlPlaneCore{closed: closed, close: cancel, ifmgr: ifmgr, domainRegistry: g}
	core.addCleanup(g.Close)
	old := newLifecycleTestControlPlane(new(UdpEndpointPool))
	old.core = core
	if err := old.Close(); err != nil || !old.closedDone.Load() {
		t.Fatalf("snapshot failure prevented safe retirement: %v", err)
	}
	logged := false
	for _, entry := range hook.AllEntries() {
		logged = logged || entry.Message == "Save domain registry on shutdown" && entry.Data["error"] != nil
	}
	if !logged {
		t.Fatal("snapshot failure was not reported")
	}
	activity.observe(ip, "retained.example.", now.Add(time.Minute))
	successor, _ := newTestRegistry(4, time.Hour)
	defer successor.Close()
	matcher, _ := routingMatcherForTest(t, prepareFlowRulesForTest(t, "", ""))
	successor.ForkFrom(old.core.domainRegistry, matcher.domainMatcher.MatchDomainBitmap, time.Now())
	activity.observe(ip, "retained.example.", now.Add(time.Minute))
	if !successor.retention("retained.example.", ip).Equal(now.Add(61 * time.Minute)) {
		t.Fatal("save failure lost in-memory evidence or queued activity")
	}
	activity.observe(ip, "retained.example.", now.Add(2*time.Minute))
	if !successor.retention("retained.example.", ip).Equal(now.Add(62 * time.Minute)) {
		t.Fatal("retained activity handle did not reach successor")
	}
}
