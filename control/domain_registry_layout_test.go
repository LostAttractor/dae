// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func TestDomainRegistryHotCompaction(t *testing.T) {
	now := time.Now()
	g, _ := newTestRegistry(1, time.Hour)
	ip1, ip2 := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	current := &domainPair{retainUntil: now.Add(time.Hour), ordinal: 4, listed: 10}
	previous := &domainPair{retainUntil: now.Add(time.Hour), ordinal: 3, listed: 9}
	old := &domainPair{retainUntil: now.Add(time.Hour), ordinal: 2, listed: 8}
	never := &domainPair{retainUntil: now.Add(time.Hour), ordinal: 1}
	mixedCold := &domainPair{retainUntil: now.Add(time.Hour), ordinal: 0}
	g.installRecords(map[string]*domainRecord{
		"current.example.":  {addresses: map[netip.Addr]*domainPair{ip1: current, ip2: mixedCold}},
		"previous.example.": {addresses: map[netip.Addr]*domainPair{ip1: previous}},
		"old.example.":      {addresses: map[netip.Addr]*domainPair{ip1: old}},
		"never.example.":    {addresses: map[netip.Addr]*domainPair{ip1: never}},
	}, func(string) []uint32 { return testBitmap() })
	dir := t.TempDir()
	g.EnablePersistence(dir)
	defer g.closePersistence()
	l := g.persist
	l.window = 10
	l.io.Lock()
	g.compact(l, now)
	l.io.Unlock()
	if l.rebuild || l.next != 5 {
		t.Fatal("compaction did not publish all pairs")
	}
	if current.ordinal >= 3 || previous.ordinal >= 3 || old.ordinal < 3 || never.ordinal < 3 || mixedCold.ordinal != current.ordinal+1 {
		t.Fatalf("incorrect grouping: current=%d previous=%d old=%d never=%d mixedCold=%d", current.ordinal, previous.ordinal, old.ordinal, never.ordinal, mixedCold.ordinal)
	}

	// A renewal of a moved pair and a new pair must use the new dictionary.
	g.Upsert("current.example.", ip1, testBitmap(), 7200, now)
	g.Upsert("new.example.", ip2, testBitmap(), 60, now.Add(time.Minute))
	g.writeRenewals(now.Add(domainRenewInterval))
	restored := restoreTestRegistry(t, dir, time.Hour, now)
	requireDiskEvidence(t, diskEvidence(restored), diskEvidence(g))
}

func TestDomainRegistryHotCompactionSparsePairs(t *testing.T) {
	now := time.Now()
	g, _ := newTestRegistry(1, time.Hour)
	records := make(map[string]*domainRecord, 500)
	var hot []*domainPair
	var before []uint32
	for domain := range 500 {
		record := &domainRecord{addresses: make(map[netip.Addr]*domainPair, 100)}
		for address := range 100 {
			pair := &domainPair{retainUntil: now.Add(time.Hour), ordinal: uint32(domain*100 + address)}
			if domain >= 200 {
				pair.listed = 8
				if (domain-200)%3 == 0 && address == 50 {
					pair.listed = 9
					hot = append(hot, pair)
					before = append(before, pair.ordinal)
				}
			}
			record.addresses[netip.AddrFrom4([4]byte{192, 0, 2, byte(address + 1)})] = pair
		}
		records[fmt.Sprintf("d%d.example.", domain)] = record
	}
	g.installRecords(records, func(string) []uint32 { return testBitmap() })
	dir := t.TempDir()
	g.EnablePersistence(dir)
	defer g.closePersistence()
	l := g.persist
	l.window = 10
	l.io.Lock()
	g.compact(l, now)
	l.io.Unlock()
	if l.rebuild || l.next != 50000 || len(hot) != 100 {
		t.Fatalf("rebuild=%v pairs=%d hot=%d", l.rebuild, l.next, len(hot))
	}
	recovered, _, err := recoverDomainEvidence(dir)
	if err != nil {
		t.Fatal(err)
	}
	for name, record := range g.byName {
		for ip, pair := range record.addresses {
			copy := recovered.records[name].addresses[ip]
			if copy.ordinal != pair.ordinal || !copy.retainUntil.Equal(pair.retainUntil) {
				t.Fatalf("compaction changed evidence or its ordinal for %s %s", name, ip)
			}
		}
	}
	var after []uint32
	for _, pair := range hot {
		after = append(after, pair.ordinal)
	}
	ideal := make([]uint32, len(hot))
	for i := range ideal {
		ideal[i] = uint32(i)
	}
	bound := now.Add(time.Hour).UnixNano()
	beforeBytes := len(encodeDomainRenew(bound, before, nil)) + 8
	afterBytes := len(encodeDomainRenew(bound, after, nil)) + 8
	if afterBytes != len(encodeDomainRenew(bound, ideal, nil))+8 || afterBytes >= beforeBytes {
		t.Fatalf("renewal frame grew from %d to %d bytes", beforeBytes, afterBytes)
	}
	t.Logf("50000 pairs, 100 renewed, 20000 never renewed: renewal frame %d -> %d bytes", beforeBytes, afterBytes)
}
