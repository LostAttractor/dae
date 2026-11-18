// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"cmp"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/daeuniverse/dae/common/fileio"
	"github.com/daeuniverse/dae/common/persist"
	log "github.com/sirupsen/logrus"
)

const (
	domainCapacityFile     = "domain-registry.capacity"
	domainCapacityMagic    = "DAEREGC\x01"
	domainCapacityFileSize = len(domainCapacityMagic) + 8*domainCapacityBuckets + 4
)

var domainCapacityMaxTime = time.Unix(0, math.MaxInt64)

// Independent of the evidence epoch: an older guard can over-isolate, but
// compaction must not remove its only copy of an omitted pair's deadline.
func readDomainCapacity(path string) (durable [domainCapacityBuckets]time.Time, unreadable bool, err error) {
	f, info, err := fileio.OpenRegular(path)
	if errors.Is(err, os.ErrNotExist) {
		return durable, false, nil
	}
	if err != nil {
		return durable, true, err
	}
	defer f.Close()
	if info.Size() != int64(domainCapacityFileSize) {
		return durable, false, errors.New("invalid capacity guard size")
	}
	var file [domainCapacityFileSize + 1]byte
	n, err := io.ReadFull(f, file[:])
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return durable, true, err
	}
	body := file[:domainCapacityFileSize-4]
	if n != domainCapacityFileSize || string(body[:len(domainCapacityMagic)]) != domainCapacityMagic ||
		crc32.Checksum(body, domainCRC) != binary.LittleEndian.Uint32(file[len(body):]) {
		return durable, false, errors.New("invalid capacity guard header or checksum")
	}
	for i := range durable {
		if n := int64(binary.LittleEndian.Uint64(body[len(domainCapacityMagic)+i*8:])); n != 0 {
			durable[i] = time.Unix(0, n)
		}
	}
	return durable, false, nil
}

func (g *DomainRegistry) restoreCapacity(l *domainLog) error {
	durable, unreadable, err := readDomainCapacity(l.capacityPath)
	if err != nil {
		l.disabled = unreadable
		// A damaged guard has unknown buckets and unknown deadlines. Do not
		// reconstruct a partial IP from the remaining ordinary evidence.
		for i := range g.incomplete {
			g.incomplete[i] = domainCapacityMaxTime
		}
		return fmt.Errorf("restore %s: %w; suppressing all domain projections", l.capacityPath, err)
	}
	l.capacityDurable = durable
	for i, until := range durable {
		if until.After(g.evaluatedAt.Add(-g.activityLag)) {
			g.incomplete[i] = until
		}
	}
	return nil
}

// Caller holds mu. Only the active persistence owner may publish the guard.
func (g *DomainRegistry) persistCapacity(bucket int, until time.Time) {
	if l := g.persist; g.capacityWriting && l != nil && l.enabled && until.After(l.capacityDurable[bucket]) {
		g.capacityPending = true
	}
}

// Return false if an active guard is not durable. An inactive registry does
// not write, including while testing a reload candidate's projection.
func (g *DomainRegistry) persistActiveCapacity() bool {
	l := g.persist
	if !g.capacityWriting || l == nil || !l.enabled {
		return true
	}
	now := time.Now()
	if now.Before(l.capacityRetry) {
		return false
	}
	durable := l.capacityDurable
	needWrite := false
	cutoff := g.evaluatedAt.Add(-g.activityLag)
	for i, until := range g.incomplete {
		if until.After(cutoff) && until.After(durable[i]) {
			durable[i] = until.Add(domainRenewInterval)
			if durable[i].After(domainCapacityMaxTime) {
				durable[i] = domainCapacityMaxTime
			}
			needWrite = true
		}
	}
	if !needWrite {
		g.capacityPending = false
		return true
	}
	g.capacityPending = true
	var file [domainCapacityFileSize]byte
	body := file[:len(file)-4]
	copy(body, domainCapacityMagic)
	for i, until := range durable {
		if until.After(cutoff) {
			binary.LittleEndian.PutUint64(body[len(domainCapacityMagic)+i*8:], uint64(until.UnixNano()))
		} else {
			durable[i] = time.Time{}
		}
	}
	binary.LittleEndian.PutUint32(file[len(body):], crc32.Checksum(body, domainCRC))
	err := l.writeDomainCapacity(file[:], persist.MkdirAll)
	if err != nil {
		l.capacityRetry = now.Add(time.Minute)
		log.WithError(err).WithField("path", l.capacityPath).Warn("Persist domain registry capacity guard; a crash may lose isolation")
		return false
	}
	l.capacityDurable = durable
	g.capacityPending = false
	return true
}

func (l *domainLog) writeDomainCapacity(data []byte, syncDirTree func(string, os.FileMode) error) error {
	dirPath := filepath.Dir(l.capacityPath)
	if !l.capacityDirSynced {
		if err := syncDirTree(dirPath, 0700); err != nil {
			return err
		}
		l.capacityDirSynced = true
	}
	dir, err := os.Open(dirPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			l.capacityDirSynced = false
		}
		return err
	}
	defer dir.Close()
	if err := persist.ReplaceFile(context.Background(), dir, filepath.Base(l.capacityPath), data); err != nil {
		return err
	}
	return dir.Sync()
}

type domainRestoredPair struct {
	record *domainRecord
	ip     netip.Addr
}

func (p domainRestoredPair) pairIPCost(ips map[netip.Addr]bool) int64 {
	matched, exists := ips[p.ip]
	return domainPairIPCost(exists, matched, p.record.bitmap != nil)
}

// Only a domain may share bytes with an already accepted bucket.
func (p domainRestoredPair) cost(names map[*domainRecord]struct{}, ips map[netip.Addr]bool, kept map[string]*domainRecord) int64 {
	cost := p.pairIPCost(ips)
	if _, exists := names[p.record]; !exists && kept[p.record.name] == nil {
		cost += domainNameMemory(p.record.name, p.record.bitmap)
	}
	return cost
}

func (p domainRestoredPair) charge(names map[*domainRecord]struct{}, ips map[netip.Addr]bool) {
	names[p.record] = struct{}{}
	ips[p.ip] = ips[p.ip] || len(p.record.bitmap) != 0
}

// Fit-check before allocating bucket references. The fit-check's IP set
// never grows past the budget and does not build a reverse index.
func (g *DomainRegistry) limitRestoredCapacity(rec *domainRecovery, matchBitmap func(string) []uint32) bool {
	var used int64
	ips := make(map[netip.Addr]bool)
	for name, record := range rec.records {
		record.name = name
		record.bitmap = cloneDomainBitmap(matchBitmap(name))
		if used <= g.memoryLimit {
			used += domainNameMemory(name, record.bitmap)
			for ip := range record.addresses {
				p := domainRestoredPair{record, ip}
				used += p.pairIPCost(ips)
				if used > g.memoryLimit {
					break
				}
				ips[ip] = ips[ip] || len(record.bitmap) != 0
			}
		}
	}
	if used <= g.memoryLimit {
		return false
	}
	names := make(map[*domainRecord]struct{})
	var groups [domainCapacityBuckets][]domainRestoredPair
	for _, record := range rec.records {
		for ip := range record.addresses {
			bucket := domainCapacityBucket(ip)
			groups[bucket] = append(groups[bucket], domainRestoredPair{record, ip})
		}
	}
	buckets := make([]int, 0, domainCapacityBuckets)
	for bucket, group := range groups {
		if len(group) != 0 {
			buckets = append(buckets, bucket)
		}
	}
	// Only whole, previously complete buckets preserve routing coverage. Keep
	// the smaller groups first, using the stable bucket id to break ties.
	slices.SortFunc(buckets, func(a, b int) int {
		if g.incomplete[a].IsZero() != g.incomplete[b].IsZero() {
			if g.incomplete[a].IsZero() {
				return -1
			}
			return 1
		}
		return cmp.Or(cmp.Compare(len(groups[a]), len(groups[b])), cmp.Compare(a, b))
	})
	kept := make(map[string]*domainRecord)
	keep := func(p domainRestoredPair) {
		r := kept[p.record.name]
		if r == nil {
			r = &domainRecord{name: p.record.name, bitmap: p.record.bitmap, addresses: make(map[netip.Addr]*domainPair)}
			kept[r.name] = r
		}
		r.addresses[p.ip] = p.record.addresses[p.ip]
	}
	remaining := g.memoryLimit
	var partial []int
	for _, bucket := range buckets {
		clear(names)
		clear(ips)
		var charge int64
		for _, p := range groups[bucket] {
			charge += p.cost(names, ips, kept)
			if charge > remaining {
				break
			}
			p.charge(names, ips)
		}
		if charge <= remaining {
			for _, p := range groups[bucket] {
				keep(p)
			}
			remaining -= charge
		} else {
			partial = append(partial, bucket)
		}
	}
	for _, bucket := range partial {
		// None of this bucket's IPs has been kept yet.
		if remaining < domainPairMemory+domainIPMemory {
			break
		}
		clear(names)
		clear(ips)
		group := groups[bucket]
		slices.SortFunc(group, func(a, b domainRestoredPair) int {
			return cmp.Compare(a.record.addresses[a.ip].ordinal, b.record.addresses[b.ip].ordinal)
		})
		for _, p := range group {
			if charge := p.cost(names, ips, kept); charge <= remaining {
				keep(p)
				p.charge(names, ips)
				remaining -= charge
			}
		}
	}
	for bucket, group := range groups {
		for _, p := range group {
			if record := kept[p.record.name]; record == nil || record.addresses[p.ip] == nil {
				if until := p.record.addresses[p.ip].retainUntil; until.After(g.incomplete[bucket]) {
					g.incomplete[bucket] = until
				}
			}
		}
	}
	rec.records = kept
	log.WithField("memory_limit", g.memoryLimit).Warn("Domain registry exceeds capacity on restore; suppressing incomplete IP projections")
	return true
}
