// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"compress/gzip"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common/persist"
	dnsmessage "github.com/miekg/dns"
)

type domainDiskAddress struct {
	address  string
	deadline time.Time
}

type domainDiskEntry struct {
	name      string
	addresses []domainDiskAddress
}

type domainDiskSnapshot []domainDiskEntry

// The registry already guarantees unique keys. A sorted, contiguous snapshot
// avoids building another pair of hash indexes just to serialize the evidence.
func (snapshot domainDiskSnapshot) MarshalJSONTo(enc *jsontext.Encoder) error {
	slices.SortFunc(snapshot, func(a, b domainDiskEntry) int { return strings.Compare(a.name, b.name) })
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	for _, entry := range snapshot {
		if err := enc.WriteToken(jsontext.String(entry.name)); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.BeginObject); err != nil {
			return err
		}
		slices.SortFunc(entry.addresses, func(a, b domainDiskAddress) int { return strings.Compare(a.address, b.address) })
		for i := range entry.addresses {
			pair := &entry.addresses[i]
			if err := enc.WriteToken(jsontext.String(pair.address)); err != nil {
				return err
			}
			if err := json.MarshalEncode(enc, &pair.deadline); err != nil {
				return err
			}
		}
		if err := enc.WriteToken(jsontext.EndObject); err != nil {
			return err
		}
	}
	return enc.WriteToken(jsontext.EndObject)
}

// Save writes gzip-compressed JSON with absolute GC deadlines. Kernel bitmaps
// are recomputed on restore, never serialized.
// Serializing writers also prevents an older snapshot replacing a newer one.
func (g *DomainRegistry) Save(path string) error {
	g.diskMu.Lock()
	defer g.diskMu.Unlock()
	g.mu.Lock()
	if !g.closed {
		reconsider := g.drainActivity()
		g.syncProjection(g.gc(g.evaluatedAt), reconsider, g.evaluatedAt)
	}
	generation := g.generation
	pairs := 0
	for _, r := range g.byName {
		pairs += len(r.addresses)
	}
	// Own all deadlines before releasing mu; sorting and encoding happen outside it.
	addresses := make([]domainDiskAddress, 0, pairs)
	entries := make(domainDiskSnapshot, 0, len(g.byName))
	for name, r := range g.byName {
		start := len(addresses)
		for ip, pair := range r.addresses {
			addresses = append(addresses, domainDiskAddress{ip.String(), pair.retainUntil})
		}
		entries = append(entries, domainDiskEntry{name, addresses[start:len(addresses):len(addresses)]})
	}
	g.mu.Unlock()
	if err := persist.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".domain-registry-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	compressed, _ := gzip.NewWriterLevel(f, gzip.BestSpeed)
	// Names and canonical addresses came from maps, so duplicate tracking is redundant.
	err = json.MarshalWrite(compressed, entries, jsontext.AllowDuplicateNames(true))
	// Finish the stream (including its checksum) before syncing and publishing.
	err = errors.Join(err, compressed.Close())
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	if err := persist.SyncDir(filepath.Dir(path)); err != nil {
		return persist.AfterPublish(err)
	}
	g.mu.Lock()
	g.savedGeneration = generation
	g.mu.Unlock()
	return nil
}

// Restore validates the complete gzip snapshot before publishing anything.
// Like reload adoption it rebuilds complete shared-IP states with current rules;
// expired entries are collected without extending their original deadlines.
// The startup owner calls only on a fresh registry before publication, while
// holding the control-plane lifecycle lock that excludes concurrent shutdown.
func (g *DomainRegistry) Restore(path string, matchBitmap func(string) []uint32, now time.Time) error {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	compressed, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("domain registry gzip: %w", err)
	}
	defer compressed.Close()
	// UnmarshalRead rejects duplicate object keys and reads through EOF, which
	// also validates the gzip trailer, checksum and any concatenated stream.
	var entries map[string]map[string]time.Time
	if err := json.UnmarshalRead(compressed, &entries); err != nil {
		return fmt.Errorf("domain registry snapshot: %w", err)
	}
	if entries == nil {
		return fmt.Errorf("domain registry snapshot must be an object")
	}
	records := make(map[string]*domainRecord, len(entries))
	for name, addresses := range entries {
		_, validName := dnsmessage.IsDomainName(name)
		if !validName || name != dnsmessage.CanonicalName(name) || len(addresses) == 0 {
			return fmt.Errorf("invalid domain registry entry for %q", name)
		}
		r := &domainRecord{addresses: make(map[netip.Addr]*domainPair, len(addresses))}
		records[name] = r
		for address, deadline := range addresses {
			ip, err := netip.ParseAddr(address)
			if err != nil || ip.IsUnspecified() || ip.Zone() != "" || ip != ip.Unmap() || deadline.IsZero() {
				return fmt.Errorf("invalid domain registry address %q for %q", address, name)
			}
			if _, duplicate := r.addresses[ip]; duplicate {
				return fmt.Errorf("duplicate domain registry address %q for %q", address, name)
			}
			r.addresses[ip] = &domainPair{retainUntil: deadline}
		}
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	now = g.clock(now)
	// Validate the entire snapshot first, but avoid allocating reverse indexes
	// and evaluating current rules for evidence that cold restore would collect.
	cutoff := now.Add(-g.activityLag)
	for name, record := range records {
		for ip, pair := range record.addresses {
			if !pair.retainUntil.After(cutoff) {
				delete(record.addresses, ip)
				g.gcCount++
				g.generation++
			}
		}
		if len(record.addresses) == 0 {
			delete(records, name)
		}
	}
	g.installRecords(records, matchBitmap)
	if err := g.rebuildProjection(now); err != nil {
		return err
	}
	g.generation++
	return nil
}
