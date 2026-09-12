// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"compress/gzip"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	dnsmessage "github.com/miekg/dns"
)

// Save writes gzip-compressed JSON with absolute GC deadlines. Kernel bitmaps
// are recomputed on restore, never serialized.
// Serializing writers also prevents an older snapshot replacing a newer one.
func (g *DomainRegistry) Save(path string) error {
	g.diskMu.Lock()
	defer g.diskMu.Unlock()
	g.mu.Lock()
	generation := g.generation
	entries := make(map[string]map[string]time.Time, len(g.byName))
	for name, r := range g.byName {
		deadlines := make(map[string]time.Time, len(r.addresses))
		for ip, pair := range r.addresses {
			deadlines[ip.String()] = pair.retainUntil
		}
		entries[name] = deadlines
	}
	g.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".domain-registry-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	compressed := gzip.NewWriter(f)
	err = json.MarshalWrite(compressed, entries, json.Deterministic(true))
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
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	if err := errors.Join(dir.Sync(), dir.Close()); err != nil {
		return err
	}
	g.mu.Lock()
	g.savedGeneration = generation
	g.mu.Unlock()
	return nil
}

// Restore validates the complete gzip snapshot before publishing anything.
// Like reload adoption it rebuilds complete shared-IP states with current rules;
// expired entries are collected without extending their original deadlines.
// Call only on an empty registry before attaching packet-processing programs.
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
	if g.closed {
		return nil
	}
	g.installRecords(records, matchBitmap)
	now = g.clock(now)
	g.gc(now)
	g.rebuildProjection(now)
	g.generation++
	return nil
}
