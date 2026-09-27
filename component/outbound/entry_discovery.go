// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"context"
	"fmt"
	"sync"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	log "github.com/sirupsen/logrus"
)

const maxConcurrentEntryLookups = 8

type entryDiscoveryKey struct {
	host, iface string
	mark        uint32
	markSet     bool // An explicit zero is different from inheriting the global mark.
}

type entryDiscovery struct {
	key      entryDiscoveryKey
	path     *PathSpec
	families uint8
	err      error
}

// ExpandIPVariants runs during materialization. Only families with a resolved
// address and a usable local route/source on the configured egress are created.
func ExpandIPVariants(ctx context.Context, paths []*PathSpec, option *dialer.GlobalOption) ([]*PathSpec, error) {
	return expandIPVariants(ctx, paths, func(ctx context.Context, path *PathSpec) (uint8, error) {
		return path.availableEntryFamilies(ctx, option, entryAddressUsable)
	})
}

func expandIPVariants(ctx context.Context, paths []*PathSpec, discover func(context.Context, *PathSpec) (uint8, error)) ([]*PathSpec, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Deduplicate physical entries, keeping references in declaration order.
	// Different marks/interfaces must never share DNS or local-route results.
	cache := make(map[entryDiscoveryKey]*entryDiscovery)
	results := make([]*entryDiscovery, len(paths))
	var entries []*entryDiscovery
	for i, path := range paths {
		if path == nil || len(path.Nodes) == 0 || path.Nodes[0] == nil || path.Nodes[0].Property == nil {
			return nil, fmt.Errorf("cannot expand a proxy path without an entry node")
		}
		key := entryDiscoveryKey{host: entryHostname(path.Nodes[0].Property.Address), iface: path.Entry.Interface}
		if path.Entry.Mark != nil {
			key.mark, key.markSet = *path.Entry.Mark, true
		}
		entry := cache[key]
		if entry == nil {
			entry = &entryDiscovery{key: key, path: path}
			cache[key] = entry
			entries = append(entries, entry)
		}
		results[i] = entry
	}

	// A fixed worker pool bounds DNS pressure without one goroutine per entry.
	queue := make(chan *entryDiscovery, len(entries))
	for _, entry := range entries {
		queue <- entry
	}
	close(queue)
	var workers sync.WaitGroup
	for range min(maxConcurrentEntryLookups, len(entries)) {
		workers.Go(func() {
			for entry := range queue {
				if ctx.Err() != nil {
					return
				}
				entry.families, entry.err = discover(ctx, entry.path)
				if entry.err != nil {
					entry.families = 0
				} else {
					entry.families &= entryHostFamilies(entry.key.host)
				}
			}
		})
	}
	workers.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.err != nil {
			log.WithFields(log.Fields{"entry": entry.key.host, "interface": entry.key.iface}).WithError(entry.err).Warn("Could not discover entry address families; skipping entry")
		}
	}

	expanded := make([]*PathSpec, 0, min(len(paths), MaxExpandedPaths))
	for i, path := range paths {
		mask := results[i].families
		if path.Entry.Families != nil {
			mask &= *path.Entry.Families
		}
		for _, family := range []int{4, 6} {
			bit := family4
			if family == 6 {
				bit = family6
			}
			if mask&bit == 0 {
				continue
			}
			if len(expanded) == MaxExpandedPaths {
				return nil, fmt.Errorf("address-family expansion exceeds limit %d", MaxExpandedPaths)
			}
			variant := *path
			variant.IPVersion = family
			variant.showIPVersion = mask == allFamilies
			expanded = append(expanded, &variant)
		}
	}
	return expanded, nil
}
