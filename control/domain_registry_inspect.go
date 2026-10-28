// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/daeuniverse/dae/common/fileio"
)

// DomainRegistryDump describes persisted evidence, not live routing or DNS TTLs.
// Expired pairs remain visible until the writer compacts them away.
type DomainRegistryDump struct {
	Epoch             string                     `json:"epoch"`
	BaselineBytes     int64                      `json:"baseline_bytes"`
	JournalBytes      int64                      `json:"journal_bytes"`
	JournalValidBytes int64                      `json:"journal_valid_bytes"`
	Warnings          []string                   `json:"warnings,omitempty"`
	Records           []DomainRegistryDumpRecord `json:"records"`
}

type DomainRegistryDumpRecord struct {
	Domain      string     `json:"domain"`
	IP          netip.Addr `json:"ip"`
	RetainUntil time.Time  `json:"retain_until"`
}

// InspectDomainRegistry reads the published baseline and its valid journal
// prefix. Unlike Restore, it never adopts temporary files or changes the store.
func InspectDomainRegistry(ctx context.Context, dir string) (result *DomainRegistryDump, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	basePath := filepath.Join(dir, domainBaseFile)
	file, baseline, err := fileio.OpenRegular(basePath)
	if err != nil {
		return nil, err
	}
	// Pin the inode so replacement cannot recycle it before SameFile checks it.
	defer func() { err = errors.Join(err, file.Close()) }()
	data, err := io.ReadAll(fileio.NewContextReader(ctx, io.NewSectionReader(file, 0, baseline.Size())))
	if err != nil {
		return nil, err
	}
	rec, err := decodeDomainBase(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", basePath, err)
	}
	journal, journalErr := readDomainRegistryFile(ctx, filepath.Join(dir, domainJournalFile))
	if journalErr != nil && !errors.Is(journalErr, os.ErrNotExist) {
		return nil, journalErr
	}
	current, err := os.Stat(basePath)
	if err != nil {
		return nil, err
	}
	if !os.SameFile(baseline, current) {
		return nil, errors.New("domain registry baseline changed while reading; retry the inspection")
	}
	result = &DomainRegistryDump{
		Epoch:         fmt.Sprintf("%016x", rec.epoch),
		BaselineBytes: rec.base,
		JournalBytes:  int64(len(journal)),
		Records:       make([]DomainRegistryDumpRecord, 0, len(rec.ordinals)),
	}
	if journalErr != nil {
		result.Warnings = append(result.Warnings, "journal is missing; showing baseline only")
	} else {
		rec.replay(journal)
		result.JournalValidBytes = rec.journal
		switch {
		case rec.journal == 0:
			result.Warnings = append(result.Warnings, "journal header or epoch does not match the baseline; journal ignored")
		case len(bytes.Trim(journal[rec.journal:], "\x00")) != 0:
			result.Warnings = append(result.Warnings, fmt.Sprintf("incomplete or corrupt journal tail ignored at byte %d", rec.journal))
		}
	}
	for name, record := range rec.records {
		for ip, pair := range record.addresses {
			result.Records = append(result.Records, DomainRegistryDumpRecord{name, ip, pair.retainUntil.UTC()})
		}
	}
	slices.SortFunc(result.Records, func(a, b DomainRegistryDumpRecord) int {
		if order := cmp.Compare(a.Domain, b.Domain); order != 0 {
			return order
		}
		return a.IP.Compare(b.IP)
	})
	return result, ctx.Err()
}

func readDomainRegistryFile(ctx context.Context, path string) ([]byte, error) {
	file, info, err := fileio.OpenRegular(path)
	if err != nil {
		return nil, err
	}
	// Ignore later appends, and never follow a growing file indefinitely.
	data, err := io.ReadAll(fileio.NewContextReader(ctx, io.NewSectionReader(file, 0, info.Size())))
	return data, errors.Join(err, file.Close())
}
