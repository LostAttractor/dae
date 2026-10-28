// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

var inspectEpochTime = time.Date(2020, 1, 2, 3, 4, 5, 6, time.UTC)

func registryInspectStore(t *testing.T) (string, []byte, []byte, int64) {
	t.Helper()
	dir := t.TempDir()
	base := encodeDomainBase(7, []domainLogEntry{
		{"z.example.", netip.MustParseAddr("2001:db8::1"), inspectEpochTime.Add(time.Hour).UnixNano()},
		{"a.example.", netip.MustParseAddr("192.0.2.1"), inspectEpochTime.Add(-time.Hour).UnixNano()},
	})
	if err := os.WriteFile(filepath.Join(dir, domainBaseFile), base, 0600); err != nil {
		t.Fatal(err)
	}
	journal := make([]byte, domainJournalChunk)
	copy(journal, domainHeader(domainJournalMagic, 7))
	if err := os.WriteFile(filepath.Join(dir, domainJournalFile), journal, 0600); err != nil {
		t.Fatal(err)
	}
	disk := domainDisk{dir: dir, epoch: 7, size: domainHeaderSize, end: domainJournalChunk}
	err := disk.append(
		encodeDomainNew([]domainLogEntry{{"z.example.", netip.MustParseAddr("192.0.2.9"), inspectEpochTime.Add(90 * time.Minute).UnixNano()}}),
		encodeDomainRenew(inspectEpochTime.Add(2*time.Hour).UnixNano(), []uint32{0}, []domainLogExact{{1, inspectEpochTime.Add(-30 * time.Minute).UnixNano()}}),
	)
	if disk.file != nil {
		err = errors.Join(err, disk.file.Close())
	}
	if err != nil {
		t.Fatal(err)
	}
	journal, err = os.ReadFile(filepath.Join(dir, domainJournalFile))
	if err != nil {
		t.Fatal(err)
	}
	return dir, base, journal, disk.size
}

func TestInspectDomainRegistryReplaysAndSortsWithoutWriting(t *testing.T) {
	dir, base, journal, valid := registryInspectStore(t)
	legacy := filepath.Join(dir, "domain-registry.json.gz")
	if err := os.WriteFile(legacy, []byte("not imported or deleted"), 0600); err != nil {
		t.Fatal(err)
	}
	dump, err := InspectDomainRegistry(t.Context(), dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []DomainRegistryDumpRecord{
		{"a.example.", netip.MustParseAddr("192.0.2.1"), inspectEpochTime.Add(-30 * time.Minute)},
		{"z.example.", netip.MustParseAddr("192.0.2.9"), inspectEpochTime.Add(90 * time.Minute)},
		{"z.example.", netip.MustParseAddr("2001:db8::1"), inspectEpochTime.Add(2 * time.Hour)},
	}
	if !slices.Equal(dump.Records, want) {
		t.Fatalf("records = %+v, want %+v", dump.Records, want)
	}
	if dump.Epoch != "0000000000000007" || dump.BaselineBytes != int64(len(base)) || dump.JournalBytes != domainJournalChunk || dump.JournalValidBytes != valid || len(dump.Warnings) != 0 {
		t.Fatalf("metadata = %+v", dump)
	}
	for name, want := range map[string][]byte{domainBaseFile: base, domainJournalFile: journal, "domain-registry.json.gz": []byte("not imported or deleted")} {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("inspection changed %s: %v", name, err)
		}
	}
}

func TestInspectDomainRegistryReportsIgnoredJournalData(t *testing.T) {
	for _, scenario := range []string{"missing", "epoch", "corrupt", "truncated", "padding"} {
		t.Run(scenario, func(t *testing.T) {
			dir, _, journal, valid := registryInspectStore(t)
			path := filepath.Join(dir, domainJournalFile)
			wantPairs, wantValid := 3, valid
			switch scenario {
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				wantPairs, wantValid = 2, 0
			case "epoch":
				binary.LittleEndian.PutUint64(journal[8:], 8)
				wantPairs, wantValid = 2, 0
			case "corrupt":
				journal[valid-1] ^= 1
				wantValid = domainHeaderSize + 8 + int64(binary.LittleEndian.Uint32(journal[domainHeaderSize:]))
			case "truncated":
				journal = journal[:valid-1]
				wantValid = domainHeaderSize + 8 + int64(binary.LittleEndian.Uint32(journal[domainHeaderSize:]))
			case "padding":
				journal[len(journal)-1] = 1
			}
			if scenario != "missing" {
				if err := os.WriteFile(path, journal, 0600); err != nil {
					t.Fatal(err)
				}
			}
			dump, err := InspectDomainRegistry(t.Context(), dir)
			if err != nil || len(dump.Records) != wantPairs || dump.JournalValidBytes != wantValid || len(dump.Warnings) != 1 {
				t.Fatalf("dump = %+v, error = %v", dump, err)
			}
			if scenario == "corrupt" || scenario == "truncated" {
				if !dump.Records[2].RetainUntil.Equal(inspectEpochTime.Add(time.Hour)) {
					t.Fatal("invalid renewal was partially applied")
				}
			}
			got, err := os.ReadFile(path)
			if scenario == "missing" {
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("inspection created a journal: %v", err)
				}
			} else if err != nil || !bytes.Equal(got, journal) {
				t.Fatalf("inspection repaired the journal: %v", err)
			}
		})
	}
}

func TestInspectDomainRegistryDoesNotAdoptTemporaryBaseline(t *testing.T) {
	dir, base, _, _ := registryInspectStore(t)
	path := filepath.Join(dir, domainBaseFile)
	if err := os.WriteFile(path+domainTempSuffix, base, 0600); err != nil {
		t.Fatal(err)
	}
	base[len(base)-1] ^= 1
	if err := os.WriteFile(path, base, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectDomainRegistry(t.Context(), dir); err == nil {
		t.Fatal("corrupt published baseline accepted")
	}
	if _, err := os.Stat(path + domainTempSuffix); err != nil {
		t.Fatalf("temporary baseline was moved: %v", err)
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, base) {
		t.Fatalf("published baseline was replaced: %v", err)
	}
}

type registryInspectReadContext struct {
	context.Context
	check func()
}

func (c registryInspectReadContext) Err() error {
	c.check()
	return c.Context.Err()
}

func TestInspectDomainRegistryPinsBaseline(t *testing.T) {
	if _, err := os.Stat("/proc/self/fd"); err != nil {
		t.Skipf("requires procfs: %v", err)
	}
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "stable", true: "replaced"}[replace], func(t *testing.T) {
			dir, _, _, _ := registryInspectStore(t)
			basePath := filepath.Join(dir, domainBaseFile)
			baseline, err := os.Stat(basePath)
			if err != nil {
				t.Fatal(err)
			}
			journal, err := os.Stat(filepath.Join(dir, domainJournalFile))
			if err != nil {
				t.Fatal(err)
			}
			replacement := basePath + ".replacement"
			if err := os.WriteFile(replacement, encodeDomainBase(9, nil), 0600); err != nil {
				t.Fatal(err)
			}
			openFiles := func() (baseOpen, journalOpen bool) {
				descriptors, err := os.ReadDir("/proc/self/fd")
				if err != nil {
					t.Fatal(err)
				}
				for _, descriptor := range descriptors {
					info, err := os.Stat(filepath.Join("/proc/self/fd", descriptor.Name()))
					if err == nil {
						baseOpen = baseOpen || os.SameFile(baseline, info)
						journalOpen = journalOpen || os.SameFile(journal, info)
					}
				}
				return
			}
			checked := false
			ctx := registryInspectReadContext{Context: t.Context(), check: func() {
				if checked {
					return
				}
				baseOpen, journalOpen := openFiles()
				if !journalOpen {
					return
				}
				checked = true
				if !baseOpen {
					t.Error("baseline closed before journal read; its inode can be reused")
				}
				// Replace at a read boundary, without timing an inode reuse race.
				if replace {
					if err := os.Rename(replacement, basePath); err != nil {
						t.Fatal(err)
					}
				}
			}}
			_, err = InspectDomainRegistry(ctx, dir)
			if replace {
				if err == nil || !strings.Contains(err.Error(), "baseline changed") {
					t.Fatalf("replacement was not detected: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if baseOpen, journalOpen := openFiles(); !checked || baseOpen || journalOpen {
				t.Fatalf("checked=%v baseline open=%v journal open=%v", checked, baseOpen, journalOpen)
			}
		})
	}
}

func TestInspectDomainRegistryReadErrors(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "missing")
		if _, err := InspectDomainRegistry(t.Context(), dir); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("missing store = %v", err)
		}
		if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("inspection created a directory")
		}
	})
	t.Run("journal directory", func(t *testing.T) {
		dir, _, _, _ := registryInspectStore(t)
		path := filepath.Join(dir, domainJournalFile)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		if _, err := InspectDomainRegistry(t.Context(), dir); !errors.Is(err, fs.ErrInvalid) {
			t.Fatalf("nonregular journal = %v", err)
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := InspectDomainRegistry(ctx, t.TempDir()); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled inspection = %v", err)
		}
	})
}
