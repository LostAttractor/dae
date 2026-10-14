// SPDX-License-Identifier: AGPL-3.0-only

package settings

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/daeuniverse/dae/common/persist"
)

func TestUpdateRestoresAfterPublishedSyncFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	mac := [6]byte{2, 1, 2, 3, 4, 5}
	if err := s.SetMITM(mac, new(true)); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("directory sync failed")
	calls := 0
	s.syncDir = func(dir string) error {
		calls++
		if calls == 1 {
			return failure
		}
		return persist.SyncDir(dir)
	}
	err = s.Update(func(next *Snapshot) error {
		next.MITM[macString(mac)] = false
		return nil
	}, func(_, _ Snapshot, save func() error) error { return save() })
	if !errors.Is(err, failure) || !persist.Published(err) {
		t.Fatalf("error = %v", err)
	}
	onDisk, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, store := range []*Store{s, onDisk} {
		if enabled, _ := store.MITM(mac); !enabled {
			t.Fatal("failed edit survived rollback")
		}
	}
	if calls != 2 {
		t.Fatalf("sync calls = %d, want attempted edit and rollback", calls)
	}
}

func TestIdenticalEditRetriesUnconfirmedDurability(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	mac := [6]byte{2, 1, 2, 3, 4, 5}
	s.syncDir = func(string) error { return errors.New("sync unavailable") }
	if err := s.SetMITM(mac, new(true)); err == nil || !persist.Published(err) {
		t.Fatalf("error = %v", err)
	}
	if enabled, _ := s.MITM(mac); !enabled {
		t.Fatal("memory differs from visible file")
	}
	calls := 0
	s.syncDir = func(dir string) error { calls++; return persist.SyncDir(dir) }
	if err := s.SetMITM(mac, new(true)); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || s.pendingSync {
		t.Fatal("unchanged edit did not retry durability")
	}
}
