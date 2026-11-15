// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/daeuniverse/dae/component/plugin"
)

func TestRuntimeStoreMigrationAcrossSymlinkFirstWrite(t *testing.T) {
	from, to := testDeviceMAC, [6]byte{2, 0, 0, 0, 0, 2}
	for _, active := range [][6]byte{from, to} {
		t.Run(testMACScope(active).key(), func(t *testing.T) {
			root := t.TempDir()
			real, alias := filepath.Join(root, "real"), filepath.Join(root, "alias")
			if err := os.Mkdir(real, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(real, alias); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(alias, "plugins", "surge", "store.json")
			old, err := openRuntimeStore(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(real, "plugins")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("preparation created storage directories: %v", err)
			}
			if !old.write(t.Context(), testMACScope(from), "cookie", "before", false) {
				t.Fatal("initialize source")
			}
			if err := old.beginExecution(t.Context(), active); err != nil {
				t.Fatal(err)
			}
			end := sync.OnceFunc(func() { old.endExecution(active) })
			defer end()
			current, err := openRuntimeStore(path)
			if err != nil {
				t.Fatal(err)
			}
			if current != old {
				t.Error("first write changed the store registry identity")
			}
			if moved, err := current.migrate(t.Context(), from, to); moved != 0 || !errors.Is(err, plugin.ErrScriptStoreBusy) {
				t.Fatalf("old generation execution did not block migration: moved=%d err=%v", moved, err)
			}
			if !old.write(t.Context(), testMACScope(from), "cookie", "after", false) {
				t.Fatal("finish source write")
			}
			end()
			if moved, err := current.migrate(t.Context(), from, to); moved != 1 || err != nil {
				t.Fatalf("migration after execution: moved=%d err=%v", moved, err)
			}
			direct, err := openRuntimeStore(filepath.Join(real, "plugins", "surge", "store.json"))
			if err != nil || direct != old {
				t.Fatalf("real path does not share the store: %v", err)
			}
			if value, err := old.read(t.Context(), testMACScope(to), "cookie"); err != nil || value != "after" {
				t.Fatalf("migration lost the old generation write: value=%v err=%v", value, err)
			}
			if value, err := old.read(t.Context(), testMACScope(from), "cookie"); err != nil || value != nil {
				t.Fatalf("source remains after migration: value=%v err=%v", value, err)
			}
			if old.generation.Load() != 1 || current.generation.Load() != 1 {
				t.Fatal("migration generation is not shared")
			}
		})
	}
}

func TestRuntimeStorePathRejectsSymlinkLoop(t *testing.T) {
	loop := filepath.Join(t.TempDir(), "loop")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	if _, err := openRuntimeStore(filepath.Join(loop, "plugins", "store.json")); err == nil {
		t.Fatalf("symlink loop was not reported: %v", err)
	}
}
