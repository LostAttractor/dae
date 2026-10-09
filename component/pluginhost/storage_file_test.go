// SPDX-License-Identifier: AGPL-3.0-only

package pluginhost

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/daeuniverse/dae/component/plugin"
)

func testStorage(t *testing.T, base, typ, id string) plugin.Storage {
	t.Helper()
	s, err := newPluginStorage(base, plugin.Spec{Type: typ, ID: id})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestStorageIsolationRestartAndPermissions(t *testing.T) {
	base := filepath.Join(t.TempDir(), "state")
	s := testStorage(t, base, "fixture", "fixture")
	if _, err := s.Get("state.json"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing key: %v", err)
	}
	if err := s.Delete("state.json"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(base); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("read/delete created storage directories: %v", err)
	}
	if err := s.Put("state.json", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	reopened := testStorage(t, base, "fixture", "fixture")
	if got, err := reopened.Get("state.json"); err != nil || string(got) != "secret" {
		t.Fatalf("restart: %q, %v", got, err)
	}
	for _, other := range []plugin.Storage{testStorage(t, base, "fixture", "two"), testStorage(t, base, "another", "fixture")} {
		if _, err := other.Get("state.json"); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("crossed instance/type namespace: %v", err)
		}
	}
	dir := filepath.Join(base, "plugins", "state", "fixture")
	for path, mode := range map[string]fs.FileMode{dir: 0700, filepath.Join(dir, "state.json"): 0600} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("permissions for %s: %v, %v", path, info, err)
		}
	}
	if err := reopened.Delete("state.json"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("state.json"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("delete not visible to original handle: %v", err)
	}
}

func TestStorageNamesBoundsAndSymlinks(t *testing.T) {
	base := t.TempDir()
	s := testStorage(t, base, "fixture", "one")
	for _, key := range []string{"", ".", "..", "/absolute", "../escape", "a/b", `a\b`, ".tmp-x", "a\x00b", strings.Repeat("x", 129)} {
		if _, err := s.Get(key); !errors.Is(err, fs.ErrInvalid) {
			t.Errorf("Get(%q): %v", key, err)
		}
		if err := s.Put(key, nil); !errors.Is(err, fs.ErrInvalid) {
			t.Errorf("Put(%q): %v", key, err)
		}
		if err := s.Delete(key); !errors.Is(err, fs.ErrInvalid) {
			t.Errorf("Delete(%q): %v", key, err)
		}
	}
	if err := s.Put("value", []byte("old")); err != nil {
		t.Fatal(err)
	}
	if err := s.Put("value", make([]byte, maxStorageValueSize+1)); !errors.Is(err, fs.ErrInvalid) {
		t.Fatalf("oversized write: %v", err)
	}
	if got, err := s.Get("value"); err != nil || string(got) != "old" {
		t.Fatalf("failed write replaced old value: %q, %v", got, err)
	}
	dir := filepath.Join(base, "plugins", "state", "fixture@one")
	if err := os.WriteFile(filepath.Join(dir, "large"), make([]byte, maxStorageValueSize+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("large"); !errors.Is(err, fs.ErrInvalid) {
		t.Fatalf("oversized read: %v", err)
	}
	if err := os.Symlink("value", filepath.Join(dir, "alias")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get("alias"); !errors.Is(err, fs.ErrInvalid) {
		t.Fatalf("read followed a symlink: %v", err)
	}
	if err := os.Symlink("fixture@one", filepath.Join(base, "plugins", "state", "fixture@two")); err != nil {
		t.Fatal(err)
	}
	if err := testStorage(t, base, "fixture", "two").Put("value", []byte("other")); !errors.Is(err, fs.ErrInvalid) {
		t.Fatalf("namespace symlink accepted: %v", err)
	}
	// Default and named instances must stay isolated even when type/instance
	// names contain separators, path syntax or percent-encoded lookalikes.
	specs := []plugin.Spec{
		{Type: "fixture", ID: "fixture"}, {Type: "fixture", ID: "one"},
		{Type: "fixture@one", ID: "fixture@one"}, {Type: "fixture%40one", ID: "fixture%40one"},
		{Type: "fixture@one", ID: "two"}, {Type: "fixture", ID: "one@two"},
		{Type: "fixture", ID: "one%40two"},
		{Type: "fixture", ID: ".."}, {Type: "fixture", ID: "%2E%2E"},
		{Type: "fixture", ID: "../one"}, {Type: "fixture", ID: "..%2Fone"},
		{Type: "fixture", ID: "/absolute"},
		{Type: ".", ID: "."}, {Type: "%2E", ID: "%2E"},
		{Type: "..", ID: ".."}, {Type: "%2E%2E", ID: "%2E%2E"},
	}
	for i, spec := range specs {
		if err := testStorage(t, base, spec.Type, spec.ID).Put("value", []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	for i, spec := range specs {
		got, err := testStorage(t, base, spec.Type, spec.ID).Get("value")
		if err != nil || !bytes.Equal(got, []byte{byte(i)}) {
			t.Fatalf("namespace collision: type=%q instance=%q: %x, %v", spec.Type, spec.ID, got, err)
		}
	}
}

func TestStorageConcurrentAtomicReplacement(t *testing.T) {
	base := t.TempDir()
	s := testStorage(t, base, "fixture", "one")
	if err := s.Put("value", bytes.Repeat([]byte{0}, 65536)); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Go(func() {
			// Independent handles exercise overlapping host generations too.
			other := testStorage(t, base, "fixture", "one")
			value := bytes.Repeat([]byte{byte(i)}, 65536)
			for range 10 {
				if err := other.Put("value", value); err != nil {
					t.Error(err)
					return
				}
				got, err := s.Get("value")
				if err != nil || len(got) != len(value) || !bytes.Equal(got, bytes.Repeat(got[:1], len(value))) {
					t.Errorf("partial value: length=%d, error=%v", len(got), err)
					return
				}
			}
		})
	}
	wg.Wait()
	entries, err := os.ReadDir(filepath.Join(base, "plugins", "state", "fixture@one"))
	if err != nil || len(entries) != 1 || entries[0].Name() != "value" {
		t.Fatalf("temporary files leaked: %v, %v", entries, err)
	}
}
