// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

// Exchange a directory/file and a symlink without a missing-path window.
func swapStoragePaths(t *testing.T, path, replacement string) {
	t.Helper()
	stop, done, started := make(chan struct{}), make(chan struct{}), make(chan struct{})
	t.Cleanup(func() { close(stop); <-done })
	go func() {
		defer close(done)
		for i := 0; ; i++ {
			err := unix.Renameat2(unix.AT_FDCWD, path, unix.AT_FDCWD, replacement, unix.RENAME_EXCHANGE)
			if i == 0 {
				close(started)
			}
			if err != nil {
				t.Error(err)
				return
			}
			select {
			case <-stop:
				return
			default:
			}
			runtime.Gosched()
		}
	}()
	<-started
}

func TestStorageNamespaceReplacementIsolation(t *testing.T) {
	for _, operation := range []string{"Get", "Put", "Delete"} {
		t.Run(operation, func(t *testing.T) {
			base := t.TempDir()
			one, two := testStorage(t, base, "fixture", "one"), testStorage(t, base, "fixture", "two")
			if err := one.Put("value", []byte("one")); err != nil {
				t.Fatal(err)
			}
			if err := two.Put("value", []byte("two")); err != nil {
				t.Fatal(err)
			}
			state := filepath.Join(base, "plugins", "state")
			swap := filepath.Join(state, "swap")
			if err := os.Symlink("fixture@two", swap); err != nil {
				t.Fatal(err)
			}
			swapStoragePaths(t, filepath.Join(state, "fixture@one"), swap)
			for range 1000 {
				switch operation {
				case "Get":
					if value, err := one.Get("value"); err == nil && string(value) != "one" {
						t.Fatalf("read another instance: %q", value)
					}
				case "Put":
					_ = one.Put("value", []byte("one"))
				case "Delete":
					_ = one.Delete("value")
				}
				if value, err := two.Get("value"); err != nil || string(value) != "two" {
					t.Fatalf("%s changed another instance: %q, %v", operation, value, err)
				}
			}
		})
	}
}

func TestStorageValueReplacementRejectsSymlink(t *testing.T) {
	base := t.TempDir()
	storage := testStorage(t, base, "fixture", "one")
	for _, key := range []string{"value", "other"} {
		if err := storage.Put(key, []byte(key)); err != nil {
			t.Fatal(err)
		}
	}
	dir := filepath.Join(base, "plugins", "state", "fixture@one")
	swap := filepath.Join(dir, "swap")
	if err := os.Symlink("other", swap); err != nil {
		t.Fatal(err)
	}
	swapStoragePaths(t, filepath.Join(dir, "value"), swap)
	for range 1000 {
		if value, err := storage.Get("value"); err == nil && string(value) != "value" {
			t.Fatalf("read through a replaced symlink: %q", value)
		}
	}
}
