// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestRuntimeStoreRejectsFIFO(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(map[bool]string{false: "open", true: "refresh"}[existing], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "store.json")
			read := func() error { _, err := openRuntimeStore(path); return err }
			if existing {
				store, err := openRuntimeStore(path)
				if err != nil {
					t.Fatal(err)
				}
				read = func() error { _, err := store.read(t.Context(), "key"); return err }
			}
			if err := unix.Mkfifo(path, 0600); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- read() }()
			select {
			case err := <-done:
				if !errors.Is(err, fs.ErrInvalid) {
					t.Fatalf("FIFO error = %v, want invalid file", err)
				}
			case <-time.After(time.Second):
				// Unblock a regressed opener so it cannot retain the global store lock.
				writer, err := os.OpenFile(path, os.O_WRONLY|unix.O_NONBLOCK, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = writer.WriteString("{}")
				_ = writer.Close()
				<-done
				t.Fatal("store read waited for a FIFO writer")
			}
		})
	}
}

func TestRuntimeStoreCacheExternalChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	store, err := openRuntimeStore(path)
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Unix(1700000000, 0)
	replace := func(contents string) {
		t.Helper()
		// Deliberately preserve size and mtime when changing old -> new. Atomic
		// writers must invalidate a cache even on a low-resolution filesystem.
		if err := os.WriteFile(path+".next", []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path+".next", stamp, stamp); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path+".next", path); err != nil {
			t.Fatal(err)
		}
	}
	read := func(want any) {
		t.Helper()
		if got, err := store.read(t.Context(), "cookie"); err != nil || got != want {
			t.Fatalf("cookie=%v, error=%v; want %v", got, err, want)
		}
	}
	read(nil)
	replace(`{"cookie":"old"}`)
	read("old")
	for range 10 {
		read("old")
	}
	replace(`{"cookie":"new"}`)
	read("new")
	// Also recognize in-place edits with a changed mtime, without relying on
	// the wall clock or the filesystem's timestamp precision.
	if err := os.WriteFile(path, []byte(`{"cookie":"edit"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, stamp.Add(time.Second), stamp.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	read("edit")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	read(nil)
	replace(`{"cookie":"back"}`)
	read("back")
	for _, invalid := range []string{`{`, strings.Repeat("x", maxStoreSize+1)} {
		replace(invalid)
		for range 2 {
			if got, err := store.read(t.Context(), "cookie"); err == nil || got != nil {
				t.Fatalf("invalid external store returned cached data: %v, %v", got, err)
			}
		}
	}
	// A writer must refresh as well, even without a preceding read. Invalid
	// reloads must not prevent recovery once a valid snapshot is committed.
	replace(`{"cookie":"latest"}`)
	if !store.write(t.Context(), "result", "signed", false) {
		t.Fatal("write after external update failed")
	}
	values, _, err := readRuntimeStoreSnapshot(path)
	if err != nil || values["cookie"] != "latest" || values["result"] != "signed" {
		t.Fatalf("writer lost external data: %v, %v", values, err)
	}
	read("latest")
}

func BenchmarkRuntimeStoreCachedRead(b *testing.B) {
	for _, size := range []int{0, 3 << 20} {
		name := "small"
		if size != 0 {
			name = "3MiB"
		}
		b.Run(name, func(b *testing.B) {
			store, err := openRuntimeStore(filepath.Join(b.TempDir(), "store.json"))
			if err != nil {
				b.Fatal(err)
			}
			if !store.write(b.Context(), "cookie", "token", false) || !store.write(b.Context(), "cached", strings.Repeat("x", size), false) {
				b.Fatal("initialize persistent store")
			}
			b.ReportAllocs()
			for b.Loop() {
				if got, err := store.read(b.Context(), "cookie"); err != nil || got != "token" {
					b.Fatalf("cookie=%v, err=%v", got, err)
				}
			}
		})
	}
}
