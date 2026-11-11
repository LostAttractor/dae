// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestRuntimeStoreRejectsFIFO(t *testing.T) {
	for _, loaded := range []bool{false, true} {
		for _, write := range []bool{false, true} {
			t.Run(fmt.Sprintf("loaded=%t/write=%t", loaded, write), func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "store.json")
				var store *runtimeStore
				if loaded {
					if err := os.WriteFile(path, []byte(`{"local":{"cookie":"old"}}`), 0600); err != nil {
						t.Fatal(err)
					}
					var err error
					store, err = openRuntimeStore(path)
					if err != nil {
						t.Fatal(err)
					}
					if got, err := store.read(t.Context(), testLocalScope, "cookie"); err != nil || got != "old" {
						t.Fatalf("initial read = %v, %v", got, err)
					}
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
				}
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() {
					if !loaded {
						var err error
						store, err = openRuntimeStore(path)
						if err != nil {
							done <- fmt.Errorf("open accessed FIFO contents: %w", err)
							return
						}
					}
					if write {
						if store.write(t.Context(), testLocalScope, "result", "signed", false) {
							done <- errors.New("write replaced FIFO")
							return
						}
					} else if _, err := store.read(t.Context(), testLocalScope, "cookie"); !errors.Is(err, fs.ErrInvalid) {
						done <- fmt.Errorf("FIFO error = %v, want invalid file", err)
						return
					}
					done <- nil
				}()
				select {
				case err := <-done:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					// Unblock a regressed reader so it cannot retain the store gate.
					writer, err := os.OpenFile(path, os.O_WRONLY|unix.O_NONBLOCK, 0)
					if err != nil {
						t.Fatal(err)
					}
					_, _ = writer.WriteString("{}")
					_ = writer.Close()
					<-done
					t.Fatal("store access waited for a FIFO writer")
				}
				if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeNamedPipe == 0 {
					t.Fatalf("failed access replaced FIFO: %v, %v", info, err)
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(`{"local":{"cookie":"fixed"}}`), 0600); err != nil {
					t.Fatal(err)
				}
				if write && !store.write(t.Context(), testLocalScope, "result", "signed", false) {
					t.Fatal("write after FIFO repair failed")
				}
				if got, err := store.read(t.Context(), testLocalScope, "cookie"); err != nil || got != "fixed" {
					t.Fatalf("read after FIFO repair = %v, %v", got, err)
				}
			})
		}
	}
}

func TestRuntimeStoreInvalidJSONFirstAccess(t *testing.T) {
	for _, write := range []bool{false, true} {
		t.Run(fmt.Sprintf("write=%t", write), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "store.json")
			if err := os.WriteFile(path, []byte(`{`), 0600); err != nil {
				t.Fatal(err)
			}
			store, err := openRuntimeStore(path)
			if err != nil {
				t.Fatalf("open decoded store contents: %v", err)
			}
			for range 2 {
				if write {
					if store.write(t.Context(), testLocalScope, "result", "signed", false) {
						t.Fatal("write replaced invalid JSON")
					}
				} else if got, err := store.read(t.Context(), testLocalScope, "cookie"); err == nil || got != nil {
					t.Fatalf("invalid JSON read = %v, %v", got, err)
				}
			}
			if data, err := os.ReadFile(path); err != nil || string(data) != "{" {
				t.Fatalf("failed access modified invalid JSON: %q, %v", data, err)
			}
			if err := os.WriteFile(path, []byte(`{"local":{"cookie":"fixed"}}`), 0600); err != nil {
				t.Fatal(err)
			}
			if write && !store.write(t.Context(), testLocalScope, "result", "signed", false) {
				t.Fatal("write after JSON repair failed")
			}
			if got, err := store.read(t.Context(), testLocalScope, "cookie"); err != nil || got != "fixed" {
				t.Fatalf("read after JSON repair = %v, %v", got, err)
			}
		})
	}
}

func TestRuntimeStoreFirstAccessUsesLatestSnapshot(t *testing.T) {
	for _, write := range []bool{false, true} {
		t.Run(fmt.Sprintf("write=%t", write), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "store.json")
			if err := os.WriteFile(path, []byte(`{"local":{"cookie":"old","retired":"drop"}}`), 0600); err != nil {
				t.Fatal(err)
			}
			store, err := openRuntimeStore(path)
			if err != nil {
				t.Fatal(err)
			}
			if store.info != nil || len(store.values) != 0 {
				t.Fatal("open loaded store contents")
			}
			if err := os.WriteFile(path+".next", []byte(`{"local":{"cookie":"new","external":"keep"}}`), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(path+".next", path); err != nil {
				t.Fatal(err)
			}
			want := map[string]string{"cookie": "new", "external": "keep"}
			if write {
				if !store.write(t.Context(), testLocalScope, "result", "signed", false) {
					t.Fatal("first write after external replacement failed")
				}
				want["result"] = "signed"
			} else if got, err := store.read(t.Context(), testLocalScope, "cookie"); err != nil || got != "new" {
				t.Fatalf("first read = %v, %v", got, err)
			}
			values, _, err := readRuntimeStoreSnapshot(path)
			if err != nil || !maps.Equal(values["local"], want) {
				t.Fatalf("latest snapshot = %v, %v; want %v", values, err, want)
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
		if got, err := store.read(t.Context(), testDeviceScope, "cookie"); err != nil || got != want {
			t.Fatalf("cookie=%v, error=%v; want %v", got, err, want)
		}
	}
	read(nil)
	replace(`{"02:00:00:00:00:01":{"cookie":"old"}}`)
	read("old")
	for range 10 {
		read("old")
	}
	replace(`{"02:00:00:00:00:01":{"cookie":"new"}}`)
	read("new")
	// Also recognize in-place edits with a changed mtime, without relying on
	// the wall clock or the filesystem's timestamp precision.
	if err := os.WriteFile(path, []byte(`{"02:00:00:00:00:01":{"cookie":"edit"}}`), 0600); err != nil {
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
	replace(`{"02:00:00:00:00:01":{"cookie":"back"}}`)
	read("back")
	for _, invalid := range []string{`{`, strings.Repeat("x", maxStoreSize+1)} {
		replace(invalid)
		for range 2 {
			if got, err := store.read(t.Context(), testDeviceScope, "cookie"); err == nil || got != nil {
				t.Fatalf("invalid external store returned cached data: %v, %v", got, err)
			}
		}
	}
	// A writer must refresh as well, even without a preceding read. Invalid
	// reloads must not prevent recovery once a valid snapshot is committed.
	replace(`{"02:00:00:00:00:01":{"cookie":"latest"}}`)
	if !store.write(t.Context(), testDeviceScope, "result", "signed", false) {
		t.Fatal("write after external update failed")
	}
	values, _, err := readRuntimeStoreSnapshot(path)
	if err != nil || values[testDeviceName]["cookie"] != "latest" || values[testDeviceName]["result"] != "signed" {
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
			if !store.write(b.Context(), testDeviceScope, "cookie", "token", false) || !store.write(b.Context(), testDeviceScope, "cached", strings.Repeat("x", size), false) {
				b.Fatal("initialize persistent store")
			}
			b.ReportAllocs()
			for b.Loop() {
				if got, err := store.read(b.Context(), testDeviceScope, "cookie"); err != nil || got != "token" {
					b.Fatalf("cookie=%v, err=%v", got, err)
				}
			}
		})
	}
}
