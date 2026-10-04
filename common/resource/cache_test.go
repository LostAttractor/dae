// SPDX-License-Identifier: AGPL-3.0-only

package resource

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCacheValidationAtomicRefreshAndTimeout(t *testing.T) {
	var revision atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch revision.Load() {
		case 0:
			io.WriteString(w, "old")
		case 1:
			io.WriteString(w, "invalid")
		case 2:
			io.WriteString(w, "new")
		default:
			<-r.Context().Done()
		}
	}))
	defer server.Close()
	source := Source{Location: server.URL}
	cache := Cache{Dir: filepath.Join(t.TempDir(), "missing", "cache")}
	opts := LoadOptions{Key: source.Location, MaxBytes: 128}
	load := func(read ReadFunc) (string, error) {
		result, err := read(source, ReadOptions{MaxBytes: 128})
		if err == nil && string(result.Data) == "invalid" {
			err = errors.New("invalid content")
		}
		return string(result.Data), err
	}
	if value, status, err := cache.Load(t.Context(), server.Client(), opts, load); err != nil || status.RefreshError != nil || status.WriteError != nil || value != "old" {
		t.Fatalf("first load: %q %+v %v", value, status, err)
	}
	path := filepath.Join(cache.Dir, cacheName(opts.Key))
	old, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	before, err := old.Stat()
	if err != nil {
		t.Fatal(err)
	}
	original, err := io.ReadAll(old)
	if err != nil {
		t.Fatal(err)
	}
	revision.Store(1)
	if value, status, err := cache.Load(t.Context(), server.Client(), opts, load); err != nil || value != "old" || status.RefreshError == nil {
		t.Fatalf("validation fallback: %q %+v %v", value, status, err)
	}
	data, _ := os.ReadFile(path)
	if !bytes.Equal(original, data) {
		t.Fatal("invalid content replaced cache")
	}
	revision.Store(2)
	if value, _, err := cache.Load(t.Context(), server.Client(), opts, load); err != nil || value != "new" {
		t.Fatalf("refresh: %q %v", value, err)
	}
	after, err := os.Stat(path)
	if err != nil || os.SameFile(before, after) || after.Mode().Perm() != 0600 {
		t.Fatalf("non-atomic/private update: %v %v", after, err)
	}
	old.Seek(0, io.SeekStart)
	data, _ = io.ReadAll(old)
	if !bytes.Equal(original, data) {
		t.Fatal("open old snapshot modified")
	}
	revision.Store(3)
	opts.RefreshDeadline = time.Now().Add(20 * time.Millisecond)
	if value, status, err := cache.Load(t.Context(), server.Client(), opts, load); err != nil || status.RefreshError == nil || value != "new" {
		t.Fatalf("timeout fallback: %q %+v %v", value, status, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := cache.Load(ctx, server.Client(), opts, load); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(path)
	if _, _, err := (Cache{}).Load(t.Context(), server.Client(), opts, load); err == nil {
		t.Fatal("disabled cache fell back")
	}
	unchanged, _ := os.ReadFile(path)
	if !bytes.Equal(data, unchanged) {
		t.Fatal("disabled cache touched snapshot")
	}
	entries, _ := os.ReadDir(cache.Dir)
	if len(entries) != 1 {
		t.Fatalf("temporary files retained: %v", entries)
	}
}

func TestCacheRejectsInvalidSnapshots(t *testing.T) {
	const source = "https://example.com/module?secret"
	opts := LoadOptions{Key: source, MaxBytes: 128}
	for _, test := range []struct {
		name   string
		mutate func(*cacheSnapshot)
	}{
		{"version", func(s *cacheSnapshot) { s.Version++ }},
		{"identity", func(s *cacheSnapshot) { s.Key += "other" }},
		{"local root", func(s *cacheSnapshot) { s.Resources[source] = Result{Location: "/etc/passwd"} }},
		{"downgrade", func(s *cacheSnapshot) { s.Resources[source] = Result{Location: "http://example.com/module"} }},
		{"local source", func(s *cacheSnapshot) { s.Resources["file:///etc/passwd"] = Result{Location: "file:///etc/passwd"} }},
		{"oversize", func(s *cacheSnapshot) { s.Resources[source] = Result{Location: source, Data: make([]byte, 129)} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			cache := Cache{Dir: t.TempDir()}
			snapshot := cacheSnapshot{Version: 1, Key: source, Resources: map[string]Result{source: {Location: source, Data: []byte("ok")}}}
			test.mutate(&snapshot)
			data, err := json.Marshal(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(cache.Dir, cacheName(source)), data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := cache.read(t.Context(), opts); err == nil {
				t.Fatal("unsafe snapshot accepted")
			}
		})
	}
}

func TestCacheWriteFailureAndReplayResourceLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "valid data")
	}))
	defer server.Close()
	opts := LoadOptions{Key: server.URL, MaxBytes: 128}
	limit := int64(128)
	load := func(read ReadFunc) (Result, error) {
		return read(Source{Location: server.URL}, ReadOptions{MaxBytes: limit})
	}
	badDir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(badDir, nil, 0600); err != nil {
		t.Fatal(err)
	}
	value, status, err := (Cache{Dir: badDir}).Load(t.Context(), server.Client(), opts, load)
	if err != nil || status.WriteError == nil || string(value.Data) != "valid data" {
		t.Fatalf("cache write failure discarded fresh data: %+v %+v %v", value, status, err)
	}
	cache := Cache{Dir: t.TempDir()}
	if _, _, err := cache.Load(t.Context(), server.Client(), opts, load); err != nil {
		t.Fatal(err)
	}
	server.Close()
	limit = 2
	if _, _, err := cache.Load(t.Context(), server.Client(), opts, load); err == nil || !strings.Contains(err.Error(), "resource byte limit") {
		t.Fatalf("cache bypassed current resource size limit: %v", err)
	}
	cache.Dir = filepath.Join(t.TempDir(), "absent")
	if _, _, err := cache.Load(t.Context(), server.Client(), opts, load); err == nil {
		t.Fatal("missing cache accepted")
	}
	if _, err := os.Stat(cache.Dir); !os.IsNotExist(err) {
		t.Fatalf("cache read created directory: %v", err)
	}
}

func TestCacheFileSafetyAndOpenedDirectory(t *testing.T) {
	for _, kind := range []string{"symlink-dir", "writable-dir", "public-file", "symlink-file", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "cache")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			name := cacheName("key")
			path := filepath.Join(dir, name)
			switch kind {
			case "symlink-dir":
				if err := os.Remove(dir); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(t.TempDir(), dir); err != nil {
					t.Fatal(err)
				}
			case "writable-dir":
				if err := os.Chmod(dir, 0770); err != nil {
					t.Fatal(err)
				}
			case "public-file":
				if err := os.WriteFile(path, []byte("x"), 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink-file":
				target := filepath.Join(t.TempDir(), "target")
				if err := os.WriteFile(target, []byte("x"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			}
			opened, err := openCacheDir(dir, false)
			if err == nil {
				defer opened.Close()
				_, err = readCacheFile(t.Context(), opened, name, 128)
			}
			if err == nil {
				t.Fatal("unsafe cache accepted")
			}
		})
	}
	dir := filepath.Join(t.TempDir(), "cache")
	opened, err := openCacheDir(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if err := os.Rename(dir, dir+"-opened"); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	if err := os.Symlink(target, dir); err != nil {
		t.Fatal(err)
	}
	if err := writeCacheFile(t.Context(), opened, "entry", []byte("value")); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(dir+"-opened", "entry")); err != nil || string(data) != "value" {
		t.Fatalf("write escaped descriptor: %q %v", data, err)
	}
	if entries, err := os.ReadDir(target); err != nil || len(entries) != 0 {
		t.Fatal("replacement directory modified")
	}
}

func TestCacheConcurrentPublicationAndPrune(t *testing.T) {
	cache := Cache{Dir: t.TempDir()}
	const source = "https://example.test/data"
	opts := LoadOptions{Key: source, MaxBytes: 128}
	snapshot := &cacheSnapshot{Version: 1, Key: source, Resources: map[string]Result{source: {Location: source, Data: []byte("value")}}}
	if err := cache.write(t.Context(), opts, snapshot); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 10 {
				if err := cache.write(t.Context(), opts, snapshot); err != nil {
					t.Error(err)
					return
				}
				if got, err := cache.read(t.Context(), opts); err != nil || string(got.Resources[source].Data) != "value" {
					t.Errorf("partial snapshot: %v %v", got, err)
					return
				}
			}
		})
	}
	wg.Wait()
	for _, name := range []string{cacheName("stale"), "unrelated.json"} {
		if err := os.WriteFile(filepath.Join(cache.Dir, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := cache.Prune([]string{source}); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(cache.Dir)
	if len(entries) != 2 {
		t.Fatalf("prune removed active/unrelated entries: %v", entries)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".resource-") {
			t.Fatal("temporary file leak")
		}
	}
}
