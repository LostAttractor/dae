// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"sync"
	"weak"
)

type runtimeStore struct {
	gate   chan struct{}
	path   string
	values map[string]string
	info   os.FileInfo // The exact file snapshot represented by values; nil if absent.
}

// Reloaded control planes can overlap while established requests finish. Share
// the store by absolute path so the old and new plane cannot lose each other's
// writes. Only live runtimes retain a store: retired instances must not keep
// every store path and its contents alive for the lifetime of the process.
var runtimeStores = struct {
	sync.Mutex
	byPath map[string]weak.Pointer[runtimeStore]
}{byPath: make(map[string]weak.Pointer[runtimeStore])}

const (
	maxStoreValueSize = 4 << 20
	maxStoreSize      = 64 << 20
)

func openRuntimeStore(path string) (*runtimeStore, error) {
	store := &runtimeStore{gate: make(chan struct{}, 1), values: make(map[string]string)}
	if path == "" {
		return store, nil
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve script persistent store: %w", err)
	}
	// Resolve an existing parent directory without requiring the store file
	// to exist on first use.
	if parent, err := filepath.EvalSymlinks(filepath.Dir(path)); err == nil {
		path = filepath.Join(parent, filepath.Base(path))
	}
	runtimeStores.Lock()
	defer runtimeStores.Unlock()
	if existing := runtimeStores.byPath[path].Value(); existing != nil {
		return existing, nil
	}
	maps.DeleteFunc(runtimeStores.byPath, func(_ string, store weak.Pointer[runtimeStore]) bool { return store.Value() == nil })
	store.path = path
	if err := store.refresh(); err != nil {
		return nil, err
	}
	runtimeStores.byPath[path] = weak.Make(store)
	return store, nil
}

func readRuntimeStoreSnapshot(path string) (map[string]string, os.FileInfo, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return make(map[string]string), nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("open script persistent store: %w", err)
	}
	defer f.Close()
	// Bind the cache stamp to this descriptor, not a later Stat(path): another
	// process may atomically replace the path while this snapshot is being read.
	info, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxStoreSize+1))
	if err != nil {
		return nil, nil, err
	}
	if len(data) > maxStoreSize {
		return nil, nil, errors.New("script persistent store exceeds 64 MiB")
	}
	var values map[string]string
	if err := json.Unmarshal(data, &values); err != nil {
		return nil, nil, fmt.Errorf("decode script persistent store: %w", err)
	}
	if values == nil {
		values = make(map[string]string)
	}
	for _, value := range values {
		if len(value) > maxStoreValueSize {
			return nil, nil, errors.New("script persistent store value exceeds 4 MiB")
		}
	}
	return values, info, nil
}

// refresh is called with gate held (or before publishing a new store). Reads check
// only metadata when unchanged. Writers call it under the cross-process lock as
// well, so their update always merges against the latest committed snapshot.
func (s *runtimeStore) refresh() error {
	info, err := os.Stat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		if s.info != nil {
			s.values, s.info = make(map[string]string), nil
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat script persistent store: %w", err)
	}
	if s.info != nil && os.SameFile(s.info, info) && s.info.Size() == info.Size() && s.info.ModTime().Equal(info.ModTime()) {
		return nil
	}
	values, loaded, err := readRuntimeStoreSnapshot(s.path)
	if err != nil {
		return err // Do not mark a failed reload as current.
	}
	s.values, s.info = values, loaded
	return nil
}

func (s *runtimeStore) read(ctx context.Context, key string) (any, error) {
	if err := s.lock(ctx); err != nil {
		return nil, err
	}
	defer s.unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.path != "" {
		if err := s.refresh(); err != nil {
			return nil, err
		}
	}
	value, ok := s.values[key]
	if !ok {
		return nil, nil
	}
	return value, ctx.Err()
}

func (s *runtimeStore) write(ctx context.Context, key, value string, remove bool) bool {
	if key == "" || len(value) > maxStoreValueSize || len(key) > maxStoreValueSize {
		return false
	}
	// Waiting on another process must not hold the in-process mutex: other
	// invocations still need to read or honor their own, shorter deadlines.
	if s.path != "" {
		lock, err := lockRuntimeStore(ctx, s.path)
		if err != nil {
			return false
		}
		defer lock.Close()
	}
	if err := s.lock(ctx); err != nil {
		return false
	}
	defer s.unlock()
	if ctx.Err() != nil {
		return false
	}
	if s.path != "" {
		if err := s.refresh(); err != nil {
			return false
		}
	}
	next := maps.Clone(s.values)
	if remove {
		delete(next, key)
	} else {
		next[key] = value
	}
	data, err := json.Marshal(next)
	if err != nil || len(data) > maxStoreSize || ctx.Err() != nil {
		return false
	}
	if path := s.path; path != "" {
		f, err := os.CreateTemp(filepath.Dir(path), ".surge-store-*")
		if err != nil {
			return false
		}
		defer os.Remove(f.Name())
		_, err = f.Write(data)
		if err == nil {
			err = f.Sync()
		}
		info, statErr := f.Stat()
		closeErr := f.Close()
		if err != nil || statErr != nil || closeErr != nil || ctx.Err() != nil || os.Rename(f.Name(), path) != nil {
			return false
		}
		s.info = info
	}
	s.values = next
	return true
}

func (s *runtimeStore) lock(ctx context.Context) error {
	select {
	case s.gate <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *runtimeStore) unlock() { <-s.gate }
