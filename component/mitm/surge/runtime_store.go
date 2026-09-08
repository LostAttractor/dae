// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
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
	mu     sync.Mutex
	path   string
	values map[string]string
}

// Reloaded control planes can overlap while established requests finish. Share
// the store by absolute path so the old and new plane cannot lose each other's
// writes. Only live runtimes retain a store: retired instances must not keep
// every store path and its contents alive for the lifetime of the process.
var runtimeStores = struct {
	sync.Mutex
	byPath map[string]weak.Pointer[runtimeStore]
}{byPath: make(map[string]weak.Pointer[runtimeStore])}

const maxStoreSize = 4 << 20

func openRuntimeStore(path string) (*runtimeStore, error) {
	store := &runtimeStore{values: make(map[string]string)}
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
	f, err := os.Open(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("open script persistent store: %w", err)
	}
	if err == nil {
		defer f.Close()
		data, err := io.ReadAll(io.LimitReader(f, maxStoreSize+1))
		if err != nil {
			return nil, err
		}
		if len(data) > maxStoreSize {
			return nil, errors.New("script persistent store exceeds 4 MiB")
		}
		if err := json.Unmarshal(data, &store.values); err != nil {
			return nil, fmt.Errorf("decode script persistent store: %w", err)
		}
		if store.values == nil {
			store.values = make(map[string]string)
		}
	}
	runtimeStores.byPath[path] = weak.Make(store)
	return store, nil
}

func (s *runtimeStore) read(key string) any {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.values[key]
	if !ok {
		return nil
	}
	return value
}

func (s *runtimeStore) write(key, value string, remove bool) bool {
	if key == "" || len(key)+len(value) > maxStoreSize {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := maps.Clone(s.values)
	if remove {
		delete(next, key)
	} else {
		next[key] = value
	}
	data, err := json.Marshal(next)
	if err != nil || len(data) > maxStoreSize {
		return false
	}
	if path := s.path; path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return false
		}
		f, err := os.CreateTemp(filepath.Dir(path), ".surge-store-*")
		if err != nil {
			return false
		}
		defer os.Remove(f.Name())
		_, err = f.Write(data)
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil || closeErr != nil || os.Rename(f.Name(), path) != nil {
			return false
		}
	}
	s.values = next
	return true
}
