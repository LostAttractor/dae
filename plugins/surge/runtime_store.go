// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"weak"

	"github.com/daeuniverse/dae/common/fileio"
	"github.com/daeuniverse/dae/common/macaddr"
	"github.com/daeuniverse/dae/common/persist"
	"github.com/daeuniverse/dae/component/plugin"
)

type runtimeStore struct {
	gate   chan struct{}
	path   string
	values map[string]map[string]string
	info   os.FileInfo // The exact file snapshot represented by values; nil if absent.

	activeMu   sync.Mutex
	active     map[[6]byte]int
	generation atomic.Uint64 // Increment only on migration publication; ordinary writes preserve DNS TTLs.
	syncDir    func(string) error
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
	store := &runtimeStore{gate: make(chan struct{}, 1), values: make(map[string]map[string]string), syncDir: persist.SyncDir}
	if path == "" {
		return store, nil
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve script persistent store: %w", err)
	}
	// Keep the registry key stable across first-write directory creation without creating it during preparation.
	dir, suffix := filepath.Dir(path), filepath.Base(path)
	for {
		parent, err := filepath.EvalSymlinks(dir)
		if err == nil {
			path = filepath.Join(parent, suffix)
			break
		}
		if !errors.Is(err, os.ErrNotExist) || filepath.Dir(dir) == dir {
			return nil, fmt.Errorf("resolve script persistent store: %w", err)
		}
		suffix = filepath.Join(filepath.Base(dir), suffix)
		dir = filepath.Dir(dir)
	}
	runtimeStores.Lock()
	defer runtimeStores.Unlock()
	if existing := runtimeStores.byPath[path].Value(); existing != nil {
		return existing, nil
	}
	maps.DeleteFunc(runtimeStores.byPath, func(_ string, store weak.Pointer[runtimeStore]) bool { return store.Value() == nil })
	store.path = path
	runtimeStores.byPath[path] = weak.Make(store)
	return store, nil
}

func readRuntimeStoreSnapshot(path string) (map[string]map[string]string, os.FileInfo, error) {
	f, info, err := fileio.OpenRegular(path)
	if errors.Is(err, os.ErrNotExist) {
		return make(map[string]map[string]string), nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("open script persistent store: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxStoreSize+1))
	if err != nil {
		return nil, nil, err
	}
	if len(data) > maxStoreSize {
		return nil, nil, errors.New("script persistent store exceeds 64 MiB")
	}
	var values map[string]map[string]string
	if err := json.Unmarshal(data, &values); err != nil {
		return nil, nil, fmt.Errorf("decode script persistent store: %w", err)
	}
	if values == nil {
		values = make(map[string]map[string]string)
	}
	for scope, entries := range values {
		if scope != "local" {
			mac, err := macaddr.ParseClient(scope)
			if err != nil || net.HardwareAddr(mac[:]).String() != scope {
				return nil, nil, errors.New("invalid script persistent store scope")
			}
		}
		if entries == nil {
			return nil, nil, errors.New("invalid script persistent store entries")
		}
		for key, value := range entries {
			if key == "" || len(key) > maxStoreValueSize || len(value) > maxStoreValueSize {
				return nil, nil, errors.New("invalid script persistent store entry")
			}
		}
	}
	return values, info, nil
}

// refresh is called with gate held. Reads check only metadata when unchanged.
// Writers call it under the cross-process lock as well, so their update always
// merges against the latest committed snapshot.
func (s *runtimeStore) refresh() error {
	info, err := os.Stat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		if s.info != nil {
			s.values, s.info = make(map[string]map[string]string), nil
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

func (s *runtimeStore) read(ctx context.Context, scope ScriptScope, key string) (any, error) {
	if !scope.valid() {
		return nil, ctx.Err()
	}
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
	value, ok := s.values[scope.key()][key]
	if !ok {
		return nil, nil
	}
	return value, ctx.Err()
}

func (s *runtimeStore) write(ctx context.Context, scope ScriptScope, key, value string, remove bool) bool {
	if !scope.valid() || key == "" || len(value) > maxStoreValueSize || len(key) > maxStoreValueSize {
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
	device := scope.key()
	next := maps.Clone(s.values)
	entries := maps.Clone(next[device])
	if remove {
		delete(entries, key)
	} else {
		if entries == nil {
			entries = make(map[string]string)
		}
		entries[key] = value
	}
	if len(entries) == 0 {
		delete(next, device)
	} else {
		next[device] = entries
	}
	return s.commit(ctx, next) == nil
}

// The caller holds gate; persistent writes also require the sidecar lock and a refreshed snapshot.
func (s *runtimeStore) commit(ctx context.Context, next map[string]map[string]string) error {
	data, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if len(data) > maxStoreSize {
		return errors.New("script persistent store exceeds 64 MiB")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if path := s.path; path != "" {
		f, err := os.CreateTemp(filepath.Dir(path), ".surge-store-*")
		if err != nil {
			return err
		}
		defer os.Remove(f.Name())
		_, err = f.Write(data)
		if err == nil {
			err = f.Sync()
		}
		info, statErr := f.Stat()
		if err := errors.Join(err, statErr, f.Close(), ctx.Err()); err != nil {
			return err
		}
		if err := os.Rename(f.Name(), path); err != nil {
			return err
		}
		s.info, s.values = info, next
		return persist.AfterPublish(s.syncDir(filepath.Dir(path)))
	}
	s.values = next
	return nil
}

func (s *runtimeStore) migrate(ctx context.Context, from, to [6]byte) (int, error) {
	if !macaddr.ValidClient(from) || !macaddr.ValidClient(to) || from == to {
		return 0, plugin.ErrScriptStoreInvalid
	}
	if s.path != "" {
		lock, err := lockRuntimeStore(ctx, s.path)
		if err != nil {
			return 0, err
		}
		defer lock.Close()
	}
	if err := s.lock(ctx); err != nil {
		return 0, err
	}
	defer s.unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.activeMu.Lock()
	busy := s.active[from] != 0 || s.active[to] != 0
	s.activeMu.Unlock()
	if busy {
		return 0, plugin.ErrScriptStoreBusy
	}
	if s.path != "" {
		if err := s.refresh(); err != nil {
			return 0, err
		}
	}
	oldKey, newKey := net.HardwareAddr(from[:]).String(), net.HardwareAddr(to[:]).String()
	entries, ok := s.values[oldKey]
	if !ok {
		return 0, plugin.ErrScriptStoreNotFound
	}
	if _, exists := s.values[newKey]; exists {
		return 0, plugin.ErrScriptStoreConflict
	}
	next := maps.Clone(s.values)
	next[newKey] = entries
	delete(next, oldKey)
	err := s.commit(ctx, next)
	if !persist.Published(err) {
		return 0, err
	}
	s.generation.Add(1)
	return len(entries), err
}

func (s *runtimeStore) beginExecution(ctx context.Context, mac [6]byte) error {
	if err := s.lock(ctx); err != nil {
		return err
	}
	defer s.unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	if s.active == nil {
		s.active = make(map[[6]byte]int)
	}
	s.active[mac]++
	return nil
}

func (s *runtimeStore) endExecution(mac [6]byte) {
	// Cleanup must clear the count without waiting for another scope's file I/O.
	s.activeMu.Lock()
	defer s.activeMu.Unlock()
	if s.active[mac]--; s.active[mac] == 0 {
		delete(s.active, mac)
	}
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
