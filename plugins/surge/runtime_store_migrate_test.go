// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common/persist"
	"github.com/daeuniverse/dae/component/plugin"
)

func TestRuntimeStoreMigrate(t *testing.T) {
	for _, disk := range []bool{false, true} {
		t.Run(fmt.Sprint(disk), func(t *testing.T) {
			path := ""
			if disk {
				path = filepath.Join(t.TempDir(), "store.json")
			}
			store, err := openRuntimeStore(path)
			if err != nil {
				t.Fatal(err)
			}
			from, to, other := testDeviceMAC, [6]byte{2, 0, 0, 0, 0, 2}, [6]byte{2, 0, 0, 0, 0, 3}
			for _, entry := range []struct {
				scope      ScriptScope
				key, value string
			}{
				{testMACScope(from), "cookie", "private"},
				{testMACScope(from), "/script/default", "opaque"},
				{testMACScope(other), "cookie", "other"},
				{testLocalScope, "cookie", "local"},
			} {
				if !store.write(t.Context(), entry.scope, entry.key, entry.value, false) {
					t.Fatal("initialize store")
				}
			}
			if store.generation.Load() != 0 {
				t.Fatal("ordinary writes changed DNS generation")
			}
			moved, err := store.migrate(t.Context(), from, to)
			if err != nil || moved != 2 || store.generation.Load() != 1 {
				t.Fatalf("migrate: moved=%d generation=%d err=%v", moved, store.generation.Load(), err)
			}
			want := map[string]map[string]string{
				testMACScope(to).key():    {"cookie": "private", "/script/default": "opaque"},
				testMACScope(other).key(): {"cookie": "other"},
				"local":                   {"cookie": "local"},
			}
			if !reflect.DeepEqual(store.values, want) {
				t.Fatalf("unexpected partitions: %v", store.values)
			}
			if disk {
				values, _, err := readRuntimeStoreSnapshot(path)
				if err != nil || !reflect.DeepEqual(values, want) {
					t.Fatalf("disk snapshot: %v %v", values, err)
				}
				shared, err := openRuntimeStore(path)
				if err != nil || shared != store {
					t.Fatalf("store not shared: %v", err)
				}
				for _, name := range []string{path, path + ".lock"} {
					info, err := os.Stat(name)
					if err != nil || info.Mode().Perm() != 0600 {
						t.Fatalf("permissions: %v %v", info, err)
					}
				}
				files, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".surge-store-*"))
				if err != nil || len(files) != 0 {
					t.Fatalf("temporary files retained: %v %v", files, err)
				}
			}
		})
	}
}

func TestRuntimeStoreMigrateRejectsWithoutChanges(t *testing.T) {
	from, to := testDeviceMAC, [6]byte{2, 0, 0, 0, 0, 2}
	for _, test := range []struct {
		name     string
		from, to [6]byte
		target   map[string]string
		want     error
	}{
		{"same", from, from, nil, plugin.ErrScriptStoreInvalid},
		{"zero", from, [6]byte{}, nil, plugin.ErrScriptStoreInvalid},
		{"multicast", [6]byte{1, 0, 0, 0, 0, 1}, to, nil, plugin.ErrScriptStoreInvalid},
		{"broadcast", from, [6]byte{255, 255, 255, 255, 255, 255}, nil, plugin.ErrScriptStoreInvalid},
		{"missing", [6]byte{2, 0, 0, 0, 0, 3}, to, nil, plugin.ErrScriptStoreNotFound},
		{"occupied", from, to, map[string]string{"cookie": "target"}, plugin.ErrScriptStoreConflict},
		{"empty-target", from, to, map[string]string{}, plugin.ErrScriptStoreConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "store.json")
			values := map[string]map[string]string{testDeviceName: {"cookie": "source"}}
			if test.target != nil {
				values[testMACScope(to).key()] = test.target
			}
			before, _ := json.Marshal(values)
			if err := os.WriteFile(path, before, 0600); err != nil {
				t.Fatal(err)
			}
			store, err := openRuntimeStore(path)
			if err != nil {
				t.Fatal(err)
			}
			if count, err := store.migrate(t.Context(), test.from, test.to); count != 0 || !errors.Is(err, test.want) {
				t.Fatalf("migrate: %d %v", count, err)
			}
			after, err := os.ReadFile(path)
			if err != nil || string(before) != string(after) || !reflect.DeepEqual(store.values, values) || store.generation.Load() != 0 {
				t.Fatalf("rejected move changed state: %v", err)
			}
		})
	}
}

func TestRuntimeStoreMigratePublication(t *testing.T) {
	for _, published := range []bool{false, true} {
		t.Run(fmt.Sprint(published), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "store.json")
			store, err := openRuntimeStore(path)
			if err != nil || !store.write(t.Context(), testDeviceScope, "cookie", "value", false) {
				t.Fatal(err)
			}
			to := [6]byte{2, 0, 0, 0, 0, 2}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if published {
				store.syncDir = func(string) error {
					cancel()
					return errors.New("simulated directory sync failure")
				}
			} else {
				cancel()
			}
			moved, err := store.migrate(ctx, testDeviceMAC, to)
			if err == nil || persist.Published(err) != published {
				t.Fatalf("publication classification: %v", err)
			}
			key, generation, count := testDeviceName, uint64(0), 0
			if published {
				key, generation, count = testMACScope(to).key(), 1, 1
			}
			values, _, readErr := readRuntimeStoreSnapshot(path)
			if readErr != nil || moved != count || store.generation.Load() != generation || !reflect.DeepEqual(store.values, values) || len(values) != 1 || values[key]["cookie"] != "value" {
				t.Fatalf("publication state: count=%d generation=%d values=%v err=%v", moved, store.generation.Load(), values, readErr)
			}
		})
	}
}

func TestRuntimeStoreMigrateCanceledLocks(t *testing.T) {
	for _, external := range []bool{false, true} {
		t.Run(fmt.Sprint(external), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "store.json")
			store, err := openRuntimeStore(path)
			if err != nil || !store.write(t.Context(), testDeviceScope, "cookie", "original", false) {
				t.Fatal(err)
			}
			if external {
				lock, err := lockRuntimeStore(t.Context(), path)
				if err != nil {
					t.Fatal(err)
				}
				defer lock.Close()
			} else {
				if err := store.lock(t.Context()); err != nil {
					t.Fatal(err)
				}
				defer store.unlock()
			}
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
			defer cancel()
			if count, err := store.migrate(ctx, testDeviceMAC, [6]byte{2, 0, 0, 0, 0, 2}); count != 0 || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("lock cancellation: %d %v", count, err)
			}
			if store.generation.Load() != 0 || store.values[testDeviceName]["cookie"] != "original" {
				t.Fatal("canceled move changed state")
			}
		})
	}
}

func TestRuntimeStoreMigrateRefreshAndConcurrency(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	store, err := openRuntimeStore(path)
	if err != nil || !store.write(t.Context(), testDeviceScope, "cookie", "original", false) {
		t.Fatal(err)
	}
	to := [6]byte{2, 0, 0, 0, 0, 2}
	if err := os.WriteFile(path, []byte(`{"local":{"cookie":"local"},"02:00:00:00:00:01":{"cookie":"latest"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Go(func() { _, err := store.migrate(t.Context(), testDeviceMAC, to); results <- err })
	}
	workers.Wait()
	close(results)
	successes, missing := 0, 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, plugin.ErrScriptStoreNotFound):
			missing++
		default:
			t.Fatal(err)
		}
	}
	if successes != 1 || missing != 1 || store.generation.Load() != 1 || store.values[testMACScope(to).key()]["cookie"] != "latest" || store.values["local"]["cookie"] != "local" {
		t.Fatalf("concurrent moves: successes=%d missing=%d values=%v", successes, missing, store.values)
	}
	if err := os.WriteFile(path, []byte(`{broken`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.migrate(t.Context(), to, testDeviceMAC); err == nil || store.generation.Load() != 1 {
		t.Fatal("invalid snapshot was overwritten")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != `{broken` {
		t.Fatalf("corrupt file changed: %v", err)
	}
}

func TestEngineMigrateScriptStore(t *testing.T) {
	r := testRuntime(t, RuntimeOptions{})
	e := &Engine{options: EngineOptions{Runtime: r.Runtime}}
	if !r.data.write(t.Context(), testDeviceScope, "key", "value", false) {
		t.Fatal("seed")
	}
	request := api.ScriptStoreMigrateRequest{FromMAC: "02-00-00-00-00-01", ToMAC: "02-00-00-00-00-AA"}
	response, err := e.MigrateScriptStore(t.Context(), request)
	if err != nil || response.KeysMoved != 1 || response.FromMAC != testDeviceName || response.ToMAC != "02:00:00:00:00:aa" {
		t.Fatalf("migrate response: %+v %v", response, err)
	}
	if _, err := (&Engine{}).MigrateScriptStore(t.Context(), request); !errors.Is(err, plugin.ErrScriptStoreUnavailable) {
		t.Fatalf("nil Runtime: %v", err)
	}
	for _, raw := range []string{"", "local", "unknown", "00:00:00:00:00:00", "01:00:00:00:00:01", "02:00:00:00:00:00:00:01", net.HardwareAddr(testDeviceMAC[:]).String()} {
		request.ToMAC = raw
		if _, err := e.MigrateScriptStore(t.Context(), request); !errors.Is(err, plugin.ErrScriptStoreInvalid) {
			t.Fatalf("invalid target %q: %v", raw, err)
		}
	}
}
