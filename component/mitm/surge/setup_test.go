// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/mitm/ca"
	"github.com/daeuniverse/dae/component/mitm/plugin"
	log "github.com/sirupsen/logrus"
)

func TestLoadSurgeProxyDownloadsAndOfflineCache(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DAE_LOCATION_CACHE", dir)
	if err := mitmca.Generate(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"), "download test", time.Hour); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Connection", "close")
		switch r.URL.Path {
		case "/entry":
			http.Redirect(w, r, "/v2/module.sgmodule", http.StatusFound)
		case "/v2/module.sgmodule":
			fmt.Fprint(w, `[MITM]
hostname = target.test
[Script]
test = type=http-request,pattern=^https://target\.test/script,script-path=../script.js
[Map Local]
^https://target\.test/data data-type=file data=../data.json
`)
		case "/script.js":
			fmt.Fprint(w, `$done({response:{status:201,body:"proxy-script"}});`)
		case "/data.json":
			fmt.Fprint(w, `{"from":"proxy"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := server.Client()
	defer client.CloseIdleConnections()
	var dials atomic.Int32
	var offline atomic.Bool
	client.Transport.(*http.Transport).DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		if network != "tcp" || address != "127.0.0.1:1" {
			return nil, fmt.Errorf("unexpected download destination: %s %s", network, address)
		}
		if offline.Load() {
			return nil, errors.New("proxy unavailable")
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	conf := Config{
		Modules:       []ModuleSource{{Name: "cached", Link: "https-file://127.0.0.1:1/entry"}},
		ScriptTimeout: time.Second, MemoryLimit: 16 << 20,
		MaxBodySize: 1 << 20, MaxConcurrentScripts: 1,
	}
	for _, cached := range []bool{false, true} {
		offline.Store(cached)
		engine, err := prepare(context.Background(), conf, plugin.Services{BaseDir: dir, PrepareClient: client, Logger: log.NewEntry(log.StandardLogger())}, "test")
		if err != nil {
			t.Fatal(err)
		}
		handler, closeTransport := proxyTestHost(t, engine).Handler("https", "target.test", 443, func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("downloaded resources should produce local responses")
		})
		for _, test := range []struct {
			path, body string
			status     int
		}{
			{"/script", "proxy-script", http.StatusCreated},
			{"/data", `{"from":"proxy"}`, http.StatusOK},
		} {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://target.test"+test.path, nil))
			if response.Code != test.status || response.Body.String() != test.body {
				t.Errorf("cached=%t path=%s: status=%d body=%q", cached, test.path, response.Code, response.Body.String())
			}
		}
		closeTransport()
	}
	if requests.Load() != 4 || dials.Load() != 5 {
		t.Fatalf("downloads bypassed supplied proxy or cache: requests=%d dials=%d", requests.Load(), dials.Load())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := prepare(ctx, conf, plugin.Services{BaseDir: dir, PrepareClient: client, Logger: log.NewEntry(log.StandardLogger())}, "test"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled startup used cache: %v", err)
	}
}

func TestLoadSurgeLocationLoadsScriptsAndPersistsStore(t *testing.T) {
	for _, test := range []struct {
		name     string
		absolute bool
	}{
		{name: "cache directory"},
		{name: "absolute paths ignore cache directory", absolute: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			configDir, envDir := t.TempDir(), t.TempDir()
			t.Setenv("DAE_LOCATION_CACHE", envDir)
			t.Chdir(configDir)
			resourceDir := envDir
			if test.absolute {
				resourceDir = t.TempDir()
			}
			if resourceDir != configDir {
				// Model an immutable Nix configuration directory with no module,
				// CA or state files in it. Verify it remains empty after execution.
				if err := os.Chmod(configDir, 0500); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(configDir, 0700) })
			}

			certPath := filepath.Join(resourceDir, "ca", "root.pem")
			keyPath := filepath.Join(resourceDir, "ca", "root.key")
			modulePath := filepath.Join(resourceDir, "modules", "example.sgmodule")
			scriptPath := filepath.Join(resourceDir, "modules", "scripts", "persist.js")
			storePath := filepath.Join(resourceDir, "state", "persistent.json")
			if err := mitmca.Generate(certPath, keyPath, "Surge location test", time.Hour); err != nil {
				t.Fatal(err)
			}
			for _, dir := range []string{filepath.Dir(scriptPath), filepath.Dir(storePath)} {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			module := `[MITM]
hostname = example.test
[Script]
persist = type=http-request,pattern=^https://example\.test/persist,script-path=scripts/persist.js
`
			script := `
const counter = Number($persistentStore.read("counter")) + 1;
if (!$persistentStore.write(String(counter), "counter")) throw Error("store write failed");
$done({response:{status:201,body:"from-module-script:"+$persistentStore.read("seed")+":"+counter}});
`
			for path, contents := range map[string]string{
				modulePath: module,
				scriptPath: script,
				storePath:  `{"counter":"5","seed":"on-disk"}`,
			} {
				if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
					t.Fatal(err)
				}
			}
			conf := Config{
				Modules:       []ModuleSource{{Link: "file:modules/example.sgmodule"}},
				Store:         "state/persistent.json",
				ScriptTimeout: time.Second, MemoryLimit: 16 << 20,
				MaxBodySize: 1 << 20, MaxConcurrentScripts: 1,
			}
			if test.absolute {
				conf.Modules = []ModuleSource{{Link: "file://" + modulePath}}
				conf.Store = storePath
			}
			engine, err := prepare(context.Background(), conf, plugin.Services{BaseDir: envDir, PrepareClient: http.DefaultClient, Logger: log.NewEntry(log.StandardLogger())}, "test")
			if err != nil {
				t.Fatal(err)
			}
			if !proxyTestHost(t, engine).Match("example.test", 443) {
				t.Fatal("module MITM hostname was not loaded")
			}
			upstreamCalled := false
			handler, closeTransport := proxyTestHost(t, engine).Handler("https", "example.test", 443, func(context.Context, string, string) (net.Conn, error) {
				upstreamCalled = true
				return nil, errors.New("script should return a synthetic response")
			})
			defer closeTransport()
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://example.test/persist", nil))
			if upstreamCalled || response.Code != http.StatusCreated || response.Body.String() != "from-module-script:on-disk:6" {
				t.Fatalf("loaded script/store did not execute: upstream=%t status=%d body=%q", upstreamCalled, response.Code, response.Body.String())
			}
			data, err := os.ReadFile(storePath)
			if err != nil {
				t.Fatal(err)
			}
			var stored map[string]string
			if err := json.Unmarshal(data, &stored); err != nil {
				t.Fatal(err)
			}
			if stored["counter"] != "6" || stored["seed"] != "on-disk" {
				t.Fatalf("persistent store was not updated at %s: %s", storePath, data)
			}
			for _, dir := range []string{configDir, envDir} {
				if dir == resourceDir {
					continue
				}
				entries, err := os.ReadDir(dir)
				if err != nil || len(entries) != 0 {
					t.Fatalf("unexpected files outside resource directory %s: %v, err=%v", dir, entries, err)
				}
			}
		})
	}
}
