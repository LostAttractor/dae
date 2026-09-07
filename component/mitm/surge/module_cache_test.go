// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestModuleCacheRefreshFallbackAndRedirect(t *testing.T) {
	var mode atomic.Int32
	var scriptDownloads atomic.Int32
	binaryBody := []byte{0, 255, 254, 128, 'x'}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/entry":
			http.Redirect(w, r, "/v2/module.sgmodule", http.StatusFound)
		case "/v2/module.sgmodule":
			switch mode.Load() {
			case 2:
				fmt.Fprint(w, "[Script]\ninvalid script")
				return
			case 3:
				w.Header().Set("Content-Length", fmt.Sprint(MaxModuleBytes+1))
				return
			case 5:
				fmt.Fprint(w, "<!DOCTYPE html><html><body>upstream error</body></html>")
				return
			case 6:
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			case 9:
				fmt.Fprint(w, "Service Unavailable")
				return
			case 10:
				return
			}
			fmt.Fprintf(w, "#!name=revision-%d\n[Script]\na = type=http-request,pattern=.,script-path=../scripts/a.js\nb = type=http-response,pattern=.,script-path=../scripts/a.js\nc = type=http-response,pattern=.,script-path=../scripts/b.js\n[Map Local]\n^https://example.test data-type=file data=../binary.bin\n", mode.Load())
		case "/scripts/a.js":
			scriptDownloads.Add(1)
			fmt.Fprintf(w, "$done({body:'revision-%d'});", mode.Load())
		case "/scripts/b.js":
			if mode.Load() == 1 {
				http.Error(w, "failed dependency", http.StatusServiceUnavailable)
				return
			}
			if mode.Load() == 7 {
				w.Header().Set("Content-Length", fmt.Sprint(MaxScriptBytes+1))
				return
			}
			if mode.Load() == 8 {
				fmt.Fprint(w, "<html><body>script source error</body></html>")
				return
			}
			fmt.Fprint(w, "$done({});")
		case "/binary.bin":
			w.Write(binaryBody)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	dir := filepath.Join(t.TempDir(), "cache")
	// Credentials and the complete query are part of the cache identity, but
	// neither may appear in a filename or fallback log.
	source := strings.Replace(server.URL, "https://", "https://fixture-user:fixture-password@", 1) + "/entry?token=fixture-token"
	cachedSource := strings.Replace(source, "https://", "https-file://", 1)
	opts := LoadOptions{CacheDir: dir}
	m, err := Load(context.Background(), cachedSource, server.Client(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "revision-0" || len(m.Scripts) != 3 || scriptDownloads.Load() != 1 || !bytes.Equal(m.MapLocals[0].Body, binaryBody) {
		t.Fatalf("unexpected initial module: %#v downloads=%d", m, scriptDownloads.Load())
	}
	redactedSource := strings.Replace(server.URL, "https://", "https-file://", 1)
	if status := m.Status(); status.State != "loaded" || status.Name != "revision-0" || status.Source != redactedSource || status.Scripts != 3 || status.MapLocals != 1 || status.Hostnames != 0 {
		t.Fatalf("unexpected initial load status: %+v", status)
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 1 || len(files[0].Name()) != 69 || strings.Contains(files[0].Name(), "fixture") {
		t.Fatalf("cache filename: %v %v", files, err)
	}
	path := moduleCachePath(dir, source, nil)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("cache permissions: %v %v", info, err)
	}
	var saved moduleCacheSnapshot
	if err := json.Unmarshal(original, &saved); err != nil || !strings.HasSuffix(saved.Module.Location, "/v2/module.sgmodule") {
		t.Fatalf("redirect location not saved: %v %#v", err, saved.Module)
	}
	for _, failure := range []int32{1, 2, 3, 5, 6, 7, 8, 9, 10} {
		t.Run(fmt.Sprint(failure), func(t *testing.T) {
			mode.Store(failure)
			m, err := Load(context.Background(), cachedSource, server.Client(), opts)
			if err != nil {
				t.Fatal(err)
			}
			if m.Name != "revision-0" || m.Scripts[0].Source != "$done({body:'revision-0'});" || !bytes.Equal(m.MapLocals[0].Body, binaryBody) || !hasModuleCacheFallback(m) {
				t.Fatalf("partial refresh escaped snapshot rollback: %#v", m)
			}
			if status := m.Status(); status.State != "cached" || status.Name != "revision-0" || status.Source != redactedSource || status.Scripts != 3 || status.MapLocals != 1 {
				t.Fatalf("status does not describe the restored snapshot: %+v", status)
			}
			now, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(now, original) {
				t.Fatalf("failed refresh replaced the good cache: %v", err)
			}
		})
	}
	mode.Store(4)
	m, err = Load(context.Background(), cachedSource, server.Client(), opts)
	if err != nil || m.Name != "revision-4" || hasModuleCacheFallback(m) {
		t.Fatalf("valid refresh not committed: %v %#v", err, m)
	}
	if status := m.Status(); status.State != "loaded" || status.Name != "revision-4" {
		t.Fatalf("successful refresh still reports a cached module: %+v", status)
	}
	server.Close()
	m, err = Load(context.Background(), cachedSource, server.Client(), opts)
	if err != nil || m.Name != "revision-4" || m.Scripts[0].Source != "$done({body:'revision-4'});" || !bytes.Equal(m.MapLocals[0].Body, binaryBody) || !hasModuleCacheFallback(m) {
		t.Fatalf("offline redirect-relative snapshot failed: %v %#v", err, m)
	}
	for _, line := range m.Warnings {
		if strings.Contains(line, "fixture-password") || strings.Contains(line, "fixture-user") || strings.Contains(line, "fixture-token") || strings.Contains(line, "?token=") {
			t.Fatalf("URL credentials leaked into fallback log: %s", line)
		}
	}
}

func TestModuleCacheSeparatesArgumentChoices(t *testing.T) {
	var offline atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if offline.Load() {
			http.Error(w, "offline", http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path == "/module.sgmodule" {
			fmt.Fprint(w, `#!arguments=language:en,debug:false
[Script]
translate = type=http-response,pattern=.,script-path={{{language}}}.js,argument={{{language}}}:{{{debug}}}
[MITM]
hostname = {{{language}}}.example.com
`)
			return
		}
		fmt.Fprintf(w, "$done({body:%q});", r.URL.Path)
	}))
	defer server.Close()
	dir := t.TempDir()
	source := strings.Replace(server.URL, "http://", "http-file://", 1) + "/module.sgmodule"
	choices := []map[string]string{
		{"language": "zh-CN", "debug": "true"},
		{"language": "en", "debug": "false"},
	}
	for _, isOffline := range []bool{false, true} {
		offline.Store(isOffline)
		for _, arguments := range choices {
			module, err := Load(context.Background(), source, server.Client(), LoadOptions{CacheDir: dir, Arguments: arguments})
			if err != nil {
				t.Fatalf("offline=%t arguments=%v: %v", isOffline, arguments, err)
			}
			language := arguments["language"]
			if len(module.Scripts) != 1 || module.Scripts[0].Source != fmt.Sprintf("$done({body:%q});", "/"+language+".js") ||
				module.Scripts[0].Argument != language+":"+arguments["debug"] ||
				len(module.Hostnames) != 1 || module.Hostnames[0] != strings.ToLower(language)+".example.com" {
				t.Fatalf("argument choices were mixed: %#v", module)
			}
			if hasModuleCacheFallback(module) != isOffline {
				t.Fatalf("offline=%t warnings=%v", isOffline, module.Warnings)
			}
		}
	}
	if _, err := Load(context.Background(), source, server.Client(), LoadOptions{CacheDir: dir, Arguments: map[string]string{"language": "fr"}}); err == nil {
		t.Fatal("offline load used a cache for a different argument choice")
	}
}

func TestModuleRemotePersistenceIsExplicit(t *testing.T) {
	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			var scriptDownloads atomic.Int32
			var dependencyOffline atomic.Bool
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/uncached":
					fmt.Fprint(w, "[MITM]\nhostname=example.test")
				case "/module":
					fmt.Fprintf(w, "[Script]\na=type=http-request,pattern=.,script-path=%s-file://%s/script.js\nb=type=http-response,pattern=.,script-path=script.js\n[Map Local]\n. data-type=file data=data.json", scheme, r.Host)
				case "/script.js":
					scriptDownloads.Add(1)
					if dependencyOffline.Load() {
						http.Error(w, "offline", http.StatusServiceUnavailable)
						return
					}
					fmt.Fprint(w, "$done({});")
				case "/data.json":
					fmt.Fprint(w, `{"cached":true}`)
				default:
					http.NotFound(w, r)
				}
			})
			server := httptest.NewUnstartedServer(handler)
			if scheme == "https" {
				server.StartTLS()
			} else {
				server.Start()
			}
			defer server.Close()
			source := server.URL + "/module"
			cachedSource := strings.Replace(source, "://", "-file://", 1)
			opts := LoadOptions{CacheDir: filepath.Join(t.TempDir(), "cache")}
			if _, err := Load(context.Background(), server.URL+"/uncached", server.Client(), opts); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(opts.CacheDir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("ordinary remote source created cache: %v", err)
			}
			// This module has one explicitly persistent dependency. Its ordinary
			// root and Map Local body must still never be restored from a cache.
			if _, err := Load(context.Background(), source, server.Client(), opts); err != nil {
				t.Fatal(err)
			}
			snapshot, err := readModuleCache(context.Background(), opts.CacheDir, source, nil, false)
			if err != nil || snapshot.Module != nil || len(snapshot.Resources) != 1 {
				t.Fatalf("ordinary remote source cached unmarked resources: %v %#v", err, snapshot)
			}
			dependencyOffline.Store(true)
			if _, err := Load(context.Background(), source, server.Client(), opts); err == nil {
				t.Fatal("ordinary reference reused a persistent reference's cached dependency")
			}
			if scriptDownloads.Load() != 2 {
				t.Fatalf("failed dependency was downloaded again: %d", scriptDownloads.Load())
			}
			dependencyOffline.Store(false)
			if _, err := Load(context.Background(), cachedSource, server.Client(), opts); err != nil {
				t.Fatal(err)
			}
			if scriptDownloads.Load() != 3 {
				t.Fatalf("ordinary and persistent declarations downloaded the same dependency twice: %d", scriptDownloads.Load())
			}
			server.Close()
			m, err := Load(context.Background(), cachedSource, server.Client(), opts)
			if err != nil || !hasModuleCacheFallback(m) || m.Scripts[0].Source != "$done({});" || m.Scripts[1].Source != m.Scripts[0].Source || string(m.MapLocals[0].Body) != `{"cached":true}` {
				t.Fatalf("complete offline module was not restored: %v %#v", err, m)
			}
			if _, err := Load(context.Background(), source, server.Client(), opts); err == nil {
				t.Fatal("ordinary remote source fell back to an existing persistent cache")
			}
		})
	}
}

func TestModuleCachesOnlyExplicitPersistentDependencies(t *testing.T) {
	var failed atomic.Bool
	var currentReads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/module":
			fmt.Fprintf(w, `#!name=current-%t
[Script]
a=type=http-request,pattern=.,script-path=current.js
b=type=http-request,pattern=.,script-path=http-file://%s/fresh-%t.js
c=type=http-response,pattern=.,script-path=http-file://%s/cached.js
d=type=http-response,pattern=.,script-path=http-file://%s/after-%t.js
`, failed.Load(), r.Host, failed.Load(), r.Host, r.Host, failed.Load())
		case "/cached.js":
			if failed.Load() {
				fmt.Fprint(w, "<html>upstream script error</html>")
				return
			}
			fmt.Fprint(w, "$done({body:'cached'});")
		case "/current.js":
			currentReads.Add(1)
			fmt.Fprintf(w, "$done({body:'current-%t'});", failed.Load())
		case "/fresh-false.js", "/fresh-true.js", "/after-false.js", "/after-true.js":
			fmt.Fprintf(w, "$done({body:'%s'});", strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), ".js"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	source := server.URL + "/module"
	opts := LoadOptions{CacheDir: t.TempDir()}
	if _, err := Load(context.Background(), source, server.Client(), opts); err != nil {
		t.Fatal(err)
	}
	snapshot, err := readModuleCache(context.Background(), opts.CacheDir, source, nil, false)
	if err != nil || snapshot.Module != nil || len(snapshot.Resources) != 3 {
		t.Fatalf("cached resources without explicit persistence: %v %#v", err, snapshot)
	}
	failed.Store(true)
	m, err := Load(context.Background(), source, server.Client(), opts)
	if err != nil || m.Name != "current-true" || m.Scripts[0].Source != "$done({body:'current-true'});" || m.Scripts[1].Source != "$done({body:'fresh-true'});" || m.Scripts[2].Source != "$done({body:'cached'});" || m.Scripts[3].Source != "$done({body:'after-true'});" {
		t.Fatalf("dependency fallback lost validated fresh resources: %v %#v", err, m)
	}
	if status := m.Status(); status.State != "cached dependencies" || status.Name != "current-true" || status.Source != server.URL || status.Scripts != 4 || status.MapLocals != 0 {
		t.Fatalf("status does not distinguish dependency fallback from a cached module: %+v", status)
	}
	if currentReads.Load() != 2 {
		t.Fatalf("fallback fetched an already loaded dependency again: %d", currentReads.Load())
	}
	snapshot, err = readModuleCache(context.Background(), opts.CacheDir, source, nil, false)
	if err != nil || len(snapshot.Resources) != 3 || snapshot.Resources[server.URL+"/fresh-true.js"].Data == nil || snapshot.Resources[server.URL+"/after-true.js"].Data == nil {
		t.Fatalf("successful dependency fallback did not retain the new dependency: %v %#v", err, snapshot)
	}
}

func TestModuleCacheLocalModuleKeepsCurrentFiles(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "$done({body:'remote'});")
	}))
	defer server.Close()
	dir := t.TempDir()
	path, script := filepath.Join(dir, "local.sgmodule"), filepath.Join(dir, "local.js")
	module := "#!name=current\n[Script]\na = type=http-request,pattern=.,script-path=local.js\nb = type=http-response,pattern=.,script-path=" + strings.Replace(server.URL, "https://", "https-file://", 1) + "/remote.js\n"
	writeModuleFixture(t, path, module)
	writeModuleFixture(t, script, "$done({body:'local-old'});")
	opts := LoadOptions{CacheDir: filepath.Join(dir, "cache")}
	if _, err := Load(context.Background(), "file://"+path, server.Client(), opts); err != nil {
		t.Fatal(err)
	}
	server.Close()
	writeModuleFixture(t, path, strings.Replace(module, "name=current", "name=changed-current-file", 1))
	writeModuleFixture(t, script, "$done({body:'local-new'});")
	m, err := Load(context.Background(), "file://"+path, server.Client(), opts)
	if err != nil || m.Name != "changed-current-file" || m.Scripts[0].Source != "$done({body:'local-new'});" || m.Scripts[1].Source != "$done({body:'remote'});" || !hasModuleCacheFallback(m) {
		t.Fatalf("local files replaced by snapshot: %v %#v", err, m)
	}
	if snapshot, err := readModuleCache(context.Background(), opts.CacheDir, path, nil, false); err != nil || snapshot.Module != nil || len(snapshot.Resources) != 1 {
		t.Fatalf("local input was stored: %v %#v", err, snapshot)
	}
	writeModuleFixture(t, path, strings.Replace(module, "/remote.js", "/new-dependency.js", 1))
	if _, err := Load(context.Background(), "file://"+path, server.Client(), opts); err == nil {
		t.Fatal("missing new HTTPS dependency was substituted from an unrelated cached URL")
	}
	writeModuleFixture(t, path, "[Script]\nmalformed current file")
	if _, err := Load(context.Background(), "file://"+path, server.Client(), opts); err == nil {
		t.Fatal("invalid current local module was replaced with a cached module")
	}
}

func TestModuleCacheNoCacheCancellationAndWriteFailure(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "[MITM]\nhostname=example.test")
	}))
	defer server.Close()
	source := server.URL + "/module"
	cachedSource := strings.Replace(source, "https://", "https-file://", 1)
	dir := t.TempDir()
	opts := LoadOptions{CacheDir: filepath.Join(dir, "cache")}
	if _, err := Load(context.Background(), cachedSource, server.Client(), opts); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Load(ctx, cachedSource, server.Client(), opts); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation was replaced by cache fallback: %v", err)
	}
	// A regular file cannot act as a cache directory. Fresh valid modules
	// still load and carry a warning describing the persistence failure.
	badDirectory := filepath.Join(dir, "not-a-directory")
	writeModuleFixture(t, badDirectory, "x")
	m, err := Load(context.Background(), cachedSource, server.Client(), LoadOptions{CacheDir: badDirectory})
	if err != nil || len(m.Warnings) == 0 || !strings.Contains(m.Warnings[0], "could not be updated") {
		t.Fatalf("cache write failure prevented valid load: %v %#v", err, m)
	}
	server.Close()
	if _, err := Load(context.Background(), cachedSource, server.Client(), LoadOptions{}); err == nil {
		t.Fatal("Load unexpectedly enabled persistent cache")
	}
	notCreated := filepath.Join(dir, "absent", "cache")
	if _, err := Load(context.Background(), cachedSource, server.Client(), LoadOptions{CacheDir: notCreated}); err == nil {
		t.Fatal("offline source without cache loaded")
	}
	if _, err := os.Stat(notCreated); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reading missing cache created directories: %v", err)
	}
}

func TestModuleCacheRefreshDeadlineDoesNotCancelFallback(t *testing.T) {
	var stall atomic.Bool
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if stall.Load() {
			<-r.Context().Done()
			return
		}
		fmt.Fprint(w, "[MITM]\nhostname=example.test")
	}))
	defer server.Close()
	source := server.URL + "/module"
	cachedSource := strings.Replace(source, "https://", "https-file://", 1)
	opts := LoadOptions{CacheDir: t.TempDir()}
	if _, err := Load(context.Background(), cachedSource, server.Client(), opts); err != nil {
		t.Fatal(err)
	}
	before := requests.Load()
	opts.RefreshDeadline = time.Now().Add(-time.Second)
	m, err := Load(context.Background(), cachedSource, server.Client(), opts)
	if err != nil || !hasModuleCacheFallback(m) || requests.Load() != before {
		t.Fatalf("expired refresh budget prevented immediate fallback: %v %#v", err, m)
	}
	stall.Store(true)
	opts.RefreshDeadline = time.Now().Add(20 * time.Millisecond)
	m, err = Load(context.Background(), cachedSource, server.Client(), opts)
	if err != nil || !hasModuleCacheFallback(m) {
		t.Fatalf("network refresh deadline canceled cache read: %v %#v", err, m)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Load(ctx, cachedSource, server.Client(), opts); !errors.Is(err, context.Canceled) {
		t.Fatalf("caller cancellation ignored: %v", err)
	}
	// The exhausted network budget must not prevent reading a local module
	// without remote dependencies, even when its persistent cache is absent.
	path := filepath.Join(t.TempDir(), "current.sgmodule")
	writeModuleFixture(t, path, "[MITM]\nhostname=local-current.test")
	m, err = Load(context.Background(), "file://"+path, server.Client(), opts)
	if err != nil || len(m.Hostnames) != 1 || m.Hostnames[0] != "local-current.test" {
		t.Fatalf("expired network budget blocked local file: %v %#v", err, m)
	}
}

func TestModuleCacheRejectsUnsafeSnapshots(t *testing.T) {
	source := "https://example.test/module?key=secret"
	base := func() *moduleCacheSnapshot {
		return &moduleCacheSnapshot{
			Version: moduleCacheVersion, Source: source,
			Module:    &moduleCachedResource{Location: source, Data: []byte("[MITM]\nhostname=example.test")},
			Resources: make(map[string]moduleCachedResource),
		}
	}
	for _, test := range []struct {
		name   string
		mutate func(*moduleCacheSnapshot)
	}{
		{"version", func(s *moduleCacheSnapshot) { s.Version++ }},
		{"identity", func(s *moduleCacheSnapshot) { s.Source += "different" }},
		{"remote-local-root", func(s *moduleCacheSnapshot) { s.Module.Location = "/tmp/local.sgmodule" }},
		{"http-root", func(s *moduleCacheSnapshot) { s.Module.Location = "http://example.test/module" }},
		{"local-resource", func(s *moduleCacheSnapshot) {
			s.Resources["file:///tmp/file"] = moduleCachedResource{Location: "file:///tmp/file"}
		}},
		{"oversized-module", func(s *moduleCacheSnapshot) { s.Module.Data = make([]byte, MaxModuleBytes+1) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			snapshot := base()
			test.mutate(snapshot)
			data, err := json.Marshal(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(moduleCachePath(dir, source, nil), data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := readModuleCache(context.Background(), dir, source, nil, true); err == nil {
				t.Fatal("unsafe snapshot was accepted")
			}
		})
	}
	t.Run("permissions-and-symlink", func(t *testing.T) {
		dir := t.TempDir()
		if err := writeModuleCache(context.Background(), dir, base()); err != nil {
			t.Fatal(err)
		}
		path := moduleCachePath(dir, source, nil)
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := readModuleCache(context.Background(), dir, source, nil, true); err == nil {
			t.Fatal("group/world-readable cache accepted")
		}
		if err := os.Chmod(path, 0600); err != nil {
			t.Fatal(err)
		}
		other := t.TempDir()
		if err := os.Symlink(path, moduleCachePath(other, source, nil)); err != nil {
			t.Fatal(err)
		}
		if _, err := readModuleCache(context.Background(), other, source, nil, true); err == nil {
			t.Fatal("symlink cache accepted")
		}
	})
}

func TestModuleCacheCannotEnableRemoteLocalAccess(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "offline", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	source := server.URL + "/module"
	cachedSource := strings.Replace(source, "https://", "https-file://", 1)
	dir := t.TempDir()
	snapshot := &moduleCacheSnapshot{
		Version: moduleCacheVersion, Source: source,
		Module:    &moduleCachedResource{Location: source, Data: []byte("[Script]\na=type=http-request,pattern=.,script-path=file:///etc/passwd")},
		Resources: make(map[string]moduleCachedResource),
	}
	if err := writeModuleCache(context.Background(), dir, snapshot); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(context.Background(), cachedSource, server.Client(), LoadOptions{CacheDir: dir}); err == nil || !strings.Contains(err.Error(), "cannot read local files") {
		t.Fatalf("cached remote module gained local file access: %v", err)
	}
}

func writeModuleFixture(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
}

func hasModuleCacheFallback(m *Module) bool {
	if m == nil {
		return false
	}
	for _, warning := range m.Warnings {
		if strings.Contains(warning, "refresh failed; using ") {
			return true
		}
	}
	return false
}
