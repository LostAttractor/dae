// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"bytes"
	"context"
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
	for _, serve := range []func(http.Handler) *httptest.Server{httptest.NewServer, httptest.NewTLSServer} {
		var mode atomic.Int32
		var downloads atomic.Int32
		binary := []byte{0, 255, 254, 128, 'x'}
		server := serve(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/entry":
				http.Redirect(w, r, "/v2/module", http.StatusFound)
			case "/v2/module":
				switch mode.Load() {
				case 2:
					fmt.Fprint(w, "[Script]\ninvalid script")
					return
				case 3:
					w.Header().Set("Content-Length", fmt.Sprint(MaxModuleBytes+1))
					return
				case 4:
					fmt.Fprint(w, "<html>error</html>")
					return
				case 5:
					fmt.Fprint(w, "Service Unavailable")
					return
				case 6:
					return
				}
				fmt.Fprintf(w, "#!name=revision-%d\n[Script]\na=type=http-request,pattern=.,script-path=../a.js\nb=type=http-response,pattern=.,script-path=../a.js\nc=type=http-response,pattern=.,script-path=../b.js\n[Map Local]\n^https://example.test data-type=file data=../binary\n", mode.Load())
			case "/a.js":
				downloads.Add(1)
				fmt.Fprintf(w, "$done({body:'revision-%d'});", mode.Load())
			case "/b.js":
				switch mode.Load() {
				case 1:
					http.Error(w, "offline", 503)
				case 7:
					w.Header().Set("Content-Length", fmt.Sprint(MaxScriptBytes+1))
				case 8:
					fmt.Fprint(w, "<html>error</html>")
				default:
					fmt.Fprint(w, "$done();")
				}
			case "/binary":
				w.Write(binary)
			default:
				http.NotFound(w, r)
			}
		}))
		t.Cleanup(server.Close)
		source := server.URL + "/entry?token=secret"
		opts := LoadOptions{CacheDir: t.TempDir()}
		m, err := Load(t.Context(), source, server.Client(), opts)
		if err != nil || hasModuleCacheFallback(m) || downloads.Load() != 1 {
			t.Fatalf("initial load/deduplication: %+v %v", m, err)
		}
		files, _ := filepath.Glob(filepath.Join(opts.CacheDir, "*.json"))
		if len(files) != 1 {
			t.Fatalf("cache files: %v", files)
		}
		original, _ := os.ReadFile(files[0])
		for state := int32(1); state <= 8; state++ {
			mode.Store(state)
			m, err := Load(t.Context(), source, server.Client(), opts)
			if err != nil || !hasModuleCacheFallback(m) || m.Name != "revision-0" || m.Scripts[0].Source != "$done({body:'revision-0'});" || m.Scripts[1].Source != m.Scripts[0].Source || !bytes.Equal(m.MapLocals[0].Body, binary) {
				t.Fatalf("state %d mixed revisions or lost binary: %+v %v", state, m, err)
			}
			if strings.Contains(strings.Join(m.Warnings, " "), "secret") {
				t.Fatal("warning exposed URL token")
			}
			data, _ := os.ReadFile(files[0])
			if !bytes.Equal(data, original) {
				t.Fatal("failed refresh replaced complete cache")
			}
		}
		mode.Store(9)
		m, err = Load(t.Context(), source, server.Client(), opts)
		if err != nil || hasModuleCacheFallback(m) || m.Name != "revision-9" {
			t.Fatalf("successful refresh: %+v %v", m, err)
		}
		server.Close()
		m, err = Load(t.Context(), source, server.Client(), opts)
		if err != nil || m.Name != "revision-9" || !hasModuleCacheFallback(m) {
			t.Fatalf("offline refresh: %+v %v", m, err)
		}
		if _, err := Load(t.Context(), source, server.Client(), LoadOptions{}); err == nil {
			t.Fatal("disabled cache fell back")
		}
	}
}

func TestModuleCacheIdentityIncludesArguments(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/module" {
			fmt.Fprint(w, "#!arguments=body:default,other:default\n[Map Local]\n^https://example.test data-type=text data=\"{{{body}}}\"\n")
		}
	}))
	defer server.Close()
	opts := LoadOptions{CacheDir: t.TempDir(), Arguments: map[string]string{"body": "first", "other": "a"}}
	if _, err := Load(t.Context(), server.URL+"/module", server.Client(), opts); err != nil {
		t.Fatal(err)
	}
	server.Close()
	opts.Arguments = map[string]string{"other": "a", "body": "first"}
	m, err := Load(t.Context(), server.URL+"/module", server.Client(), opts)
	if err != nil || string(m.MapLocals[0].Body) != "first" {
		t.Fatalf("equivalent arguments did not share cache: %+v %v", m, err)
	}
	opts.Arguments["body"] = "second"
	if _, err := Load(t.Context(), server.URL+"/module", server.Client(), opts); err == nil {
		t.Fatal("different arguments reused cache")
	}
}

func TestModuleCacheLocalModuleKeepsCurrentFiles(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "$done({body:'remote'});")
	}))
	defer server.Close()
	dir := t.TempDir()
	path, script := filepath.Join(dir, "local.sgmodule"), filepath.Join(dir, "local.js")
	module := "#!name=current\n[Script]\na=type=http-request,pattern=.,script-path=local.js\nb=type=http-response,pattern=.,script-path=" + server.URL + "/remote.js\n"
	writeModuleFixture(t, path, module)
	writeModuleFixture(t, script, "$done({body:'local-old'});")
	opts := LoadOptions{CacheDir: filepath.Join(dir, "cache")}
	if _, err := Load(t.Context(), "file://"+path, server.Client(), opts); err != nil {
		t.Fatal(err)
	}
	server.Close()
	writeModuleFixture(t, path, strings.Replace(module, "name=current", "name=changed", 1))
	writeModuleFixture(t, script, "$done({body:'local-new'});")
	m, err := Load(t.Context(), "file://"+path, server.Client(), opts)
	if err != nil || m.Name != "changed" || m.Scripts[0].Source != "$done({body:'local-new'});" || m.Scripts[1].Source != "$done({body:'remote'});" || m.Status().State != "cached dependencies" {
		t.Fatalf("local files replaced by snapshot: %+v %v", m, err)
	}
	writeModuleFixture(t, path, strings.Replace(module, "/remote.js", "/new.js", 1))
	if _, err := Load(t.Context(), "file://"+path, server.Client(), opts); err == nil {
		t.Fatal("new dependency substituted with unrelated URL")
	}
	writeModuleFixture(t, path, "[Script]\nmalformed current file")
	if _, err := Load(t.Context(), "file://"+path, server.Client(), opts); err == nil {
		t.Fatal("invalid local module replaced with cached input")
	}
}

func TestModuleCacheRefreshDeadlineAndCancellation(t *testing.T) {
	var stall atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if stall.Load() {
			<-r.Context().Done()
			return
		}
		fmt.Fprint(w, "[MITM]\nhostname=example.test")
	}))
	defer server.Close()
	opts := LoadOptions{CacheDir: t.TempDir()}
	if _, err := Load(t.Context(), server.URL, server.Client(), opts); err != nil {
		t.Fatal(err)
	}
	stall.Store(true)
	for _, timeout := range []time.Duration{-time.Second, 20 * time.Millisecond} {
		opts.RefreshDeadline = time.Now().Add(timeout)
		m, err := Load(t.Context(), server.URL, server.Client(), opts)
		if err != nil || !hasModuleCacheFallback(m) {
			t.Fatalf("refresh timeout canceled cache read: %+v %v", m, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Load(ctx, server.URL, server.Client(), opts); !errors.Is(err, context.Canceled) {
		t.Fatalf("caller cancellation ignored: %v", err)
	}
	path := filepath.Join(t.TempDir(), "local.sgmodule")
	writeModuleFixture(t, path, "[MITM]\nhostname=local.test")
	if _, err := Load(t.Context(), "file://"+path, server.Client(), opts); err != nil {
		t.Fatalf("network budget blocked local files: %v", err)
	}
}

func writeModuleFixture(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
}

func hasModuleCacheFallback(m *Module) bool {
	return m != nil && strings.Contains(strings.Join(m.Warnings, "\n"), "refresh failed; using ")
}
