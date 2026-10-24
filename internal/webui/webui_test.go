// SPDX-License-Identifier: AGPL-3.0-only

//go:build !no_webui

package webui

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json/v2"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

func writeMetadata(t *testing.T, dir, origin string) {
	t.Helper()
	data, err := json.Marshal(map[string]string{"api_origin": origin})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dae-web.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestEmbeddedBundle(t *testing.T) {
	handler := Handler("")
	if _, err := fs.Stat(assets, "index.html"); err != nil {
		t.Fatal(err)
	}
	if err := fs.WalkDir(assets, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		t.Run(name, func(t *testing.T) {
			requestPath := "/" + name
			if path.Base(name) == "index.html" {
				requestPath = strings.TrimSuffix(requestPath, "index.html")
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest("GET", (&url.URL{Path: requestPath}).String(), nil))
			data, err := fs.ReadFile(assets, name)
			if err != nil || w.Code != 200 || w.Body.String() != string(data) {
				t.Fatalf("bundle mismatch: %v, %d", err, w.Code)
			}
			if !strings.Contains(w.Header().Get("Content-Security-Policy"), "connect-src 'self'") {
				t.Error("missing origin policy")
			}
			if _, err := fs.Stat(assets, name+".gz"); err == nil {
				request := httptest.NewRequest("GET", (&url.URL{Path: requestPath}).String(), nil)
				request.Header.Set("Accept-Encoding", "gzip")
				w = httptest.NewRecorder()
				handler.ServeHTTP(w, request)
				if w.Code != 200 || w.Header().Get("Content-Encoding") != "gzip" {
					t.Fatalf("compressed bundle response: %d %v", w.Code, w.Header())
				}
				reader, err := gzip.NewReader(w.Body)
				if err != nil {
					t.Fatal(err)
				}
				defer reader.Close()
				decoded, err := io.ReadAll(reader)
				if err != nil || !bytes.Equal(decoded, data) {
					t.Fatalf("compressed bundle mismatch: %v", err)
				}
			}
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestExternalBundleUpdatesWithoutRebuilding(t *testing.T) {
	dir := t.TempDir()
	writeMetadata(t, dir, "")
	if err := os.WriteFile(filepath.Join(dir, "removed.js"), []byte("// old bundle"), 0644); err != nil {
		t.Fatal(err)
	}
	handler := Handler(dir)
	for _, body := range []string{"first bundle", "updated bundle"} {
		if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
		if w.Code != 200 || w.Body.String() != body {
			t.Fatalf("stale external bundle: %d %s", w.Code, w.Body.String())
		}
	}
	if err := os.Remove(filepath.Join(dir, "removed.js")); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/removed.js", nil))
	if w.Code != 404 {
		t.Fatal("missing external asset did not return 404")
	}
}

func TestExternalBundleConfinesSymlinks(t *testing.T) {
	dir := t.TempDir()
	writeMetadata(t, dir, "")
	outside := t.TempDir()
	for _, file := range []struct{ path, content string }{
		{filepath.Join(dir, "index.html"), "public asset"},
		{filepath.Join(outside, "secret"), "private content"},
	} {
		if err := os.WriteFile(file.path, []byte(file.content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range map[string]string{
		"inside.html":   "index.html",
		"escape":        filepath.Join(outside, "secret"),
		"directory":     outside,
		"index.html.gz": filepath.Join(outside, "secret"),
	} {
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	handler := Handler(dir)
	for _, path := range []string{"/escape", "/directory/secret", "/directory/", "/", "/inside.html"} {
		t.Run(path, func(t *testing.T) {
			r := httptest.NewRequest("GET", path, nil)
			r.Header.Set("Accept-Encoding", "gzip")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if strings.Contains(w.Body.String(), "private content") || strings.Contains(w.Body.String(), "secret") {
				t.Fatalf("external file exposed: %d %s", w.Code, w.Body.String())
			}
			if path == "/" || path == "/inside.html" {
				if w.Code != 200 || w.Body.String() != "public asset" || w.Header().Get("Content-Encoding") != "" {
					t.Fatalf("in-root asset unavailable: %d %s", w.Code, w.Body.String())
				}
			} else if w.Code == 200 {
				t.Fatal("escaping symlink was served")
			}
		})
	}
}

func TestBundleMetadataPolicy(t *testing.T) {
	for _, test := range []struct{ origin, source string }{
		{"", ""},
		{"https://api.example:9080", "https://api.example:9080/api/"},
		{"https://192.0.2.1", "https://192.0.2.1/api/"},
		{"https://[2001:db8::1]:9080", "https://*:9080/api/"},
		{"https://[::1]", "https://*:443/api/"},
	} {
		t.Run(test.origin, func(t *testing.T) {
			dir := t.TempDir()
			writeMetadata(t, dir, test.origin)
			if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("bundle"), 0600); err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("GET", "/", nil)
			r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("192.0.2.2"), Port: 9081}))
			w := httptest.NewRecorder()
			Handler(dir, netip.MustParseAddrPort("203.0.113.254:443"), netip.MustParseAddrPort("[2001:db8::254]:444")).ServeHTTP(w, r)
			policy := w.Header().Get("Content-Security-Policy")
			if w.Code != 200 || !strings.Contains(policy, "connect-src 'self'") || !strings.Contains(policy, test.source) {
				t.Fatalf("bundle policy: %d %s", w.Code, policy)
			}
			for _, source := range []string{"https://192.0.2.2:9081/api/", "https://203.0.113.254:443/test/", "https://*:444/test/"} {
				if !strings.Contains(policy, source) {
					t.Fatalf("missing proof source %s: %s", source, policy)
				}
			}
			if strings.Contains(policy, " https: ") || strings.Contains(policy, " https:;") || strings.Contains(policy, "https://[") {
				t.Fatalf("unbounded or unsupported source: %s", policy)
			}
		})
	}
}

func TestBundleMetadataFailsClosed(t *testing.T) {
	for _, metadata := range []string{
		"", "{}", "null", `{"api_origin":null}`, `{"api_origin":1}`, `{"api_origin":"","other":""}`,
		`{"api_origin":"","api_origin":"https://api.example"}`,
		`{"api_origin":"http://api.example"}`, `{"api_origin":"https://api.example/api"}`,
		`{"api_origin":"https://api.example/"}`, `{"api_origin":"https://user:secret@api.example"}`,
		`{"api_origin":"https://api.example?x=1"}`, `{"api_origin":"https://api.example#fragment"}`,
		`{"api_origin":"https://api.example;script-src *"}`, `{"api_origin":"https://API.example"}`,
		`{"api_origin":"https://api.example:443"}`, `{"api_origin":"https://api.example:0"}`, `{"api_origin":"https://api.example:65536"}`,
		`{"api_origin":"https://[not-an-ip]"}`, `{"api_origin":"https://[fe80::1%25eth0]"}`, `{"api_origin":"https://[2001:0DB8::1]"}`,
		`{"api_origin":"https://api.example:"}`, `{"api_origin":"https://api.example:09080"}`, strings.Repeat(" ", 4097),
	} {
		t.Run(metadata, func(t *testing.T) {
			dir := t.TempDir()
			if metadata != "" {
				if err := os.WriteFile(filepath.Join(dir, "dae-web.json"), []byte(metadata), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("must not serve"), 0600); err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			Handler(dir).ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
			if w.Code != 503 || strings.Contains(w.Body.String(), "must not serve") || strings.Contains(w.Header().Get("Content-Security-Policy"), "connect-src") {
				t.Fatalf("invalid bundle served: %d %v %s", w.Code, w.Header(), w.Body.String())
			}
		})
	}
	dir, outside := t.TempDir(), t.TempDir()
	writeMetadata(t, outside, "https://api.example")
	if err := os.Symlink(filepath.Join(outside, "dae-web.json"), filepath.Join(dir, "dae-web.json")); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	Handler(dir).ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 503 {
		t.Fatal("metadata escaped the bundle root")
	}
}

func TestExternalBundleDirectoryReplacement(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundle")
	handler := Handler(dir)
	for _, body := range []string{"old bundle", "new bundle"} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		origin := "https://old.example"
		if body == "new bundle" {
			origin = "https://new.example"
		}
		writeMetadata(t, dir, origin)
		if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
		if w.Code != 200 || w.Body.String() != body {
			t.Fatalf("replacement bundle unavailable: %d %s", w.Code, w.Body.String())
		}
		if policy := w.Header().Get("Content-Security-Policy"); !strings.Contains(policy, origin+"/api/") || body == "new bundle" && strings.Contains(policy, "old.example") {
			t.Fatalf("stale bundle policy: %s", policy)
		}
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 503 {
		t.Fatalf("missing external root: status %d", w.Code)
	}
}
