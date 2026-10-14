// SPDX-License-Identifier: AGPL-3.0-only

package webui

import (
	"bytes"
	"compress/gzip"
	"io"
	"io/fs"
	"net/http/httptest"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestExternalBundleDirectoryReplacement(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bundle")
	handler := Handler(dir)
	for _, body := range []string{"old bundle", "new bundle"} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
		if w.Code != 200 || w.Body.String() != body {
			t.Fatalf("replacement bundle unavailable: %d %s", w.Code, w.Body.String())
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
