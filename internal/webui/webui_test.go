// SPDX-License-Identifier: AGPL-3.0-only

package webui

import (
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
