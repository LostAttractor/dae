// SPDX-License-Identifier: AGPL-3.0-only

package webui

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIndependentBundle(t *testing.T) {
	dir := t.TempDir()
	if err := Export(dir); err != nil {
		t.Fatal(err)
	}
	handler := Handler("")
	for _, path := range []string{"/", "/app.js", "/api.js", "/style.css"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		name := strings.TrimPrefix(path, "/")
		if name == "" {
			name = "index.html"
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || w.Code != 200 || w.Body.String() != string(data) {
			t.Fatalf("bundle mismatch %s: %v, %d", name, err, w.Code)
		}
		if !strings.Contains(w.Header().Get("Content-Security-Policy"), "connect-src 'self'") {
			t.Error("missing origin policy")
		}
	}
}

func TestExternalBundleUpdatesWithoutRebuilding(t *testing.T) {
	dir := t.TempDir()
	if err := Export(dir); err != nil {
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
	if err := os.Remove(filepath.Join(dir, "api.js")); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/api.js", nil))
	if w.Code != 404 {
		t.Fatal("missing external asset did not return 404")
	}
}
