// SPDX-License-Identifier: AGPL-3.0-only
//go:build no_webui

package webui

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestOmittedWebCannotServeExternalFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("web"), 0600); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	Handler(root).ServeHTTP(response, httptest.NewRequest("GET", "http://127.0.0.1/", nil))
	if response.Code != 404 {
		t.Fatal("web exposed in API-only build")
	}
}
