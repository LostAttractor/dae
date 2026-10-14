// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestModuleHTTPWarningSurvivesCacheFallback(t *testing.T) {
	for _, localModule := range []bool{false, true} {
		t.Run(map[bool]string{true: "local module HTTP script", false: "HTTP module"}[localModule], func(t *testing.T) {
			var baseURL string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/script.js" {
					fmt.Fprint(w, "$done();")
				} else {
					fmt.Fprintf(w, "[Script]\na = type=generic,script-path=%s/script.js?token=secret\n", baseURL)
				}
			}))
			defer server.Close()
			baseURL = server.URL
			source := baseURL + "/module?token=secret"
			if localModule {
				path := filepath.Join(t.TempDir(), "module.sgmodule")
				contents := fmt.Sprintf("[Script]\na = type=generic,script-path=%s/script.js?token=secret\n", baseURL)
				if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
					t.Fatal(err)
				}
				source = "file://" + path
			}
			options := LoadOptions{CacheDir: t.TempDir()}
			for _, offline := range []bool{false, true} {
				if offline {
					server.Close()
				}
				module, err := Load(t.Context(), source, server.Client(), options)
				if err != nil {
					t.Fatal(err)
				}
				var count int
				for _, warning := range module.Warnings {
					if strings.Contains(warning, "unencrypted HTTP") {
						count++
					}
					if strings.Contains(warning, "secret") || strings.Contains(warning, "script.js") {
						t.Fatalf("warning exposed URL path or token: %s", warning)
					}
				}
				if count != 1 || hasModuleCacheFallback(module) != offline {
					t.Fatalf("offline=%v: warnings=%v", offline, module.Warnings)
				}
			}
		})
	}
}

func TestModuleHTTPSAndDowngradeProtection(t *testing.T) {
	var insecureRequests atomic.Int32
	insecure := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		insecureRequests.Add(1)
		fmt.Fprint(w, "$done();")
	}))
	defer insecure.Close()
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/module":
			fmt.Fprint(w, "[Script]\na = type=generic,script-path=script.js\n")
		case "/script.js":
			fmt.Fprint(w, "$done();")
		case "/bad-dependency":
			fmt.Fprintf(w, "[Script]\na = type=generic,script-path=%s/script.js\n", insecure.URL)
		case "/bad-module-redirect", "/bad-script-redirect":
			http.Redirect(w, r, insecure.URL+"/script.js", http.StatusFound)
		case "/redirect-dependency":
			fmt.Fprint(w, "[Script]\na = type=generic,script-path=bad-script-redirect\n")
		}
	}))
	defer secure.Close()
	module, err := Load(t.Context(), secure.URL+"/module", secure.Client(), LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(module.Warnings) != 0 {
		t.Fatalf("secure source warned: %v", module.Warnings)
	}
	for _, path := range []string{"/bad-dependency", "/bad-module-redirect", "/redirect-dependency"} {
		if _, err := Load(t.Context(), secure.URL+path, secure.Client(), LoadOptions{}); err == nil || !strings.Contains(err.Error(), "downgrade") {
			t.Fatalf("HTTPS downgrade %s: %v", path, err)
		}
	}
	if insecureRequests.Load() != 0 {
		t.Fatal("HTTPS downgrade reached HTTP server")
	}
	entry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, secure.URL+"/module", http.StatusFound)
	}))
	defer entry.Close()
	module, err = Load(t.Context(), entry.URL+"/entry", secure.Client(), LoadOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(module.Warnings) != 1 || !strings.Contains(module.Warnings[0], "unencrypted HTTP") {
		t.Fatalf("HTTP-to-HTTPS redirect hid insecure first hop: %v", module.Warnings)
	}
}
