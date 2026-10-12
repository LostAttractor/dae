// SPDX-License-Identifier: AGPL-3.0-only

package webui

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAssetRepresentations(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "assets"), 0755); err != nil {
		t.Fatal(err)
	}
	const asset = "/assets/app-Abcd123_.js"
	const body = "export const sample = 'traffic';\n"
	for _, name := range []string{asset, "/index.html", "/plain.js"} {
		var zipped bytes.Buffer
		writer := gzip.NewWriter(&zipped)
		if _, err := writer.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(dir, name)
		if err := os.WriteFile(file, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file+".gz", zipped.Bytes(), 0644); err != nil {
			t.Fatal(err)
		}
	}
	handler := Handler(dir)
	for _, test := range []struct {
		name, accept string
		compressed   bool
		status       int
	}{
		{"identity", "", false, 200},
		{"gzip", "gzip", true, 200},
		{"browser", "gzip, deflate, br", true, 200},
		{"case and whitespace", "GZip ; q=1", true, 200},
		{"wildcard", "*", true, 200},
		{"explicit refusal", "gzip;q=0, *;q=1", false, 200},
		{"prefer identity", "gzip;q=0.5, identity;q=1", false, 200},
		{"prefer gzip", "gzip;q=0.5, identity;q=0.1", true, 200},
		{"gzip only", "gzip, identity;q=0", true, 200},
		{"identity exception", "*;q=0, identity", false, 200},
		{"bad quality", "gzip;q=broken", false, 200},
		{"nonfinite quality", "gzip;q=NaN", false, 200},
		{"out of range quality", "gzip;q=2", false, 200},
		{"no supported encoding", "br, identity;q=0", false, 406},
		{"refuse all", "*;q=0", false, 406},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, asset, nil)
			request.Header.Set("Accept-Encoding", test.accept)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, request)
			if w.Code != test.status || (w.Header().Get("Content-Encoding") == "gzip") != test.compressed {
				t.Fatalf("response: %d %v", w.Code, w.Header())
			}
			if w.Header().Get("Vary") != "Accept-Encoding" {
				t.Fatal("representations must vary by accepted encoding")
			}
			if test.status != 200 {
				if w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("errors must not be cached")
				}
				return
			}
			if w.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" || !strings.Contains(w.Header().Get("Content-Type"), "javascript") {
				t.Fatalf("asset headers: %v", w.Header())
			}
			got := w.Body.Bytes()
			if test.compressed {
				reader, err := gzip.NewReader(bytes.NewReader(got))
				if err != nil {
					t.Fatal(err)
				}
				defer reader.Close()
				got, err = io.ReadAll(reader)
				if err != nil {
					t.Fatal(err)
				}
			}
			if string(got) != body {
				t.Fatalf("decoded body = %q", got)
			}
		})
	}
	for _, test := range []struct {
		name, method, path, accept, rangeHeader, etag string
		status                                        int
	}{
		{"head", "HEAD", asset, "gzip", "", "", 200},
		{"revalidate", "GET", asset, "gzip", "", `W/"app-Abcd123_.js"`, 304},
		{"identity range", "GET", asset, "", "bytes=0-5", "", 206},
		{"gzip range", "GET", asset, "gzip", "bytes=0-5", "", 200},
		{"gzip multipart range", "GET", asset, "gzip", "bytes=0-2,4-5", "", 200},
		{"gzip out of bounds range", "GET", asset, "gzip", "bytes=999-", "", 200},
		{"gzip-only range", "GET", asset, "gzip, identity;q=0", "bytes=0-2,4-5", "", 200},
		{"HTML", "GET", "/", "gzip", "", "", 200},
		{"unhashed", "GET", "/plain.js", "gzip", "", "", 200},
		{"index redirect", "GET", "/index.html", "gzip", "", "", 301},
		{"file redirect", "GET", asset + "/", "gzip", "", "", 301},
		{"missing", "GET", "/assets/missing-Abcd123_.js", "gzip", "", "", 404},
		{"method", "POST", asset, "gzip", "", "", 405},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(test.method, test.path, nil)
			r.Header.Set("Accept-Encoding", test.accept)
			r.Header.Set("Range", test.rangeHeader)
			r.Header.Set("If-None-Match", test.etag)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != test.status {
				t.Fatalf("status = %d: %s", w.Code, w.Body.String())
			}
			if (test.method == "HEAD" || test.status == 304) && w.Body.Len() != 0 {
				t.Fatal("HEAD/304 response has a body")
			}
			if test.status == 206 && (w.Body.String() != "export" || w.Header().Get("Content-Encoding") != "") {
				t.Fatalf("incorrect byte range: %v %q", w.Header(), w.Body.String())
			}
			if test.status == 200 && test.rangeHeader != "" {
				if w.Header().Get("Content-Encoding") != "gzip" {
					t.Fatal("expected a complete gzip representation")
				}
				reader, err := gzip.NewReader(w.Body)
				if err != nil {
					t.Fatal(err)
				}
				defer reader.Close()
				decoded, err := io.ReadAll(reader)
				if err != nil || string(decoded) != body {
					t.Fatalf("compressed range response mismatch: %q, %v", decoded, err)
				}
			}
			if test.path != asset && strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
				t.Fatal("only successful content-hashed assets may be cached")
			}
			if test.status == 200 && test.path != asset && w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("HTML and unhashed files must stay fresh")
			}
		})
	}

	// Editing an external file invalidates an older sidecar; removing the file
	// must not leave its compressed representation publicly reachable via its URL.
	index := filepath.Join(dir, "index.html")
	if err := os.WriteFile(index, []byte("updated"), 0644); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(index, future, future); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "/", nil)
	request.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, request)
	if w.Code != 200 || w.Body.String() != "updated" || w.Header().Get("Content-Encoding") != "" {
		t.Fatal("served stale compressed HTML")
	}
	if err := os.Remove(index); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, request)
	if w.Header().Get("Content-Encoding") != "" || strings.Contains(w.Body.String(), body) {
		t.Fatal("served an orphaned sidecar")
	}
}
