// SPDX-License-Identifier: AGPL-3.0-only

package resource

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReadLocalBinaryAndSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "body.bin")
	want := []byte{' ', 0, 255, '\n', ' '}
	if err := os.WriteFile(path, want, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "current.bin")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	for _, location := range []string{path, link} {
		result, err := Read(context.Background(), nil, Source{Location: location}, ReadOptions{MaxBytes: int64(len(want))})
		if err != nil || !bytes.Equal(result.Data, want) || result.Location != location {
			t.Fatalf("Read(%q) = %#v, %v", location, result, err)
		}
		if _, err := Read(context.Background(), nil, Source{Location: location}, ReadOptions{MaxBytes: int64(len(want) - 1)}); err == nil {
			t.Fatal("accepted an oversized local resource")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Read(ctx, nil, Source{Location: path}, ReadOptions{MaxBytes: 100}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled local read returned %v", err)
	}
}

func TestReadRejectsNonRegularFilesWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	pipe := filepath.Join(dir, "pipe")
	if err := unix.Mkfifo(pipe, 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, pipe} {
		if _, err := Read(context.Background(), nil, Source{Location: path}, ReadOptions{MaxBytes: 100}); err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("Read(%q) returned %v", path, err)
		}
	}
}

func TestReadHTTPPreservesClientAndFinalLocation(t *testing.T) {
	const payload = " \x00binary\xff\n "
	var userAgent string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/module" {
			http.Redirect(w, r, "/final/module?token=value#fragment", http.StatusFound)
			return
		}
		userAgent = r.UserAgent()
		w.WriteHeader(http.StatusPartialContent)
		_, _ = io.WriteString(w, payload)
	}))
	defer server.Close()
	redirects := 0
	client := server.Client()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		redirects++
		return nil
	}
	source, err := Parse(server.URL+"/module", "")
	if err != nil {
		t.Fatal(err)
	}
	result, err := Read(context.Background(), client, source, ReadOptions{MaxBytes: 100, UserAgent: "dae-resource-test"})
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Data) != payload || result.Location != server.URL+"/final/module?token=value" || redirects != 1 || userAgent != "dae-resource-test" {
		t.Fatalf("unexpected result %#v, redirects=%d userAgent=%q", result, redirects, userAgent)
	}
	if err := client.CheckRedirect(nil, nil); err != nil || redirects != 2 {
		t.Fatalf("Read replaced the caller's redirect callback: %v, %d", err, redirects)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestReadHTTPRejectsStatusAndOversizedBodies(t *testing.T) {
	for _, test := range []struct {
		name          string
		status        int
		contentLength int64
		body          string
	}{
		{"status", http.StatusBadGateway, 0, ""},
		{"known size", http.StatusOK, 5, "12345"},
		{"stream size", http.StatusOK, -1, "12345"},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: test.status, ContentLength: test.contentLength, Body: io.NopCloser(strings.NewReader(test.body)), Request: req}, nil
			})}
			if _, err := Read(context.Background(), client, Source{Location: "https://example.com/resource"}, ReadOptions{MaxBytes: 4}); err == nil {
				t.Fatal("accepted an unsuccessful or oversized response")
			}
		})
	}
}

func TestReadHTTPRedirectBoundaries(t *testing.T) {
	for _, test := range []struct {
		name, source, target string
	}{
		{"HTTPS downgrade", "https://example.com/source", "http://example.com/target"},
		{"local file", "http://example.com/source", "file:///etc/passwd"},
		{"persistent scheme", "http://example.com/source", "https-file://example.com/target"},
	} {
		t.Run(test.name, func(t *testing.T) {
			requests := 0
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				requests++
				return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{test.target}}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
			})}
			if _, err := Read(context.Background(), client, Source{Location: test.source}, ReadOptions{MaxBytes: 100}); err == nil {
				t.Fatal("accepted a forbidden redirect")
			}
			if requests != 1 {
				t.Fatalf("followed a forbidden redirect: %d requests", requests)
			}
		})
	}
}

func TestReadPreservesTransportErrorsAndCancellation(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, context.Canceled
	})}
	_, err := Read(context.Background(), client, Source{Location: "https://user:password@example.com/path-secret?query-secret"}, ReadOptions{MaxBytes: 100})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("lost cancellation: %v", err)
	}
	for _, secret := range []string{"user", "password", "path-secret", "query-secret"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("diagnostic leaked %q: %v", secret, err)
		}
	}
}
