/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package subscription

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	componentoutbound "github.com/daeuniverse/dae/component/outbound"
)

func TestResolveSubscriptionAsSIP008EncodesUserinfo(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		password      string
		wantUnencoded bool
	}{
		{name: "legacy Stream", method: "aes-256-cfb", password: "stream-password"},
		{name: "legacy AEAD", method: "aes-256-gcm", password: "legacy:/password"},
		{name: "AEAD 2022", method: "2022-blake3-aes-256-gcm", password: "RCF/0OOYmo6crue3LwlEyD8izLAbuUuyPic/vasJH/o=", wantUnencoded: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := json.Marshal(sip008{
				Version: 1,
				Servers: []sip008Server{{
					Remarks:    "test",
					Server:     "127.0.0.1",
					ServerPort: 443,
					Password:   tt.password,
					Method:     tt.method,
				}},
			})
			if err != nil {
				t.Fatal(err)
			}

			nodes, err := ResolveSubscriptionAsSIP008(payload)
			if err != nil {
				t.Fatal(err)
			}
			if len(nodes) != 1 {
				t.Fatalf("got %d nodes, want 1", len(nodes))
			}
			u, err := url.Parse(nodes[0])
			if err != nil {
				t.Fatal(err)
			}
			if tt.wantUnencoded {
				password, ok := u.User.Password()
				if !ok || u.User.Username() != tt.method || password != tt.password {
					t.Fatalf("userinfo = %q, want %q", u.User.String(), url.UserPassword(tt.method, tt.password))
				}
				if got, want := u.User.String(), url.UserPassword(tt.method, tt.password).String(); got != want {
					t.Fatalf("escaped userinfo = %q, want %q", got, want)
				}
				return
			}

			if _, hasPassword := u.User.Password(); hasPassword {
				t.Fatalf("legacy userinfo %q is not Base64URL", u.User.String())
			}
			decoded, err := base64.RawURLEncoding.DecodeString(u.User.Username())
			if err != nil {
				t.Fatal(err)
			}
			if got, want := string(decoded), tt.method+":"+tt.password; got != want {
				t.Fatalf("decoded userinfo = %q, want %q", got, want)
			}
		})
	}
}

func TestResolveSubscriptionAsSIP008EncodesPlugin(t *testing.T) {
	tests := []struct {
		name       string
		plugin     string
		pluginOpts string
		wantPlugin string
		wantPath   string
	}{
		{name: "no plugin"},
		{name: "options without plugin are ignored", pluginOpts: "obfs=http"},
		{name: "plugin without options", plugin: "v2ray-plugin", wantPlugin: "v2ray-plugin", wantPath: "/"},
		{name: "plugin with options", plugin: "obfs-local", pluginOpts: "obfs=http;obfs-host=example.com", wantPlugin: "obfs-local;obfs=http;obfs-host=example.com", wantPath: "/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := json.Marshal(sip008{
				Version: 1,
				Servers: []sip008Server{{
					Remarks:    "test",
					Server:     "127.0.0.1",
					ServerPort: 443,
					Password:   "password",
					Method:     "aes-256-gcm",
					Plugin:     tt.plugin,
					PluginOpts: tt.pluginOpts,
				}},
			})
			if err != nil {
				t.Fatal(err)
			}

			nodes, err := ResolveSubscriptionAsSIP008(payload)
			if err != nil {
				t.Fatal(err)
			}
			if len(nodes) != 1 {
				t.Fatalf("got %d nodes, want 1", len(nodes))
			}
			u, err := url.Parse(nodes[0])
			if err != nil {
				t.Fatal(err)
			}
			if got := u.Query().Get("plugin"); got != tt.wantPlugin {
				t.Fatalf("plugin = %q, want %q", got, tt.wantPlugin)
			}
			if got := u.Path; got != tt.wantPath {
				t.Fatalf("path = %q, want %q", got, tt.wantPath)
			}
			if tt.wantPlugin == "" && u.RawQuery != "" {
				t.Fatalf("empty plugin produced query %q", u.RawQuery)
			}
			if tt.plugin != "" {
				if err := componentoutbound.ValidateNodeLink(nodes[0]); err != nil {
					t.Fatalf("downstream rejected generated SIP002 link: %v", err)
				}
			}
		})
	}
}

func TestResolveSubscriptionRejectsTooManyNodes(t *testing.T) {
	servers := make([]sip008Server, maxSubscriptionNodes+1)
	payload, err := json.Marshal(sip008{Version: 1, Servers: servers})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveSubscriptionAsSIP008(payload); err == nil {
		t.Fatal("oversized SIP008 node list was accepted")
	}

	var raw strings.Builder
	for range maxSubscriptionNodes + 1 {
		raw.WriteString("ss://node\n")
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(raw.String()))
	if nodes, err := resolveSubscriptionAsBase64([]byte(encoded)); err == nil || nodes != nil {
		t.Fatalf("oversized base64 node list = %d nodes, %v; want error", len(nodes), err)
	}
}

func TestResolveSIP008FieldCompatibility(t *testing.T) {
	capitalized := []byte(`{"Version":1,"Servers":[]}`)
	if nodes, err := ResolveSubscriptionAsSIP008(capitalized); err != nil || len(nodes) != 0 {
		t.Fatalf("capitalized fields = %v, %v; want accepted empty list", nodes, err)
	}
	duplicate := []byte(`{"version":1,"servers":[],"Servers":[]}`)
	if _, err := ResolveSubscriptionAsSIP008(duplicate); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate fields error = %v, want duplicate rejection", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type closeTrackingBody struct {
	io.Reader
	closed bool
}

func (b *closeTrackingBody) Close() error {
	b.closed = true
	return nil
}

func TestFetchRemoteSubscription(t *testing.T) {
	tests := []struct {
		name          string
		statusCode    int
		contentLength int64
		bodySize      int64
		wantErr       bool
	}{
		{name: "within limit", statusCode: http.StatusOK, contentLength: maxRemoteSubscriptionSize, bodySize: maxRemoteSubscriptionSize},
		{name: "non-2xx status", statusCode: http.StatusTeapot, contentLength: 4, bodySize: 4, wantErr: true},
		{name: "content length exceeds limit", statusCode: http.StatusOK, contentLength: maxRemoteSubscriptionSize + 1, wantErr: true},
		{name: "chunked body exceeds limit", statusCode: http.StatusOK, contentLength: -1, bodySize: maxRemoteSubscriptionSize + 1, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := &closeTrackingBody{Reader: io.LimitReader(
				bytes.NewReader(make([]byte, maxRemoteSubscriptionSize+1)),
				tt.bodySize,
			)}
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.Method != http.MethodGet {
					t.Fatalf("method = %q, want GET", req.Method)
				}
				if got := req.Header.Get("User-Agent"); got == "" {
					t.Fatal("User-Agent is empty")
				}
				return &http.Response{
					StatusCode:    tt.statusCode,
					ContentLength: tt.contentLength,
					Body:          body,
				}, nil
			})}

			got, err := fetchRemoteSubscription(client, "https://example.com/subscription")
			if !body.closed {
				t.Fatal("response body was not closed")
			}
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && int64(len(got)) != tt.bodySize {
				t.Fatalf("read %d bytes, want %d", len(got), tt.bodySize)
			}
		})
	}
}

func TestResolveSubscriptionContextCancelsFetch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, _, err := ResolveSubscriptionContext(ctx, server.Client(), t.TempDir(), server.URL, componentoutbound.ValidateNodeLink)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ResolveSubscriptionContext error = %v, want deadline exceeded", err)
	}
}

func TestPersistentSubscriptionContextDoesNotFallbackAfterCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	link := "cached:" + strings.Replace(server.URL, "http://", "http-file://", 1)
	_, _, err := ResolveSubscriptionContext(ctx, server.Client(), t.TempDir(), link, componentoutbound.ValidateNodeLink)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ResolveSubscriptionContext error = %v, want deadline exceeded", err)
	}
}

func TestValidateSubscriptionNodesHonorsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	_, err := validateSubscriptionNodes(ctx, []string{"first", "second"}, func(string) error {
		calls++
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("validation error = %v, want context cancellation", err)
	}
	if calls != 1 {
		t.Fatalf("validator calls = %d, want 1", calls)
	}
}

func TestValidateSubscriptionNodesObservesFinalCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	_, err := validateSubscriptionNodes(ctx, []string{"only"}, func(string) error {
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("validation error = %v, want context cancellation", err)
	}
}

func encodedSubscription(nodes ...string) []byte {
	return []byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(nodes, "\n") + "\n")))
}

func testSSNode(host string) string {
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:test-password"))
	return "ss://" + userinfo + "@" + host + ":443"
}

func writePersistedSubscription(t *testing.T, dir, tag string, content []byte) string {
	t.Helper()
	persistDir := filepath.Join(dir, "persist.d")
	if err := os.MkdirAll(persistDir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(persistDir, tag+".sub")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func persistentURL(tag, rawURL string) string {
	return tag + ":" + strings.Replace(rawURL, "http://", "http-file://", 1)
}

func TestResolveSubscriptionInvalidResponsePreservesCache(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{name: "non-2xx status", status: http.StatusBadGateway, body: "upstream unavailable"},
		{name: "malformed 2xx", status: http.StatusOK, body: "not a subscription"},
		{name: "HTML URL error page", status: http.StatusOK, body: "<!doctype html>\n<a href=\"https://example.com/help\">service unavailable</a>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			cachedNode := testSSNode("cached.example")
			cached := encodedSubscription("unsupported://cached", cachedNode)
			path := writePersistedSubscription(t, dir, "test", cached)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			tag, nodes, err := ResolveSubscription(server.Client(), dir, persistentURL("test", server.URL), componentoutbound.ValidateNodeLink)
			if err != nil {
				t.Fatal(err)
			}
			if tag != "test" || len(nodes) != 1 || nodes[0] != cachedNode {
				t.Fatalf("fallback result = %q, %v", tag, nodes)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, cached) {
				t.Fatal("invalid response replaced persisted subscription")
			}
		})
	}
}

func TestResolveSubscriptionRejectsUnsafePersistenceTag(t *testing.T) {
	tests := []string{"../escape", "nested/name", `nested\name`, ".", ".."}
	for _, tag := range tests {
		t.Run(tag, func(t *testing.T) {
			dir := t.TempDir()
			requested := false
			server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				requested = true
			}))
			defer server.Close()

			_, _, err := ResolveSubscription(server.Client(), dir, persistentURL(tag, server.URL), componentoutbound.ValidateNodeLink)
			if err == nil || !strings.Contains(err.Error(), "safe basename") {
				t.Fatalf("error = %v, want unsafe tag error", err)
			}
			if requested {
				t.Fatal("unsafe persistence tag was fetched")
			}
			if _, err := os.Stat(filepath.Join(dir, "persist.d")); !os.IsNotExist(err) {
				t.Fatalf("persist directory created for unsafe tag: %v", err)
			}
		})
	}
}

func TestResolveSubscriptionFiltersEverySource(t *testing.T) {
	validNode := testSSNode("valid.example")
	mixed := encodedSubscription("unsupported://invalid", validNode)
	invalid := encodedSubscription("unsupported://invalid")

	t.Run("fresh remote", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(mixed)
		}))
		defer server.Close()

		_, nodes, err := ResolveSubscription(server.Client(), t.TempDir(), server.URL, componentoutbound.ValidateNodeLink)
		if err != nil {
			t.Fatal(err)
		}
		if len(nodes) != 1 || nodes[0] != validNode {
			t.Fatalf("nodes = %v, want only %q", nodes, validNode)
		}
	})

	t.Run("direct file", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "nodes.sub"), mixed, 0600); err != nil {
			t.Fatal(err)
		}

		_, nodes, err := ResolveSubscription(http.DefaultClient, dir, "file://nodes.sub", componentoutbound.ValidateNodeLink)
		if err != nil {
			t.Fatal(err)
		}
		if len(nodes) != 1 || nodes[0] != validNode {
			t.Fatalf("nodes = %v, want only %q", nodes, validNode)
		}
	})

	t.Run("cached fallback", func(t *testing.T) {
		dir := t.TempDir()
		writePersistedSubscription(t, dir, "test", mixed)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "unavailable", http.StatusBadGateway)
		}))
		defer server.Close()

		_, nodes, err := ResolveSubscription(server.Client(), dir, persistentURL("test", server.URL), componentoutbound.ValidateNodeLink)
		if err != nil {
			t.Fatal(err)
		}
		if len(nodes) != 1 || nodes[0] != validNode {
			t.Fatalf("nodes = %v, want only %q", nodes, validNode)
		}
	})

	tests := []struct {
		name         string
		subscription func(t *testing.T, dir string) (*http.Client, string)
		wantErr      string
	}{
		{
			name: "fresh remote",
			subscription: func(t *testing.T, _ string) (*http.Client, string) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					_, _ = w.Write(invalid)
				}))
				t.Cleanup(server.Close)
				return server.Client(), server.URL
			},
			wantErr: "remote subscription is unusable",
		},
		{
			name: "direct file",
			subscription: func(t *testing.T, dir string) (*http.Client, string) {
				if err := os.WriteFile(filepath.Join(dir, "invalid.sub"), invalid, 0600); err != nil {
					t.Fatal(err)
				}
				return http.DefaultClient, "file://invalid.sub"
			},
			wantErr: "direct subscription file is unusable",
		},
		{
			name: "cached fallback",
			subscription: func(t *testing.T, dir string) (*http.Client, string) {
				writePersistedSubscription(t, dir, "test", invalid)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					http.Error(w, "unavailable", http.StatusBadGateway)
				}))
				t.Cleanup(server.Close)
				return server.Client(), persistentURL("test", server.URL)
			},
			wantErr: "cached fallback is unusable",
		},
	}
	for _, tt := range tests {
		t.Run("rejects unusable "+tt.name, func(t *testing.T) {
			dir := t.TempDir()
			client, subscription := tt.subscription(t, dir)
			_, nodes, err := ResolveSubscription(client, dir, subscription, componentoutbound.ValidateNodeLink)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
			}
			if nodes != nil {
				t.Fatalf("unusable nodes returned: %v", nodes)
			}
		})
	}
}

func TestResolveSubscriptionRequiresValidator(t *testing.T) {
	_, _, err := ResolveSubscription(http.DefaultClient, t.TempDir(), "https://example.com/subscription", nil)
	if err == nil || !strings.Contains(err.Error(), "validator is required") {
		t.Fatalf("error = %v, want validator error", err)
	}
}

func TestResolveSubscriptionRejectsUnsafePersistDirectory(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(t *testing.T, dir string)
		wantErr string
	}{
		{
			name: "symlink",
			prepare: func(t *testing.T, dir string) {
				target := t.TempDir()
				if err := os.Symlink(target, filepath.Join(dir, "persist.d")); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: "symbolic link",
		},
		{
			name: "non-directory",
			prepare: func(t *testing.T, dir string) {
				if err := os.WriteFile(filepath.Join(dir, "persist.d"), []byte("not a directory"), 0600); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: "not a directory",
		},
		{
			name: "group writable",
			prepare: func(t *testing.T, dir string) {
				path := filepath.Join(dir, "persist.d")
				if err := os.Mkdir(path, 0770); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0770); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: "are unsafe",
		},
		{
			name: "world writable",
			prepare: func(t *testing.T, dir string) {
				path := filepath.Join(dir, "persist.d")
				if err := os.Mkdir(path, 0702); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0702); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: "are unsafe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			tt.prepare(t, dir)
			fresh := encodedSubscription(testSSNode("fresh.example"))
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(fresh)
			}))
			defer server.Close()

			_, nodes, err := ResolveSubscription(server.Client(), dir, persistentURL("test", server.URL), componentoutbound.ValidateNodeLink)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
			}
			if nodes != nil {
				t.Fatalf("nodes returned despite unsafe persist directory: %v", nodes)
			}
		})
	}
}

func TestPersistSubscriptionUsesOpenedDirectory(t *testing.T) {
	dir := t.TempDir()
	persistDir, err := openPersistDir(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer persistDir.Close()

	openedPath := filepath.Join(dir, "opened-persist.d")
	if err := os.Rename(filepath.Join(dir, "persist.d"), openedPath); err != nil {
		t.Fatal(err)
	}
	replacementTarget := t.TempDir()
	if err := os.Symlink(replacementTarget, filepath.Join(dir, "persist.d")); err != nil {
		t.Fatal(err)
	}
	content := encodedSubscription(testSSNode("fresh.example"))
	if err := persistSubscription(persistDir, "test.sub", content); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(filepath.Join(openedPath, "test.sub"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatal("persisted content differs")
	}
	if _, err := os.Stat(filepath.Join(replacementTarget, "test.sub")); !os.IsNotExist(err) {
		t.Fatalf("replacement directory was modified: %v", err)
	}
}

func TestPrunePersistedSubscriptions(t *testing.T) {
	dir := t.TempDir()
	activePath := writePersistedSubscription(t, dir, "active", []byte("active"))
	stalePath := writePersistedSubscription(t, dir, "stale", []byte("stale"))

	if err := PrunePersistedSubscriptions(dir, map[string]struct{}{"active": {}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(activePath); err != nil {
		t.Fatalf("active cache was removed: %v", err)
	}
	if _, err := os.Stat(stalePath); !os.IsNotExist(err) {
		t.Fatalf("stale cache was not removed: %v", err)
	}
}

func TestPersistentTagUsesConfiguredPersistenceMode(t *testing.T) {
	for _, test := range []struct {
		name string
		link string
		tag  string
		ok   bool
	}{
		{name: "persistent HTTP", link: "keep:http-file://example.com/sub", tag: "keep", ok: true},
		{name: "persistent HTTPS", link: "keep:https-file://example.com/sub", tag: "keep", ok: true},
		{name: "ordinary HTTP", link: "keep:http://example.com/sub"},
		{name: "local file", link: "keep:file://nodes.sub"},
		{name: "unsafe tag", link: "../keep:http-file://example.com/sub"},
	} {
		t.Run(test.name, func(t *testing.T) {
			tag, ok := PersistentTag(test.link)
			if tag != test.tag || ok != test.ok {
				t.Fatalf("PersistentTag() = %q, %v; want %q, %v", tag, ok, test.tag, test.ok)
			}
		})
	}
}

func TestResolveFileRejectsFinalSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "nodes.sub")
	if err := os.WriteFile(target, encodedSubscription(testSSNode("outside.example")), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "nodes.sub")); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse("file://nodes.sub")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveFile(u, dir); err == nil {
		t.Fatal("ResolveFile followed a final symlink")
	}
}

func TestResolveFileRejectsIntermediateSymlink(t *testing.T) {
	dir := t.TempDir()
	targetDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(targetDir, "nodes.sub"), encodedSubscription(testSSNode("outside.example")), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(targetDir, filepath.Join(dir, "links")); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse("file://links/nodes.sub")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveFile(u, dir); err == nil {
		t.Fatal("ResolveFile followed an intermediate symlink")
	}
}

func TestOpenPersistDirCreatesMissingSubscriptionDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing", "subscriptions")
	persistDir, err := openPersistDir(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer persistDir.Close()
	if info, err := persistDir.Stat(); err != nil || !info.IsDir() {
		t.Fatalf("persist directory stat = %v, %v", info, err)
	}
}

func TestPrunePersistedSubscriptionsRejectsSymlinkDirectory(t *testing.T) {
	dir := t.TempDir()
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(dir, "persist.d")); err != nil {
		t.Fatal(err)
	}

	err := PrunePersistedSubscriptions(dir, nil)
	if err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("error = %v, want symbolic link error", err)
	}
}

func TestResolveSubscriptionAtomicallyPersistsValidResponse(t *testing.T) {
	dir := t.TempDir()
	cachedNode := testSSNode("cached.example")
	freshNode := testSSNode("fresh.example")
	cached := encodedSubscription(cachedNode)
	fresh := encodedSubscription(freshNode)
	path := writePersistedSubscription(t, dir, "test", cached)
	oldFile, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer oldFile.Close()
	oldInfo, err := oldFile.Stat()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(fresh)
	}))
	defer server.Close()

	_, nodes, err := ResolveSubscription(server.Client(), dir, persistentURL("test", server.URL), componentoutbound.ValidateNodeLink)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0] != freshNode {
		t.Fatalf("nodes = %v", nodes)
	}
	newInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(oldInfo, newInfo) {
		t.Fatal("persisted subscription was updated in place instead of replaced")
	}
	if got := newInfo.Mode().Perm(); got != 0600 {
		t.Fatalf("persisted subscription mode = %04o, want 0600", got)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, fresh) {
		t.Fatal("persisted subscription differs from valid response")
	}
	oldContent, err := io.ReadAll(oldFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oldContent, cached) {
		t.Fatal("open handle to previous subscription was modified")
	}
	tmpFiles, err := filepath.Glob(filepath.Join(filepath.Dir(path), ".test.sub.tmp-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(tmpFiles) != 0 {
		t.Fatalf("temporary subscription files remain: %v", tmpFiles)
	}
}
