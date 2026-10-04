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
	"sync/atomic"
	"testing"
	"time"

	componentoutbound "github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/config"
	log "github.com/sirupsen/logrus"
)

func TestResolveSubscriptionAsSIP008EncodesUserinfo(t *testing.T) {
	for _, tt := range []struct {
		method, password string
		unencoded        bool
	}{
		{"aes-256-cfb", "stream-password", false},
		{"aes-256-gcm", "legacy:/password", false},
		{"2022-blake3-aes-256-gcm", "RCF/0OOYmo6crue3LwlEyD8izLAbuUuyPic/vasJH/o=", true},
	} {
		t.Run(tt.method, func(t *testing.T) {
			payload, err := json.Marshal(sip008{Version: 1, Servers: []sip008Server{{Remarks: "test", Server: "127.0.0.1", ServerPort: 443, Password: tt.password, Method: tt.method}}})
			if err != nil {
				t.Fatal(err)
			}
			nodes, err := ResolveSubscriptionAsSIP008(payload)
			if err != nil || len(nodes) != 1 {
				t.Fatalf("nodes=%v err=%v", nodes, err)
			}
			u, err := url.Parse(nodes[0])
			if err != nil {
				t.Fatal(err)
			}
			if tt.unencoded {
				if u.User.String() != url.UserPassword(tt.method, tt.password).String() {
					t.Fatalf("userinfo=%s", u.User)
				}
			} else {
				if _, ok := u.User.Password(); ok {
					t.Fatal("legacy userinfo is not Base64URL")
				}
				decoded, err := base64.RawURLEncoding.DecodeString(u.User.Username())
				if err != nil || string(decoded) != tt.method+":"+tt.password {
					t.Fatalf("userinfo=%q %v", decoded, err)
				}
			}
		})
	}
}

func TestResolveSubscriptionAsSIP008EncodesPlugin(t *testing.T) {
	for _, tt := range []struct{ plugin, options, want, path string }{
		{}, {options: "obfs=http"},
		{"v2ray-plugin", "", "v2ray-plugin", "/"},
		{"obfs-local", "obfs=http;obfs-host=example.com", "obfs-local;obfs=http;obfs-host=example.com", "/"},
	} {
		payload, err := json.Marshal(sip008{Version: 1, Servers: []sip008Server{{Remarks: "test", Server: "127.0.0.1", ServerPort: 443, Password: "password", Method: "aes-256-gcm", Plugin: tt.plugin, PluginOpts: tt.options}}})
		if err != nil {
			t.Fatal(err)
		}
		nodes, err := ResolveSubscriptionAsSIP008(payload)
		if err != nil || len(nodes) != 1 {
			t.Fatalf("nodes=%v err=%v", nodes, err)
		}
		u, err := url.Parse(nodes[0])
		if err != nil {
			t.Fatal(err)
		}
		if u.Query().Get("plugin") != tt.want || u.Path != tt.path || tt.want == "" && u.RawQuery != "" {
			t.Fatalf("plugin URL=%s", u)
		}
		if tt.plugin != "" {
			if err := componentoutbound.ValidateNodeLink(nodes[0]); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestResolveSubscriptionRejectsTooManyNodes(t *testing.T) {
	payload, err := json.Marshal(sip008{Version: 1, Servers: make([]sip008Server, maxSubscriptionNodes+1)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveSubscriptionAsSIP008(payload); err == nil {
		t.Fatal("oversized SIP008 accepted")
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("ss://node\n", maxSubscriptionNodes+1)))
	if nodes, err := resolveSubscriptionAsBase64([]byte(encoded)); err == nil || nodes != nil {
		t.Fatal("oversized Base64 accepted")
	}
}

func TestResolveSIP008FieldCompatibility(t *testing.T) {
	if nodes, err := ResolveSubscriptionAsSIP008([]byte(`{"Version":1,"Servers":[]}`)); err != nil || len(nodes) != 0 {
		t.Fatalf("capitalized fields: %v %v", nodes, err)
	}
	if _, err := ResolveSubscriptionAsSIP008([]byte(`{"version":1,"servers":[],"Servers":[]}`)); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicates: %v", err)
	}
}

func TestResolveSubscriptionRedactsTransportErrorURL(t *testing.T) {
	const raw = "office:https://user:password@example.com:8443/private/token?key=secret#fragment"
	if got := RedactURL(raw); got != "office:https://example.com:8443" {
		t.Fatal(got)
	}
	sentinel := errors.New("transport failed")
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, sentinel })}
	_, _, err := ResolveSubscriptionContext(t.Context(), client, ResolveOptions{}, raw, componentoutbound.ValidateNodeLink)
	if !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "https://example.com:8443") {
		t.Fatalf("transport error: %v", err)
	}
	for _, secret := range []string{"user", "password", "private", "token", "secret", "fragment"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("URL leaked: %v", err)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type closeTrackingBody struct {
	io.Reader
	closed bool
}

func (b *closeTrackingBody) Close() error { b.closed = true; return nil }

func TestResolveSubscriptionRemoteLimitsAndUserAgent(t *testing.T) {
	for _, tt := range []struct {
		name   string
		status int
		length int64
		data   []byte
	}{
		{"valid", 200, -1, encodedSubscription(testSSNode("valid.example"))},
		{"status", 418, 4, []byte("oops")},
		{"length", 200, maxRemoteSubscriptionSize + 1, nil},
		{"chunked", 200, -1, make([]byte, maxRemoteSubscriptionSize+1)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body := &closeTrackingBody{Reader: bytes.NewReader(tt.data)}
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.Method != "GET" || req.Header.Get("User-Agent") != "dae/"+config.Version+" (like v2rayA/1.0 WebRequestHelper) (like v2rayN/1.0 WebRequestHelper)" {
					t.Fatalf("request=%v", req)
				}
				return &http.Response{StatusCode: tt.status, ContentLength: tt.length, Body: body}, nil
			})}
			_, nodes, err := ResolveSubscriptionContext(t.Context(), client, ResolveOptions{}, "https://example.com/sub", componentoutbound.ValidateNodeLink)
			if !body.closed || (err == nil) != (tt.name == "valid") || err != nil && nodes != nil {
				t.Fatalf("closed=%t nodes=%v err=%v", body.closed, nodes, err)
			}
		})
	}
}

func TestResolveSubscriptionInvalidResponsePreservesCache(t *testing.T) {
	for _, serve := range []func(http.Handler) *httptest.Server{httptest.NewServer, httptest.NewTLSServer} {
		for _, invalid := range []string{
			"not a subscription", "<!doctype html><a href=\"https://example.com/help\">error</a>",
			"Subscription request timed out. Please try again later.", "订阅请求过于频繁，请稍后重试",
			`{"status":"error","message":"subscription request timed out"}`, "", `{"version":1,"servers":[`,
			`{"version":1,"servers":[]}`, string(encodedSubscription("unsupported://invalid")),
			string(encodedSubscription("Subscription request timed out")),
		} {
			var failed atomic.Bool
			node := testSSNode("cached.example")
			server := serve(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if failed.Load() {
					io.WriteString(w, invalid)
					return
				}
				w.Write(encodedSubscription("unsupported://discard", node))
			}))
			opts := ResolveOptions{CacheDir: t.TempDir()}
			load := func() (string, []string, error) {
				return ResolveSubscriptionContext(t.Context(), server.Client(), opts, "test:"+server.URL, componentoutbound.ValidateNodeLink)
			}
			if _, _, err := load(); err != nil {
				t.Fatal(err)
			}
			files, _ := filepath.Glob(filepath.Join(opts.CacheDir, "*.json"))
			if len(files) != 1 {
				t.Fatalf("files=%v", files)
			}
			before, _ := os.ReadFile(files[0])
			failed.Store(true)
			for _, offline := range []bool{false, true} {
				if offline {
					server.Close()
				}
				tag, nodes, err := load()
				if err != nil || tag != "test" || len(nodes) != 1 || nodes[0] != node {
					t.Fatalf("fallback=%q %v %v", tag, nodes, err)
				}
				after, _ := os.ReadFile(files[0])
				if !bytes.Equal(before, after) {
					t.Fatal("failed refresh changed cache")
				}
			}
		}
	}
}

func TestSubscriptionCacheLogsConfirmedOutcome(t *testing.T) {
	logger := log.StandardLogger()
	output, level, formatter := logger.Out, logger.Level, logger.Formatter
	var logs bytes.Buffer
	logger.SetOutput(&logs)
	logger.SetLevel(log.InfoLevel)
	logger.SetFormatter(new(log.JSONFormatter))
	t.Cleanup(func() { logger.SetOutput(output); logger.SetLevel(level); logger.SetFormatter(formatter) })
	const source = "https://account:password-secret@example.com/path-secret?token-secret"
	for _, state := range []string{"usable", "missing", "invalid"} {
		opts := ResolveOptions{CacheDir: t.TempDir()}
		var offline bool
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			if offline {
				return nil, errors.New("upstream unavailable")
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(encodedSubscription(testSSNode("cached.example"))))}, nil
		})}
		if state != "missing" {
			if _, _, err := ResolveSubscriptionContext(t.Context(), client, opts, source, componentoutbound.ValidateNodeLink); err != nil {
				t.Fatal(err)
			}
			if state == "invalid" {
				files, _ := filepath.Glob(filepath.Join(opts.CacheDir, "*.json"))
				if err := os.WriteFile(files[0], []byte("invalid"), 0600); err != nil {
					t.Fatal(err)
				}
			}
		}
		offline = true
		logs.Reset()
		_, nodes, err := ResolveSubscriptionContext(t.Context(), client, opts, source, componentoutbound.ValidateNodeLink)
		if state == "usable" {
			if err != nil || len(nodes) != 1 || strings.Count(logs.String(), `"level":"warning"`) != 1 || !strings.Contains(logs.String(), "using cached nodes") {
				t.Fatalf("logs=%s err=%v", &logs, err)
			}
		} else if err == nil || logs.Len() != 0 {
			t.Fatalf("false fallback warning: %s %v", &logs, err)
		}
		diagnostic := logs.String()
		if err != nil {
			diagnostic += err.Error()
		}
		if strings.Contains(diagnostic, "secret") || strings.Contains(diagnostic, "account") {
			t.Fatalf("leak: %s", diagnostic)
		}
	}
}

func TestResolveSubscriptionCancellationAndValidation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if _, _, err := ResolveSubscriptionContext(ctx, server.Client(), ResolveOptions{CacheDir: t.TempDir()}, server.URL, componentoutbound.ValidateNodeLink); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(encodedSubscription(testSSNode("first.example"), testSSNode("second.example"))))}, nil
	})}
	ctx, cancelValidation := context.WithCancel(t.Context())
	defer cancelValidation()
	_, nodes, err := ResolveSubscriptionContext(ctx, client, ResolveOptions{CacheDir: t.TempDir()}, "http://example.com/sub", func(string) error { cancelValidation(); return nil })
	if !errors.Is(err, context.Canceled) || nodes != nil {
		t.Fatalf("validation cancellation: %v %v", nodes, err)
	}
	if _, _, err := ResolveSubscriptionContext(t.Context(), client, ResolveOptions{}, "http://example.com/sub", nil); err == nil {
		t.Fatal("nil validator accepted")
	}
	if nodes, err := validateSubscriptionNodes(t.Context(), []string{"ss://invalid"}, func(string) error { panic("bad validator") }); err == nil || nodes != nil {
		t.Fatal("panic accepted")
	}
}

func TestValidateSubscriptionNodesFiltersMixedContent(t *testing.T) {
	valid := testSSNode("valid.example")
	for _, content := range [][]string{{valid, "unsupported://invalid"}, {valid, "ss://%%%"}} {
		nodes, err := resolveSubscriptionContent(t.Context(), encodedSubscription(content...), componentoutbound.ValidateNodeLink)
		if err != nil || len(nodes) != 1 || nodes[0] != valid {
			t.Fatalf("nodes=%v err=%v", nodes, err)
		}
	}
}

func TestResolveFileRejectsSymlinks(t *testing.T) {
	for _, intermediate := range []bool{false, true} {
		dir, target := t.TempDir(), t.TempDir()
		if err := os.WriteFile(filepath.Join(target, "nodes.sub"), encodedSubscription(testSSNode("outside.example")), 0600); err != nil {
			t.Fatal(err)
		}
		link, destination := "nodes.sub", filepath.Join(target, "nodes.sub")
		if intermediate {
			link, destination = "links", target
		}
		if err := os.Symlink(destination, filepath.Join(dir, link)); err != nil {
			t.Fatal(err)
		}
		raw := "file:nodes.sub"
		if intermediate {
			raw = "file:links/nodes.sub"
		}
		u, _ := url.Parse(raw)
		if _, err := ResolveFile(u, dir); err == nil {
			t.Fatal("relative file followed symlink")
		}
	}
}

func testSSNode(host string) string {
	return "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:test-password")) + "@" + host + ":443"
}

func encodedSubscription(nodes ...string) []byte {
	return []byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(nodes, "\n"))))
}
