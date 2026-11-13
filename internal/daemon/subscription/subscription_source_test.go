// SPDX-License-Identifier: AGPL-3.0-only

package subscription

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/resource"
	componentoutbound "github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/config"
)

func TestResolveSubscriptionWithSchemeNamedTags(t *testing.T) {
	t.Run("file tag with persistent HTTPS", func(t *testing.T) {
		dir := t.TempDir()
		node := testSSNode("persistent.example")
		content := encodedSubscription(node)
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(content)
		}))
		defer server.Close()
		sub := config.Subscription{Name: "file", Link: server.URL}
		for _, offline := range []bool{false, true} {
			if offline {
				server.Close()
			}
			tag, nodes, err := ResolveSubscriptionContext(t.Context(), server.Client(), ResolveOptions{CacheDir: dir}, sub.String(), componentoutbound.NewNodeValidator(t.Context(), &config.Global{}))
			if err != nil || tag != sub.Name || len(nodes) != 1 || nodes[0] != node {
				t.Fatalf("offline=%t: tag=%q nodes=%v err=%v", offline, tag, nodes, err)
			}
		}
	})
	t.Run("http tag with relative file", func(t *testing.T) {
		dir := t.TempDir()
		node := testSSNode("local.example")
		if err := os.WriteFile(filepath.Join(dir, "nodes.sub"), encodedSubscription(node), 0600); err != nil {
			t.Fatal(err)
		}
		sub := config.Subscription{Name: "http", Link: "file:nodes.sub"}
		tag, nodes, err := ResolveSubscriptionContext(t.Context(), http.DefaultClient, ResolveOptions{BaseDir: dir}, sub.String(), componentoutbound.NewNodeValidator(t.Context(), &config.Global{}))
		if err != nil || tag != sub.Name || len(nodes) != 1 || nodes[0] != node {
			t.Fatalf("scheme-named local tag returned tag=%q nodes=%v err=%v", tag, nodes, err)
		}
	})
}

func TestResolveSubscriptionRelativeFileSources(t *testing.T) {
	dir := t.TempDir()
	node := testSSNode("local.example")
	if err := os.WriteFile(filepath.Join(dir, "nodes 100%.sub"), encodedSubscription(node), 0600); err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relativeDir, err := filepath.Rel(cwd, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, configDir := range []string{dir, relativeDir} {
		for _, test := range []struct{ link, tag string }{
			{"file:nodes%20100%25.sub", ""},
			{"local:file:nodes%20100%25.sub", "local"},
		} {
			t.Run(configDir+"/"+test.tag, func(t *testing.T) {
				tag, nodes, err := ResolveSubscriptionContext(t.Context(), http.DefaultClient, ResolveOptions{BaseDir: configDir}, test.link, componentoutbound.NewNodeValidator(t.Context(), &config.Global{}))
				if err != nil || tag != test.tag || len(nodes) != 1 || nodes[0] != node {
					t.Fatalf("relative source returned tag=%q nodes=%v err=%v", tag, nodes, err)
				}
			})
		}
	}
}

func TestResolveSubscriptionRejectsInvalidSources(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nodes.sub")
	if err := os.WriteFile(path, encodedSubscription(testSSNode("local.example")), 0600); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid subscription source reached the HTTP transport")
		return nil, nil
	})}
	for _, link := range []string{
		"file://nodes.sub", "local:file://nodes.sub", "nodes.sub", "local:nodes.sub", path,
		"ftp://example.com/nodes.sub", "file:nodes.sub?token=secret", "file:nodes.sub#fragment",
	} {
		t.Run(link, func(t *testing.T) {
			_, nodes, err := ResolveSubscriptionContext(t.Context(), client, ResolveOptions{BaseDir: dir}, link, componentoutbound.NewNodeValidator(t.Context(), &config.Global{}))
			if err == nil || len(nodes) != 0 {
				t.Fatalf("invalid source returned nodes=%v err=%v", nodes, err)
			}
		})
	}
}

func TestSubscriptionCacheIdentityUsesURLRatherThanTag(t *testing.T) {
	node := testSSNode("cached.example")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(encodedSubscription(node))
	}))
	defer server.Close()
	opts := ResolveOptions{CacheDir: t.TempDir()}
	if _, _, err := ResolveSubscriptionContext(t.Context(), server.Client(), opts, "same:"+server.URL+"/one", componentoutbound.NewNodeValidator(t.Context(), &config.Global{})); err != nil {
		t.Fatal(err)
	}
	server.Close()
	for _, tag := range []string{"", "renamed", "../name"} {
		link := server.URL + "/one"
		if tag != "" {
			link = tag + ":" + link
		}
		gotTag, nodes, err := ResolveSubscriptionContext(t.Context(), server.Client(), opts, link, componentoutbound.NewNodeValidator(t.Context(), &config.Global{}))
		if err != nil || gotTag != tag || len(nodes) != 1 || nodes[0] != node {
			t.Fatalf("tag affected cache identity: tag=%q nodes=%v err=%v", gotTag, nodes, err)
		}
	}
	if _, _, err := ResolveSubscriptionContext(t.Context(), server.Client(), opts, "same:"+server.URL+"/two", componentoutbound.NewNodeValidator(t.Context(), &config.Global{})); err == nil {
		t.Fatal("same tag reused another URL's cache")
	}
}

func TestDisabledRemoteSubscriptionCacheDoesNotReadOrWrite(t *testing.T) {
	for _, tls := range []bool{false, true} {
		name := "HTTP"
		if tls {
			name = "HTTPS"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			node := testSSNode("fresh.example")
			handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(encodedSubscription(node))
			})
			server := httptest.NewUnstartedServer(handler)
			if tls {
				server.StartTLS()
			} else {
				server.Start()
			}
			defer server.Close()
			link := "ordinary:" + server.URL
			tag, nodes, err := ResolveSubscriptionContext(t.Context(), server.Client(), ResolveOptions{BaseDir: dir}, link, componentoutbound.NewNodeValidator(t.Context(), &config.Global{}))
			if err != nil || tag != "ordinary" || len(nodes) != 1 || nodes[0] != node {
				t.Fatalf("ordinary download returned tag=%q nodes=%v err=%v", tag, nodes, err)
			}
			if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
				t.Fatalf("disabled cache wrote files: %v %v", entries, err)
			}
			if _, _, err := ResolveSubscriptionContext(t.Context(), server.Client(), ResolveOptions{CacheDir: dir}, link, componentoutbound.NewNodeValidator(t.Context(), &config.Global{})); err != nil {
				t.Fatal(err)
			}
			files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
			if len(files) != 1 {
				t.Fatalf("files=%v", files)
			}
			cachePath := files[0]
			cached, _ := os.ReadFile(cachePath)
			server.Close()
			_, nodes, err = ResolveSubscriptionContext(t.Context(), server.Client(), ResolveOptions{BaseDir: dir}, link, componentoutbound.NewNodeValidator(t.Context(), &config.Global{}))
			if err == nil || len(nodes) != 0 {
				t.Fatalf("ordinary download fell back to cached nodes=%v err=%v", nodes, err)
			}
			got, err := os.ReadFile(cachePath)
			if err != nil || !bytes.Equal(got, cached) {
				t.Fatalf("ordinary download changed existing cache: %v", err)
			}
		})
	}
}

func TestLocalSubscriptionInputReplayKeepsValidatedSource(t *testing.T) {
	for _, absolute := range []bool{false, true} {
		base := t.TempDir()
		targetDir := filepath.Join(base, "real")
		if absolute {
			targetDir = t.TempDir()
		}
		if err := os.MkdirAll(targetDir, 0700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(targetDir, "nodes.sub")
		want := testSSNode("accepted.example")
		content := append([]byte("@ ignored instruction\n"), encodedSubscription(want)...)
		if err := os.WriteFile(target, content, 0600); err != nil {
			t.Fatal(err)
		}
		link := "saved:file:real/nodes.sub"
		if absolute {
			linkPath := filepath.Join(base, "nodes.sub")
			if err := os.Symlink(target, linkPath); err != nil {
				t.Fatal(err)
			}
			link = "saved:" + (&url.URL{Scheme: "file", Path: linkPath}).String()
		}
		options := ResolveOptions{BaseDir: base}
		validate := componentoutbound.NewNodeValidator(t.Context(), &config.Global{})
		ctx, inputs := resource.WithInputRecording(t.Context())
		tag, nodes, err := ResolveSubscriptionContext(ctx, http.DefaultClient, options, link, validate)
		if err != nil || tag != "saved" || len(nodes) != 1 || nodes[0] != want {
			t.Fatalf("absolute=%v initial source: tag=%q nodes=%v err=%v", absolute, tag, nodes, err)
		}
		var encoded bytes.Buffer
		if err := inputs.Encode(&encoded); err != nil {
			t.Fatal(err)
		}
		saved, err := resource.DecodeInputs(&encoded)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte("invalid replacement"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(target, 0644); err != nil {
			t.Fatal(err)
		}
		replay := resource.WithInputReplay(t.Context(), saved)
		for _, remove := range []bool{false, true} {
			if remove {
				if err := os.RemoveAll(base); err != nil {
					t.Fatal(err)
				}
				if err := os.RemoveAll(targetDir); err != nil {
					t.Fatal(err)
				}
			}
			tag, nodes, err = ResolveSubscriptionContext(replay, http.DefaultClient, options, link, validate)
			if err != nil || tag != "saved" || len(nodes) != 1 || nodes[0] != want {
				t.Fatalf("absolute=%v remove=%v replay reread or revalidated file: %v %v", absolute, remove, nodes, err)
			}
		}
		if _, _, err := ResolveSubscriptionContext(resource.WithInputReplay(t.Context(), nil), http.DefaultClient, options, link, validate); !errors.Is(err, resource.ErrInputReplay) {
			t.Fatalf("missing local subscription input was not fatal: %v", err)
		}
	}
}

func TestLocalSubscriptionPathsPreserveNonUTF8Bytes(t *testing.T) {
	base := filepath.Join(t.TempDir(), "parent-\xff")
	if err := os.Mkdir(base, 0700); err != nil {
		t.Fatal(err)
	}
	names := []string{"nodes-\xff.sub", "nodes-\xfe.sub"}
	contents := [][]byte{encodedSubscription(testSSNode("one.example")), encodedSubscription(testSSNode("two.example"))}
	for i, name := range names {
		if err := os.WriteFile(filepath.Join(base, name), contents[i], 0600); err != nil {
			t.Fatal(err)
		}
	}
	check := func(ctx context.Context) {
		t.Helper()
		for i, name := range names {
			for _, raw := range []string{
				"file:" + url.PathEscape(name),
				(&url.URL{Scheme: "file", Path: filepath.Join(base, name)}).String(),
			} {
				u, err := url.Parse(raw)
				if err != nil {
					t.Fatal(err)
				}
				got, err := ResolveFile(ctx, u, base)
				if err != nil || !bytes.Equal(got, contents[i]) {
					t.Fatalf("raw subscription %q: %q, %v", raw, got, err)
				}
			}
		}
	}
	check(t.Context())
	record, inputs := resource.WithInputRecording(t.Context())
	check(record)
	var encoded bytes.Buffer
	if err := inputs.Encode(&encoded); err != nil {
		t.Fatal(err)
	}
	saved, err := resource.DecodeInputs(&encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(base); err != nil {
		t.Fatal(err)
	}
	check(resource.WithInputReplay(t.Context(), saved))
}

func TestLocalSubscriptionRecordingRetainsSecurityChecks(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "nodes.sub")
	if err := os.WriteFile(path, encodedSubscription(testSSNode("safe.example")), 0600); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse("file:nodes.sub")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	ctx, _ := resource.WithInputRecording(t.Context())
	if _, err := ResolveFile(ctx, u, base); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("recording accepted unsafe permissions: %v", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, maxRemoteSubscriptionSize+1); err != nil {
		t.Fatal(err)
	}
	ctx, _ = resource.WithInputRecording(t.Context())
	if _, err := ResolveFile(ctx, u, base); err == nil {
		t.Fatal("recording accepted oversized local subscription")
	}
	outside := filepath.Join(t.TempDir(), "outside.sub")
	if err := os.WriteFile(outside, encodedSubscription(testSSNode("outside.example")), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	ctx, _ = resource.WithInputRecording(t.Context())
	if _, err := ResolveFile(ctx, u, base); err == nil {
		t.Fatal("recording followed a relative subscription outside its root")
	}
}

func TestSubscriptionValidationCannotSkipFatalInputs(t *testing.T) {
	for _, fatal := range []error{resource.ErrInputReplay, resource.ErrInputRecording} {
		calls := 0
		_, err := validateSubscriptionNodes(t.Context(), []string{"first", "second"}, func(string) error {
			calls++
			if calls == 1 {
				return fatal
			}
			return nil
		})
		if !errors.Is(err, fatal) || calls != 1 {
			t.Fatalf("fatal input was skipped: calls=%d err=%v", calls, err)
		}
	}
}
