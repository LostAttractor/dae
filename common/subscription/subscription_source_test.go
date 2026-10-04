// SPDX-License-Identifier: AGPL-3.0-only

package subscription

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

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
			tag, nodes, err := ResolveSubscriptionContext(t.Context(), server.Client(), ResolveOptions{CacheDir: dir}, sub.String(), componentoutbound.ValidateNodeLink)
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
		tag, nodes, err := ResolveSubscriptionContext(t.Context(), http.DefaultClient, ResolveOptions{BaseDir: dir}, sub.String(), componentoutbound.ValidateNodeLink)
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
				tag, nodes, err := ResolveSubscriptionContext(t.Context(), http.DefaultClient, ResolveOptions{BaseDir: configDir}, test.link, componentoutbound.ValidateNodeLink)
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
			_, nodes, err := ResolveSubscriptionContext(t.Context(), client, ResolveOptions{BaseDir: dir}, link, componentoutbound.ValidateNodeLink)
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
	if _, _, err := ResolveSubscriptionContext(t.Context(), server.Client(), opts, "same:"+server.URL+"/one", componentoutbound.ValidateNodeLink); err != nil {
		t.Fatal(err)
	}
	server.Close()
	for _, tag := range []string{"", "renamed", "../name"} {
		link := server.URL + "/one"
		if tag != "" {
			link = tag + ":" + link
		}
		gotTag, nodes, err := ResolveSubscriptionContext(t.Context(), server.Client(), opts, link, componentoutbound.ValidateNodeLink)
		if err != nil || gotTag != tag || len(nodes) != 1 || nodes[0] != node {
			t.Fatalf("tag affected cache identity: tag=%q nodes=%v err=%v", gotTag, nodes, err)
		}
	}
	if _, _, err := ResolveSubscriptionContext(t.Context(), server.Client(), opts, "same:"+server.URL+"/two", componentoutbound.ValidateNodeLink); err == nil {
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
			tag, nodes, err := ResolveSubscriptionContext(t.Context(), server.Client(), ResolveOptions{BaseDir: dir}, link, componentoutbound.ValidateNodeLink)
			if err != nil || tag != "ordinary" || len(nodes) != 1 || nodes[0] != node {
				t.Fatalf("ordinary download returned tag=%q nodes=%v err=%v", tag, nodes, err)
			}
			if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
				t.Fatalf("disabled cache wrote files: %v %v", entries, err)
			}
			if _, _, err := ResolveSubscriptionContext(t.Context(), server.Client(), ResolveOptions{CacheDir: dir}, link, componentoutbound.ValidateNodeLink); err != nil {
				t.Fatal(err)
			}
			files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
			if len(files) != 1 {
				t.Fatalf("files=%v", files)
			}
			cachePath := files[0]
			cached, _ := os.ReadFile(cachePath)
			server.Close()
			_, nodes, err = ResolveSubscriptionContext(t.Context(), server.Client(), ResolveOptions{BaseDir: dir}, link, componentoutbound.ValidateNodeLink)
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
