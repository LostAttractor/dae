// SPDX-License-Identifier: AGPL-3.0-only

package subscription

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
		sub := config.Subscription{Name: "file", Link: strings.Replace(server.URL, "https://", "https-file://", 1)}
		if tag, persistent := PersistentTag(sub.String()); tag != sub.Name || !persistent {
			t.Fatalf("persistent tag = %q, %t, want file, true", tag, persistent)
		}
		for _, offline := range []bool{false, true} {
			if offline {
				server.Close()
			}
			tag, nodes, err := ResolveSubscription(server.Client(), dir, sub.String(), componentoutbound.ValidateNodeLink)
			if err != nil || tag != sub.Name || len(nodes) != 1 || nodes[0] != node {
				t.Fatalf("offline=%t: tag=%q nodes=%v err=%v", offline, tag, nodes, err)
			}
		}
		cached, err := os.ReadFile(filepath.Join(dir, "persist.d", "file.sub"))
		if err != nil || !bytes.Equal(cached, content) {
			t.Fatalf("scheme-named tag did not preserve its cache: %v", err)
		}
	})
	t.Run("http tag with relative file", func(t *testing.T) {
		dir := t.TempDir()
		node := testSSNode("local.example")
		if err := os.WriteFile(filepath.Join(dir, "nodes.sub"), encodedSubscription(node), 0600); err != nil {
			t.Fatal(err)
		}
		sub := config.Subscription{Name: "http", Link: "file:nodes.sub"}
		tag, nodes, err := ResolveSubscription(http.DefaultClient, dir, sub.String(), componentoutbound.ValidateNodeLink)
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
				tag, nodes, err := ResolveSubscription(http.DefaultClient, configDir, test.link, componentoutbound.ValidateNodeLink)
				if err != nil || tag != test.tag || len(nodes) != 1 || nodes[0] != node {
					t.Fatalf("relative source returned tag=%q nodes=%v err=%v", tag, nodes, err)
				}
			})
		}
	}
}

func TestResolveSubscriptionRejectsLegacyAndBareSources(t *testing.T) {
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
			_, nodes, err := ResolveSubscription(client, dir, link, componentoutbound.ValidateNodeLink)
			if err == nil || len(nodes) != 0 {
				t.Fatalf("invalid source returned nodes=%v err=%v", nodes, err)
			}
		})
	}
}

func TestOrdinaryRemoteSubscriptionDoesNotPersistOrFallback(t *testing.T) {
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
			tag, nodes, err := ResolveSubscription(server.Client(), dir, link, componentoutbound.ValidateNodeLink)
			if err != nil || tag != "ordinary" || len(nodes) != 1 || nodes[0] != node {
				t.Fatalf("ordinary download returned tag=%q nodes=%v err=%v", tag, nodes, err)
			}
			if _, err := os.Stat(filepath.Join(dir, "persist.d")); !os.IsNotExist(err) {
				t.Fatalf("ordinary download created persistence directory: %v", err)
			}
			cached := encodedSubscription(testSSNode("cached.example"))
			cachePath := writePersistedSubscription(t, dir, "ordinary", cached)
			server.Close()
			_, nodes, err = ResolveSubscription(server.Client(), dir, link, componentoutbound.ValidateNodeLink)
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
