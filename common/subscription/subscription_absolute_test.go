// SPDX-License-Identifier: AGPL-3.0-only

package subscription

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	componentoutbound "github.com/daeuniverse/dae/component/outbound"
)

func TestResolveSubscriptionAbsoluteFileOutsideConfigDirectory(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "missing-config")
	externalDir := filepath.Join(root, "external")
	if err := os.Mkdir(externalDir, 0700); err != nil {
		t.Fatal(err)
	}
	node := testSSNode("absolute.example")
	for _, test := range []struct {
		name string
		mode os.FileMode
	}{
		{"nodes.sub", 0600},
		{"nodes with spaces.sub", 0600},
		{"nodes 100%2F complete.sub", 0640},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(externalDir, test.name)
			if err := os.WriteFile(path, encodedSubscription(node), test.mode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, test.mode); err != nil {
				t.Fatal(err)
			}
			link := "absolute:" + (&url.URL{Scheme: "file", Path: path}).String()
			tag, nodes, err := ResolveSubscriptionContext(t.Context(), http.DefaultClient, ResolveOptions{BaseDir: configDir}, link, componentoutbound.ValidateNodeLink)
			if err != nil {
				t.Fatal(err)
			}
			if tag != "absolute" || len(nodes) != 1 || nodes[0] != node {
				t.Fatalf("absolute file returned tag=%q nodes=%v, want absolute and %q", tag, nodes, node)
			}
			if _, err := os.Stat(configDir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("reading an absolute subscription created its unrelated config directory: %v", err)
			}
		})
	}
}

func TestResolveSubscriptionAbsoluteFileFollowsSymlinks(t *testing.T) {
	for _, intermediate := range []bool{false, true} {
		name := "final component"
		if intermediate {
			name = "intermediate component"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			targetDir := filepath.Join(root, "target")
			if err := os.Mkdir(targetDir, 0700); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(targetDir, "nodes.sub")
			node := testSSNode("symlink.example")
			if err := os.WriteFile(target, encodedSubscription(node), 0600); err != nil {
				t.Fatal(err)
			}
			linkPath := filepath.Join(root, "link")
			readPath := linkPath
			if intermediate {
				target = targetDir
				readPath = filepath.Join(linkPath, "nodes.sub")
			}
			if err := os.Symlink(target, linkPath); err != nil {
				t.Fatal(err)
			}
			link := (&url.URL{Scheme: "file", Path: readPath}).String()
			_, nodes, err := ResolveSubscriptionContext(t.Context(), http.DefaultClient, ResolveOptions{BaseDir: filepath.Join(root, "missing-config")}, link, componentoutbound.ValidateNodeLink)
			if err != nil || len(nodes) != 1 || nodes[0] != node {
				t.Fatalf("absolute symlink returned nodes=%v error=%v, want %q", nodes, err, node)
			}
		})
	}
}

func TestResolveSubscriptionAbsoluteFileReadsRotatedSecrets(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "missing-config")
	runDir := filepath.Join(root, "run")
	secretsLink := filepath.Join(runDir, "secrets")
	link := "flowercloud:" + (&url.URL{Scheme: "file", Path: filepath.Join(secretsLink, "dae", "subscription", "flowercloud")}).String()
	for _, version := range []string{"1", "2"} {
		targetDir := filepath.Join(runDir, "secrets.d", version, "dae", "subscription")
		if err := os.MkdirAll(targetDir, 0700); err != nil {
			t.Fatal(err)
		}
		node := testSSNode("version" + version + ".example")
		if err := os.WriteFile(filepath.Join(targetDir, "flowercloud"), encodedSubscription(node), 0600); err != nil {
			t.Fatal(err)
		}
		nextLink := filepath.Join(runDir, ".secrets-next")
		if err := os.Symlink(filepath.Join("secrets.d", version), nextLink); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(nextLink, secretsLink); err != nil {
			t.Fatal(err)
		}
		tag, nodes, err := ResolveSubscriptionContext(t.Context(), http.DefaultClient, ResolveOptions{BaseDir: configDir}, link, componentoutbound.ValidateNodeLink)
		if err != nil || tag != "flowercloud" || len(nodes) != 1 || nodes[0] != node {
			t.Fatalf("secret version %s returned tag=%q nodes=%v error=%v, want %q", version, tag, nodes, err, node)
		}
	}
	if _, err := os.Stat(configDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reading rotated secrets created its unrelated config directory: %v", err)
	}
}

func TestResolveSubscriptionAbsoluteFileChecksSymlinkTargetPermissions(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.sub")
	if err := os.WriteFile(target, encodedSubscription(testSSNode("unsafe.example")), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0644); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(root, "nodes.sub")
	if err := os.Symlink(target, linkPath); err != nil {
		t.Fatal(err)
	}
	link := (&url.URL{Scheme: "file", Path: linkPath}).String()
	_, nodes, err := ResolveSubscriptionContext(t.Context(), http.DefaultClient, ResolveOptions{BaseDir: filepath.Join(root, "missing-config")}, link, componentoutbound.ValidateNodeLink)
	if err == nil || len(nodes) != 0 || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("unsafe symlink target returned nodes=%v error=%v, want permission rejection", nodes, err)
	}
}

func TestResolveSubscriptionAbsoluteFileRejectsBrokenAndCircularSymlinks(t *testing.T) {
	for _, circular := range []bool{false, true} {
		name := "broken"
		if circular {
			name = "circular"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			linkPath := filepath.Join(root, "nodes.sub")
			target := filepath.Join(root, "target.sub")
			if err := os.Symlink(target, linkPath); err != nil {
				t.Fatal(err)
			}
			if circular {
				if err := os.Symlink(linkPath, target); err != nil {
					t.Fatal(err)
				}
			}
			link := (&url.URL{Scheme: "file", Path: linkPath}).String()
			_, nodes, err := ResolveSubscriptionContext(t.Context(), http.DefaultClient, ResolveOptions{BaseDir: filepath.Join(root, "missing-config")}, link, componentoutbound.ValidateNodeLink)
			if err == nil || len(nodes) != 0 {
				t.Fatalf("%s symlink returned nodes=%v error=%v, want rejection", name, nodes, err)
			}
		})
	}
}

func TestResolveSubscriptionAbsoluteFileRejectsDirectoryAndUnsafePermissions(t *testing.T) {
	for _, test := range []struct {
		name, reason string
		mode         os.FileMode
		directory    bool
	}{
		{"directory", "regular file", 0700, true},
		{"others readable", "permissions", 0644, false},
		{"group writable", "permissions", 0660, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "nodes.sub")
			if test.directory {
				if err := os.Mkdir(path, test.mode); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(path, encodedSubscription(testSSNode("permissions.example")), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, test.mode); err != nil {
					t.Fatal(err)
				}
			}
			link := (&url.URL{Scheme: "file", Path: path}).String()
			_, nodes, err := ResolveSubscriptionContext(t.Context(), http.DefaultClient, ResolveOptions{BaseDir: filepath.Join(root, "missing-config")}, link, componentoutbound.ValidateNodeLink)
			if err == nil || len(nodes) != 0 || !strings.Contains(err.Error(), test.reason) {
				t.Fatalf("absolute %s returned nodes=%v error=%v, want %q rejection", test.name, nodes, err, test.reason)
			}
		})
	}
}

func TestResolveSubscriptionRelativeFileCannotEscapeConfigDirectory(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "config")
	if err := os.Mkdir(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "outside.sub"), encodedSubscription(testSSNode("outside.example")), 0600); err != nil {
		t.Fatal(err)
	}
	for _, link := range []string{
		"file:../outside.sub",
		"file:nested/../../outside.sub",
		"file:nested/%2e%2e/%2e%2e/outside.sub",
	} {
		t.Run(link, func(t *testing.T) {
			_, nodes, err := ResolveSubscriptionContext(t.Context(), http.DefaultClient, ResolveOptions{BaseDir: configDir}, link, componentoutbound.ValidateNodeLink)
			if err == nil || len(nodes) != 0 {
				t.Fatalf("relative traversal returned nodes=%v error=%v, want rejection", nodes, err)
			}
		})
	}
}
