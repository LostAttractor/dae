//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only

package processgroup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPoolParentMountRoot(t *testing.T) {
	for _, tc := range []struct {
		name, root, current, controllers string
		memoryMax, want                  bool
	}{
		{"hierarchy-root", "mount", "daemon", "memory", false, false},
		{"hierarchy-root-service-name", "dae.service", "daemon", "memory", false, false},
		{"delegated-root", "mount", "daemon", "memory pids", true, true},
		{"delegated-service-root", "dae.service", "daemon", "memory", true, true},
		{"delegated-scope-root", "test.scope", "daemon", "memory", true, true},
		{"disabled-memory", "mount", "daemon", "pids", true, false},
		{"disabled-service-root", "dae.service", "daemon", "pids", true, false},
		{"root-service-needs-subgroup", "dae.service", ".", "memory", true, false},
		{"root-scope-needs-subgroup", "test.scope", ".", "memory", true, false},
		{"slice-root", "app.slice", "daemon", "memory", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), tc.root)
			current := filepath.Join(root, tc.current)
			if err := os.MkdirAll(current, 0700); err != nil {
				t.Fatal(err)
			}
			if current != root {
				if err := os.WriteFile(filepath.Join(current, "cgroup.subtree_control"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.memoryMax {
				if err := os.WriteFile(filepath.Join(root, "memory.max"), []byte("max"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			control := filepath.Join(root, "cgroup.subtree_control")
			if err := os.WriteFile(control, []byte(tc.controllers), 0600); err != nil {
				t.Fatal(err)
			}
			got, err := poolParent(root, current)
			if tc.want {
				if err != nil || got != root {
					t.Fatalf("parent=%q, err=%v, want %q", got, err, root)
				}
			} else if err == nil || got != "" {
				t.Fatalf("accepted undelegated root: %q, %v", got, err)
			}
			data, err := os.ReadFile(control)
			if err != nil || string(data) != tc.controllers {
				t.Fatalf("modified mount-root controllers: %q, %v", data, err)
			}
		})
	}
}

func TestPoolParentRejectsInvalidPaths(t *testing.T) {
	root := t.TempDir()
	for _, tc := range []struct {
		name, root, current, wantErr string
	}{
		{"relative-root", "mount", root, "absolute"},
		{"relative-current", root, "daemon", "absolute"},
		{"outside-root", root, filepath.Dir(root), "outside mount"},
		{"root-prefix-is-not-ancestor", root, root + "-other/daemon", "outside mount"},
		{"root-parent-traversal", root + "/child/..", root, "parent traversal"},
		{"current-parent-traversal", root, root + "/child/../daemon", "parent traversal"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := poolParent(tc.root, tc.current)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) || got != "" {
				t.Fatalf("invalid path = (%q, %v), want error containing %q", got, err, tc.wantErr)
			}
		})
	}
}

func TestPoolParentDelegationBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, unit, current string
		writable            bool
		want                string
	}{
		{"service", "app.slice/dae.service", "app.slice/dae.service/daemon", true, "app.slice/dae.service"},
		{"scope", "app.slice/test.scope", "app.slice/test.scope/daemon", true, "app.slice/test.scope"},
		{"enable-failure", "app.slice/dae.service", "app.slice/dae.service/daemon", false, ""},
		{"missing-subgroup", "app.slice/dae.service", "app.slice/dae.service", true, ""},
		{"nested-service", "app.slice/outer.service/inner.service", "app.slice/outer.service/inner.service/daemon", true, "app.slice/outer.service/inner.service"},
		{"slice", "app.slice", "app.slice/daemon", true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			current, unit := filepath.Join(root, tc.current), filepath.Join(root, tc.unit)
			if err := os.MkdirAll(current, 0700); err != nil {
				t.Fatal(err)
			}
			for path := current; ; path = filepath.Dir(path) {
				control := filepath.Join(path, "cgroup.subtree_control")
				if path == unit && !tc.writable {
					// A failed enable must not fall back to an ancestor.
					if err := os.Mkdir(control, 0700); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(control, nil, 0600); err != nil {
					t.Fatal(err)
				}
				if path == root {
					break
				}
			}
			// An otherwise usable ancestor must never let us escape the unit.
			if err := os.WriteFile(filepath.Join(root, "memory.max"), []byte("max"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "cgroup.subtree_control"), []byte("memory"), 0600); err != nil {
				t.Fatal(err)
			}
			got, err := poolParent(root, current)
			if tc.want == "" {
				if err == nil || got != "" {
					t.Fatalf("escaped delegation boundary: %q, %v", got, err)
				}
			} else if err != nil || got != filepath.Join(root, tc.want) {
				t.Fatalf("parent=%q, err=%v", got, err)
			}
			data, err := os.ReadFile(filepath.Join(root, "cgroup.subtree_control"))
			if err != nil || string(data) != "memory" {
				t.Fatal("modified ancestor controller", string(data), err)
			}
		})
	}
}
