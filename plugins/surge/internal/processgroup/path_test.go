//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only

package processgroup

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/procfs"
)

func TestCurrentPathCoordinates(t *testing.T) {
	for _, tc := range []struct {
		name, root, path, member string
	}{
		{"hierarchy", "/", "/app.slice/dae.service/daemon", "/app.slice/dae.service/daemon"},
		{"mount-root-relative", "/app.slice/dae.service", "/app.slice/dae.service/daemon", "/daemon"},
		{"namespace-relative", "/app.slice/dae.service", "/daemon", "/daemon"},
		{"namespace-root", "/app.slice/dae.service", "/", "/"},
		{"hierarchy-at-mount-root", "/app.slice/dae.service", "/app.slice/dae.service", "/"},
		{"escaped-root", "/delegated space\tback\\slash", "/delegated space\tback\\slash/daemon", "/daemon"},
		{"literal-octal-root", `/delegated\040`, `/delegated\040/daemon`, "/daemon"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mountPoint := filepath.Join(t.TempDir(), "mount space\tline\nback\\040")
			current := filepath.Join(mountPoint, tc.member)
			writeMembership(t, current, fmt.Sprintf("%d\n%d\n", os.Getpid()+1, os.Getpid()))
			if other := filepath.Join(mountPoint, tc.path); other != current {
				writeMembership(t, other, fmt.Sprintf("%d\n", os.Getpid()+1))
			}
			escape := strings.NewReplacer(`\`, `\134`, " ", `\040`, "\t", `\011`, "\n", `\012`)
			procRoot := t.TempDir()
			if err := os.Mkdir(filepath.Join(procRoot, "self"), 0700); err != nil {
				t.Fatal(err)
			}
			line := fmt.Sprintf("23 1 0:42 %s %s rw - cgroup2 cgroup rw\n", escape.Replace(tc.root), escape.Replace(mountPoint))
			if err := os.WriteFile(filepath.Join(procRoot, "self/mountinfo"), []byte(line), 0600); err != nil {
				t.Fatal(err)
			}
			fs, err := procfs.NewFS(procRoot)
			if err != nil {
				t.Fatal(err)
			}
			mounts, err := fs.GetMounts()
			if err != nil {
				t.Fatal(err)
			}
			root, got, err := currentPath(tc.path, mounts)
			if err != nil || root != mountPoint || got != current {
				t.Fatalf("currentPath = (%q, %q, %v), want (%q, %q)", root, got, err, mountPoint, current)
			}
		})
	}
}

func TestCurrentPathOutsideNamespaceMount(t *testing.T) {
	mountPoint := t.TempDir()
	current := filepath.Join(mountPoint, "daemon")
	writeMembership(t, current, fmt.Sprintf("%d\n", os.Getpid()))
	inside := &procfs.MountInfo{FSType: "cgroup2", Root: "/", MountPoint: mountPoint}
	for _, root := range []string{"/..", "/../..", "/../../outside"} {
		t.Run(root, func(t *testing.T) {
			outside := &procfs.MountInfo{FSType: "cgroup2", Root: root, MountPoint: mountPoint}
			if _, _, err := currentPath("/daemon", []*procfs.MountInfo{outside}); err == nil {
				t.Fatal("accepted a mount outside the cgroup namespace")
			}
			for _, mounts := range [][]*procfs.MountInfo{{outside, inside}, {inside, outside}} {
				gotRoot, got, err := currentPath("/daemon", mounts)
				if err != nil || gotRoot != mountPoint || got != current {
					t.Fatalf("namespace mount = (%q, %q, %v), want (%q, %q)", gotRoot, got, err, mountPoint, current)
				}
			}
		})
	}
}

func TestCurrentPathRejectsInvalidPaths(t *testing.T) {
	for _, tc := range []struct {
		name, root, mountPoint, path, wantErr string
	}{
		{"relative-cgroup", "/", "/mount", "daemon", "absolute"},
		{"empty-cgroup", "/", "/mount", "", "absolute"},
		{"cgroup-parent", "/", "/mount", "/../daemon", "parent traversal"},
		{"cgroup-hidden-parent", "/", "/mount", "/private/../daemon", "parent traversal"},
		{"cgroup-nul", "/", "/mount", "/daemon\x00", "absolute"},
		{"relative-root", "private", "/mount", "/daemon", "absolute"},
		{"root-parent", "/private/../", "/mount", "/daemon", "parent traversal"},
		{"relative-mount", "/", "mount", "/daemon", "absolute"},
		{"mount-parent", "/", "/mount/../private", "/daemon", "parent traversal"},
		{"invalid-root-escape", `/private\057..`, "/mount", "/daemon", "escape"},
		{"invalid-mount-escape", "/", `/mount\x20`, "/daemon", "escape"},
		{"short-mount-escape", "/", `/mount\04`, "/daemon", "escape"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mounts := []*procfs.MountInfo{{FSType: "cgroup2", Root: tc.root, MountPoint: tc.mountPoint}}
			root, current, err := currentPath(tc.path, mounts)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) || root != "" || current != "" {
				t.Fatalf("invalid coordinates = (%q, %q, %v), want error containing %q", root, current, err, tc.wantErr)
			}
		})
	}
}

func TestCurrentPathMembership(t *testing.T) {
	for _, tc := range []struct {
		name, path, member, procs string
	}{
		{"other-process", "/daemon", "/daemon", fmt.Sprintf("%d\n", os.Getpid()+1)},
		{"empty-group", "/daemon", "/daemon", ""},
		{"invalid-membership", "/daemon", "/daemon", "not-a-pid\n"},
		{"root-prefix-is-not-ancestor", "/private-other/daemon", "/-other/daemon", fmt.Sprintf("%d\n", os.Getpid())},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mountPoint := t.TempDir()
			writeMembership(t, filepath.Join(mountPoint, tc.member), tc.procs)
			// A descendant's membership must not validate its parent.
			writeMembership(t, filepath.Join(mountPoint, tc.member, "child"), fmt.Sprintf("%d\n", os.Getpid()))
			mounts := []*procfs.MountInfo{{FSType: "cgroup2", Root: "/private", MountPoint: mountPoint}}
			root, current, err := currentPath(tc.path, mounts)
			if err == nil || root != "" || current != "" {
				t.Fatalf("accepted wrong membership: (%q, %q, %v)", root, current, err)
			}
		})
	}
}

func TestCurrentPathAmbiguity(t *testing.T) {
	mountPoint := t.TempDir()
	procs := fmt.Sprintf("%d\n", os.Getpid())
	writeMembership(t, filepath.Join(mountPoint, "daemon"), procs)
	writeMembership(t, filepath.Join(mountPoint, "private/daemon"), procs)
	mount := &procfs.MountInfo{FSType: "cgroup2", Root: "/private", MountPoint: mountPoint}
	if _, _, err := currentPath("/private/daemon", []*procfs.MountInfo{mount}); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("want ambiguous coordinates in one mount, got %v", err)
	}
	otherPoint := t.TempDir()
	writeMembership(t, filepath.Join(otherPoint, "daemon"), procs)
	other := &procfs.MountInfo{FSType: "cgroup2", Root: "/private", MountPoint: otherPoint}
	if _, _, err := currentPath("/daemon", []*procfs.MountInfo{mount, other}); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("want ambiguous mounts, got %v", err)
	}
	if _, _, err := currentPath("/daemon", []*procfs.MountInfo{mount, mount}); err != nil {
		t.Fatalf("identical coordinates are not ambiguous: %v", err)
	}
}

func writeMembership(t *testing.T, path, procs string) {
	t.Helper()
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "cgroup.procs"), []byte(procs), 0600); err != nil {
		t.Fatal(err)
	}
}
