//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only

package processgroup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/containerd/cgroups/v3/cgroup2"
	"github.com/prometheus/procfs"
)

// Current returns the cgroup v2 mount and current group, verified against this process's PID.
func Current() (root, current string, err error) {
	path, err := cgroup2.PidGroupPath(os.Getpid())
	if err != nil {
		return "", "", err
	}
	mounts, err := procfs.GetMounts()
	if err != nil {
		return "", "", err
	}
	return currentPath(path, mounts)
}

func currentPath(path string, mounts []*procfs.MountInfo) (root, current string, err error) {
	path, err = cleanAbsolute(path)
	if err != nil {
		return "", "", err
	}
	for _, mount := range mounts {
		if mount.FSType != "cgroup2" {
			continue
		}
		// Inherited mounts outside the cgroup namespace have /../ roots.
		if mount.Root == "/.." || strings.HasPrefix(mount.Root, "/../") {
			continue
		}
		mountRoot, err := mountPath(mount.Root)
		if err != nil {
			return "", "", fmt.Errorf("cgroup mount root: %w", err)
		}
		mountPoint, err := mountPath(mount.MountPoint)
		if err != nil {
			return "", "", fmt.Errorf("cgroup mount point: %w", err)
		}
		// A namespace-relative path may not include mountinfo's hierarchy root.
		candidates := []string{filepath.Join(mountPoint, path)}
		if relative, err := filepath.Rel(mountRoot, path); err == nil && filepath.IsLocal(relative) {
			candidate := filepath.Join(mountPoint, relative)
			if !slices.Contains(candidates, candidate) {
				candidates = append(candidates, candidate)
			}
		}
		for _, candidate := range candidates {
			manager, err := cgroup2.Load("/", cgroup2.WithMountpoint(candidate))
			if err != nil {
				return "", "", err
			}
			pids, err := manager.Procs(false)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return "", "", fmt.Errorf("verify cgroup membership in %s: %w", candidate, err)
			}
			if !slices.Contains(pids, uint64(os.Getpid())) {
				continue
			}
			if current != "" && (root != mountPoint || current != candidate) {
				return "", "", fmt.Errorf("ambiguous cgroup mount coordinates for %q", path)
			}
			root, current = mountPoint, candidate
		}
	}
	if current == "" {
		return "", "", fmt.Errorf("no cgroup v2 mount contains process %d at %q", os.Getpid(), path)
	}
	return root, current, nil
}

func cleanAbsolute(path string) (string, error) {
	if !filepath.IsAbs(path) || strings.ContainsRune(path, '\x00') {
		return "", fmt.Errorf("invalid absolute cgroup path %q", path)
	}
	for component := range strings.SplitSeq(path, "/") {
		if component == ".." {
			return "", fmt.Errorf("cgroup path %q contains parent traversal", path)
		}
	}
	return filepath.Clean(path), nil
}

func mountPath(value string) (string, error) {
	var path strings.Builder
	for {
		prefix, rest, escaped := strings.Cut(value, `\`)
		path.WriteString(prefix)
		if !escaped {
			return cleanAbsolute(path.String())
		}
		if len(rest) < 3 {
			return "", fmt.Errorf("invalid mount path escape in %q", value)
		}
		switch rest[:3] {
		case "040":
			path.WriteByte(' ')
		case "011":
			path.WriteByte('\t')
		case "012":
			path.WriteByte('\n')
		case "134":
			path.WriteByte('\\')
		default:
			return "", fmt.Errorf("invalid mount path escape in %q", value)
		}
		value = rest[3:]
	}
}

func poolParent(root, current string) (string, error) {
	root, err := cleanAbsolute(root)
	if err != nil {
		return "", err
	}
	current, err = cleanAbsolute(current)
	if err != nil {
		return "", err
	}
	if relative, err := filepath.Rel(root, current); err != nil || !filepath.IsLocal(relative) {
		return "", fmt.Errorf("cgroup %q is outside mount %q", current, root)
	}
	for path := current; ; path = filepath.Dir(path) {
		name := filepath.Base(path)
		if strings.HasSuffix(name, ".service") || strings.HasSuffix(name, ".scope") {
			if path == current {
				return "", fmt.Errorf("%s needs Delegate=memory and DelegateSubgroup=daemon", path)
			}
			if path != root {
				// systemd places the daemon in a subgroup when delegation is configured.
				if err := os.WriteFile(filepath.Join(path, "cgroup.subtree_control"), []byte("+memory"), 0600); err != nil {
					return "", fmt.Errorf("enable delegated memory controller in %s: %w", path, err)
				}
				return path, nil
			}
		}
		if strings.HasSuffix(name, ".slice") {
			return "", fmt.Errorf("%s is not delegated (systemd: Delegate=memory and DelegateSubgroup=daemon)", path)
		}
		if path == root {
			// The real hierarchy root has no memory.max, even with memory enabled.
			if _, err := os.ReadFile(filepath.Join(path, "memory.max")); err != nil {
				return "", fmt.Errorf("cgroup mount root %s lacks a usable memory limit: %w", path, err)
			}
		}
		// Non-systemd supervisors can supply an already enabled private subtree.
		controllers, err := os.ReadFile(filepath.Join(path, "cgroup.subtree_control"))
		if err != nil {
			return "", err
		}
		if slices.Contains(strings.Fields(string(controllers)), "memory") {
			return path, nil
		}
		if path == root {
			return "", fmt.Errorf("cgroup mount root %s has no delegated memory controller", path)
		}
	}
}
