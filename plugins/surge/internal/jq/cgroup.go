// SPDX-License-Identifier: AGPL-3.0-only

package jq

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

const (
	WorkerMemory = 128 << 20
	MaxWorkers   = 4
	PoolMemory   = WorkerMemory * MaxWorkers
)

type memoryGroup struct {
	path string
	file *os.File
}

func createMemoryGroup(parent, name string, limit int64, children bool) (*memoryGroup, error) {
	path := filepath.Join(parent, name)
	if err := os.Mkdir(path, 0700); err != nil {
		return nil, err
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.Remove(path)
		}
	}()
	for _, setting := range []struct{ name, value string }{
		{"memory.max", strconv.FormatInt(limit, 10)}, {"memory.swap.max", "0"},
	} {
		if err := os.WriteFile(filepath.Join(path, setting.name), []byte(setting.value), 0600); err != nil {
			return nil, err
		}
		got, err := os.ReadFile(filepath.Join(path, setting.name))
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(string(got)) != setting.value {
			return nil, fmt.Errorf("verify %s: got %q, want %q", setting.name, got, setting.value)
		}
	}
	if children {
		if err := os.WriteFile(filepath.Join(path, "cgroup.subtree_control"), []byte("+memory"), 0600); err != nil {
			return nil, err
		}
	} else if err := os.WriteFile(filepath.Join(path, "memory.oom.group"), []byte("1"), 0600); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	complete = true
	return &memoryGroup{path: path, file: file}, nil
}

// Only create private groups beneath an ancestor that already delegates memory.
// Never move the daemon or change controllers on existing system groups.
func newPoolGroup() (*memoryGroup, error) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return nil, err
	}
	var relative string
	for line := range strings.SplitSeq(string(data), "\n") {
		if value, ok := strings.CutPrefix(line, "0::"); ok {
			relative = value
			break
		}
	}
	if relative == "" {
		return nil, fmt.Errorf("cgroup v2 memory controller is required")
	}
	const root = "/sys/fs/cgroup"
	path := filepath.Join(root, filepath.Clean("/"+relative))
	name := fmt.Sprintf("dae-surge-jq-%d-%s", os.Getpid(), rand.Text()[:12])
	for {
		controllers, readErr := os.ReadFile(filepath.Join(path, "cgroup.subtree_control"))
		if readErr == nil && slices.Contains(strings.Fields(string(controllers)), "memory") {
			group, createErr := createMemoryGroup(path, name, PoolMemory, true)
			if createErr == nil {
				return group, nil
			}
			err = createErr
		}
		if path == root {
			break
		}
		path = filepath.Dir(path)
	}
	if err == nil {
		err = fmt.Errorf("no ancestor delegates the memory controller")
	}
	return nil, fmt.Errorf("Surge jq requires permission to create cgroup v2 memory.max and memory.swap.max limits: %w", err)
}

func (g *memoryGroup) close() error {
	_ = g.file.Close()
	return os.Remove(g.path)
}

// Run refuses an internal entry point that was not started inside a hard limit.
func Run(input io.Reader, output io.Writer) error {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if path, ok := strings.CutPrefix(line, "0::"); ok {
			path = filepath.Join("/sys/fs/cgroup", filepath.Clean("/"+path))
			memory, err := os.ReadFile(filepath.Join(path, "memory.max"))
			if err != nil {
				return err
			}
			limit, err := strconv.ParseInt(strings.TrimSpace(string(memory)), 10, 64)
			if err != nil || limit <= 0 || limit > WorkerMemory {
				return ErrUnavailable
			}
			swap, err := os.ReadFile(filepath.Join(path, "memory.swap.max"))
			if err != nil || strings.TrimSpace(string(swap)) != "0" {
				return ErrUnavailable
			}
			return Serve(input, output)
		}
	}
	return ErrUnavailable
}
