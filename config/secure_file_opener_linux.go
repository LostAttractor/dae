//go:build linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

type secureFileOpener struct {
	entryDir     string
	canonicalDir string
	procRoot     string
	root         *os.File
}

func newSecureFileOpener(entryDir string) (*secureFileOpener, error) {
	rootFd, err := unix.Open(entryDir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	root := os.NewFile(uintptr(rootFd), entryDir)
	procRoot := filepath.Join("/proc/self/fd", strconv.Itoa(rootFd))
	canonicalDir, err := filepath.EvalSymlinks(procRoot)
	if err != nil {
		root.Close()
		return nil, fmt.Errorf("failed to resolve entry directory: %w", err)
	}
	return &secureFileOpener{
		entryDir:     entryDir,
		canonicalDir: filepath.Clean(canonicalDir),
		procRoot:     procRoot,
		root:         root,
	}, nil
}

func (o *secureFileOpener) Open(path string) (*os.File, error) {
	rel, err := relativePathWithin(o.entryDir, path)
	if err != nil {
		return nil, err
	}

	// Resolve host-absolute and relative symlinks from the stable root descriptor.
	// Opening the canonical target beneath the same descriptor prevents a raced
	// path component from escaping after this snapshot.
	canonicalPath, err := filepath.EvalSymlinks(filepath.Join(o.procRoot, rel))
	if err != nil {
		return nil, fmt.Errorf("failed to resolve config file: %w", err)
	}
	canonicalRel, err := relativePathWithin(o.canonicalDir, filepath.Clean(canonicalPath))
	if err != nil {
		return nil, err
	}
	fd, err := unix.Openat2(int(o.root.Fd()), canonicalRel, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func openConfigEntry(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func (o *secureFileOpener) Close() error {
	return o.root.Close()
}
