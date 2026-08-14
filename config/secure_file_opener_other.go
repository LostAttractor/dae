//go:build !linux

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"fmt"
	"os"
	"path/filepath"
)

type secureFileOpener struct {
	entryDir     string
	canonicalDir string
}

func newSecureFileOpener(entryDir string) (*secureFileOpener, error) {
	canonicalDir, err := filepath.EvalSymlinks(entryDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve entry directory: %w", err)
	}
	return &secureFileOpener{
		entryDir:     entryDir,
		canonicalDir: filepath.Clean(canonicalDir),
	}, nil
}

func (o *secureFileOpener) Open(path string) (*os.File, error) {
	if _, err := relativePathWithin(o.entryDir, path); err != nil {
		return nil, err
	}
	canonicalPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve config file: %w", err)
	}
	canonicalPath = filepath.Clean(canonicalPath)
	if _, err := relativePathWithin(o.canonicalDir, canonicalPath); err != nil {
		return nil, err
	}
	// Platforms without openat2 get snapshot containment. Opening the canonical
	// target avoids re-following the input symlink, but directory mutation can race.
	return os.Open(canonicalPath)
}

func (o *secureFileOpener) Close() error {
	return nil
}
