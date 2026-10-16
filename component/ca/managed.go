// SPDX-License-Identifier: AGPL-3.0-only

package ca

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/daeuniverse/dae/common/persist"
	"golang.org/x/sys/unix"
)

const ManagedDirectory = "pki"
const DefaultName = "dae Local CA"
const DefaultValidity = 3650 * 24 * time.Hour

func ManagedPaths(directory string) (certificate, key string) {
	return filepath.Join(directory, "ca.pem"), filepath.Join(directory, "ca.key")
}

// Ensure creates an identity only when its entire store is absent. An existing
// store with missing, invalid or expired files is an error, never a new identity.
func Ensure(directory string) (*Authority, error) {
	if _, err := os.Lstat(directory); errors.Is(err, os.ErrNotExist) {
		if err := Initialize(directory, DefaultName, DefaultValidity); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("CA store %s must be a directory", directory)
	}
	cert, key := ManagedPaths(directory)
	authority, err := Load(cert, key)
	if err != nil {
		return nil, fmt.Errorf("load persistent CA in %s (restore its files or explicitly replace the identity): %w", directory, err)
	}
	return authority, nil
}

// Initialize publishes a complete store in one atomic, no-replace rename.
// Concurrent initializers cannot replace the winner or observe a partial pair.
func Initialize(directory, name string, validity time.Duration) error {
	if _, err := os.Lstat(directory); err == nil {
		return fmt.Errorf("CA store %s already exists: %w", directory, os.ErrExist)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(directory)
	if err := persist.MkdirAll(parent, 0700); err != nil {
		return err
	}
	staged, err := os.MkdirTemp(parent, ".dae-ca-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staged)
	cert, key := ManagedPaths(staged)
	if err := Generate(cert, key, name, validity); err != nil {
		return err
	}
	if err := unix.Renameat2(unix.AT_FDCWD, staged, unix.AT_FDCWD, directory, unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("publish CA store %s: %w", directory, err)
	}
	return persist.AfterPublish(persist.SyncDir(parent))
}
