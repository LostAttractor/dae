// SPDX-License-Identifier: AGPL-3.0-only

// Package persist provides filesystem publication and durability primitives.
package persist

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// PublishedError means the new namespace entry is visible, but its durability
// could not be confirmed. Callers must not treat it as an unapplied operation.
type PublishedError struct{ Err error }

func (e *PublishedError) Error() string {
	return fmt.Sprintf("published but durability is unconfirmed: %v", e.Err)
}
func (e *PublishedError) Unwrap() error { return e.Err }

func AfterPublish(err error) error {
	if err == nil {
		return nil
	}
	return &PublishedError{Err: err}
}

func Published(err error) bool {
	_, ok := errors.AsType[*PublishedError](err)
	return err == nil || ok
}

func SyncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}

// MkdirAll makes namespace creation durable, including a retry after an earlier
// sync failed. Existing directories alone do not prove their entries were synced.
func MkdirAll(path string, mode os.FileMode) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for {
		if err := SyncDir(path); err != nil {
			return err
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
	}
}
