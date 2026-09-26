// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/daeuniverse/dae/component/plugin"
	"golang.org/x/sys/unix"
)

const maxStorageValueSize = 8 << 20

var errStorageTooLarge = fmt.Errorf("plugin storage value exceeds 8 MiB: %w", fs.ErrInvalid)

type fileStorage struct {
	base      string
	namespace string
}

// newPluginStorage only selects the namespace; preparation must not create files.
func newPluginStorage(baseDir string, spec plugin.Spec) (plugin.Storage, error) {
	if baseDir == "" {
		return nil, nil
	}
	if spec.Type == "" || spec.ID == "" {
		return nil, fmt.Errorf("plugin storage requires a type and instance: %w", fs.ErrInvalid)
	}
	base, err := filepath.Abs(baseDir)
	if err != nil {
		return nil, err
	}
	escape := func(s string) string {
		if s == "." || s == ".." {
			return strings.ReplaceAll(s, ".", "%2E")
		}
		// Reserve @ for the type/instance separator, including in default names.
		return strings.ReplaceAll(url.PathEscape(s), "@", "%40")
	}
	namespace := escape(spec.Type)
	if spec.ID != spec.Type {
		namespace += "@" + escape(spec.ID)
	}
	return &fileStorage{base: base, namespace: namespace}, nil
}

func validStorageKey(key string) bool {
	if len(key) == 0 || len(key) > 128 {
		return false
	}
	for i, c := range []byte(key) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' {
			continue
		}
		if i == 0 || c != '.' && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

// Open each namespace relative to its parent, keeping all value operations
// rooted in the instance directory. Namespace directories cannot be symlinks.
func (s *fileStorage) open(key string, create bool) (*os.Root, error) {
	if !validStorageKey(key) {
		return nil, fs.ErrInvalid
	}
	if create {
		if err := os.MkdirAll(s.base, 0700); err != nil {
			return nil, err
		}
	}
	root, err := os.OpenRoot(s.base)
	if err != nil {
		return nil, err
	}
	for _, name := range []string{"plugins", "state", s.namespace} {
		next, err := openStorageDir(root, name, create)
		root.Close()
		if err != nil {
			return nil, err
		}
		root = next
	}
	return root, nil
}

func openStorageDir(parent *os.Root, name string, create bool) (*os.Root, error) {
	if create {
		if err := parent.Mkdir(name, 0700); err != nil && !errors.Is(err, fs.ErrExist) {
			return nil, err
		} else if err == nil {
			if err := syncStorageDir(parent); err != nil {
				return nil, err
			}
		}
	}
	info, err := parent.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("plugin storage namespace is not a directory: %w", fs.ErrInvalid)
	}
	next, err := parent.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	// OpenRoot follows in-root symlinks. Check the held directory, not the path
	// again, so replacement after Lstat cannot redirect operations to a sibling.
	opened, err := next.Stat(".")
	if err == nil && !os.SameFile(info, opened) {
		err = fs.ErrInvalid
	}
	if err != nil {
		next.Close()
		return nil, err
	}
	return next, nil
}

func (s *fileStorage) Get(key string) ([]byte, error) {
	root, err := s.open(key, false)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	// Root.Open follows in-root symlinks even with O_NOFOLLOW. Use the held
	// directory fd and inspect the opened file; atomic Put replacements remain
	// readable without a check/open race. Nonblocking open also rejects FIFOs
	// without waiting for a writer before the regular-file check.
	dir, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	fd, err := unix.Openat(int(dir.Fd()), key, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ELOOP) {
		return nil, fs.ErrInvalid
	}
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), key)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fs.ErrInvalid
	}
	if info.Size() > maxStorageValueSize {
		return nil, errStorageTooLarge
	}
	value, err := io.ReadAll(io.LimitReader(f, maxStorageValueSize+1))
	if len(value) > maxStorageValueSize {
		return nil, errStorageTooLarge
	}
	return value, err
}

func (s *fileStorage) Put(key string, value []byte) error {
	if len(value) > maxStorageValueSize {
		return errStorageTooLarge
	}
	root, err := s.open(key, true)
	if err != nil {
		return err
	}
	defer root.Close()
	tmp := ".tmp-" + rand.Text()
	f, err := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(tmp)
	_, err = f.Write(value)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err := root.Rename(tmp, key); err != nil {
		return err
	}
	return syncStorageDir(root)
}

func (s *fileStorage) Delete(key string) error {
	root, err := s.open(key, false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer root.Close()
	if err := root.Remove(key); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	// Also sync a missing key: this may retry a successful removal whose prior
	// directory sync failed, so absence alone does not confirm durability.
	return syncStorageDir(root)
}

func syncStorageDir(root *os.Root) error {
	f, err := root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}
