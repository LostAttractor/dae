// SPDX-License-Identifier: AGPL-3.0-only

package resource

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/daeuniverse/dae/common"
	"golang.org/x/sys/unix"
)

// OpenLocalFile opens an absolute path without blocking on named pipes and
// verifies the opened descriptor is a regular file. The caller owns the file.
// A nonempty root confines the path to that directory and rejects symlinks in
// every path component below it. An empty root allows explicit symlink targets.
func OpenLocalFile(path, root string) (*os.File, os.FileInfo, error) {
	if !filepath.IsAbs(path) {
		return nil, nil, errors.New("local resource location must be an absolute path")
	}
	var file *os.File
	var err error
	if root != "" {
		root, err = filepath.Abs(root)
		if err != nil {
			return nil, nil, err
		}
		if err = common.EnsureFileInSubDir(path, root); err != nil {
			return nil, nil, err
		}
		file, err = openRootedFile(root, path)
	} else {
		// Fstat and reads use this descriptor even if a secret symlink rotates.
		var fd int
		fd, err = unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err != nil {
			err = &os.PathError{Op: "open resource", Path: path, Err: err}
		} else {
			file = os.NewFile(uintptr(fd), path)
		}
	}
	if err != nil {
		return nil, nil, err
	}
	info, err := file.Stat()
	if err == nil && !info.Mode().IsRegular() {
		err = fmt.Errorf("resource source must be a regular file: %s", path)
	}
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	return file, info, nil
}

func openRootedFile(root, path string) (*os.File, error) {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(filepath.Clean(relative), string(filepath.Separator))
	if len(parts) == 0 || parts[0] == "." || parts[0] == ".." {
		return nil, fmt.Errorf("invalid relative resource path %q", relative)
	}

	dirFd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open resource directory", Path: root, Err: err}
	}
	for i, part := range parts {
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
		if i != len(parts)-1 {
			flags |= unix.O_DIRECTORY
		} else {
			flags |= unix.O_NONBLOCK
		}
		fd, openErr := unix.Openat(dirFd, part, flags, 0)
		if openErr != nil {
			componentPath := filepath.Join(root, filepath.Join(parts[:i+1]...))
			pathErr := localFileOpenError(dirFd, part, componentPath, openErr)
			_ = unix.Close(dirFd)
			return nil, pathErr
		}
		_ = unix.Close(dirFd)
		if i == len(parts)-1 {
			return os.NewFile(uintptr(fd), path), nil
		}
		dirFd = fd
	}
	return nil, fmt.Errorf("invalid resource path %q", path)
}

func localFileOpenError(dirFd int, name, path string, err error) error {
	// Linux reports ENOTDIR, rather than ELOOP, when O_NOFOLLOW and
	// O_DIRECTORY reject an intermediate symlink. Inspect only for diagnostics;
	// the failed open is never retried with weaker flags.
	if errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP) {
		var stat unix.Stat_t
		if unix.Fstatat(dirFd, name, &stat, unix.AT_SYMLINK_NOFOLLOW) == nil && stat.Mode&unix.S_IFMT == unix.S_IFLNK {
			err = fmt.Errorf("symbolic links are not allowed: %w", err)
		}
	}
	return &os.PathError{Op: "open resource path", Path: path, Err: err}
}
