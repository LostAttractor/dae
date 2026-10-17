// SPDX-License-Identifier: AGPL-3.0-only

// Package fileio provides bounded reads and descriptor-based file checks.
package fileio

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"

	"golang.org/x/sys/unix"
)

var ErrTooLarge = errors.New("input exceeds size limit")

// OpenRegular follows explicit symlinks and checks the opened descriptor.
// Nonblocking open rejects FIFOs without waiting for a writer. The caller owns f.
func OpenRegular(path string) (f *os.File, info os.FileInfo, err error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f = os.NewFile(uintptr(fd), path)
	info, err = StatRegular(f)
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, info, nil
}

// StatRegular also supports callers with their own rooted or no-symlink opener.
func StatRegular(f *os.File) (os.FileInfo, error) {
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file: %w", f.Name(), fs.ErrInvalid)
	}
	return info, nil
}

// ReadBounded rejects input longer than limit. Cancellation is checked between
// reads; callers must provide deadlines for readers whose Read can block.
func ReadBounded(ctx context.Context, reader io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 || limit == math.MaxInt64 {
		return nil, errors.New("byte limit must be positive and less than MaxInt64")
	}
	data, err := io.ReadAll(io.LimitReader(NewContextReader(ctx, reader), limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%w (%d bytes)", ErrTooLarge, limit)
	}
	return data, ctx.Err()
}
