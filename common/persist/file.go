// SPDX-License-Identifier: AGPL-3.0-only

package persist

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// ReplaceFile writes a private file, syncs its contents and atomically replaces
// name relative to the held directory. On error the destination is unchanged.
// The caller owns directory syncing and any state update after publication.
func ReplaceFile(ctx context.Context, dir *os.File, name string, data []byte) error {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return fmt.Errorf("replacement requires a single filename: %w", fs.ErrInvalid)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	temporary := ".dae-" + rand.Text()
	fd, err := unix.Openat(int(dir.Fd()), temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), temporary)
	defer unix.Unlinkat(int(dir.Fd()), temporary, 0)
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if err := errors.Join(err, f.Close()); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return unix.Renameat(int(dir.Fd()), temporary, int(dir.Fd()), name)
}
