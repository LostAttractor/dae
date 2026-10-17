// SPDX-License-Identifier: AGPL-3.0-only

package resource

import (
	"context"
	"errors"
	"os"

	"github.com/daeuniverse/dae/common/fileio"
	"github.com/daeuniverse/dae/common/persist"
	"golang.org/x/sys/unix"
)

func openCacheDir(path string, create bool) (*os.File, error) {
	if create {
		if err := persist.MkdirAll(path, 0700); err != nil {
			return nil, err
		}
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), path)
	var stat unix.Stat_t
	err = unix.Fstat(fd, &stat)
	if err == nil && (stat.Uid != uint32(os.Geteuid()) || stat.Mode&0022 != 0) {
		err = errors.New("resource cache directory must be owned by dae and not writable by group or others")
	}
	if err != nil {
		dir.Close()
		return nil, err
	}
	return dir, nil
}

func readCacheFile(ctx context.Context, dir *os.File, name string, limit int64) ([]byte, error) {
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, err
	}
	if stat.Uid != uint32(os.Geteuid()) || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0077 != 0 || stat.Size > limit {
		return nil, errors.New("resource cache must be an owned, private regular file within the size limit")
	}
	return fileio.ReadBounded(ctx, f, limit)
}

func writeCacheFile(ctx context.Context, dir *os.File, name string, data []byte) error {
	if err := persist.ReplaceFile(ctx, dir, name, data); err != nil {
		return err
	}
	return persist.AfterPublish(dir.Sync())
}
