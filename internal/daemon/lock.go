// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

const daemonLockPath = "/var/run/dae.lock"

// AcquireLock excludes other instances before configuration or resource loading.
func AcquireLock() (*os.File, error) {
	return acquireDaemonLock(daemonLockPath)
}

func validateDaemonLock(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	expected, err := os.Stat(daemonLockPath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || !os.SameFile(info, expected) {
		return errors.New("inherited instance lock has a different identity")
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fmt.Errorf("validate inherited instance lock: %w", err)
	}
	return nil
}

// Keep the same inode and reject leaf symlinks so another daemon cannot split ownership.
func acquireDaemonLock(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("open daemon lock: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			err = errors.New("dae is already running; use 'dae reload' to reload configuration or replace the running executable")
		} else {
			err = fmt.Errorf("acquire daemon lock: %w", err)
		}
		return nil, errors.Join(err, file.Close())
	}
	return file, nil
}
