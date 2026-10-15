//go:build linux

package netproxy

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

func BindToDeviceControl(c syscall.RawConn, name string) error {
	var sockErr error
	if err := c.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, name)
	}); err != nil {
		return err
	}
	if sockErr != nil {
		return fmt.Errorf("bind to interface %q: %w", name, sockErr)
	}
	return nil
}
