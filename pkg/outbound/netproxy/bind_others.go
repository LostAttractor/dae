//go:build !linux

package netproxy

import (
	"fmt"
	"syscall"
)

func BindToDeviceControl(_ syscall.RawConn, name string) error {
	return fmt.Errorf("binding to interface %q is unsupported on this platform", name)
}
