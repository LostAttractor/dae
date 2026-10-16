/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package dialer

import (
	"fmt"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

var fwmarkIoctl int

func init() {
	switch runtime.GOOS {
	case "linux", "android":
		fwmarkIoctl = 36 /* unix.SO_MARK */
	case "freebsd":
		fwmarkIoctl = 0x1015 /* unix.SO_USER_COOKIE */
	case "openbsd":
		fwmarkIoctl = 0x1021 /* unix.SO_RTABLE */
	}
}

func SoMarkControl(c syscall.RawConn, mark int) error {
	var sockOptErr error
	controlErr := c.Control(func(fd uintptr) {
		err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, fwmarkIoctl, mark)
		if err != nil {
			sockOptErr = fmt.Errorf("error setting SO_MARK socket option: %w", err)
		}
	})
	if controlErr != nil {
		return fmt.Errorf("error invoking socket control function: %w", controlErr)
	}
	return sockOptErr
}

func TproxyControl(c syscall.RawConn) error {
	var sockOptErr error
	controlErr := c.Control(func(fd uintptr) {
		// - https://www.kernel.org/doc/Documentation/networking/tproxy.txt
		if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TRANSPARENT, 1); err != nil {
			sockOptErr = fmt.Errorf("error setting IP_TRANSPARENT socket option: %w", err)
			return
		}

		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
			sockOptErr = fmt.Errorf("error setting SO_REUSEADDR socket option: %w", err)
			return
		}

		e4 := unix.SetsockoptInt(int(fd), syscall.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
		e6 := unix.SetsockoptInt(int(fd), syscall.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1)
		if e4 != nil && e6 != nil {
			if e4 != nil {
				sockOptErr = fmt.Errorf("error setting IP_RECVORIGDSTADDR socket option: %w", e4)
			} else {
				sockOptErr = fmt.Errorf("error setting IPV6_RECVORIGDSTADDR socket option: %w", e6)
			}
			return
		}
	})
	if controlErr != nil {
		return fmt.Errorf("error invoking socket control function: %w", controlErr)
	}
	return sockOptErr
}

func TransparentControl(c syscall.RawConn) error {
	var sockOptErr error
	controlErr := c.Control(func(fd uintptr) {
		if err := syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1); err != nil {
			sockOptErr = fmt.Errorf("error setting IP_TRANSPARENT socket option: %w", err)
		}
	})
	if controlErr != nil {
		return fmt.Errorf("error invoking socket control function: %w", controlErr)
	}
	return sockOptErr
}
