//go:build !linux

// Copied from https://github.com/cilium/ebpf/tree/v0.10.0/internal/unix

package unix

import (
	"fmt"
	"runtime"
	"syscall"
)

var errNonLinux = fmt.Errorf("unsupported platform %s/%s", runtime.GOOS, runtime.GOARCH)

const EACCES syscall.Errno = 1

type Utsname struct {
	Release [65]byte
}

func Uname(buf *Utsname) error {
	return errNonLinux
}

func ByteSliceToString(s []byte) string {
	return ""
}
