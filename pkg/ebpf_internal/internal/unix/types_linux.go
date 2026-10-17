//go:build linux

// Copied from https://github.com/cilium/ebpf/tree/v0.10.0/internal/unix

package unix

import linux "golang.org/x/sys/unix"

const EACCES = linux.EACCES

type Utsname = linux.Utsname

func Uname(buf *Utsname) error {
	return linux.Uname(buf)
}

func ByteSliceToString(s []byte) string {
	return linux.ByteSliceToString(s)
}
