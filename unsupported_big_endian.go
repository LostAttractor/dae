//go:build linux && (armbe || arm64be || mips || mips64 || mips64p32 || ppc64 || s390 || s390x || sparc || sparc64)

package main

var _ = daeDoesNotSupportBigEndianArchitectures
