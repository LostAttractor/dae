//go:build cgo && linux

// SPDX-License-Identifier: AGPL-3.0-only

package quickjs

import (
	"runtime"
	"testing"
)

func BenchmarkHostString(b *testing.B) {
	for _, test := range []struct{ name, source string }{
		{"ASCII_1KiB", `"a".repeat(1024)`},
		{"ASCII_256KiB", `"a".repeat(256 * 1024)`},
		{"Unicode_256KiB", `"你好🚀".repeat(256 * 1024 / 10)`},
	} {
		b.Run(test.name, func(b *testing.B) {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			vm, err := NewVM(128<<20, 1<<20)
			if err != nil {
				b.Fatal(err)
			}
			defer vm.Close()
			if err := vm.SetHostFunc(func(args []string) (any, error) { return len(args[0]) > 0, nil }); err != nil {
				b.Fatal(err)
			}
			if err := vm.Eval("const payload=" + test.source); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				if err := vm.Eval("__daeHost(payload)"); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
