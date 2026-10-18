//go:build cgo && linux && !surge_nodejs

// SPDX-License-Identifier: AGPL-3.0-only

package quickjs

import (
	"strings"
	"testing"
)

func TestBytecodeKeepsFreshRuntimeAndLimits(t *testing.T) {
	var bytecode []byte
	t.Run("compile", func(t *testing.T) {
		vm := testVM(t, 16<<20)
		var err error
		bytecode, err = vm.Compile(`if (globalThis.previous) throw Error("leaked global"); globalThis.previous = true; __daeHost("fresh");`)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := vm.Compile("function ("); err == nil {
			t.Fatal("invalid source compiled")
		}
	})
	for range 2 {
		t.Run("execute", func(t *testing.T) {
			vm := testVM(t, 16<<20)
			var got string
			if err := vm.SetHostFunc(func(args []string) (any, error) { got = args[0]; return nil, nil }); err != nil {
				t.Fatal(err)
			}
			if err := vm.EvalBytecode(bytecode); err != nil || got != "fresh" {
				t.Fatalf("fresh evaluation: %s %v", got, err)
			}
			vm.Interrupt()
			if err := vm.EvalBytecode(bytecode); err == nil || !strings.Contains(err.Error(), "interrupted") {
				t.Fatalf("cached evaluation bypassed interruption: %v", err)
			}
		})
	}
}
