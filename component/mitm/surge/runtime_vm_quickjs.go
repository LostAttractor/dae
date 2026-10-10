//go:build !surge_nodejs

// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"runtime"
	"time"

	"github.com/daeuniverse/dae/component/mitm/surge/internal/quickjs"
)

const compiledJSRuntime = "quickjs"

type runtimeBackend struct{ memoryLimit uint64 }

func newRuntimeBackend(_ context.Context, opts RuntimeOptions) (*runtimeBackend, error) {
	return &runtimeBackend{memoryLimit: uint64(opts.MemoryLimit)}, nil
}
func (*runtimeBackend) Close() {}

type quickJSVM struct {
	*quickjs.VM
	stop func() bool
}

func (b *runtimeBackend) newVM(ctx context.Context) (scriptVM, error) {
	// QuickJS tracks the native C stack, including during Go host callbacks.
	runtime.LockOSThread()
	vm, err := quickjs.NewVM(b.memoryLimit, 1<<20)
	if err != nil {
		runtime.UnlockOSThread()
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	remaining := time.Until(deadline)
	if remaining <= 0 {
		vm.Close()
		runtime.UnlockOSThread()
		return nil, context.DeadlineExceeded
	}
	if err := vm.SetEvalTimeout(remaining); err != nil {
		vm.Close()
		runtime.UnlockOSThread()
		return nil, err
	}
	return &quickJSVM{VM: vm, stop: context.AfterFunc(ctx, vm.Interrupt)}, nil
}

func (vm *quickJSVM) Bootstrap() error {
	return vm.Eval(runtimeBootstrapSource)
}

func (vm *quickJSVM) Close() {
	vm.stop()
	vm.VM.Close()
	runtime.UnlockOSThread()
}
