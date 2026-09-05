//go:build cgo && linux

// SPDX-License-Identifier: AGPL-3.0-only

// Package quickjs applies Surge's execution limits to buke/quickjs-go. A VM
// stays on one locked OS thread from construction through Close; Interrupt
// only updates a Go atomic and is the sole concurrent operation.
package quickjs

import (
	"errors"
	"fmt"
	"sync/atomic"
	"time"
	"unicode/utf16"

	qjs "github.com/buke/quickjs-go"
)

// VM owns an isolated runtime and a context without std/os, module loading,
// timers, or networking. Host callbacks must not reenter VM methods.
type VM struct {
	runtime       *qjs.Runtime
	context       *qjs.Context
	hostInstalled bool
	memoryLimit   uint64
	interrupted   atomic.Bool
	deadline      time.Time
}

// NewVM requires a locked OS thread. The native stack limit is capped to the
// current pthread's available stack, retaining space for callbacks and unwind.
func NewVM(memoryLimit, stackBytes uint64) (*VM, error) {
	if memoryLimit == 0 || stackBytes == 0 || uint64(uintptr(memoryLimit)) != memoryLimit || uint64(uintptr(stackBytes)) != stackBytes {
		return nil, errors.New("quickjs: nonzero memory and stack limits must fit size_t")
	}
	stackLimit, err := nativeStackLimit(stackBytes)
	if err != nil {
		return nil, err
	}
	vm := &VM{memoryLimit: memoryLimit}
	vm.runtime = qjs.NewRuntime(
		qjs.WithMemoryLimit(memoryLimit),
		qjs.WithLibcHandlers(false),
		qjs.WithGCThreshold(256<<10),
		qjs.WithMaxStackSize(stackLimit),
		qjs.WithCanBlock(false),
		qjs.WithModuleImport(false),
		qjs.WithStrictOSThread(true),
	)
	vm.runtime.SetInterruptHandler(func() int {
		if vm.stopped() {
			return 1
		}
		return 0
	})
	vm.context = vm.runtime.NewBareContext()
	if vm.context == nil {
		vm.Close()
		return nil, errors.New("quickjs: cannot allocate context within memory limit")
	}
	return vm, nil
}

func (vm *VM) stopped() bool {
	if !vm.deadline.IsZero() && !time.Now().Before(vm.deadline) {
		vm.interrupted.Store(true)
	}
	return vm.interrupted.Load()
}

func (vm *VM) check() error {
	if vm == nil || vm.runtime == nil {
		return errors.New("quickjs: VM is closed")
	}
	if vm.stopped() {
		return errors.New("quickjs: execution interrupted")
	}
	return nil
}

// result consumes an owned result and checks cancellation even when a short
// script or a caught host error did not reach QuickJS's interrupt callback.
func (vm *VM) result(value *qjs.Value) error {
	if value != nil {
		defer value.Free()
	}
	if err := vm.check(); err != nil {
		return err
	}
	if value == nil {
		return errors.New("quickjs: no evaluation result")
	}
	if value.IsException() {
		return vm.exception()
	}
	return nil
}

func (vm *VM) exception() error {
	err := vm.context.Exception()
	// Error properties may invoke script getters while formatting the error.
	if stopped := vm.check(); stopped != nil {
		return stopped
	}
	if err == nil {
		err = errors.New("javascript exception")
	}
	return fmt.Errorf("quickjs: %w", err)
}

// SetHostFunc accepts string arguments and returns a string, bool, or nil.
// Reading arguments never invokes script getters or user-defined conversions.
func (vm *VM) SetHostFunc(callback func([]string) (any, error)) error {
	if err := vm.check(); err != nil {
		return err
	}
	if callback == nil {
		return errors.New("quickjs: nil host callback")
	}
	if vm.hostInstalled {
		return errors.New("quickjs: host callback already installed")
	}
	vm.hostInstalled = true
	function := vm.context.NewFunction(func(ctx *qjs.Context, _ *qjs.Value, values []*qjs.Value) (result *qjs.Value) {
		defer func() {
			if recover() != nil {
				result = ctx.ThrowTypeError("Go host callback panicked")
			}
			if vm.stopped() {
				if result != nil {
					result.Free()
				}
				result = ctx.ThrowInternalError("interrupted")
			}
		}()
		if vm.stopped() {
			return ctx.ThrowInternalError("interrupted")
		}
		args, err := vm.arguments(values)
		if err != nil {
			return vm.hostError(err)
		}
		output, err := callback(args)
		if err != nil {
			return vm.hostError(err)
		}
		switch output := output.(type) {
		case nil:
			return ctx.NewNull()
		case bool:
			return ctx.NewBool(output)
		case string:
			if uint64(len(output)) <= vm.memoryLimit {
				return ctx.NewString(output)
			}
			return vm.hostError(errors.New("host string exceeds memory limit"))
		default:
			return vm.hostError(fmt.Errorf("unsupported host value %T", output))
		}
	})
	// Set transfers ownership of the function to the global object.
	vm.context.Globals().Set("__daeHost", function)
	if vm.context.HasException() {
		return vm.exception()
	}
	return vm.check()
}

func (vm *VM) arguments(values []*qjs.Value) ([]string, error) {
	if len(values) > 5 {
		return nil, errors.New("host callback accepts at most 5 arguments")
	}
	args := make([]string, len(values))
	var totalBytes uint64
	for i, value := range values {
		if !value.IsString() {
			return nil, fmt.Errorf("host argument %d must be a string", i+1)
		}
		// ToString uses a NUL-terminated C conversion. UTF-16 preserves
		// embedded NUL bytes and Unicode across the host boundary.
		units, err := value.ToStringUTF16()
		if err != nil {
			return nil, err
		}
		text := string(utf16.Decode(units))
		if uint64(len(text)) > vm.memoryLimit-totalBytes {
			return nil, errors.New("host argument strings exceed memory limit")
		}
		totalBytes += uint64(len(text))
		args[i] = text
	}
	return args, nil
}

func (vm *VM) hostError(err error) *qjs.Value {
	message := err.Error()
	if len(message) > 4095 {
		message = message[:4095]
	}
	return vm.context.ThrowTypeError("%s", message)
}

// SetEvalTimeout arms a monotonic deadline for the whole invocation. Expired
// or explicitly interrupted VMs cannot be revived by resetting the deadline.
func (vm *VM) SetEvalTimeout(timeout time.Duration) error {
	if err := vm.check(); err != nil {
		return err
	}
	if timeout <= 0 {
		return errors.New("quickjs: evaluation timeout must be positive")
	}
	vm.deadline = time.Now().Add(timeout)
	return nil
}

func (vm *VM) Eval(source string) error {
	if err := vm.check(); err != nil {
		return err
	}
	if uint64(len(source)) > vm.memoryLimit {
		return errors.New("quickjs: source exceeds memory limit")
	}
	return vm.result(vm.context.Eval(source, qjs.EvalFileName("surge.js")))
}

// Dispatch delivers an HTTP/timer event to the bootstrap's __daeDispatch.
func (vm *VM) Dispatch(id int, data string) error {
	if err := vm.check(); err != nil {
		return err
	}
	if uint64(len(data)) > vm.memoryLimit {
		return errors.New("quickjs: event data exceeds memory limit")
	}
	eventID := vm.context.NewInt64(int64(id))
	defer eventID.Free()
	payload := vm.context.NewString(data)
	defer payload.Free()
	if payload.IsException() {
		return vm.exception()
	}
	return vm.result(vm.context.Globals().Call("__daeDispatch", eventID, payload))
}

// ExecutePendingJobs drains JS microtasks, checking the invocation deadline
// between every job, including short self-replenishing Promise chains.
func (vm *VM) ExecutePendingJobs() error {
	for {
		if err := vm.check(); err != nil {
			return err
		}
		ran, err := vm.runtime.ExecutePendingJob()
		if stopped := vm.check(); stopped != nil {
			return stopped
		}
		if err != nil {
			return fmt.Errorf("quickjs: %w", err)
		}
		if !ran {
			return nil
		}
	}
}

// Interrupt never touches native state and may run concurrently with Eval.
func (vm *VM) Interrupt() {
	if vm != nil {
		vm.interrupted.Store(true)
	}
}

// Close is idempotent and must run on the owning OS thread.
func (vm *VM) Close() {
	if vm == nil || vm.runtime == nil {
		return
	}
	vm.runtime.Close()
	vm.context = nil
	vm.runtime = nil
}
