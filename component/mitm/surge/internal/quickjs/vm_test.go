//go:build cgo && linux && !surge_nodejs

// SPDX-License-Identifier: AGPL-3.0-only

package quickjs

import (
	"errors"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func testVM(t *testing.T, memory uint64) *VM {
	t.Helper()
	runtime.LockOSThread()
	vm, err := NewVM(memory, 1<<20)
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		vm.Close()
		runtime.UnlockOSThread()
	})
	if err := vm.SetEvalTimeout(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	return vm
}

func TestStringBridge(t *testing.T) {
	vm := testVM(t, 16<<20)
	var got []string
	if err := vm.SetHostFunc(func(args []string) (any, error) {
		got = args
		return "reply\x00你好🚀", nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := vm.Eval(`if (__daeHost("", "a\u0000你好🚀") !== "reply\u0000你好🚀") throw Error("return string corrupted");`); err != nil {
		t.Fatal(err)
	}
	want := []string{"", "a\x00你好🚀"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("host arguments = %#v, want %#v", got, want)
	}
	if err := vm.Eval(`function __daeDispatch(id, data) { __daeHost(String(id), data); }`); err != nil {
		t.Fatal(err)
	}
	if err := vm.Dispatch(7, "payload\x00中文"); err != nil {
		t.Fatal(err)
	}
	want = []string{"7", "payload\x00中文"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Dispatch arguments = %#v, want %#v", got, want)
	}
}

func TestInputJSON(t *testing.T) {
	vm := testVM(t, 1<<20)
	if err := vm.SetInputJSON([]byte(`{"body":"你好\u0000🚀", "__proto__":{"inherited":true}}`)); err != nil {
		t.Fatal(err)
	}
	if err := vm.Eval(`
      if (__daeInput.body !== "你好\x00🚀") throw Error("input string corrupted");
      if (__daeInput.inherited || !Object.hasOwn(__daeInput, "__proto__")) throw Error("input must be data");
    `); err != nil {
		t.Fatal(err)
	}
	if err := vm.SetInputJSON([]byte(`{"incomplete":`)); err == nil {
		t.Fatal("invalid input JSON accepted")
	}
	if err := vm.SetInputJSON([]byte(strings.Repeat(" ", (1<<20)+1))); err == nil {
		t.Fatal("input exceeding memory budget accepted")
	}
	vm.Interrupt()
	if err := vm.SetInputJSON([]byte(`{}`)); err == nil || !strings.Contains(err.Error(), "interrupted") {
		t.Fatalf("interrupted input: %v", err)
	}
}

func TestHostErrorsAndStringArguments(t *testing.T) {
	vm := testVM(t, 16<<20)
	if err := vm.SetHostFunc(func(args []string) (any, error) {
		switch args[0] {
		case "failure":
			return nil, errors.New("host failed")
		case "panic":
			panic("private panic data")
		case "badResult":
			return map[string]any{}, nil
		case "bool":
			return true, nil
		case "null":
			return nil, nil
		}
		return args[0], nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := vm.Eval(`
		let converted = false;
		const cases = [
			() => __daeHost("failure"), () => __daeHost("panic"), () => __daeHost("badResult"),
			() => __daeHost({toString() { converted = true; return "bad"; }}),
			() => __daeHost(Symbol("x")), () => __daeHost(1n), () => __daeHost(true),
			() => __daeHost(1), () => __daeHost(null), () => __daeHost(undefined),
			() => __daeHost(...Array(6).fill("x"))
		];
		for (const run of cases) {
			let caught = false;
			try { run(); } catch (e) { caught = e instanceof TypeError; }
			if (!caught) throw Error("missing catchable TypeError");
		}
		if (converted) throw Error("object conversion executed user code");
		if (__daeHost("bool") !== true || __daeHost("null") !== null) throw Error("host result corrupted");
	`); err != nil {
		t.Fatal(err)
	}
	if err := vm.Eval(`__daeHost("failure")`); err == nil || !strings.Contains(err.Error(), "TypeError: host failed") {
		t.Fatalf("host error = %v", err)
	}
	if err := vm.Eval(`throw new Error("script failed")`); err == nil || !strings.Contains(err.Error(), "Error: script failed") {
		t.Fatalf("eval error = %v", err)
	}
	if err := vm.Dispatch(1, "missing function"); err == nil {
		t.Fatal("missing dispatcher succeeded")
	}
	if err := vm.Eval(`__daeHost("context survives errors")`); err != nil {
		t.Fatal(err)
	}
}

func TestExecutionDeadline(t *testing.T) {
	for name, source := range map[string]string{
		"loop":                 `while (true) {}`,
		"catch":                `for (;;) { try { while (true) {} } catch (e) {} }`,
		"promise_loop":         `Promise.resolve().then(() => { while (true) {} })`,
		"promise_chain":        `function spin() { Promise.resolve().then(spin); } spin();`,
		"exception_conversion": `throw Object.defineProperty(new Error("bad"), "name", { get() { while (true) {} } });`,
	} {
		t.Run(name, func(t *testing.T) {
			vm := testVM(t, 16<<20)
			if err := vm.SetEvalTimeout(30 * time.Millisecond); err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			err := vm.Eval(source)
			if err == nil {
				err = vm.ExecutePendingJobs()
			}
			if err == nil || !strings.Contains(err.Error(), "interrupted") {
				t.Fatalf("deadline error = %v", err)
			}
			if elapsed := time.Since(start); elapsed > time.Second {
				t.Fatalf("deadline took %s", elapsed)
			}
			if err := vm.SetEvalTimeout(time.Second); err == nil {
				t.Fatal("rearming revived an interrupted VM")
			}
			if err := vm.Eval(`1 + 1`); err == nil {
				t.Fatal("interruption was reset")
			}
		})
	}
}

func TestConcurrentInterrupt(t *testing.T) {
	for _, source := range []string{
		`while (true) {}`,
		`function spin() { Promise.resolve().then(spin); } spin();`,
	} {
		t.Run(source, func(t *testing.T) {
			vm := testVM(t, 16<<20)
			joined := make(chan struct{})
			go func() {
				defer close(joined)
				time.Sleep(20 * time.Millisecond)
				vm.Interrupt()
			}()
			start := time.Now()
			err := vm.Eval(source)
			if err == nil {
				err = vm.ExecutePendingJobs()
			}
			<-joined
			if err == nil || !strings.Contains(err.Error(), "interrupted") {
				t.Fatalf("interrupt error = %v", err)
			}
			if elapsed := time.Since(start); elapsed > time.Second {
				t.Fatalf("interrupt took %s", elapsed)
			}
		})
	}
}

func TestInterruptDuringHostCallback(t *testing.T) {
	vm := testVM(t, 16<<20)
	joined := make(chan struct{})
	if err := vm.SetHostFunc(func([]string) (any, error) {
		go func() {
			vm.Interrupt()
			close(joined)
		}()
		<-joined
		return "should not be observed", nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := vm.Eval(`try { __daeHost(); } catch (e) {} "done"`); err == nil || !strings.Contains(err.Error(), "interrupted") {
		t.Fatalf("callback interrupt error = %v", err)
	}
}

func TestMemoryAndNativeStackLimits(t *testing.T) {
	vm := testVM(t, 2<<20)
	if err := vm.Eval(`new Uint8Array(32 * 1024 * 1024)`); err == nil {
		t.Fatal("allocation exceeded memory limit")
	}
	if err := vm.Eval(`function recurse() { return 1 + recurse(); } recurse()`); err == nil || !strings.Contains(err.Error(), "Maximum call stack size exceeded") {
		t.Fatalf("recursion error = %v", err)
	}
}

func TestSharedArrayBufferMemoryLimit(t *testing.T) {
	vm := testVM(t, 2<<20)
	checkSmall := func() {
		t.Helper()
		if err := vm.Eval(`(() => {
			const words = new Int32Array(new SharedArrayBuffer(8));
			Atomics.store(words, 0, 41);
			if (Atomics.add(words, 0, 1) !== 41 || Atomics.load(words, 0) !== 42)
				throw Error("small shared buffer atomics failed");
		})();`); err != nil {
			t.Fatalf("small SharedArrayBuffer: %v", err)
		}
	}
	checkSmall()
	for _, source := range []string{
		`new SharedArrayBuffer(16 * 1024 * 1024)`,
		`new SharedArrayBuffer(8, {maxByteLength: 16 * 1024 * 1024})`,
	} {
		if err := vm.Eval(source); err == nil {
			t.Fatalf("shared buffer exceeded 2 MiB memory limit: %s", source)
		}
		checkSmall()
	}
}

func TestAllocationFailureAndClose(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if vm, err := NewVM(1, 1<<20); err == nil {
		vm.Close()
		t.Fatal("impossibly low memory limit succeeded")
	}
	if vm, err := NewVM(16<<20, 1); err == nil {
		vm.Close()
		t.Fatal("impossibly low native stack limit succeeded")
	}
	vm, err := NewVM(16<<20, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	vm.Close()
	vm.Close()
	vm.Interrupt()
	if err := vm.Eval(`1`); err == nil {
		t.Fatal("closed VM eval succeeded")
	}
}
