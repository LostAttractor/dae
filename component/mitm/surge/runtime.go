// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"runtime"
	"time"

	"github.com/daeuniverse/dae/component/mitm/surge/internal/quickjs"
	"github.com/daeuniverse/dae/pkg/membuffer"
	"golang.org/x/net/publicsuffix"
)

//go:embed runtime_bootstrap.js
var runtimeBootstrap string

//go:embed runtime_web.js
var runtimeWebBootstrap string

// Runtime shares only its persistent key/value store. Every Run creates a fresh
// QuickJS VM, so globals and callbacks never leak between concurrent requests.
type Runtime struct {
	opts        RuntimeOptions
	data        *runtimeStore
	environment map[string]string
}

func NewRuntime(opts RuntimeOptions) (*Runtime, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultScriptTimeout
	}
	if opts.MemoryLimit <= 0 {
		opts.MemoryLimit = 128 << 20
	}
	if opts.MemoryLimit < 1<<20 {
		return nil, errors.New("script memory limit must be at least 1 MiB")
	}
	if uint64(opts.MemoryLimit) > uint64(^uintptr(0)) {
		return nil, errors.New("script memory limit exceeds the address space on this architecture")
	}
	data, err := openRuntimeStore(opts.StorePath)
	if err != nil {
		return nil, err
	}
	return &Runtime{opts: opts, data: data, environment: scriptEnvironment()}, nil
}

// Run executes source with a wall-clock budget shared by synchronous code,
// promise jobs, timers, and HTTP requests. No QuickJS std/os helpers or module
// loaders are installed: scripts receive only the explicit Surge host bridge.
// The caller supplies a body budget and limit, and closes the returned Result.
func (r *Runtime) Run(parent context.Context, source string, in Invocation) (result *Result, err error) {
	started := time.Now()
	sessionID := rand.Text()[:12]
	timeout := r.opts.Timeout
	if in.Timeout > 0 {
		timeout = in.Timeout
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// QuickJS tracks the native C stack. Keep creation, execution, callbacks,
	// and destruction on the same OS thread; other goroutines only send events
	// or set the engine's atomic interrupt flag.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	vm, err := quickjs.NewVM(uint64(r.opts.MemoryLimit), 1<<20)
	if err != nil {
		return nil, err
	}
	defer vm.Close()
	// The deadline covers the entire invocation, including all later
	// promise jobs and callbacks. It does not need rearming between phases.
	deadline, _ := ctx.Deadline()
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return nil, context.DeadlineExceeded
	}
	if err := vm.SetEvalTimeout(remaining); err != nil {
		return nil, err
	}
	// Interrupt only sets a Go atomic, so cancellation can safely race Close.
	// Stop the callback on return; no watcher goroutine or native-state join is needed.
	stopInterrupt := context.AfterFunc(ctx, vm.Interrupt)
	defer stopInterrupt()
	client := in.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	// Cookie state belongs to this invocation, never to another intercepted client.
	sessionClient := *client
	sessionClient.Jar, _ = cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	execution := &scriptExecution{
		runtime: r, ctx: ctx, client: &sessionClient, timeout: timeout,
		sessionID:  sessionID,
		moduleName: in.ModuleName, scriptName: in.ScriptName, scriptType: in.ScriptType,
		bodyMemory: in.BodyMemory, bodyLimit: in.BodyLimit,
		dom:    newRuntimeDOM(ctx, min(r.opts.MemoryLimit/4, 8<<20)),
		events: make(chan runtimeEvent),
	}
	defer func() {
		contextErr := ctx.Err()
		cancel()
		execution.httpWorkers.Wait()
		if contextErr != nil {
			result.Close()
			result, err = nil, contextErr
		}
		if result == nil {
			execution.result.Close()
			if errors.Is(execution.bodyError, membuffer.ErrBudgetExhausted) {
				err = execution.bodyError
			}
		}
	}()
	if err := vm.SetHostFunc(execution.hostCall); err != nil {
		return nil, err
	}
	path := in.ScriptPath
	if path == "" {
		path = source
	}
	input, err := json.Marshal(map[string]any{
		"domain": in.Domain, "cronexp": in.CronExp, "trigger": in.Trigger,
		"request": runtimeMessage(in.Request, in.FullHeaderMode), "response": runtimeMessage(in.Response, in.FullHeaderMode),
		"name": in.ScriptName, "type": in.ScriptType, "argument": in.Argument,
		"argumentSet": in.ArgumentSet || in.Argument != "",
		"binary":      in.BinaryBodyMode, "fullHeaders": in.FullHeaderMode,
		"storeKey":  fmt.Sprintf("/script/%x", sha256.Sum256([]byte(path))),
		"startTime": float64(started.UnixMilli()) / 1000, "sessionID": sessionID,
		"environment": r.environment,
	})
	if err != nil {
		return nil, err
	}
	if err := vm.SetInputJSON(input); err != nil {
		return nil, fmt.Errorf("initialize Surge script input: %w", err)
	}
	if err := vm.Eval(runtimeWebBootstrap + "\n" + runtimeBootstrap); err != nil {
		return nil, fmt.Errorf("initialize Surge script: %w", err)
	}
	if err := vm.Eval(source); err != nil {
		return nil, fmt.Errorf("execute Surge script %q: %w", in.ScriptName, err)
	}
	return execution.waitResult(vm)
}

func runtimeMessage(m *Message, fullHeaders bool) any {
	if m == nil {
		return nil
	}
	v := map[string]any{"url": m.URL, "method": m.Method, "id": m.ID, "headers": runtimeHeaders(m.Headers, fullHeaders), "status": m.Status}
	if len(m.Body) != 0 {
		v["bodyBase64"] = base64.StdEncoding.EncodeToString(m.Body)
	}
	if m.Trailers != nil {
		v["h2_trailers"] = runtimeHeaders(m.Trailers, fullHeaders)
	}
	return v
}
