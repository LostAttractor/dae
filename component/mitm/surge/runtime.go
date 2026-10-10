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
	"time"

	"github.com/daeuniverse/dae/pkg/membuffer"
	"golang.org/x/net/publicsuffix"
)

//go:embed runtime_bootstrap.js
var runtimeBootstrap string

//go:embed runtime_web.js
var runtimeWebBootstrap string

//go:embed runtime_fetch.js
var runtimeFetchBootstrap string

var runtimeBootstrapSource = runtimeWebBootstrap + "\n" + runtimeFetchBootstrap + "\n" + runtimeBootstrap

// Runtime shares its persistent store and recent notifications. Every Run creates a fresh
// JavaScript context, so globals and callbacks never leak between requests.
type Runtime struct {
	opts          RuntimeOptions
	data          *runtimeStore
	environment   map[string]string
	notifications notificationHistory
	backend       *runtimeBackend
}

// NewRuntime uses ctx for preparation, including the external runtime probe.
// Invocation lifetimes are owned by the contexts passed to Run.
func NewRuntime(ctx context.Context, opts RuntimeOptions) (*Runtime, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
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
	backend, err := newRuntimeBackend(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &Runtime{opts: opts, data: data, environment: scriptEnvironment(), backend: backend}, nil
}

func (r *Runtime) Close() error {
	if r != nil && r.backend != nil {
		r.backend.Close()
	}
	return nil
}

// Run executes source with a wall-clock budget shared by synchronous code,
// promise jobs, timers, and HTTP requests. Scripts receive the Surge host bridge
// without Node globals, QuickJS std/os helpers, or native module loaders.
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
	vm, err := r.backend.newVM(ctx)
	if err != nil {
		return nil, err
	}
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
		httpCancels: make(map[int]context.CancelFunc),
		dom:         newRuntimeDOM(ctx, min(r.opts.MemoryLimit/4, 8<<20)),
		events:      make(chan runtimeEvent),
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
	// Release the VM before cancellation so a healthy Node worker can be reused.
	defer vm.Close()
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
	if err := vm.Bootstrap(); err != nil {
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
