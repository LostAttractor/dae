// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common/macaddr"
	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/robfig/cron/v3"
	log "github.com/sirupsen/logrus"
)

var _ plugin.Worker = (*Engine)(nil)
var _ plugin.ScriptTrigger = (*Engine)(nil)

func parseCronSchedule(expression string) (cron.Schedule, error) {
	fields := strings.Fields(expression)
	if n := len(fields); n != 5 && n != 6 {
		return nil, errors.New("requires five fields, or six fields with leading seconds")
	}
	if strings.Contains(fields[0], "=") {
		return nil, errors.New("cron uses the daemon's local timezone; timezone prefixes are not supported")
	}
	return cron.NewParser(cron.SecondOptional | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow).Parse(expression)
}

// One event loop owns pending tasks; goroutines start only after acquiring a shared execution slot.
type taskRunner struct {
	mu             sync.Mutex
	started        bool
	active         bool
	ctx            context.Context
	client         *http.Client
	running        sync.WaitGroup
	jobs           []*scriptTask
	enabled        map[[6]byte]bool
	lanQueryFailed bool
	deviceQueryID  uint64
	deviceApplied  uint64
	deviceChecked  uint64
	deviceCheck    *taskDeviceCheck
	deviceTimeout  time.Duration
	queue          []*taskRun
	wake           chan struct{}
}

type scriptTask struct {
	module     *Module
	script     *Script
	status     api.ScriptTaskStatus
	isolateLAN bool
	targets    map[ScriptScope]*scriptTargetTask
}

type scriptTargetTask struct {
	busy   bool
	status api.ScriptTaskStatus
}

type taskRun struct {
	job     *scriptTask
	target  *scriptTargetTask
	scope   ScriptScope
	started time.Time
	trigger string
	slot    bool
}

type taskDeviceResult struct {
	id      uint64
	devices map[[6]byte]bool
	err     error
}

type taskDeviceCheck struct {
	done    chan struct{}
	cancel  context.CancelFunc
	waiters int
	result  taskDeviceResult
}

type taskCronDue struct {
	at      time.Time
	skipped uint64
}

func newTaskRunner(e *Engine) (*taskRunner, error) {
	var runner *taskRunner
	for _, module := range e.options.Modules {
		for i := range module.TaskScripts {
			script := &module.TaskScripts[i]
			if script.Type == "cron" && script.schedule == nil {
				var err error
				script.schedule, err = parseCronSchedule(script.CronExp)
				if err != nil {
					return nil, fmt.Errorf("script %q cronexp: %w", script.Name, err)
				}
			}
			if runner == nil {
				runner = &taskRunner{}
			}
			status := api.ScriptTaskStatus{Name: script.Name, Type: script.Type,
				TimeoutSeconds: e.scriptTimeout(script).Seconds(), State: "pending"}
			if script.Type == "cron" {
				status.CronExp, status.Timezone = script.CronExp, time.Local.String()
			}
			job := &scriptTask{module: module, script: script, status: status, isolateLAN: e.isolateLAN(script), targets: make(map[ScriptScope]*scriptTargetTask)}
			runner.deviceTimeout = max(runner.deviceTimeout, e.scriptTimeout(script))
			job.target(ScriptScope{Kind: ScriptScopeLocal})
			runner.jobs = append(runner.jobs, job)
		}
	}
	return runner, nil
}

func (e *Engine) enabledDevices(ctx context.Context) (map[[6]byte]bool, error) {
	devices := make(map[[6]byte]bool)
	if e.options.Devices == nil {
		return devices, nil
	}
	macs, err := e.options.Devices.MITMEnabled(ctx)
	if err != nil {
		return nil, err
	}
	for _, mac := range macs {
		if macaddr.ValidClient(mac) {
			devices[mac] = true
		}
	}
	return devices, nil
}

func (c *taskRunner) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (job *scriptTask) target(scope ScriptScope) *scriptTargetTask {
	if target := job.targets[scope]; target != nil {
		return target
	}
	status := job.status
	status.Scope, status.MAC = scope.name(), scope.deviceName()
	target := &scriptTargetTask{status: status}
	job.targets[scope] = target
	return target
}

func (c *taskRunner) enabledScope(job *scriptTask, scope ScriptScope) bool {
	return scope.Kind == ScriptScopeLocal || scope.Kind == ScriptScopeDevice && job.isolateLAN && c.enabled[scope.MAC]
}

// The caller holds mu; retain current and running targets, not a second device inventory.
func (c *taskRunner) setDevices(devices map[[6]byte]bool) {
	c.enabled, c.lanQueryFailed = devices, false
	for _, job := range c.jobs {
		if job.isolateLAN {
			for mac := range devices {
				job.target(ScriptScope{Kind: ScriptScopeDevice, MAC: mac})
			}
		}
		for scope, target := range job.targets {
			if !c.enabledScope(job, scope) && !target.busy {
				delete(job.targets, scope)
				continue
			}
			if !target.busy {
				target.status.State = c.idleState(job)
			}
		}
	}
}

func needsLAN(jobs []*scriptTask) bool {
	for _, job := range jobs {
		if job.isolateLAN {
			return true
		}
	}
	return false
}

func (e *Engine) discoverTaskDevices(ctx context.Context) <-chan taskDeviceResult {
	c := e.tasks
	result := make(chan taskDeviceResult, 1)
	c.mu.Lock()
	c.deviceQueryID++
	id := c.deviceQueryID
	c.mu.Unlock()
	c.running.Go(func() {
		result <- e.queryTaskDevices(ctx, id)
	})
	return result
}

func (e *Engine) dispatchDeviceTasks(ctx context.Context, result taskDeviceResult, due map[*scriptTask]*taskCronDue) {
	if ctx.Err() != nil {
		return
	}
	c := e.tasks
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctx.Err() != nil || !c.active {
		return
	}
	e.applyTaskDevices(result)
	if c.lanQueryFailed || result.err != nil && result.id > c.deviceApplied {
		for _, pending := range due {
			e.metrics.skips.WithLabelValues("cron", "device_query_failed").Add(float64(1 + pending.skipped))
		}
		return
	}
	for job, pending := range due {
		for mac := range c.enabled {
			scope := ScriptScope{Kind: ScriptScopeDevice, MAC: mac}
			target := job.targets[scope]
			skipped := pending.skipped
			// A task completed during discovery already covers this deadline; do not rerun it late.
			if target.busy || target.status.LastFinishedAt.After(pending.at) {
				skipped++
			} else {
				e.startTask(job, scope, time.Now(), "")
			}
			target.status.Skipped += skipped
			e.metrics.skips.WithLabelValues("cron", "overlap").Add(float64(skipped))
		}
	}
}

func (c *taskRunner) idleState(job *scriptTask) string {
	if !c.active {
		if c.started {
			return "stopped"
		}
		return "pending"
	}
	if job.script.Type == "generic" {
		return "ready"
	}
	if job.status.NextRun.IsZero() {
		return "unscheduled"
	}
	return "scheduled"
}

func (e *Engine) Run(ctx context.Context, client *http.Client) error {
	c := e.tasks
	if c == nil {
		return nil
	}
	c.mu.Lock()
	if c.started {
		c.mu.Unlock()
		return errors.New("surge: script worker already started")
	}
	c.started = true
	if client == nil {
		for _, job := range c.jobs {
			for _, target := range job.targets {
				target.status.State, target.status.LastError = "stopped", "http_client_unavailable"
			}
		}
		c.mu.Unlock()
		return errors.New("surge: script tasks require a routed background HTTP client")
	}
	c.active, c.ctx, c.client = true, ctx, client
	c.wake = make(chan struct{}, 1)
	for _, job := range c.jobs {
		if job.script.schedule != nil {
			job.status.NextRun = job.script.schedule.Next(time.Now().Round(0))
		}
	}
	c.setDevices(nil)
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.active = false
		pending := c.queue
		c.queue = nil
		c.mu.Unlock()
		for _, run := range pending {
			e.finishTask(run, false, context.Canceled)
		}
		c.running.Wait()
		c.mu.Lock()
		defer c.mu.Unlock()
		for _, job := range c.jobs {
			job.status.State, job.status.NextRun = "stopped", time.Time{}
			for _, target := range job.targets {
				target.status.State = "stopped"
			}
		}
	}()
	var discovery <-chan taskDeviceResult
	var discovering map[*scriptTask]*taskCronDue
	pendingLAN := make(map[*scriptTask]*taskCronDue)
	if needsLAN(c.jobs) && ctx.Err() == nil {
		discovery = e.discoverTaskDevices(ctx)
	}
	for ctx.Err() == nil {
		now := time.Now()
		c.mu.Lock()
		for _, job := range c.jobs {
			if job.status.NextRun.IsZero() || job.status.NextRun.After(now) {
				continue
			}
			job.status.NextRun = job.script.schedule.Next(now.Round(0))
			scope := ScriptScope{Kind: ScriptScopeLocal}
			target := job.targets[scope]
			if target.busy {
				target.status.Skipped++
				e.metrics.skip("cron", "overlap")
			} else {
				e.startTask(job, scope, now, "")
			}
			if !job.isolateLAN {
				continue
			}
			pending := discovering[job]
			if pending == nil {
				pending = pendingLAN[job]
			}
			if pending != nil {
				pending.skipped++
			} else {
				pendingLAN[job] = &taskCronDue{at: now}
			}
		}
		c.mu.Unlock()
		if discovery == nil && len(pendingLAN) != 0 && ctx.Err() == nil {
			discovering, pendingLAN = pendingLAN, make(map[*scriptTask]*taskCronDue)
			discovery = e.discoverTaskDevices(ctx)
		}
		now = time.Now()
		var expired []*taskRun
		var next time.Time
		c.mu.Lock()
		pending := c.queue[:0]
		for _, run := range c.queue {
			deadline := run.started.Add(e.scriptTimeout(run.job.script))
			if !deadline.After(now) {
				expired = append(expired, run)
			} else {
				pending = append(pending, run)
				if next.IsZero() || deadline.Before(next) {
					next = deadline
				}
			}
		}
		clear(c.queue[len(pending):])
		c.queue = pending
		for _, job := range c.jobs {
			if at := job.status.NextRun; !at.IsZero() && (next.IsZero() || at.Before(next)) {
				next = at
			}
		}
		var slots chan struct{}
		if len(c.queue) != 0 {
			slots = e.slots
		}
		c.mu.Unlock()
		for _, run := range expired {
			e.finishTask(run, false, context.DeadlineExceeded)
		}
		var timer *time.Timer
		var timerC <-chan time.Time
		if !next.IsZero() {
			timer = time.NewTimer(min(time.Until(next), time.Minute))
			timerC = timer.C
		}
		select {
		case <-ctx.Done():
		case <-c.wake:
		case <-timerC:
		case result := <-discovery:
			e.dispatchDeviceTasks(ctx, result, discovering)
			discovery, discovering = nil, nil
		case slots <- struct{}{}:
			c.mu.Lock()
			run := c.queue[0]
			c.queue[0] = nil
			c.queue = c.queue[1:]
			run.slot = true
			c.running.Go(func() {
				defer c.signal()
				defer func() { <-e.slots }()
				e.runTask(run)
			})
			c.mu.Unlock()
		}
		if timer != nil {
			timer.Stop()
		}
	}
	return ctx.Err()
}

func (e *Engine) queryTaskDevices(ctx context.Context, id uint64) taskDeviceResult {
	devices, err := e.enabledDevices(ctx)
	return taskDeviceResult{id: id, devices: devices, err: err}
}

// The caller holds mu. Completion order is not necessarily observation order.
func (e *Engine) applyTaskDevices(result taskDeviceResult) {
	c := e.tasks
	if result.id <= c.deviceApplied || result.err != nil && result.id < c.deviceChecked {
		return
	}
	c.deviceApplied = result.id
	if result.err == nil {
		c.setDevices(result.devices)
		return
	}
	c.enabled = nil
	c.lanQueryFailed = true
	if e.options.Logger != nil && !errors.Is(result.err, context.Canceled) {
		e.options.Logger.WithError(resource.RedactError(result.err)).Warn("Surge script device query failed")
	}
}

// Only overlapping execution checks share a scan. No later execution uses a cached result.
func (e *Engine) checkTaskDevice(ctx context.Context, scope ScriptScope) error {
	c := e.tasks
	c.mu.Lock()
	check := c.deviceCheck
	if check == nil {
		queryCtx, cancel := context.WithTimeout(c.ctx, c.deviceTimeout)
		check = &taskDeviceCheck{done: make(chan struct{}), cancel: cancel}
		c.deviceCheck = check
		c.deviceQueryID++
		id := c.deviceQueryID
		c.running.Go(func() {
			result := e.queryTaskDevices(queryCtx, id)
			c.mu.Lock()
			defer c.mu.Unlock()
			check.result = result
			if c.deviceCheck == check {
				c.deviceCheck = nil
				if queryCtx.Err() == nil {
					if result.err == nil {
						c.deviceChecked = result.id
					}
					// A healthy execution check normally leaves device history alone.
					if result.err != nil || c.lanQueryFailed {
						e.applyTaskDevices(result)
					}
				}
			}
			check.cancel()
			close(check.done)
		})
	}
	check.waiters++
	c.mu.Unlock()
	select {
	case <-ctx.Done():
	case <-check.done:
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	check.waiters--
	if check.waiters == 0 && c.deviceCheck == check {
		c.deviceCheck = nil
		check.cancel()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if check.result.err != nil || c.deviceApplied > check.result.id && c.lanQueryFailed {
		return plugin.ErrScriptDeviceUnavailable
	}
	if !check.result.devices[scope.MAC] || c.deviceApplied > check.result.id && !c.enabled[scope.MAC] {
		return plugin.ErrScriptDeviceDisabled
	}
	return nil
}

func (e *Engine) runTask(run *taskRun) {
	e.metrics.wait.WithLabelValues(run.job.script.Type).Observe(time.Since(run.started).Seconds())
	ctx, cancel := context.WithDeadline(e.tasks.ctx, run.started.Add(e.scriptTimeout(run.job.script)))
	defer cancel()
	executed := false
	var err error
	defer func() { e.finishTask(run, executed, err) }()
	if err = ctx.Err(); err != nil {
		return
	}
	if run.scope.Kind == ScriptScopeDevice {
		if err = e.checkTaskDevice(ctx, run.scope); err != nil {
			return
		}
	}
	if err = ctx.Err(); err != nil {
		return
	}
	e.tasks.mu.Lock()
	run.target.status.State = "running"
	e.tasks.mu.Unlock()
	if e.options.Logger != nil {
		e.options.Logger.WithFields(log.Fields{"event": "task_start", "script_type": run.job.script.Type,
			"module": run.job.module.Name, "script": run.job.script.Name, "scope": run.scope.name(), "mac": run.scope.deviceName()}).Trace("Surge script task started")
	}
	executed = true
	result, err := e.runInvocation(ctx, run.job.module, run.job.script, Invocation{
		Trigger: run.trigger, HTTPClient: e.tasks.client, Scope: run.scope,
	})
	result.Close()
}

func (e *Engine) finishTask(run *taskRun, executed bool, err error) {
	finished := time.Now()
	result, reason := "success", ""
	if err != nil {
		result, reason = "failed", traceErrorReason(err)
	}
	if errors.Is(err, plugin.ErrScriptDeviceDisabled) {
		result, reason = "skipped", "device_disabled"
	} else if errors.Is(err, plugin.ErrScriptDeviceUnavailable) {
		result, reason = "skipped", "device_query_failed"
	}
	c := e.tasks
	c.mu.Lock()
	device := run.target
	device.busy = false
	device.status.State = c.idleState(run.job)
	device.status.LastFinishedAt, device.status.LastDurationMS = finished, finished.Sub(run.started).Milliseconds()
	device.status.LastResult, device.status.LastError = result, reason
	if result == "failed" {
		device.status.Failures++
	} else if result == "skipped" {
		device.status.Skipped++
	}
	if !c.lanQueryFailed && !c.enabledScope(run.job, run.scope) {
		delete(run.job.targets, run.scope)
	}
	c.mu.Unlock()
	if !run.slot {
		e.metrics.wait.WithLabelValues(run.job.script.Type).Observe(finished.Sub(run.started).Seconds())
	}
	outcome := result
	if !executed {
		outcome = "skipped"
		e.metrics.skip(run.job.script.Type, reason)
	}
	e.metrics.scripts.WithLabelValues(run.job.script.Type, outcome).Inc()
	if e.options.Logger != nil {
		entry := e.options.Logger.WithFields(log.Fields{"event": "task_end", "script_type": run.job.script.Type,
			"module": run.job.module.Name, "script": run.job.script.Name, "scope": run.scope.name(), "mac": run.scope.deviceName(),
			"outcome": result, "reason": reason, "elapsed_ms": finished.Sub(run.started).Milliseconds()})
		if err != nil && !errors.Is(err, context.Canceled) && result != "skipped" {
			entry.WithError(resource.RedactError(err)).Warn("Surge script task failed")
		} else {
			entry.Trace("Surge script task finished")
		}
	}
}

// The caller holds mu; resolve script definitions independently of device row counts.
func (c *taskRunner) find(request api.ScriptRunRequest) (*scriptTask, error) {
	var found *scriptTask
	for _, job := range c.jobs {
		if job.script.Name != request.Script || request.Module != "" && job.module.Name != request.Module {
			continue
		}
		if found != nil {
			return nil, plugin.ErrScriptAmbiguous
		}
		found = job
	}
	if found == nil {
		return nil, plugin.ErrScriptNotFound
	}
	return found, nil
}

func (e *Engine) startTask(job *scriptTask, scope ScriptScope, now time.Time, trigger string) {
	target := job.targets[scope]
	target.busy = true
	target.status.State, target.status.LastStartedAt = "waiting", now
	target.status.LastFinishedAt, target.status.LastDurationMS = time.Time{}, 0
	target.status.LastResult, target.status.LastError = "", ""
	target.status.LastTrigger = cmp.Or(trigger, "cron")
	target.status.Runs++
	e.tasks.queue = append(e.tasks.queue, &taskRun{job: job, target: target, scope: scope, started: now, trigger: trigger})
	e.tasks.signal()
}

func (e *Engine) TriggerScript(ctx context.Context, request api.ScriptRunRequest) (api.ScriptRunResponse, error) {
	c := e.tasks
	if c == nil {
		return api.ScriptRunResponse{}, plugin.ErrScriptNotFound
	}
	scope := ScriptScope{Kind: ScriptScopeLocal}
	if request.MAC != "" {
		mac, err := macaddr.ParseClient(request.MAC)
		if err != nil {
			return api.ScriptRunResponse{}, plugin.ErrScriptDeviceInvalid
		}
		scope = ScriptScope{Kind: ScriptScopeDevice, MAC: mac}
	}
	c.mu.Lock()
	if !c.active || c.ctx.Err() != nil {
		c.mu.Unlock()
		return api.ScriptRunResponse{}, plugin.ErrScriptInactive
	}
	job, err := c.find(request)
	if err != nil {
		c.mu.Unlock()
		return api.ScriptRunResponse{}, err
	}
	if scope.Kind == ScriptScopeDevice && !job.isolateLAN {
		c.mu.Unlock()
		return api.ScriptRunResponse{}, plugin.ErrScriptDeviceUnsupported
	}
	workerCtx := c.ctx
	var deviceQueryID uint64
	if scope.Kind == ScriptScopeDevice {
		c.deviceQueryID++
		deviceQueryID = c.deviceQueryID
	}
	c.mu.Unlock()
	// Admission has its own budget; accepted tasks belong to the worker's lifetime.
	ctx, cancel := context.WithTimeout(ctx, e.scriptTimeout(job.script))
	defer cancel()
	stop := context.AfterFunc(workerCtx, cancel)
	defer stop()
	if err := ctx.Err(); err != nil {
		return api.ScriptRunResponse{}, err
	}
	var devices taskDeviceResult
	if scope.Kind == ScriptScopeDevice {
		devices = e.queryTaskDevices(ctx, deviceQueryID)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctx.Err() != nil {
		return api.ScriptRunResponse{}, ctx.Err()
	}
	if !c.active || c.ctx != workerCtx || workerCtx.Err() != nil {
		return api.ScriptRunResponse{}, plugin.ErrScriptInactive
	}
	if scope.Kind == ScriptScopeDevice {
		e.applyTaskDevices(devices)
		if c.lanQueryFailed {
			return api.ScriptRunResponse{}, plugin.ErrScriptDeviceUnavailable
		}
		if !c.enabled[scope.MAC] {
			return api.ScriptRunResponse{}, plugin.ErrScriptDeviceDisabled
		}
	}
	target := job.targets[scope]
	if target.busy {
		return api.ScriptRunResponse{}, plugin.ErrScriptBusy
	}
	e.startTask(job, scope, time.Now(), "http-api")
	status := target.status
	status.NextRun = job.status.NextRun
	return api.ScriptRunResponse{Module: job.module.Name, Run: status.Runs, Status: status}, nil
}
