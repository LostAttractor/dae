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

// Shared by the engine's authority-scoped copies. Preparation only creates job
// descriptions; the host starts Run after activating routing and stops it before
// retiring the background HTTP client on shutdown/reload.
type taskRunner struct {
	mu      sync.Mutex
	started bool
	active  bool
	ctx     context.Context
	client  *http.Client
	running sync.WaitGroup
	jobs    []*scriptTask
}

type scriptTask struct {
	module *Module
	script *Script
	busy   bool // Includes waiting for a shared script slot.
	status api.ScriptTaskStatus
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
			status := api.ScriptTaskStatus{
				Name: script.Name, Type: script.Type,
				TimeoutSeconds: e.scriptTimeout(script).Seconds(), State: "pending",
			}
			if script.Type == "cron" {
				status.CronExp, status.Timezone = script.CronExp, time.Local.String()
			}
			runner.jobs = append(runner.jobs, &scriptTask{module: module, script: script, status: status})
		}
	}
	return runner, nil
}

// Run implements plugin.Worker. Each job has at most one outstanding invocation;
// only cron jobs have timers. All tasks share the HTTP/DNS execution slots.
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
			job.status.State, job.status.LastError = "stopped", "http_client_unavailable"
		}
		c.mu.Unlock()
		return errors.New("surge: script tasks require a routed background HTTP client")
	}
	c.active, c.ctx, c.client = true, ctx, client
	now := time.Now()
	for _, job := range c.jobs {
		if job.script.schedule != nil {
			job.status.NextRun = job.script.schedule.Next(now.Round(0))
		}
		job.status.State = c.idleState(job)
	}
	c.mu.Unlock()
	defer func() {
		// Admission and WaitGroup.Add share this lock. No manual request can
		// add work after retirement starts, even when the group is empty.
		c.mu.Lock()
		c.active = false
		c.mu.Unlock()
		c.running.Wait()
		c.mu.Lock()
		defer c.mu.Unlock()
		for _, job := range c.jobs {
			job.status.State, job.status.NextRun = "stopped", time.Time{}
		}
	}()
	for ctx.Err() == nil {
		now = time.Now()
		var next time.Time
		c.mu.Lock()
		for _, job := range c.jobs {
			if job.status.NextRun.IsZero() {
				continue
			}
			if !job.status.NextRun.After(now) {
				// Cron follows wall time; invocation budgets retain now's monotonic
				// clock so clock corrections cannot extend an already running job.
				job.status.NextRun = job.script.schedule.Next(now.Round(0))
				if job.busy {
					job.status.Skipped++
					e.metrics.skip("cron", "overlap")
				} else {
					e.startTask(job, now, "")
				}
			}
			if due := job.status.NextRun; !due.IsZero() && (next.IsZero() || due.Before(next)) {
				next = due
			}
		}
		c.mu.Unlock()
		if next.IsZero() {
			<-ctx.Done()
			break
		}
		// Recheck wall time at least once a minute after clock adjustments.
		timer := time.NewTimer(min(time.Until(next), time.Minute))
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	return ctx.Err()
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

func (e *Engine) runTask(job *scriptTask, started time.Time, trigger string) {
	script := job.script
	ctx, cancel := context.WithDeadline(e.tasks.ctx, started.Add(e.scriptTimeout(script)))
	defer cancel()
	executed := false
	var err error
	defer func() {
		finished := time.Now()
		result, reason := "success", ""
		if err != nil {
			result, reason = "failed", traceErrorReason(err)
		}
		e.tasks.mu.Lock()
		job.busy = false
		job.status.State = e.tasks.idleState(job)
		job.status.LastFinishedAt, job.status.LastDurationMS = finished, finished.Sub(started).Milliseconds()
		job.status.LastResult, job.status.LastError = result, reason
		if err != nil {
			job.status.Failures++
		}
		e.tasks.mu.Unlock()
		outcome := result
		if !executed {
			outcome = "skipped"
			e.metrics.skip(script.Type, reason)
		}
		e.metrics.scripts.WithLabelValues(script.Type, outcome).Inc()
		if e.options.Logger != nil {
			entry := e.options.Logger.WithFields(log.Fields{"event": "task_end", "script_type": script.Type, "module": job.module.Name,
				"script": script.Name, "outcome": result, "reason": reason, "elapsed_ms": finished.Sub(started).Milliseconds()})
			if err != nil && !errors.Is(err, context.Canceled) {
				entry.WithError(resource.RedactError(err)).Warn("Surge script task failed")
			} else {
				entry.Trace("Surge script task finished")
			}
		}
	}()
	if err = ctx.Err(); err != nil {
		return
	}
	release, err := e.acquire(ctx, script.Type)
	if err != nil {
		return
	}
	defer release()
	e.tasks.mu.Lock()
	job.status.State = "running"
	e.tasks.mu.Unlock()
	if e.options.Logger != nil {
		e.options.Logger.WithFields(log.Fields{"event": "task_start", "script_type": script.Type, "module": job.module.Name, "script": script.Name}).Trace("Surge script task started")
	}
	executed = true
	var result *Result
	result, err = e.runInvocation(ctx, script, Invocation{
		ModuleName: job.module.Name, ScriptName: script.Name, ScriptType: script.Type, CronExp: script.CronExp, Trigger: trigger,
		Argument: script.Argument, Timeout: e.scriptTimeout(script), BinaryBodyMode: script.BinaryBodyMode,
		ArgumentSet: script.ArgumentSet, ScriptPath: script.Path, FullHeaderMode: script.FullHeaderMode,
		HTTPClient: e.tasks.client, BodyMemory: e.options.BodyMemory, BodyLimit: e.options.MaxBodySize,
	})
	result.Close()
}

// find selects within one instance. A module is optional only for unique names.
// The caller holds mu; module/script definitions are immutable after loading.
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
	if found.busy {
		return nil, plugin.ErrScriptBusy
	}
	return found, nil
}

// startTask admits and tracks work under the active worker. The caller holds
// tasks.mu and has checked job.busy. An empty trigger denotes a scheduled run;
// only manual runs expose $trigger to the script.
func (e *Engine) startTask(job *scriptTask, now time.Time, trigger string) {
	job.busy = true
	job.status.State, job.status.LastStartedAt = "waiting", now
	job.status.LastFinishedAt, job.status.LastDurationMS = time.Time{}, 0
	job.status.LastResult, job.status.LastError = "", ""
	job.status.LastTrigger = cmp.Or(trigger, "cron")
	job.status.Runs++
	e.tasks.running.Go(func() { e.runTask(job, now, trigger) })
}

// TriggerScript accepts work owned by the running daemon, independent of the
// short-lived API request. It does not change the task's next scheduled time.
func (e *Engine) TriggerScript(request api.ScriptRunRequest) (api.ScriptRunResponse, error) {
	c := e.tasks
	if c == nil {
		return api.ScriptRunResponse{}, plugin.ErrScriptNotFound
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.active || c.ctx.Err() != nil {
		return api.ScriptRunResponse{}, plugin.ErrScriptInactive
	}
	job, err := c.find(request)
	if err != nil {
		return api.ScriptRunResponse{}, err
	}
	e.startTask(job, time.Now(), "http-api")
	return api.ScriptRunResponse{Module: job.module.Name, Run: job.status.Runs, Status: job.status}, nil
}
