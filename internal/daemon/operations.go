// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/internal/handoff"
	log "github.com/sirupsen/logrus"
)

const operationQueueLimit = 16
const operationHistoryLimit = 64

type operationRecord struct {
	status     api.Operation
	request    api.OperationRequest
	executable *os.File
	logPipe    *os.File
}

// All ingress shares this bounded queue. Only the daemon loop runs work, and
// handlers return immediately so publication can drain plane API requests.
type operations struct {
	requests  chan string
	mu        sync.Mutex
	closed    bool
	replacing bool
	active    string
	records   map[string]*operationRecord
	completed []string
	refresh   *operationRecord
	nextCheck time.Time
}

func newOperations() *operations {
	return &operations{requests: make(chan string, operationQueueLimit), records: make(map[string]*operationRecord)}
}

func (o *operations) SubmitOperation(request api.OperationRequest) (api.Operation, error) {
	if request.ExecutablePID != 0 || request.ExecutableFD != 0 || request.Replace {
		return api.Operation{}, api.ErrOperationInvalid
	}
	return o.submit(request, "api")
}

// Ownership transfers only after the request has been accepted.
func (o *operations) SubmitExecutableOperation(request api.OperationRequest, executable, logPipe *os.File) (api.Operation, error) {
	if request.Kind != "reload" || executable == nil || request.ExecutablePID <= 0 {
		return api.Operation{}, api.ErrOperationInvalid
	}
	return o.enqueue(request, "api", executable, logPipe)
}

func (o *operations) submit(request api.OperationRequest, trigger string) (api.Operation, error) {
	return o.enqueue(request, trigger, nil, nil)
}

func (o *operations) enqueue(request api.OperationRequest, trigger string, executable, logPipe *os.File) (api.Operation, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return api.Operation{}, api.ErrOperationsClosed
	}
	if o.replacing {
		return api.Operation{}, api.ErrOperationsBusy
	}
	if request.Kind != "reload" && request.Kind != "suspend" && request.Kind != "refresh" || request.Kind == "refresh" && request.Abort {
		return api.Operation{}, api.ErrOperationInvalid
	}
	if len(o.requests) == cap(o.requests) || request.Kind == "refresh" && o.refresh != nil && o.refresh.status.FinishedAt.IsZero() {
		return api.Operation{}, api.ErrOperationsBusy
	}
	status := api.Operation{ID: rand.Text(), Kind: request.Kind, State: "queued", Trigger: trigger, QueuedAt: time.Now()}
	record := &operationRecord{status: status, request: request, executable: executable, logPipe: logPipe}
	o.records[status.ID] = record
	if request.Kind == "refresh" {
		o.refresh = record
	}
	o.requests <- status.ID
	return status, nil
}

func (o *operations) beginReplacement() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.requests) != 0 {
		return api.ErrOperationsBusy
	}
	o.replacing = true
	return nil
}

func (o *operations) endReplacement() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.replacing = false
}

func (o *operations) Operation(id string) (api.Operation, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	record, ok := o.records[id]
	if !ok {
		return api.Operation{}, false
	}
	return record.status, true
}

func (o *operations) start(id string) (api.OperationRequest, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	record := o.records[id]
	if o.closed || o.active != "" || record == nil || record.status.State != "queued" {
		return api.OperationRequest{}, false
	}
	o.active = id
	record.status.State, record.status.StartedAt = "running", time.Now()
	return record.request, true
}

func (o *operations) progress(id, message string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if record := o.records[id]; record != nil && o.active == id {
		record.status.Progress = message
		if record.logPipe != nil {
			handoff.WriteStage(record.logPipe, message)
		}
	}
}

func (o *operations) finish(id, result string, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.active != id || id == "" {
		return
	}
	o.active = ""
	record := o.records[id]
	record.status.Result = result
	record.status.State = "completed"
	if err != nil {
		record.status.State, record.status.Error = "failed", resource.RedactError(err).Error()
	}
	o.complete(record)
}

func (o *operations) complete(record *operationRecord) {
	if record.executable != nil {
		_ = record.executable.Close()
		record.executable = nil
	}
	if record.logPipe != nil {
		_ = record.logPipe.Close()
		record.logPipe = nil
	}
	record.status.FinishedAt = time.Now()
	o.completed = append(o.completed, record.status.ID)
	if len(o.completed) > operationHistoryLimit {
		delete(o.records, o.completed[0])
		o.completed = o.completed[1:]
	}
}

func (o *operations) stop() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closed = true
	for _, record := range o.records {
		if record.status.State == "queued" {
			record.status.State, record.status.Error = "canceled", "daemon is stopping"
			o.complete(record)
		}
	}
}

func (o *operations) ResourceRefreshStatus() api.ResourceRefreshStatus {
	o.mu.Lock()
	defer o.mu.Unlock()
	status := api.ResourceRefreshStatus{NextCheck: o.nextCheck}
	if o.refresh != nil {
		status.Operation = new(o.refresh.status)
	}
	return status
}

func (o *operations) setNext(next time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.nextCheck = next
}

func (a *application) executeOperation(ctx context.Context, id string) error {
	request, ok := a.operations.start(id)
	if !ok {
		return nil
	}
	status, _ := a.operations.Operation(id)
	previous := a.progress
	a.progress = func(message string) { a.operations.progress(id, message) }
	defer func() { a.progress = previous }()
	if err := notifyService(ctx, "reloading"); err != nil {
		err = fmt.Errorf("notify service reloading: %w", err)
		a.operations.finish(id, "", err)
		return err
	}
	var result string
	var err error
	o := a.operations
	o.mu.Lock()
	record := o.records[id]
	executable, logPipe := record.executable, record.logPipe
	o.mu.Unlock()
	if executable != nil {
		a.report("Comparing daemon executables...")
	}
	replace, err := needsReplacement(executable, request.Replace)
	if err != nil {
		// Keep the accepted configuration when the executable cannot be verified.
	} else if replace {
		result, err = a.replace(ctx, id, executable, logPipe)
	} else if request.Kind == "refresh" {
		result, err = a.apply(ctx, a.conf, false, false, status.Trigger == "automatic")
	} else {
		result, err = a.reload(ctx, request.Kind == "suspend", request.Abort)
	}
	if _, fatal := errors.AsType[*activationError](err); !fatal {
		if notifyErr := notifyService(ctx, "ready"); notifyErr != nil {
			err = errors.Join(err, fmt.Errorf("notify service ready: %w", notifyErr))
		}
	}
	a.operations.finish(id, result, err)
	if err != nil {
		log.WithError(resource.RedactError(err)).WithFields(log.Fields{"id": id, "kind": request.Kind}).Warn("Configuration operation failed")
	} else {
		log.WithFields(log.Fields{"id": id, "kind": request.Kind, "result": result}).Info("Configuration operation completed")
	}
	return err
}
