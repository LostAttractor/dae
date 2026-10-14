// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"crypto/rand"
	"os"
	"sync"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/internal/apiserver"
	"github.com/okzk/sdnotify"
	log "github.com/sirupsen/logrus"
)

const operationQueueLimit = 16
const operationHistoryLimit = 64

type operationRecord struct {
	status  api.Operation
	request api.OperationRequest
}

// All ingress shares this bounded queue. Only the daemon loop runs work, and
// handlers return immediately so publication can drain plane API requests.
type operations struct {
	requests  chan string
	mu        sync.Mutex
	closed    bool
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
	return o.submit(request, "api")
}

func (o *operations) submit(request api.OperationRequest, trigger string) (api.Operation, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return api.Operation{}, apiserver.ErrOperationsClosed
	}
	if request.Kind != "reload" && request.Kind != "suspend" && request.Kind != "refresh" || request.ExpectedPID < 0 || request.Kind == "refresh" && request.Abort {
		return api.Operation{}, apiserver.ErrOperationInvalid
	}
	if request.ExpectedPID != 0 && request.ExpectedPID != os.Getpid() {
		return api.Operation{}, apiserver.ErrOperationPID
	}
	if len(o.requests) == cap(o.requests) || request.Kind == "refresh" && o.refresh != nil && o.refresh.status.FinishedAt.IsZero() {
		return api.Operation{}, apiserver.ErrOperationsBusy
	}
	status := api.Operation{ID: rand.Text(), Kind: request.Kind, State: "queued", Trigger: trigger, QueuedAt: time.Now()}
	record := &operationRecord{status: status, request: request}
	o.records[status.ID] = record
	if request.Kind == "refresh" {
		o.refresh = record
	}
	o.requests <- status.ID
	return status, nil
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
	sdnotify.Reloading()
	var result string
	var err error
	if request.Kind == "refresh" {
		result, err = a.apply(ctx, a.conf, false, false, status.Trigger == "automatic")
	} else {
		result, err = a.reload(ctx, request.Kind == "suspend", request.Abort)
	}
	a.operations.finish(id, result, err)
	if err != nil {
		log.WithError(resource.RedactError(err)).WithFields(log.Fields{"id": id, "kind": request.Kind}).Warn("Configuration operation failed")
	} else {
		log.WithFields(log.Fields{"id": id, "kind": request.Kind, "result": result}).Info("Configuration operation completed")
	}
	sdnotify.Ready()
	return err
}
