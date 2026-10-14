// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/api/client"
	"github.com/daeuniverse/dae/internal/apiserver"
)

func TestOperationAPIQueueAndStatus(t *testing.T) {
	o := newOperations()
	server := httptest.NewServer(apiserver.NewHandler(apiserver.Options{APIKey: "secret", Operations: o}))
	defer server.Close()
	remote, err := client.New(client.Options{Endpoint: server.URL, APIKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	refresh, err := remote.RefreshResources(t.Context())
	if err != nil || refresh.ID == "" || refresh.Kind != "refresh" || refresh.State != "queued" {
		t.Fatalf("enqueue: %+v %v", refresh, err)
	}
	if _, err := remote.RefreshResources(t.Context()); err == nil {
		t.Fatal("duplicate refresh accepted")
	}
	reload, err := remote.SubmitOperation(t.Context(), api.OperationRequest{Kind: "reload", Abort: true})
	if err != nil || reload.ID == refresh.ID {
		t.Fatalf("independent reload: %+v %v", reload, err)
	}
	if id := <-o.requests; id != refresh.ID {
		t.Fatal("queue reordered")
	}
	o.start(refresh.ID)
	o.progress(refresh.ID, "downloading")
	status, err := remote.Operation(t.Context(), reload.ID)
	if err != nil || status.State != "queued" || status.Progress != "" {
		t.Fatalf("cross-operation progress: %+v %v", status, err)
	}
	o.finish(refresh.ID, "", errors.New("download https://example.test/private?token=SECRET failed"))
	status, err = remote.Operation(t.Context(), refresh.ID)
	if err != nil || status.State != "failed" || status.Error != "download https://example.test failed" || status.FinishedAt.IsZero() {
		t.Fatalf("result: %+v %v", status, err)
	}
	<-o.requests
	request, ok := o.start(reload.ID)
	if !ok || !request.Abort {
		t.Fatal("abort must belong to the reload request")
	}
	o.finish(reload.ID, "No changes", nil)
	// A late callback cannot overwrite another operation's completion.
	o.finish(refresh.ID, "wrong", nil)
	next := time.Now().Add(time.Hour)
	o.setNext(next)
	resources, err := remote.ResourceRefreshStatus(t.Context())
	if err != nil || resources.Operation.ID != refresh.ID || resources.Operation.State != "failed" || !resources.NextCheck.Equal(next) {
		t.Fatalf("refresh status: %+v %v", resources, err)
	}
	if _, err := remote.SubmitOperation(t.Context(), api.OperationRequest{Kind: "suspend", ExpectedPID: os.Getpid() + 1}); err == nil {
		t.Fatal("mismatched PID accepted")
	}
}

func TestOperationsBoundedAndCanceled(t *testing.T) {
	o := newOperations()
	var wg sync.WaitGroup
	for range operationQueueLimit * 2 {
		wg.Go(func() { _, _ = o.SubmitOperation(api.OperationRequest{Kind: "reload"}) })
	}
	wg.Wait()
	if len(o.requests) != operationQueueLimit || len(o.records) != operationQueueLimit {
		t.Fatalf("unbounded queue: %d %d", len(o.requests), len(o.records))
	}
	active := <-o.requests
	o.start(active)
	o.stop()
	if _, err := o.SubmitOperation(api.OperationRequest{Kind: "suspend"}); !errors.Is(err, apiserver.ErrOperationsClosed) {
		t.Fatal(err)
	}
	for id, record := range o.records {
		if id != active && (record.status.State != "canceled" || record.status.FinishedAt.IsZero()) {
			t.Fatal(record.status)
		}
	}
	o.finish(active, "", errors.New("shutdown"))
	if record, _ := o.Operation(active); record.State != "failed" {
		t.Fatal(record)
	}

	o = newOperations()
	first := ""
	for range operationHistoryLimit + 1 {
		status, err := o.SubmitOperation(api.OperationRequest{Kind: "reload"})
		if err != nil {
			t.Fatal(err)
		}
		if first == "" {
			first = status.ID
		}
		<-o.requests
		o.start(status.ID)
		o.finish(status.ID, "OK", nil)
	}
	if _, ok := o.Operation(first); ok || len(o.records) != operationHistoryLimit {
		t.Fatal("completed history is not bounded")
	}
	if _, ok := newOperations().Operation(first); ok {
		t.Fatal("previous daemon operation was accepted")
	}
}

func TestLocalOperationsSurvivePlaneDrain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api.sock")
	server, err := apiserver.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	o := newOperations()
	server.SetOperations(o)
	remote, err := client.New(client.Options{Endpoint: "unix://" + path})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	// No plane handler is installed. Submitting cannot wait for publication.
	status, err := remote.SubmitOperation(t.Context(), api.OperationRequest{Kind: "suspend"})
	if err != nil {
		t.Fatal(err)
	}
	<-o.requests
	o.start(status.ID)
	server.SetHandler(nil)
	if current, err := remote.Operation(t.Context(), status.ID); err != nil || current.State != "running" {
		t.Fatalf("during publication: %+v %v", current, err)
	}
	o.finish(status.ID, "Suspended", nil)
	if current, err := remote.Operation(t.Context(), status.ID); err != nil || current.State != "completed" {
		t.Fatalf("after publication: %+v %v", current, err)
	}
}
