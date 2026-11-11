// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/api/client"
	"github.com/daeuniverse/dae/internal/apiserver"
)

func TestExecutableOperationAuthenticationAndOwnership(t *testing.T) {
	o := newOperations()
	path := filepath.Join(t.TempDir(), "dae.sock")
	server, err := apiserver.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	server.SetOperations(o)
	remote, err := client.New(client.Options{Endpoint: "unix://" + path})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	for _, request := range []api.OperationRequest{
		{Kind: "reload", Replace: true},
		{Kind: "reload", ExecutablePID: os.Getpid() + 1},
		{Kind: "suspend", ExecutablePID: os.Getpid()},
	} {
		if _, err := remote.SubmitOperation(t.Context(), request); err == nil {
			t.Fatalf("accepted invalid request: %+v", request)
		}
	}
	for _, complete := range []bool{false, true} {
		status, err := remote.SubmitOperation(t.Context(), api.OperationRequest{Kind: "reload", ExecutablePID: os.Getpid(), Replace: true})
		if err != nil {
			t.Fatal(err)
		}
		file := o.records[status.ID].executable
		if replace, err := needsReplacement(file, false); replace || err != nil {
			t.Fatalf("wrong peer executable: %v, %v", replace, err)
		}
		<-o.requests
		if complete {
			o.start(status.ID)
			o.finish(status.ID, "ok", nil)
		} else {
			o.stop()
			o.closed = false
		}
		if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("FD not closed on completion/cancel: %v", err)
		}
	}
	if err := o.beginReplacement(); err != nil {
		t.Fatal(err)
	}
	if _, err := o.SubmitOperation(api.OperationRequest{Kind: "reload"}); !errors.Is(err, apiserver.ErrOperationsBusy) {
		t.Fatal(err)
	}
	o.endReplacement()
	if _, err := o.SubmitOperation(api.OperationRequest{Kind: "reload"}); err != nil {
		t.Fatal(err)
	}
	if err := o.beginReplacement(); !errors.Is(err, apiserver.ErrOperationsBusy) {
		t.Fatalf("discarded queued operations: %v", err)
	}

	tcp := httptest.NewServer(apiserver.NewHandler(apiserver.Options{APIKey: "key", Operations: o}))
	defer tcp.Close()
	remoteTCP, err := client.New(client.Options{Endpoint: tcp.URL, APIKey: "key"})
	if err != nil {
		t.Fatal(err)
	}
	defer remoteTCP.Close()
	_, err = remoteTCP.SubmitOperation(t.Context(), api.OperationRequest{Kind: "reload", Replace: true, ExecutablePID: os.Getpid()})
	response, ok := errors.AsType[*client.Error](err)
	if !ok || response.StatusCode != http.StatusForbidden {
		t.Fatalf("remote replacement accepted: %v", err)
	}
}
