// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api/client"
	"github.com/daeuniverse/dae/internal/apiserver"
)

func TestResourceRefreshAPIQueueAndStatus(t *testing.T) {
	refresher := newResourceRefresher()
	server := httptest.NewServer(apiserver.NewHandler(apiserver.Options{APIKey: "secret", Resources: refresher}))
	defer server.Close()
	remote, err := client.New(client.Options{Endpoint: server.URL, APIKey: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	status, err := remote.RefreshResources(t.Context())
	if err != nil || status.Run != 1 || status.State != "queued" {
		t.Fatalf("enqueue: %+v %v", status, err)
	}
	if _, err := remote.RefreshResources(t.Context()); err == nil {
		t.Fatal("duplicate refresh accepted")
	}
	if refresher.start(true) {
		t.Fatal("automatic refresh displaced queued API work")
	}
	<-refresher.requests
	refresher.start(false)
	// The request returned before publication, so draining the API cannot deadlock.
	status, err = remote.ResourceRefreshStatus(t.Context())
	if err != nil || status.State != "running" || status.StartedAt.IsZero() {
		t.Fatalf("running: %+v %v", status, err)
	}
	refresher.finish("", errors.New("download https://example.test/private?token=SECRET failed"))
	status, err = remote.ResourceRefreshStatus(t.Context())
	if err != nil || status.State != "failed" || status.Error != "download https://example.test failed" || status.FinishedAt.IsZero() {
		t.Fatalf("result: %+v %v", status, err)
	}
	next := time.Now().Add(time.Hour)
	refresher.setNext(next)
	if !refresher.start(true) {
		t.Fatal("automatic refresh could not start after failure")
	}
	refresher.finish("No changes", nil)
	status = new(refresher.ResourceRefreshStatus())
	if status.Run != 2 || status.Trigger != "automatic" || status.Error != "" || status.Result != "No changes" || !status.NextCheck.Equal(next) {
		t.Fatalf("recovery: %+v", status)
	}
}
