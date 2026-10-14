// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"context"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/api/client"
)

func TestOperationWaitUsesExactIdentity(t *testing.T) {
	for _, kind := range []string{"reload", "suspend"} {
		for _, other := range []api.Operation{{ID: "different", Kind: kind, State: "completed"}, {ID: "mine", Kind: "refresh", State: "completed"}} {
			opts := operationWaitOptions{id: "mine", kind: kind, timeout: time.Minute, pollInterval: time.Second, poll: func(context.Context, string) (*api.Operation, error) { return &other, nil }}
			if _, err := waitForOperation(t.Context(), opts); err == nil {
				t.Fatal("accepted completion of a different operation")
			}
		}
	}
}

func TestOperationWaitProgressAndFailures(t *testing.T) {
	for _, kind := range []string{"reload", "suspend"} {
		for _, outcome := range []string{"completed", "failed", "canceled", "running", "missing"} {
			t.Run(kind+"/"+outcome, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					polls, updates := 0, 0
					opts := operationWaitOptions{id: "mine", kind: kind, timeout: 5 * time.Second, pollInterval: time.Second, onProgress: func(string) { updates++ }}
					opts.poll = func(ctx context.Context, id string) (*api.Operation, error) {
						if id != "mine" {
							t.Fatal(id)
						}
						polls++
						if polls == 1 {
							return nil, &client.Error{StatusCode: 503}
						}
						state := outcome
						if polls == 2 {
							state = "running"
						}
						if state == "missing" {
							return nil, &client.Error{StatusCode: 404}
						}
						return &api.Operation{ID: id, Kind: kind, State: state, Progress: "publishing", Result: "done", Error: "rejected"}, nil
					}
					result, err := waitForOperation(t.Context(), opts)
					if updates != 1 {
						t.Fatalf("progress updates = %d", updates)
					}
					if outcome == "completed" {
						if err != nil || result != "done" {
							t.Fatalf("%q %v", result, err)
						}
					} else {
						if err == nil || result != "" {
							t.Fatalf("%q %v", result, err)
						}
						if outcome == "running" && !strings.Contains(err.Error(), "last step: publishing") {
							t.Fatal(err)
						}
					}
				})
			})
		}
	}
}
