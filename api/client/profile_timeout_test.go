// SPDX-License-Identifier: AGPL-3.0-only
package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

type profileRoundTrip func(*http.Request) (*http.Response, error)

func (f profileRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestProfileTimeoutBudget(t *testing.T) {
	for _, test := range []struct {
		name                              string
		profile                           string
		seconds                           int
		timeout, contextTimeout, sampling time.Duration
		wantTimeout                       bool
	}{
		{name: "default CPU", profile: "profile", sampling: 30 * time.Second},
		{name: "explicit CPU duration", profile: "profile", seconds: 60, sampling: 60 * time.Second},
		{name: "delta heap", profile: "heap", seconds: 20, sampling: 20 * time.Second},
		{name: "explicit short timeout", profile: "profile", timeout: time.Second, sampling: 30 * time.Second, wantTimeout: true},
		{name: "context deadline", profile: "profile", contextTimeout: time.Second, sampling: 30 * time.Second, wantTimeout: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				c, err := New(Options{Endpoint: "https://127.0.0.1:9080", APIKey: "admin", Timeout: test.timeout})
				if err != nil {
					t.Fatal(err)
				}
				originalTimeout := c.http.Timeout
				c.http.Transport = profileRoundTrip(func(r *http.Request) (*http.Response, error) {
					if r.Header.Get("Authorization") != "Bearer admin" {
						t.Error("profile lost credentials")
					}
					select {
					case <-time.After(test.sampling):
						return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("profile"))}, nil
					case <-r.Context().Done():
						return nil, r.Context().Err()
					}
				})
				ctx := t.Context()
				if test.contextTimeout > 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, test.contextTimeout)
					defer cancel()
				}
				var out strings.Builder
				err = c.Profile(ctx, test.profile, test.seconds, &out)
				if test.wantTimeout {
					if !errors.Is(err, context.DeadlineExceeded) {
						t.Fatalf("expected deadline, got %v", err)
					}
				} else if err != nil || out.String() != "profile" {
					t.Fatal(out.String(), err)
				}
				if c.http.Timeout != originalTimeout {
					t.Fatal("profile mutated the shared client timeout")
				}
			})
		})
	}
}
