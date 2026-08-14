/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package subscription

import (
	"bytes"
	"io"
	"net/http"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type closeTrackingBody struct {
	io.Reader
	closed bool
}

func (b *closeTrackingBody) Close() error {
	b.closed = true
	return nil
}

func TestFetchRemoteSubscription(t *testing.T) {
	tests := []struct {
		name          string
		contentLength int64
		bodySize      int64
		wantErr       bool
	}{
		{name: "within limit", contentLength: maxRemoteSubscriptionSize, bodySize: maxRemoteSubscriptionSize},
		{name: "content length exceeds limit", contentLength: maxRemoteSubscriptionSize + 1, wantErr: true},
		{name: "chunked body exceeds limit", contentLength: -1, bodySize: maxRemoteSubscriptionSize + 1, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := &closeTrackingBody{Reader: io.LimitReader(
				bytes.NewReader(make([]byte, maxRemoteSubscriptionSize+1)),
				tt.bodySize,
			)}
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.Method != http.MethodGet {
					t.Fatalf("method = %q, want GET", req.Method)
				}
				if got := req.Header.Get("User-Agent"); got == "" {
					t.Fatal("User-Agent is empty")
				}
				return &http.Response{
					StatusCode:    http.StatusOK,
					ContentLength: tt.contentLength,
					Body:          body,
				}, nil
			})}

			got, err := fetchRemoteSubscription(client, "https://example.com/subscription")
			if !body.closed {
				t.Fatal("response body was not closed")
			}
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && int64(len(got)) != tt.bodySize {
				t.Fatalf("read %d bytes, want %d", len(got), tt.bodySize)
			}
		})
	}
}
