// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/membuffer"
)

type signaledBody struct {
	io.ReadCloser
	started chan struct{}
	once    sync.Once
}

func (b *signaledBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.started) })
	return b.ReadCloser.Read(p)
}

func TestHTTPSlowBodyReleasesExecutionSlot(t *testing.T) {
	for _, phase := range []string{"http-request", "http-response"} {
		t.Run(phase, func(t *testing.T) {
			module, err := Parse("[Body Rewrite]\n"+phase+" /slow 'before' 'after'", nil)
			if err != nil {
				t.Fatal(err)
			}
			budget := membuffer.NewBudget(1 << 20)
			e := newTestEngine(t, EngineOptions{Modules: []*Module{module}, MaxConcurrentScripts: 1, BodyMemory: budget})
			reader, writer := io.Pipe()
			defer reader.Close()
			defer writer.Close()
			body := &signaledBody{ReadCloser: reader, started: make(chan struct{})}
			r := httptest.NewRequest(http.MethodPost, "http://example.com/slow", nil)
			response := &http.Response{Request: r, StatusCode: http.StatusOK, Header: make(http.Header), Body: body}
			done := make(chan error, 1)
			go func() {
				if phase == "http-request" {
					r.Body = body
					_, err := e.processRequest(&plugin.Exchange{Request: r})
					response.Body = r.Body
					done <- err
				} else {
					done <- e.processResponse(response, nil)
				}
			}()
			<-body.started
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			fast := httptest.NewRequestWithContext(ctx, http.MethodGet, "http://example.com/unmatched", nil)
			if _, err := e.processRequest(&plugin.Exchange{Request: fast}); err != nil {
				t.Fatalf("slow body blocked unrelated request: %v", err)
			}
			io.WriteString(writer, "before")
			writer.Close()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || string(got) != "after" {
				t.Fatalf("slow request did not resume: %q, %v", got, err)
			}
			if used := budget.Status().Used; used != 0 || len(e.slots) != 0 {
				t.Fatalf("retained body memory=%d slots=%d", used, len(e.slots))
			}
		})
	}
}

func TestHTTPAdmissionWaitDoesNotFailAtRegexBudget(t *testing.T) {
	module, err := Parse("[Header Rewrite]\nhttp-request . header-add X-Processed yes", nil)
	if err != nil {
		t.Fatal(err)
	}
	e := newTestEngine(t, EngineOptions{Modules: []*Module{module}, MaxConcurrentScripts: 1})
	release, err := e.acquire(t.Context(), "fixture")
	if err != nil {
		t.Fatal(err)
	}
	go func() { time.Sleep(350 * time.Millisecond); release() }()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com/", nil)
	if _, err := e.processRequest(&plugin.Exchange{Request: r}); err != nil || r.Header.Get("X-Processed") != "yes" {
		t.Fatalf("queue wait consumed execution budget: %v, %v", err, r.Header)
	}
}

func TestHTTPBodyCancellationInterruptsRead(t *testing.T) {
	module, err := Parse("[Body Rewrite]\nhttp-request . 'before' 'after'", nil)
	if err != nil {
		t.Fatal(err)
	}
	budget := membuffer.NewBudget(1 << 20)
	e := newTestEngine(t, EngineOptions{Modules: []*Module{module}, MaxConcurrentScripts: 1, BodyMemory: budget})
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go io.WriteString(client, "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 6\r\n\r\nb")
	r, err := http.ReadRequest(bufio.NewReader(server))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	r = r.WithContext(ctx)
	body := &signaledBody{ReadCloser: r.Body, started: make(chan struct{})}
	r.Body = body
	done := make(chan error, 1)
	go func() {
		_, err := e.processRequest(&plugin.Exchange{Request: r, SetReadDeadline: server.SetReadDeadline})
		done <- err
	}()
	<-body.started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation lost: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not unblock HTTP/1 body read")
	}
	r.Body.Close()
	if used := budget.Status().Used; used != 0 || len(e.slots) != 0 {
		t.Fatalf("cancellation retained memory=%d slots=%d", used, len(e.slots))
	}
}
