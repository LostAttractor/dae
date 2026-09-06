package mitm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/mitmca"
)

type testPlugin struct {
	plan Plan
	wrap func(Flow, Handler) Handler
}

func (p *testPlugin) Plan() Plan                           { return p.plan }
func (p *testPlugin) Wrap(flow Flow, next Handler) Handler { return p.wrap(flow, next) }
func response(body string) *http.Response {
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}
func testHost(t *testing.T, options Options, instances ...Instance) *Host {
	t.Helper()
	h, err := New(options, instances...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h
}

func TestPluginChainOrderAndScope(t *testing.T) {
	var instances []Instance
	var calls []string
	wraps := 0
	for _, name := range []string{"a", "b", "excluded"} {
		scope := []string{"api.example.com"}
		if name == "excluded" {
			scope = []string{"-api.example.com", "*"}
		}
		p := &testPlugin{plan: Plan{Scopes: []Scope{{Hostnames: scope}}}, wrap: func(flow Flow, next Handler) Handler {
			wraps++
			if flow.Host != "api.example.com" {
				t.Errorf("mutated connection identity: %+v", flow)
			}
			return func(e *Exchange) (*http.Response, error) {
				calls = append(calls, name+" request")
				e.Request.URL.Host = "changed.example.com"
				r, err := next(e)
				calls = append(calls, name+" response")
				return r, err
			}
		}}
		instances = append(instances, Instance{ID: name, Type: "test", Plugin: p})
	}
	h := testHost(t, Options{Authority: &mitmca.Authority{}}, instances...)
	chain := h.chain(Flow{Host: "api.example.com", Port: 443}, func(*Exchange) (*http.Response, error) { calls = append(calls, "upstream"); return response("ok"), nil })
	for range 2 {
		calls = nil
		r, err := chain(&Exchange{Request: httptest.NewRequest("GET", "https://api.example.com/", nil)})
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		want := []string{"a request", "b request", "upstream", "b response", "a response"}
		if !reflect.DeepEqual(calls, want) {
			t.Fatalf("got %v want %v", calls, want)
		}
	}
	if wraps != 2 {
		t.Fatalf("middleware rebuilt per request: wraps=%d", wraps)
	}
}

func TestPluginLocalResponse(t *testing.T) {
	p := &testPlugin{plan: Plan{Scopes: []Scope{{Hostnames: []string{"*"}}}}, wrap: func(Flow, Handler) Handler {
		return func(*Exchange) (*http.Response, error) { return response("local"), nil }
	}}
	h := testHost(t, Options{Authority: &mitmca.Authority{}}, Instance{ID: "local", Plugin: p})
	chain := h.chain(Flow{Host: "example.com", Port: 443}, func(*Exchange) (*http.Response, error) {
		t.Error("local response reached upstream")
		return nil, errors.New("unexpected upstream")
	})
	r, err := chain(&Exchange{})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	body, _ := io.ReadAll(r.Body)
	if string(body) != "local" {
		t.Fatal(string(body))
	}
}

type workerPlugin struct {
	testPlugin
	started, stopped chan struct{}
	client           *http.Client
	closed           bool
}

func (p *workerPlugin) Run(ctx context.Context, client *http.Client) error {
	p.client = client
	close(p.started)
	<-ctx.Done()
	close(p.stopped)
	return ctx.Err()
}
func (p *workerPlugin) Close() error { p.closed = true; return nil }
func TestPluginLifecycle(t *testing.T) {
	client := &http.Client{}
	p := &workerPlugin{started: make(chan struct{}), stopped: make(chan struct{})}
	h := testHost(t, Options{HTTPClient: client}, Instance{ID: "worker", Plugin: p})
	select {
	case <-p.started:
		t.Fatal("worker started in preparation")
	default:
	}
	if err := h.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.started:
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}
	if p.client != client {
		t.Fatal("worker did not receive the runtime HTTP client")
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.stopped:
	default:
		t.Fatal("worker was not joined")
	}
	if !p.closed {
		t.Fatal("plugin resources were not closed")
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if err := h.Start(context.Background()); err == nil {
		t.Fatal("restarted closed host")
	}
}

func TestLoadRollsBackPreparedPlugins(t *testing.T) {
	p := &workerPlugin{started: make(chan struct{}), stopped: make(chan struct{})}
	name := fmt.Sprintf("rollback_test_%d", serial.Add(1))
	Register(name, func(context.Context, Spec, Services) (Plugin, error) { return p, nil })
	_, err := Load(context.Background(), []Spec{{ID: "first", Type: name}, {ID: "second", Type: "not_registered"}}, Options{}, Services{})
	if err == nil || !p.closed {
		t.Fatalf("failed preparation leaked resources: err=%v closed=%v", err, p.closed)
	}
	select {
	case <-p.started:
		t.Fatal("failed preparation started a worker")
	default:
	}
}

func TestHostRequiresCAForHTTPScopes(t *testing.T) {
	_, err := New(Options{}, Instance{ID: "tls", Plugin: &testPlugin{plan: Plan{Scopes: []Scope{{Hostnames: []string{"*"}}}}}})
	if err == nil {
		t.Fatal("accepted HTTPS scope without a CA")
	}
	// Workers and destination-only plugins have no HTTP scopes.
	testHost(t, Options{}, Instance{ID: "no_http", Plugin: &testPlugin{}})
}

type trackedBody struct {
	io.Reader
	closed bool
}

func (b *trackedBody) Close() error { b.closed = true; return nil }
func TestPluginHTTPErrorClosesBodyAndGuardsAuthority(t *testing.T) {
	body := &trackedBody{Reader: strings.NewReader("secret")}
	p := &testPlugin{plan: Plan{Scopes: []Scope{{Hostnames: []string{"example.com"}}}}, wrap: func(Flow, Handler) Handler {
		return func(*Exchange) (*http.Response, error) {
			r := response("")
			r.Body = body
			return r, errors.New("failure")
		}
	}}
	h := testHost(t, Options{Authority: &mitmca.Authority{}}, Instance{ID: "test", Plugin: p})
	handler, closeTransport := h.Handler("http", "example.com", 80, nil)
	defer closeTransport()
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "http://wrong.example/", nil))
	if w.Code != 421 {
		t.Fatal(w.Code)
	}
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "http://example.com/", nil))
	if w.Code != 502 || !body.closed {
		t.Fatalf("code=%d closed=%v", w.Code, body.closed)
	}
}

func TestScopePorts(t *testing.T) {
	for _, s := range []struct {
		pattern string
		port    uint16
		want    bool
	}{{"example.com", 443, true}, {"example.com", 80, true}, {"example.com:8443", 80, true}, {"example.com", 8443, false}, {"example.com:0", 8443, true}, {"example.com:443junk", 443, false}, {"*.example.com", 443, false}} {
		if got := (Scope{Hostnames: []string{s.pattern}}).Match("example.com", s.port); got != s.want {
			t.Errorf("%+v: %v", s, got)
		}
	}
}
