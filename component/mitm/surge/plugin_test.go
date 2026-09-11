package surge

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/mitm/ca"
	"github.com/daeuniverse/dae/component/plugin"
)

func TestSurgePluginsShareHostAndKeepIndependentState(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-A") != "1" || r.Header.Get("X-B") != "1" {
			t.Errorf("missing independent request scripts: %v", r.Header)
		}
		fmt.Fprint(w, "origin")
	}))
	defer upstream.Close()
	var instances []mitm.Instance
	var options mitm.Options
	for _, id := range []string{"A", "B"} {
		m := moduleScopeModule(t, id, "api.example.com", `[Script]
request=type=http-request,pattern=.,script-path=request.js
response=type=http-response,pattern=.,requires-body=1,script-path=response.js
`, map[string]string{
			"request":  fmt.Sprintf(`const n=Number($persistentStore.read("n")||0)+1;$persistentStore.write(String(n),"n");$done({headers:{...$request.headers,"X-%s":String(n)}});`, id),
			"response": fmt.Sprintf(`$done({body:$response.body+"%s"});`, id),
		})
		e := moduleScopeEngine(t, m)
		options.Authority = &mitmca.Authority{}
		instances = append(instances, mitm.Instance{ID: id, Type: "surge", Plugin: e})
	}
	h, err := mitm.New(options, instances...)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	handler, closeTransport := h.Handler("http", "api.example.com", 80, testUpstream(func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
	}))
	defer closeTransport()
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "http://api.example.com/", nil))
	body, err := io.ReadAll(w.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || string(body) != "originBA" {
		t.Fatalf("code=%d body=%q", w.Code, body)
	}
}

func TestHostOnlyPlanAndUnsupportedDNS(t *testing.T) {
	for _, value := range []string{"server:system", "script:dns.js", "alias.example"} {
		_, err := Parse("[Host]\napi.example.com = "+value+"\n*.example.com = 198.51.100.2\n", nil)
		if err == nil || !strings.Contains(err.Error(), "module line 2") {
			t.Fatalf("missing Host diagnostic: %v", err)
		}
	}
	module, err := Parse("[Host]\napi.example.com = 198.51.100.1\n*.example.com = 198.51.100.2\n", nil)
	if err != nil {
		t.Fatal(err)
	}
	engine := &Engine{options: EngineOptions{BodyMemory: plugin.BodyMemory, Modules: []*Module{module}}}
	host, err := mitm.New(mitm.Options{}, mitm.Instance{ID: "hosts", Plugin: engine})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	if p := host.Plan(); len(p.Scopes) != 0 || len(p.Destinations) != 2 {
		t.Fatalf("Host-only plan: %+v", p)
	}
}

func TestSurgeHostTLSAndDrain(t *testing.T) {
	for _, http2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("http2=%v", http2), func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			_, trust, dial := integrationUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(entered)
				<-release
				fmt.Fprint(w, "upstream")
			}))
			e, roots := integrationEngine(t, map[string]string{"http-response": `$done({body:$response.body+"-plugin"});`}, trust)
			h, err := mitm.New(e.hostOptions, mitm.Instance{ID: "surge", Type: "surge", Plugin: e.Engine})
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			client := integrationClient(t, e, roots, dial, http2, h)
			result := make(chan error, 1)
			go func() {
				r, err := client.Get("https://example.com/")
				if err == nil {
					defer r.Body.Close()
					body, readErr := io.ReadAll(r.Body)
					err = readErr
					if err == nil && (string(body) != "upstream-plugin" || http2 && r.ProtoMajor != 2) {
						err = fmt.Errorf("response %s %q", r.Proto, body)
					}
				}
				result <- err
			}()
			select {
			case <-entered:
			case err := <-result:
				close(release)
				t.Fatalf("request failed: %v", err)
			case <-time.After(5 * time.Second):
				close(release)
				t.Fatal("request stalled")
			}
			closed := make(chan error, 1)
			go func() { closed <- h.Close() }()
			select {
			case err := <-closed:
				close(release)
				t.Fatalf("host closed before active request drained: %v", err)
			case <-time.After(30 * time.Millisecond):
			}
			close(release)
			if err := <-result; err != nil {
				t.Fatal(err)
			}
			if err := <-closed; err != nil {
				t.Fatal(err)
			}
		})
	}
}
