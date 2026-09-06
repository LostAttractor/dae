package surgemodule

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/mitmca"
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
	handler, closeTransport := h.Handler("http", "api.example.com", 80, func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
	})
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
