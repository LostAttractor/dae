// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/internal/pluginctx"
)

func TestRuntimeHTTPPolicyAcrossRedirects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "http://second.example/final", http.StatusFound)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()
	var policies []string
	client, closeClient := mitm.NewRoutedHTTPClient(func(r *http.Request) (mitm.UpstreamPlan, error) {
		policy := pluginctx.HTTPPolicy(r.Context())
		policies = append(policies, policy)
		return mitm.UpstreamPlan{Key: r.URL.Host + "/" + policy, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", server.Listener.Addr().String())
		}}, nil
	})
	defer closeClient()
	r := testRuntime(t, RuntimeOptions{})
	result, err := r.Run(t.Context(), `
const request = options => new Promise((resolve, reject) => $httpClient.get(options, (error, response, data) => error ? reject(Error(error)) : resolve(data)));
(async () => {
  await request({url:"http://first.example/redirect", policy:"proxy"});
  await (await fetch("http://first.example/redirect", {method:"PUT", body:"payload", policy:"DIRECT"})).text();
  $done({body:await request("http://first.example/plain")});
})();`, Invocation{HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	if len(policies) != 5 || policies[0] != "proxy" || policies[1] != "proxy" || policies[2] != "DIRECT" || policies[3] != "DIRECT" || policies[4] != "" || string(result.Body.Bytes()) != "ok" {
		t.Fatalf("policy leaked or was lost: %v", policies)
	}
}

func TestRuntimeHTTPPolicyRequiresRoutedClient(t *testing.T) {
	client := &http.Client{Transport: runtimeRoundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Error("explicit policy used an unconfigured client")
		return nil, fmt.Errorf("unexpected request")
	})}
	r := testRuntime(t, RuntimeOptions{})
	result, err := r.Run(t.Context(), `$httpClient.get({url:"http://example.com/",policy:"proxy"}, error => {
  if (!error || !error.includes("policy selection")) throw Error("missing policy error");
  $done();
});`, Invocation{HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	result.Close()
}
