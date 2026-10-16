// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func redirectTestScript(api, url string, manual bool) string {
	if api == "$httpClient" {
		return fmt.Sprintf(`$httpClient.post({url:%q, body:"script-private-body", "auto-redirect":%t}, (error, response) => {
  $done({body:error ? String(error) : String(response.status)});
});`, url, !manual)
	}
	mode := "follow"
	if manual {
		mode = "manual"
	}
	return fmt.Sprintf(`fetch(%q, {method:"POST", body:"script-private-body", redirect:%q}).then(
  response => $done({body:String(response.status)}), error => $done({body:String(error)})
);`, url, mode)
}

func TestRuntimeHTTPRejectsDowngradeBeforeNetwork(t *testing.T) {
	for _, api := range []string{"$httpClient", "fetch"} {
		t.Run(api, func(t *testing.T) {
			var plainRequests atomic.Int32
			plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				plainRequests.Add(1)
			}))
			defer plain.Close()
			secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				data, err := io.ReadAll(req.Body)
				if err != nil || req.Method != "POST" || string(data) != "script-private-body" {
					t.Errorf("initial request: %s %q %v", req.Method, data, err)
				}
				http.Redirect(w, req, plain.URL, http.StatusTemporaryRedirect)
			}))
			defer secure.Close()
			r := testRuntime(t, RuntimeOptions{})
			result, err := r.Run(t.Context(), redirectTestScript(api, secure.URL, false), Invocation{HTTPClient: secure.Client()})
			if err != nil {
				t.Fatal(err)
			}
			defer result.Close()
			if got := string(result.Body.Bytes()); !strings.Contains(got, "downgrade") || plainRequests.Load() != 0 {
				t.Fatalf("result=%q, plaintext requests=%d", got, plainRequests.Load())
			}
		})
	}
}

func TestRuntimeHTTPRedirectSchemes(t *testing.T) {
	for _, api := range []string{"$httpClient", "fetch"} {
		t.Run(api, func(t *testing.T) {
			r := testRuntime(t, RuntimeOptions{})
			for _, test := range []struct {
				name         string
				locations    []string
				blocked      bool
				manual       bool
				clientManual bool
				mutate       bool
			}{
				{name: "direct HTTP", locations: []string{"http://one.test/"}},
				{name: "HTTP cross-host", locations: []string{"http://one.test/", "http://two.test/"}},
				{name: "upgrade", locations: []string{"http://one.test/", "https://two.test/"}},
				{name: "HTTPS same-origin", locations: []string{"https://one.test/", "https://one.test/next"}},
				{name: "HTTPS cross-host", locations: []string{"https://one.test/", "https://two.test/"}},
				{name: "downgrade same-host", locations: []string{"https://one.test/", "http://one.test/next"}, blocked: true},
				{name: "downgrade cross-host", locations: []string{"https://one.test/", "http://two.test/"}, blocked: true},
				{name: "downgrade after HTTPS hop", locations: []string{"https://one.test/", "https://two.test/", "http://three.test/"}, blocked: true},
				{name: "downgrade after upgrade", locations: []string{"http://one.test/", "https://two.test/", "http://three.test/"}, blocked: true},
				{name: "manual downgrade", locations: []string{"https://one.test/", "http://two.test/"}, manual: true},
				{name: "client manual downgrade", locations: []string{"https://one.test/", "http://two.test/"}, clientManual: true},
				{name: "callback downgrade", locations: []string{"https://one.test/", "https://two.test/"}, blocked: true, mutate: true},
			} {
				for _, status := range []int{301, 302, 303, 307, 308} {
					t.Run(fmt.Sprintf("%s/%d", test.name, status), func(t *testing.T) {
						var requests atomic.Int32
						client := &http.Client{Transport: runtimeRoundTripFunc(func(req *http.Request) (*http.Response, error) {
							if req.Body != nil {
								defer req.Body.Close()
							}
							i := int(requests.Add(1)) - 1
							if i >= len(test.locations) || req.URL.String() != test.locations[i] {
								return nil, fmt.Errorf("unexpected request %d: %s", i, req.URL)
							}
							response := &http.Response{StatusCode: 200, Header: make(http.Header), Body: http.NoBody, Request: req}
							if i+1 < len(test.locations) {
								response.StatusCode = status
								response.Header.Set("Location", test.locations[i+1])
							}
							return response, nil
						})}
						if test.mutate {
							client.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
								req.URL.Scheme = "http"
								return nil
							}
						} else if test.clientManual {
							client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
						}
						result, err := r.Run(t.Context(), redirectTestScript(api, test.locations[0], test.manual), Invocation{HTTPClient: client})
						if err != nil {
							t.Fatal(err)
						}
						defer result.Close()
						got, want, wantRequests := string(result.Body.Bytes()), "200", len(test.locations)
						if test.blocked {
							want = "downgrade"
							wantRequests--
						} else if test.manual || test.clientManual {
							want, wantRequests = strconv.Itoa(status), 1
						}
						if !strings.Contains(got, want) || int(requests.Load()) != wantRequests {
							t.Fatalf("result=%q requests=%d, want %q requests=%d", got, requests.Load(), want, wantRequests)
						}
					})
				}
			}
		})
	}
}
