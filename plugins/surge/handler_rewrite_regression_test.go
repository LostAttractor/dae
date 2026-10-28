// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/component/plugin"
)

func TestScriptURLRewriteAuthority(t *testing.T) {
	for _, test := range []struct {
		name, result, host string
	}{
		{"URL only", `{url:"https://mirror.example:8443/rewritten"}`, "mirror.example:8443"},
		{"explicit Host", `{url:"https://mirror.example:8443/rewritten",headers:{Host:"vhost.example"}}`, "vhost.example"},
	} {
		t.Run(test.name, func(t *testing.T) {
			engine := testProxyEngine(t, "[Script]\nrewrite = type=http-request,pattern=.,script-path=a.js", "$done("+test.result+");")
			req := plugin.NewRequest(httptest.NewRequest(http.MethodGet, "https://example.com/original", nil), engine.options.BodyMemory)
			defer req.Body().Close()
			if response, err := engine.processRequest(&plugin.Exchange{Request: req}); err != nil || response != nil {
				t.Fatalf("response=%v err=%v", response, err)
			}
			forwarded := forwardTestRequest(t, req)
			defer forwarded.Body.Close()
			if forwarded.URL.String() != "https://mirror.example:8443/rewritten" || forwarded.Host != test.host || forwarded.Header.Get("Host") != "" {
				t.Fatalf("URL=%s Host=%s headers=%v", forwarded.URL, forwarded.Host, forwarded.Header)
			}
		})
	}
}

func TestScriptDecodeFailureReplaysOriginal(t *testing.T) {
	for _, encoding := range []string{"zstd", "gzip", "deflate", "br", strings.Repeat("gzip,", 5)} {
		for _, phase := range []string{"http-request", "http-response"} {
			t.Run(phase+"/"+encoding, func(t *testing.T) {
				engine := testProxyEngine(t, "[Script]\nrewrite = type="+phase+",pattern=.,requires-body=1,script-path=a.js", `$done({body:"must not run"});`)
				raw := []byte{0xff, 0xff, 0xff}
				headers := http.Header{"Content-Encoding": {encoding}, "Etag": {"original"}, "Content-Length": {"3"}}
				var body io.ReadCloser
				var forwarded http.Header
				if phase == "http-request" {
					r := httptest.NewRequest(http.MethodPost, "https://example.com/", bytes.NewReader(raw))
					r.Header = headers.Clone()
					req := plugin.NewRequest(r, engine.options.BodyMemory)
					defer req.Body().Close()
					if response, err := engine.processRequest(&plugin.Exchange{Request: req}); err != nil || response != nil {
						t.Fatalf("response=%v err=%v", response, err)
					}
					r = forwardTestRequest(t, req)
					body, forwarded = r.Body, r.Header
				} else {
					r := &http.Response{Request: httptest.NewRequest(http.MethodGet, "https://example.com/", nil), StatusCode: http.StatusOK,
						Header: headers.Clone(), Body: io.NopCloser(bytes.NewReader(raw)), ContentLength: int64(len(raw))}
					response := plugin.NewResponse(r, engine.options.BodyMemory)
					defer response.Close()
					if err := engine.processResponse(response, http.DefaultClient); err != nil {
						t.Fatal(err)
					}
					r = takeTestResponse(t, response)
					body, forwarded = r.Body, r.Header
				}
				got, err := io.ReadAll(body)
				_ = body.Close()
				if err != nil || !bytes.Equal(got, raw) || !reflect.DeepEqual(forwarded, headers) {
					t.Fatalf("replay changed: body=%x headers=%v error=%v", got, forwarded, err)
				}
			})
		}
	}
}
