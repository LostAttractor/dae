// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
)

func TestProxyIntegrationMapLocalSkipsScriptAndUpstreamHTTP(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("http2=%t", h2), func(t *testing.T) {
			_, trust, dial := integrationUpstream(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("Map Local sent an upstream HTTP request")
			}))
			engine, roots := integrationEngine(t, map[string]string{
				"http-request": `$done({response:{body:"unexpected script execution"}});`,
			}, trust)
			module, err := Parse(`[Map Local]
^https://example.com/grpc data-type=base64 data="AAAAAAA=" header="content-type: application/grpc|grpc-status: 0"
`, nil)
			if err != nil {
				t.Fatal(err)
			}
			engine.options.Modules[0].MapLocals = module.MapLocals
			var dials atomic.Int32
			client := integrationClient(t, engine, roots, func(ctx context.Context, network, address string) (net.Conn, error) {
				dials.Add(1)
				return dial(ctx, network, address)
			}, h2)
			resp, err := client.Post("https://example.com/grpc", "application/grpc", bytes.NewReader([]byte{0, 0, 0, 0, 0}))
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || !bytes.Equal(body, []byte{0, 0, 0, 0, 0}) || resp.Header.Get("Grpc-Status") != "0" || resp.Header.Get("Content-Type") != "application/grpc" {
				t.Fatalf("local gRPC response body=%v headers=%v err=%v", body, resp.Header, err)
			}
			if h2 && resp.ProtoMajor != 2 {
				t.Fatal("expected HTTP/2")
			}
			if dials.Load() != 0 {
				t.Fatalf("local response dialed upstream %d times", dials.Load())
			}
		})
	}
}

func TestProxyIntegrationScriptGRPCTrailers(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("http2=%t", h2), func(t *testing.T) {
			_, trust, dial := integrationUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/grpc")
				w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
				_, _ = w.Write([]byte("original"))
				w.Header().Set("Grpc-Status", "7")
				w.Header().Set("Grpc-Message", "original-message")
			}))
			engine, roots := integrationEngine(t, map[string]string{
				"http-response": `
if ($response.h2_trailers["grpc-status"] !== "7") throw Error("missing upstream trailers");
if ($response.headers["content-type"] !== "application/grpc") throw Error("case-sensitive headers");
$done({body:"rewritten", h2_trailers:{"grpc-status":"0","grpc-message":"rewritten-message"}});
`,
			}, trust)
			client := integrationClient(t, engine, roots, dial, h2)
			resp, err := client.Get("https://example.com/grpc")
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || string(body) != "rewritten" || resp.Trailer.Get("Grpc-Status") != "0" || resp.Trailer.Get("Grpc-Message") != "rewritten-message" {
				t.Fatalf("body=%q trailer=%v err=%v", body, resp.Trailer, err)
			}
		})
	}
}

func TestProxyIntegrationSyntheticGRPCTrailers(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprintf("http2=%t", h2), func(t *testing.T) {
			engine, roots := integrationEngine(t, map[string]string{
				"http-request": `$done({response:{body:"local",headers:{"content-type":"application/grpc"},h2_trailers:{"grpc-status":"0"}}});`,
			}, nil)
			client := integrationClient(t, engine, roots, nil, h2)
			resp, err := client.Get("https://example.com/grpc")
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || string(body) != "local" || resp.Trailer.Get("Grpc-Status") != "0" {
				t.Fatalf("body=%q trailer=%v err=%v", body, resp.Trailer, err)
			}
		})
	}
}

func TestScriptTrailersRejectFraming(t *testing.T) {
	for _, key := range []string{"Content-Length", "Transfer-Encoding", "Host", "Trailer"} {
		if _, err := resultTrailers(http.Header{key: {"value"}}); err == nil {
			t.Errorf("accepted forbidden trailer %s", key)
		}
	}
}
