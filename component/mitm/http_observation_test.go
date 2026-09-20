// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

type requestEndHook struct{ entries chan *log.Entry }

func (h *requestEndHook) Levels() []log.Level { return log.AllLevels }
func (h *requestEndHook) Fire(entry *log.Entry) error {
	if entry.Data["event"] == "mitm_request_end" {
		h.entries <- entry
	}
	return nil
}

func observationLogger() (*log.Entry, *logtest.Hook, *requestEndHook) {
	logger := log.New()
	logger.SetLevel(log.TraceLevel)
	logger.SetOutput(io.Discard)
	hook := logtest.NewLocal(logger)
	end := &requestEndHook{entries: make(chan *log.Entry, 16)}
	logger.AddHook(end)
	return log.NewEntry(logger), hook, end
}

func (h *requestEndHook) next(t *testing.T) *log.Entry {
	t.Helper()
	select {
	case entry := <-h.entries:
		return entry
	case <-time.After(3 * time.Second):
		t.Fatal("request completion was not recorded")
		return nil
	}
}

// Exercise the real TCP/H3 listeners, transports, ResponseController and trailer
// encoding with observation enabled. A reset after headers must remain a failed
// stream, and must not prevent a subsequent RPC on the downstream connection.
func TestObservedGRPCPassthrough(t *testing.T) {
	for _, test := range []struct {
		protocol string
		level    log.Level
	}{{"h2", log.TraceLevel}, {"h3", log.TraceLevel}, {"h3", log.InfoLevel}} {
		protocol := test.protocol
		t.Run(protocol+"/"+test.level.String(), func(t *testing.T) {
			logger, hook, end := observationLogger()
			logger.Logger.SetLevel(test.level)
			authority, roots := http3TestAuthority(t)
			payload := "\x00\x00\x00\x00\x0bsecret-body"
			reset := make(chan struct{})
			upstreamHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ProtoMajor == 1 {
					t.Error("gRPC test upstream did not negotiate HTTP/2 or HTTP/3")
				}
				if got := r.Header.Get("X-Forwarded-For"); got != "" {
					t.Errorf("transparent proxy injected X-Forwarded-For: %q", got)
				}
				if r.Header.Get("Te") != "trailers" {
					t.Error("lost gRPC trailer negotiation")
				}
				_, _ = io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "application/grpc")
				w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
				if r.URL.Path == "/reset" {
					w.Header().Set("Content-Length", "16384")
					_, _ = io.WriteString(w, strings.Repeat("x", 8192))
					_ = http.NewResponseController(w).Flush()
					select {
					case <-reset:
					case <-r.Context().Done():
					}
					panic(http.ErrAbortHandler)
				}
				// Include both announced and late-discovered trailers.
				if r.URL.Path == "/announced" {
					w.Header().Set("Trailer", "Grpc-Status")
				}
				_, _ = io.WriteString(w, payload)
				_ = http.NewResponseController(w).Flush()
				if r.URL.Path == "/announced" {
					w.Header().Set("Grpc-Status", "0")
				} else {
					w.Header().Set(http.TrailerPrefix+"Grpc-Status", "14")
				}
			})
			host := testHost(t, Options{Authority: authority, UpstreamTLSConfig: &tls.Config{RootCAs: roots}, Logger: logger})
			var client *http.Client
			if protocol == "h3" {
				peer := http3TestUpstream(t, authority.TLSConfig("example.com"), upstreamHandler)
				client, _, _ = http3TestClient(t, host, roots, "example.com", peer)
			} else {
				upstream := httptest.NewUnstartedServer(upstreamHandler)
				upstream.EnableHTTP2 = true
				upstream.TLS = authority.TLSConfig("example.com")
				upstream.TLS.NextProtos = []string{"h2", "http/1.1"}
				upstream.StartTLS()
				t.Cleanup(upstream.Close)
				client, _ = tcpDrainClient(t, host, roots, protocol, testUpstream(func(ctx context.Context, network, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
				}))
			}
			var connection, pathID string
			for _, path := range []string{"/announced", "/secret-path", "/reset", "/announced"} {
				r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://example.com"+path+"?token=secret-query", strings.NewReader("secret-upload"))
				if err != nil {
					t.Fatal(err)
				}
				r.Header.Set("Content-Type", "application/grpc")
				r.Header.Set("Te", "trailers")
				r.Header.Set("Authorization", "Bearer secret-auth")
				resp, err := client.Do(r)
				if err != nil {
					t.Fatal(err)
				}
				if path == "/reset" {
					close(reset)
				}
				body, readErr := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if test.level == log.InfoLevel {
					if path == "/reset" {
						if readErr == nil {
							t.Fatal("truncated stream succeeded with diagnostics disabled")
						}
					} else if readErr != nil || string(body) != payload || resp.Trailer.Get("Grpc-Status") == "" {
						t.Fatalf("response changed with diagnostics disabled: %v", readErr)
					}
					continue
				}
				entry := end.next(t)
				if connection == "" {
					connection = entry.Data["connection_id"].(string)
				}
				if connection == "" || entry.Data["connection_id"] != connection || entry.Data["request_id"] == "" {
					t.Fatalf("lost downstream connection identity: %v", entry.Data)
				}
				if entry.Data["status"] != http.StatusOK {
					t.Fatalf("%s: unexpected response status: %v", path, entry.Data)
				}
				if path == "/reset" {
					if readErr == nil || entry.Data["read_error"] == nil || entry.Data["body_eof"] != false || entry.Data["outcome"] != "transfer_error" {
						t.Fatalf("masked truncated stream: bytes=%d error=%v diagnostic=%v", len(body), readErr, entry.Data)
					}
					continue
				}
				code := uint64(14)
				if path == "/announced" {
					code = 0
					if pathID != "" && entry.Data["path_id"] != pathID {
						t.Fatal("same path has different diagnostic identity")
					}
					pathID = entry.Data["path_id"].(string)
				}
				if readErr != nil || string(body) != payload || resp.Trailer.Get("Grpc-Status") != strconv.FormatUint(code, 10) {
					t.Fatalf("%s: changed gRPC response: body=%q trailers=%v error=%v diagnostic=%v", path, body, resp.Trailer, readErr, entry.Data)
				}
				if entry.Data["grpc_status"] != code || entry.Data["body_eof"] != true || entry.Data["outcome"] != "completed" || entry.Data["response_read_bytes"] != int64(len(payload)) || entry.Data["response_written_bytes"] != int64(len(payload)) {
					t.Fatalf("incorrect response diagnostic: %v", entry.Data)
				}
			}
			reused := false
			for _, entry := range hook.AllEntries() {
				if entry.Data["event"] == "mitm_upstream_connection" && entry.Data["reused"] == true {
					reused = true
				}
				text, err := entry.String()
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(text, "secret-") {
					t.Fatalf("diagnostic leaked request or response contents: %s", text)
				}
			}
			if test.level == log.TraceLevel && !reused {
				t.Fatal("upstream reuse was not recorded")
			}
		})
	}
}

type failingResponseWriter struct{ *httptest.ResponseRecorder }

func (w failingResponseWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestObservedResponseWriteFailureAndRejection(t *testing.T) {
	logger, _, end := observationLogger()
	host := testHost(t, Options{Logger: logger})
	handler := host.handlerForFlow("http", plugin.Flow{Host: "example.com", Port: 80}, roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response("body"), nil
	}), http.DefaultClient)
	r := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	// Make ReverseProxy use the same abort behavior as a real HTTP server.
	r = r.WithContext(context.WithValue(r.Context(), http.ServerContextKey, &http.Server{}))
	func() {
		defer func() {
			if failure := recover(); failure != http.ErrAbortHandler {
				t.Errorf("response write failure did not preserve abort: %v", failure)
			}
		}()
		handler.ServeHTTP(failingResponseWriter{httptest.NewRecorder()}, r)
	}()
	entry := end.next(t)
	if entry.Data["write_error"] != io.ErrClosedPipe.Error() || entry.Data["outcome"] != "transfer_error" {
		t.Fatalf("missing downstream write error: %v", entry.Data)
	}
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://wrong.example/", nil))
	entry = end.next(t)
	if entry.Data["status"] != http.StatusMisdirectedRequest || entry.Data["request_id"] == "" || entry.Data["outcome"] != "local_rejection" {
		t.Fatalf("missing authority rejection: %v", entry.Data)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	handler.ServeHTTP(httptest.NewRecorder(), r.WithContext(ctx))
	entry = end.next(t)
	if entry.Data["context_error"] != context.Canceled.Error() || entry.Data["outcome"] != "canceled" {
		t.Fatalf("missing cancellation: %v", entry.Data)
	}
}
