package mitm

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

func TestRequestFailureLogging(t *testing.T) {
	for _, level := range []log.Level{log.InfoLevel, log.DebugLevel} {
		t.Run(level.String(), func(t *testing.T) {
			logger := log.New()
			logger.SetOutput(io.Discard)
			logger.SetLevel(level)
			hook := logtest.NewLocal(logger)
			host := testHost(t, Options{Logger: log.NewEntry(logger)})
			handler, closeTransport := host.Handler("http", "example.test", 80, testUpstream(func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("dial https://user:password@example.test/secret-path?token=secret-query failed")
			}))
			defer closeTransport()
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://example.test/", nil))
			if response.Code != http.StatusBadGateway {
				t.Fatalf("status=%d", response.Code)
			}
			entries := hook.AllEntries()
			if level == log.InfoLevel {
				if len(entries) != 0 {
					t.Fatalf("single-request failure reached default logs: %v", entries)
				}
				return
			}
			if len(entries) != 1 || entries[0].Level != log.DebugLevel || entries[0].Data["host"] != "example.test" || entries[0].Data["request_id"] == "" {
				t.Fatalf("failure must have one correlated debug diagnostic: %v", entries)
			}
			message := entries[0].Data["error"].(error).Error()
			for _, secret := range []string{"password", "secret-path", "secret-query"} {
				if strings.Contains(message, secret) {
					t.Fatalf("diagnostic leaked %q: %s", secret, message)
				}
			}

			hook.Reset()
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://example.test/", nil).WithContext(ctx))
			if entries := hook.AllEntries(); len(entries) != 0 {
				t.Fatalf("request cancellation emitted an error diagnostic: %v", entries)
			}
		})
	}
}
