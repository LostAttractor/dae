// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/daeuniverse/dae/pkg/membuffer"
	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
)

// A client that retains its upload can retry a rejected stream even when the
// proxy cannot. Ambiguous failures must never use the same signal.
func TestUnbufferedRequestRejection(t *testing.T) {
	for _, protocol := range []string{"h2", "h3"} {
		for _, mode := range []string{"known-large", "unknown-large", "memory-pressure"} {
			for _, rejected := range []bool{true, false} {
				t.Run(fmt.Sprintf("%s/%s/rejected=%t", protocol, mode, rejected), func(t *testing.T) {
					authority, roots := http3TestAuthority(t)
					payload := strings.Repeat("x", requestReplayLimit+1)
					budget := membuffer.NewBudget(1 << 20)
					if mode == "memory-pressure" {
						payload, budget = "request", membuffer.NewBudget(1)
					}
					host := testHost(t, Options{Authority: authority, UpstreamTLSConfig: &tls.Config{RootCAs: roots}, BodyMemory: budget})
					var client *http.Client
					var attempts *atomic.Int32
					want := http.StatusOK
					if protocol == "h2" {
						fault := "INTERNAL_ERROR"
						if rejected {
							fault = "REFUSED_STREAM"
						}
						peer, count := retryTestPeer(t, authority.TLSConfig("example.com"), fault, payload)
						attempts = count
						client, _ = tcpDrainClient(t, host, roots, "h2", testUpstream(func(ctx context.Context, network, _ string) (net.Conn, error) {
							return (&net.Dialer{}).DialContext(ctx, network, peer)
						}))
					} else {
						code := http3.ErrCodeInternalError
						if rejected {
							code = http3.ErrCodeRequestRejected
						}
						peer, count := retryTestHTTP3Peer(t, authority.TLSConfig("example.com"), code, payload)
						attempts = count
						client, _, _ = http3TestClient(t, host, roots, "example.com", peer)
						want = http.StatusNoContent
					}
					request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://example.com/rpc", strings.NewReader(payload))
					if err != nil {
						t.Fatal(err)
					}
					if mode == "unknown-large" {
						request.ContentLength = -1
					}
					response, err := client.Do(request)
					if err != nil {
						t.Fatal(err)
					}
					_, readErr := io.Copy(io.Discard, response.Body)
					response.Body.Close()
					count := int32(2)
					if !rejected {
						want, count = http.StatusBadGateway, 1
					}
					if readErr != nil || response.StatusCode != want || attempts.Load() != count {
						t.Fatalf("status=%d attempts=%d read=%v; want %d/%d", response.StatusCode, attempts.Load(), readErr, want, count)
					}
					if used := budget.Status().Used; used != 0 {
						t.Fatalf("retry storage retained %d bytes", used)
					}
				})
			}
		}
	}
}

func TestHTTP1ReplayFailureIsNotUnprocessed(t *testing.T) {
	r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://example.com/", strings.NewReader("body"))
	if err != nil {
		t.Fatal(err)
	}
	r.GetBody = func() (io.ReadCloser, error) { return nil, errReplayLimit }
	attempt := preserveRequestRejection(r, false)
	_, err = attempt.GetBody()
	if _, rejected := errors.AsType[*requestNotProcessedError](err); rejected || !errors.Is(err, errReplayLimit) {
		t.Fatalf("ambiguous HTTP/1 retry became an unprocessed request: %v", err)
	}
}

func TestHTTP3FinalRejectionScope(t *testing.T) {
	rejected := &quic.StreamError{Remote: true, ErrorCode: quic.StreamErrorCode(http3.ErrCodeRequestRejected)}
	for _, tc := range []struct {
		name   string
		err    error
		cancel bool
		want   bool
	}{
		{"remote stream", fmt.Errorf("attempt failed: %w", rejected), false, true},
		{"local stream", &quic.StreamError{ErrorCode: quic.StreamErrorCode(http3.ErrCodeRequestRejected)}, false, false},
		{"connection code", &quic.ApplicationError{Remote: true, ErrorCode: quic.ApplicationErrorCode(http3.ErrCodeRequestRejected)}, false, false},
		{"ambiguous", &quic.StreamError{Remote: true, ErrorCode: quic.StreamErrorCode(http3.ErrCodeInternalError)}, false, false},
		{"canceled context", rejected, true, false},
		{"canceled attempt", errors.Join(rejected, context.Canceled), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.cancel {
				cancel()
			}
			request, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://example.com/", nil)
			err := preserveHTTP3Rejection(request, tc.err)
			if _, marked := errors.AsType[*requestNotProcessedError](err); marked != tc.want {
				t.Fatalf("safe retry=%t want=%t error=%v", marked, tc.want, err)
			}
			if !errors.Is(err, tc.err) {
				t.Fatal("lost original failure")
			}
		})
	}
}
