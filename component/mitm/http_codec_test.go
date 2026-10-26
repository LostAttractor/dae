// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/plugin/codec"
	"github.com/daeuniverse/dae/pkg/membuffer"
	"github.com/daeuniverse/quic-go/http3"
)

func httpCodecFrame(t *testing.T, payload string, compressed bool) []byte {
	t.Helper()
	data := []byte(payload)
	if compressed {
		var buf bytes.Buffer
		writer := gzip.NewWriter(&buf)
		if _, err := writer.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		data = buf.Bytes()
	}
	frame := make([]byte, 5, 5+len(data))
	if compressed {
		frame[0] = 1
	}
	binary.BigEndian.PutUint32(frame[1:], uint32(len(data)))
	return append(frame, data...)
}

func httpCodecWait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("codec stream did not finish")
	}
}

type httpCodecClosedBody struct {
	io.ReadCloser
	closed chan struct{}
}

func (b *httpCodecClosedBody) Close() error {
	err := b.ReadCloser.Close()
	close(b.closed)
	return err
}

func TestHTTPCodecStreaming(t *testing.T) {
	for _, protocol := range []string{"h2", "h3"} {
		for _, finish := range []string{"eof", "cancel", "close"} {
			t.Run(protocol+"/"+finish, func(t *testing.T) {
				budget := membuffer.NewBudget(8 << 20)
				t.Cleanup(func() {
					if status := budget.Status(); status.Used != 0 {
						t.Errorf("body memory leaked: %+v", status)
					}
				})
				first := httpCodecFrame(t, "first", true)
				tail := httpCodecFrame(t, "untouched tail", true)
				wantFirst := httpCodecFrame(t, "rewritten first", false)
				releaseTail, upstreamDone, transformedClosed := make(chan struct{}), make(chan struct{}), make(chan struct{})
				wantProto := map[string]int{"h2": 2, "h3": 3}[protocol]
				upstreamHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer close(upstreamDone)
					if r.ProtoMajor != wantProto {
						t.Errorf("upstream protocol = %s", r.Proto)
					}
					w.Header().Set("Content-Type", "application/grpc")
					w.Header().Set("Grpc-Encoding", "gzip")
					w.Header().Set("Trailer", "Grpc-Status")
					if _, err := w.Write(first); err != nil {
						t.Error(err)
						return
					}
					if err := http.NewResponseController(w).Flush(); err != nil {
						t.Error(err)
						return
					}
					select {
					case <-releaseTail:
						if _, err := w.Write(tail); err != nil {
							t.Error(err)
						}
						w.Header().Set("Grpc-Status", "13")
					case <-r.Context().Done():
					}
				})
				var calls atomic.Int32
				p := &testPlugin{plan: plugin.Plan{Scopes: []plugin.HTTPScope{{Scope: testScope("example.com")}}}, wrap: func(_ plugin.Flow, next plugin.Handler) plugin.Handler {
					return func(e *plugin.Exchange) (*plugin.Response, error) {
						r, err := next(e)
						if err != nil {
							return nil, err
						}
						c, err := codec.New(e.Request.Head.Context(), budget, codec.Limits{Wire: 1 << 16, Decoded: 1 << 16})
						if err != nil {
							_ = r.Close()
							return nil, err
						}
						httpEncoding := strings.Join(r.Head.Header.Values("Content-Encoding"), ",")
						grpcEncoding := r.Head.Header.Get("Grpc-Encoding")
						err = r.Body().Transform(func(source io.ReadCloser) (io.ReadCloser, error) {
							output, err := c.GRPCTransform(source, httpEncoding, grpcEncoding, func(m *codec.Message) (*membuffer.View, error) {
								calls.Add(1)
								if string(m.Payload()) == "first" {
									return membuffer.Copy([]byte("rewritten first"), budget)
								}
								return nil, nil
							})
							if err != nil {
								return nil, err
							}
							return &httpCodecClosedBody{ReadCloser: output, closed: transformedClosed}, nil
						})
						if err != nil {
							_ = r.Close()
							return nil, err
						}
						r.SetDelivery(plugin.DeliveryStreaming)
						return r, nil
					}
				}}
				authority, roots := http3TestAuthority(t)
				host := testHost(t, Options{Authority: authority, UpstreamTLSConfig: &tls.Config{RootCAs: roots}, BodyMemory: budget}, Instance{Plugin: p})
				var client *http.Client
				if protocol == "h3" {
					upstream := http3TestUpstream(t, authority.TLSConfig("example.com"), upstreamHandler)
					client, _, _ = http3TestClient(t, host, roots, "example.com", upstream)
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
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/stream", nil)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				if resp.ProtoMajor != wantProto || resp.StatusCode != http.StatusOK || resp.Header.Get("Grpc-Encoding") != "gzip" {
					t.Fatalf("response = %s %d, headers=%v", resp.Proto, resp.StatusCode, resp.Header)
				}
				got := make([]byte, len(wantFirst))
				if _, err := io.ReadFull(resp.Body, got); err != nil || !bytes.Equal(got, wantFirst) {
					t.Fatalf("first frame = %x, want %x: %v", got, wantFirst, err)
				}
				if calls.Load() != 1 || resp.Trailer.Get("Grpc-Status") != "" {
					t.Fatalf("tail crossed gate: calls=%d trailer=%v", calls.Load(), resp.Trailer)
				}
				switch finish {
				case "eof":
					close(releaseTail)
					got, err = io.ReadAll(resp.Body)
					if err != nil || !bytes.Equal(got, tail) {
						t.Fatalf("tail frame = %x, want original %x: %v", got, tail, err)
					}
					if resp.Trailer.Get("Grpc-Status") != "13" || calls.Load() != 2 {
						t.Fatalf("final trailer=%v calls=%d", resp.Trailer, calls.Load())
					}
				case "cancel":
					cancel()
					_, err = io.ReadAll(resp.Body)
					h3err, isH3 := errors.AsType[*http3.Error](err)
					if !errors.Is(err, context.Canceled) && !(isH3 && h3err.ErrorCode == http3.ErrCodeRequestCanceled) {
						t.Fatalf("canceled stream error = %v", err)
					}
				case "close":
					if err := resp.Body.Close(); err != nil {
						t.Fatal(err)
					}
				}
				httpCodecWait(t, upstreamDone)
				httpCodecWait(t, transformedClosed)
				if status := budget.Status(); status.Used != 0 {
					t.Fatalf("body memory after stream closed: %+v", status)
				}
			})
		}
	}
}

type httpCodecCountingBody struct {
	*bytes.Reader
	reads, closes int
}

func (b *httpCodecCountingBody) Read(p []byte) (int, error) {
	b.reads++
	return b.Reader.Read(p)
}

func (b *httpCodecCountingBody) Close() error {
	b.closes++
	return nil
}

func TestHTTPCodecTransformInstallation(t *testing.T) {
	for _, encoding := range []string{"gzip", "identity"} {
		t.Run(encoding, func(t *testing.T) {
			budget := membuffer.NewBudget(8 << 20)
			t.Cleanup(func() {
				if status := budget.Status(); status.Used != 0 {
					t.Errorf("body memory leaked: %+v", status)
				}
			})
			original := httpCodecFrame(t, "original", true)
			source := &httpCodecCountingBody{Reader: bytes.NewReader(original)}
			r := plugin.NewResponse(&http.Response{StatusCode: http.StatusOK, Body: source, ContentLength: int64(len(original)), Header: http.Header{
				"Content-Encoding": {encoding}, "Content-Length": {strconv.Itoa(len(original))}, "Etag": {`"original"`}, "Grpc-Encoding": {"gzip"},
			}}, budget)
			defer r.Close()
			r.SetDelivery(plugin.DeliveryStreaming)
			head := r.Head
			before := *head
			before.Header = head.Header.Clone()
			c, err := codec.New(t.Context(), budget, codec.Limits{Wire: 1 << 16, Decoded: 1 << 16})
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			err = r.Body().Transform(func(input io.ReadCloser) (io.ReadCloser, error) {
				return c.GRPCTransform(input, encoding, "gzip", func(*codec.Message) (*membuffer.View, error) {
					calls++
					return nil, nil
				})
			})
			if source.reads != 0 || source.closes != 0 || calls != 0 || budget.Status().Used != 0 {
				t.Fatalf("installation consumed input: reads=%d closes=%d calls=%d budget=%+v", source.reads, source.closes, calls, budget.Status())
			}
			wantBody, wantDelivery := original, plugin.DeliveryStreaming
			if encoding == "gzip" {
				if !errors.Is(err, codec.ErrUnsupported) || r.Head != head || !reflect.DeepEqual(*r.Head, before) || r.Delivery() != wantDelivery {
					t.Fatalf("rejected installation changed response: err=%v head=%+v delivery=%v", err, r.Head, r.Delivery())
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if r.Delivery() != plugin.DeliveryDefault || r.Head.ContentLength != -1 || r.Head.Header.Get("Content-Encoding") != "" || r.Head.Header.Get("Etag") != "" || r.Head.Header.Get("Content-Length") != "" || r.Head.Header.Get("Grpc-Encoding") != "gzip" {
					t.Fatalf("transform metadata: head=%+v delivery=%v", r.Head, r.Delivery())
				}
				r.SetDelivery(plugin.DeliveryStreaming)
				wantBody, wantDelivery = []byte("replacement"), plugin.DeliveryDefault
				view, err := membuffer.Copy(wantBody, budget)
				if err != nil {
					t.Fatal(err)
				}
				r.Body().Replace(view)
				view.Close()
				if source.reads != 0 || source.closes != 1 || calls != 0 || r.Delivery() != wantDelivery || r.Head.ContentLength != int64(len(wantBody)) {
					t.Fatalf("replacement retained transform: reads=%d closes=%d calls=%d delivery=%v length=%d", source.reads, source.closes, calls, r.Delivery(), r.Head.ContentLength)
				}
			}
			wire, delivery, err := r.TakeHTTP()
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(wire.Body)
			_ = wire.Body.Close()
			if err != nil || !bytes.Equal(got, wantBody) || delivery != wantDelivery || source.closes != 1 || calls != 0 {
				t.Fatalf("final response: body=%x delivery=%v closes=%d calls=%d error=%v", got, delivery, source.closes, calls, err)
			}
		})
	}
}
