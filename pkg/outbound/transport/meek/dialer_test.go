package meek

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

type testDialer struct{}

func (testDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("unexpected dial")
}
func (testDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("unexpected listen")
}

func TestDialerCloseStopsSessionAndRejectsDial(t *testing.T) {
	first, err := NewDialer(testDialer{}, Config{URL: "https://front.example/path", TLSConfig: &tls.Config{ServerName: "cdn.example"}})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := first.DialContext(context.Background(), "tcp", "target.example:443")
	if err != nil {
		t.Fatal(err)
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Read(make([]byte, 1)); !errors.Is(err, context.Canceled) {
		t.Fatalf("read after owner close: %v", err)
	}
	if _, err = first.DialContext(context.Background(), "tcp", "target:443"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("dial after close: %v", err)
	}
}

func newTestSession(t *testing.T, handler http.HandlerFunc) *clientSession {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	var workers sync.WaitGroup
	s := newClientSession(context.Background(), server.Client().Transport, server.URL, &workers)
	t.Cleanup(func() { _ = s.Close(); workers.Wait() })
	return s
}

func TestSessionWireBufferOwnershipAndReadDeadline(t *testing.T) {
	s := newTestSession(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("X-Session-ID") == "" {
			t.Error("invalid polling request")
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = w.Write(data)
	})
	_ = s.SetReadDeadline(time.Now())
	if _, err := s.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read deadline: %v", err)
	}
	_ = s.SetReadDeadline(time.Now().Add(time.Second))
	payload := []byte("payload")
	if _, err := s.Write(payload); err != nil {
		t.Fatal(err)
	}
	clear(payload)
	var received [7]byte
	if _, err := io.ReadFull(s, received[:]); err != nil {
		t.Fatal(err)
	}
	if string(received[:]) != "payload" {
		t.Fatalf("caller buffer reused before send: %q", received)
	}
}

func TestSessionCloseUnblocksFullReaderQueue(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	s := newTestSession(t, func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		_, _ = w.Write([]byte("data"))
	})
	for i := 0; i < cap(s.readerChan); i++ {
		s.readerChan <- []byte("queued")
	}
	<-started
	close(release)
	done := make(chan error, 1)
	go func() { done <- s.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("close blocked on full receive queue")
	}
}

func TestSessionWriteDeadlineAndFailureDoNotReplay(t *testing.T) {
	var calls atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	s := newTestSession(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		w.WriteHeader(http.StatusBadGateway)
	})
	<-started
	_ = s.SetWriteDeadline(time.Now().Add(10 * time.Millisecond))
	if n, err := s.Write([]byte("not queued")); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("write deadline: %d %v", n, err)
	}
	close(release)
	_ = s.SetReadDeadline(time.Now().Add(time.Second))
	_, err := s.Read(make([]byte, 1))
	if failure := netproxy.ClassifyFailure(err); failure.Code != "502" || failure.Scope != netproxy.ScopeStream {
		t.Fatalf("lost response cause: %+v", failure)
	}
	<-s.done
	if got := calls.Load(); got != 1 {
		t.Fatalf("failed request replayed %d times", got)
	}
	if err := s.SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed worker accepted a new timer: %v", err)
	}
}

func TestCustomDialerNegotiatesRealHTTP2Peer(t *testing.T) {
	protocols := make(chan int, 8)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS.ServerName != "cdn.example" {
			t.Errorf("TLS peer received SNI %q", r.TLS.ServerName)
		}
		protocols <- r.ProtoMajor
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush() // An H2 peer can respond while request upload continues.
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return
		}
		_, _ = w.Write(body)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	parent := directTestDialer{}
	d, err := NewDialer(parent, Config{URL: server.URL, TLSConfig: &tls.Config{ServerName: "cdn.example", InsecureSkipVerify: true}})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	c, err := d.DialContext(context.Background(), "tcp", "target.test:443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	payload := bytes.Repeat([]byte("payload"), 10000)
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	actual := make([]byte, len(payload))
	if _, err := io.ReadFull(c, actual); err != nil || !bytes.Equal(actual, payload) {
		t.Fatalf("H2 exchange %v", err)
	}
	if version := <-protocols; version != 2 {
		t.Fatalf("negotiated HTTP/%d", version)
	}
}

type directTestDialer struct{}

func (directTestDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return new(net.Dialer).DialContext(ctx, network, address)
}
func (directTestDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("unexpected packet")
}

type earlyResponseTransport struct{ body io.ReadCloser }

func (t *earlyResponseTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	t.body = request.Body
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("early"))}, nil
}
func TestEarlyResponseCannotReleasePOSTRequestMemory(t *testing.T) {
	transport := new(earlyResponseTransport)
	s := &clientSession{transport: transport, url: "https://peer.test/", tag: "session"}
	original := []byte("request body retained by transport")
	want := bytes.Clone(original)
	response, err := s.roundTrip(context.Background(), original)
	if err != nil || string(response) != "early" {
		t.Fatal(err)
	}
	// RoundTripper has not closed request.Body yet. The next poll may reuse its
	// aggregation buffer immediately after roundTrip returns.
	clear(original)
	retained, err := io.ReadAll(transport.body)
	_ = transport.body.Close()
	if err != nil || !bytes.Equal(retained, want) {
		t.Fatalf("late request read saw reused buffer: %q %v", retained, err)
	}
}
