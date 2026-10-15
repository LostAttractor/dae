package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/hysteria2/internal/utils"
	"github.com/daeuniverse/quic-go"
)

func fastOpenTestPair(t *testing.T) (*tcpConn, *quic.Stream, *netproxy.Lease) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}}, NextProtos: []string{"hy2-deadline"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	ctx, cancel := context.WithTimeout(t.Context(), 2*netproxy.DialTimeout)
	t.Cleanup(cancel)
	conn, err := quic.DialAddr(ctx, listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"hy2-deadline"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.CloseWithError(0, "") })
	server, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.CloseWithError(0, "") })
	stream, err := conn.OpenStream()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	peer, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(peer, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	parent := netproxy.NewLease(netproxy.NewResourceRef())
	c := &tcpConn{Orig: &utils.QStream{Stream: stream, Lease: parent.NewStream(), Fail: func(err error) { parent.Abort(err) }}}
	t.Cleanup(func() { _ = c.Close() })
	return c, peer, parent
}

func waitFastOpenResponseRead(t *testing.T, c *tcpConn) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		started := !c.responseDeadline.IsZero()
		c.mu.Unlock()
		if started {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("response read did not start")
}

func TestFastOpenResponseBudgetSurvivesDeadlineUpdates(t *testing.T) {
	t.Parallel()
	c, peer, parent := fastOpenTestPair(t)
	if err := c.SetReadDeadline(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	start := time.Now()
	go func() { _, err := c.Read(make([]byte, 1)); done <- err }()
	waitFastOpenResponseRead(t, c)
	for range 20 {
		if err := c.SetReadDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
		if err := c.SetDeadline(time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case err := <-done:
		failure := netproxy.ClassifyFailure(err)
		if !errors.Is(err, os.ErrDeadlineExceeded) || failure.Origin != netproxy.OriginLocalProtocol {
			t.Fatalf("response budget lost its provenance: %+v", failure)
		}
		if elapsed := time.Since(start); elapsed < netproxy.DialTimeout-100*time.Millisecond {
			t.Fatalf("response failed before its budget: %v", elapsed)
		}
		if c.DependencyLease().AbortCause() == nil || !parent.Valid() {
			t.Fatal("response timeout did not abort only its stream")
		}
		if n, again := c.Write([]byte("late")); n != 0 || again != err {
			t.Fatalf("write after timeout = %d, %v; want %v", n, again, err)
		}
	case <-time.After(netproxy.DialTimeout + 2*time.Second):
		t.Fatal("application deadline extended the FastOpen response budget")
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	_, err := peer.Read(make([]byte, 1))
	if reset, ok := errors.AsType[*quic.StreamError](err); !ok || !reset.Remote {
		t.Fatalf("timeout did not cancel the peer stream: %v", err)
	}
}

func TestFastOpenCallerDeadlineAndClose(t *testing.T) {
	for _, action := range []string{"deadline", "close"} {
		t.Run(action, func(t *testing.T) {
			t.Parallel()
			c, _, parent := fastOpenTestPair(t)
			done := make(chan error, 1)
			go func() { _, err := c.Read(make([]byte, 1)); done <- err }()
			waitFastOpenResponseRead(t, c)
			origin := netproxy.OriginLocalCleanup
			if action == "deadline" {
				origin = netproxy.OriginCaller
				_ = c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
			} else {
				_ = c.Close()
			}
			select {
			case err := <-done:
				if failure := netproxy.ClassifyFailure(err); failure.Origin != origin {
					t.Fatalf("%s lost its source: %+v", action, failure)
				}
				if !parent.Valid() || (c.DependencyLease().AbortCause() != nil) != (action == "deadline") {
					t.Fatal("caller deadline/close applied the wrong lifetime action")
				}
			case <-time.After(time.Second):
				t.Fatal("caller action did not unblock the response read")
			}
		})
	}
}

func TestFastOpenRestoresLatestReadDeadline(t *testing.T) {
	t.Parallel()
	c, peer, parent := fastOpenTestPair(t)
	_ = c.SetReadDeadline(time.Now().Add(time.Hour))
	done := make(chan error, 1)
	go func() {
		var b [1]byte
		_, err := c.Read(b[:])
		if err == nil && b[0] != 'a' {
			err = errors.New("response parser consumed application data")
		}
		done <- err
	}()
	waitFastOpenResponseRead(t, c)
	deadline := time.Now().Add(250 * time.Millisecond)
	_ = c.SetReadDeadline(deadline)
	if _, err := peer.Write([]byte{0, 0, 0, 'a'}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	go func() { _, err := c.Read(make([]byte, 1)); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) || time.Now().Before(deadline) {
			t.Fatalf("application deadline was not restored: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("stale deadline replaced the concurrent update")
	}
	if !parent.Valid() || c.DependencyLease().AbortCause() != nil {
		t.Fatal("ordinary established read deadline aborted a stream/session")
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	_ = peer.Close()
	if _, err := c.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("normal FIN = %v, want EOF", err)
	}
}

func TestFastOpenStreamResetAbortsBeforeInvalidation(t *testing.T) {
	t.Parallel()
	c, peer, parent := fastOpenTestPair(t)
	peer.CancelWrite(42)
	_, err := c.Read(make([]byte, 1))
	failure := netproxy.ClassifyFailure(err)
	if failure.Scope != netproxy.ScopeStream || failure.Code != "42" || c.DependencyLease().AbortCause() == nil || !parent.Valid() {
		t.Fatalf("reset lost its abort or closed the parent: %+v", failure)
	}
}

func TestFastOpenRejectionInterruptsConcurrentWrite(t *testing.T) {
	t.Parallel()
	c, peer, parent := fastOpenTestPair(t)
	written := make(chan error, 1)
	go func() { _, err := c.Write(make([]byte, 8<<20)); written <- err }()
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	if err := writeTargetRejection(peer, "refused"); err != nil {
		t.Fatal(err)
	}
	_, readErr := c.Read(make([]byte, 1))
	if _, ok := errors.AsType[*TargetDialError](readErr); !ok {
		t.Fatalf("response = %v, want rejection", readErr)
	}
	select {
	case writeErr := <-written:
		if writeErr != readErr || !parent.Valid() {
			t.Fatalf("concurrent write lost the terminal cause: %v, want %v", writeErr, readErr)
		}
	case <-time.After(time.Second):
		t.Fatal("response failure left a blocked writer")
	}
}

// Interpose only at the read boundary: the real QUIC stream has returned its
// timeout, then another caller clears/extends the deadline before classification.
type responseReadFunc func([]byte) (int, error)

func (f responseReadFunc) Read(p []byte) (int, error) { return f(p) }

func TestFastOpenCallerDeadlineSurvivesUpdateAfterReadFailure(t *testing.T) {
	for _, next := range []time.Time{{}, time.Now().Add(time.Hour)} {
		c, _, parent := fastOpenTestPair(t)
		c.responseDeadline = time.Now().Add(netproxy.DialTimeout)
		if err := c.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		reader := responseDeadlineReader{conn: c, reader: responseReadFunc(func(p []byte) (int, error) {
			n, err := c.Orig.Read(p)
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Errorf("stream read: %v", err)
			}
			if updateErr := c.SetReadDeadline(next); updateErr != nil {
				t.Error(updateErr)
			}
			return n, err
		})}
		_, err := reader.Read(make([]byte, 1))
		if failure := netproxy.ClassifyFailure(err); failure.Origin != netproxy.OriginCaller {
			t.Fatalf("deadline update lost operation provenance: %+v", failure)
		}
		if !parent.Valid() {
			t.Fatal("caller deadline invalidated the session")
		}
	}
}

func TestFastOpenSuccessfulReadDiscardsExpiredDeadlineEvidence(t *testing.T) {
	c, _, _ := fastOpenTestPair(t)
	c.responseDeadline = time.Now().Add(netproxy.DialTimeout)
	_ = c.SetReadDeadline(time.Now().Add(-time.Millisecond))
	reader := responseDeadlineReader{conn: c, reader: responseReadFunc(func(p []byte) (int, error) { _ = c.SetReadDeadline(time.Time{}); p[0] = 0; return 1, nil })}
	if _, err := reader.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	c.responseDeadline = time.Now().Add(-time.Millisecond)
	reader.reader = responseReadFunc(func([]byte) (int, error) {
		return 0, netproxy.WrapFailure(os.ErrDeadlineExceeded, netproxy.Failure{Scope: netproxy.ScopeOperation, Reason: netproxy.ReasonDeadline})
	})
	if _, err := reader.Read(make([]byte, 1)); netproxy.ClassifyFailure(err).Origin != netproxy.OriginLocalProtocol {
		t.Fatalf("later timeout inherited stale caller evidence: %v", err)
	}
}
