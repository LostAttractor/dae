package protocol

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	quic "github.com/daeuniverse/quic-go"
)

type unpublishedDeadline struct {
	context.Context
	at time.Time
}

func (c unpublishedDeadline) Deadline() (time.Time, bool) { return c.at, true }

func TestHandshakeSocketDeadlineBeforeContextTimer(t *testing.T) {
	conn, peer := net.Pipe()
	defer peer.Close()
	ctx := unpublishedDeadline{Context: context.Background(), at: time.Now().Add(-time.Second)}
	err := Handshake(ctx, conn, func() error { _, err := conn.Write([]byte("blocked")); return err })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lost caller deadline: %v", err)
	}
	if _, err := conn.Write(nil); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("unfinished socket remained open: %v", err)
	}
}

func TestHandshakeExpiredDeadlineIsNotEvidenceOfLocalClose(t *testing.T) {
	conn, peer := net.Pipe()
	defer peer.Close()
	ctx := unpublishedDeadline{Context: context.Background(), at: time.Now().Add(-time.Second)}
	err := Handshake(ctx, conn, func() error { return io.ErrClosedPipe })
	for _, failure := range netproxy.Failures(err) {
		if failure.Cause == io.ErrClosedPipe && failure.Origin == netproxy.OriginLocalCleanup {
			t.Fatal("inferred a local close although the cancellation callback never ran")
		}
	}
}

func TestHandshakeCancellationRetainsCauseAndStopsIO(t *testing.T) {
	for _, wrapped := range []bool{false, true} {
		t.Run(fmt.Sprintf("wrapped=%t", wrapped), func(t *testing.T) {
			testHandshakeCancellation(t, wrapped)
		})
	}
}

func testHandshakeCancellation(t *testing.T, wrapped bool) {
	t.Helper()
	conn, peer := net.Pipe()
	defer peer.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- Handshake(ctx, conn, func() error {
			close(started)
			_, err := conn.Write([]byte("blocked"))
			if wrapped {
				return fmt.Errorf("socks5 read reply: %w", err)
			}
			return err
		})
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("lost cancellation: %v", err)
		}
		for _, f := range netproxy.Failures(err) {
			if f.Origin != netproxy.OriginCaller && f.Origin != netproxy.OriginLocalCleanup {
				t.Fatalf("cancellation appears to be an upstream failure: %+v", f)
			}
		}
	case <-time.After(time.Second):
		t.Fatal("handshake did not release blocked write")
	}
}

func TestHandshakeHandoffSurvivesCallerCancellation(t *testing.T) {
	conn, peer := net.Pipe()
	defer conn.Close()
	defer peer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := Handshake(ctx, conn, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	<-ctx.Done()
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = peer.Write([]byte("ok")) }()
	var p [2]byte
	if _, err := io.ReadFull(conn, p[:]); err != nil {
		t.Fatalf("handed-off connection was closed or kept dial deadline: %v", err)
	}
}

func TestHandshakeCancellationDoesNotHideIndependentFatal(t *testing.T) {
	conn, peer := net.Pipe()
	defer peer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fatal := &quic.TransportError{Remote: true, ErrorCode: 1}
	err := Handshake(ctx, conn, func() error {
		cancel()
		_, _ = conn.Write([]byte("wait for cancellation callback"))
		return fmt.Errorf("socks5 read reply: %w", fatal)
	})
	found := false
	for _, f := range netproxy.Failures(err) {
		if errors.Is(f.Cause, fatal) {
			found = true
			if f.Scope != netproxy.ScopeSharedResource || f.Origin == netproxy.OriginLocalCleanup {
				t.Fatalf("independent failure suppressed: %+v", f)
			}
		}
	}
	if !found {
		t.Fatalf("fatal missing: %v", err)
	}
}
