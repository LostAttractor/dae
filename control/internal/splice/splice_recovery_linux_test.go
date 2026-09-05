//go:build linux && dae_splice

package splice

import (
	"errors"
	"io"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
)

type recoveryConn struct {
	net.Conn
	read   func([]byte) (int, error)
	write  func([]byte) (int, error)
	closed chan struct{}
	once   sync.Once
}

func (c *recoveryConn) Read(p []byte) (int, error)            { return c.read(p) }
func (c *recoveryConn) Write(p []byte) (int, error)           { return c.write(p) }
func (c *recoveryConn) Close() error                          { c.once.Do(func() { close(c.closed) }); return nil }
func (c *recoveryConn) CloseWrite() error                     { return nil }
func (c *recoveryConn) SetReadDeadline(time.Time) error       { return nil }
func (c *recoveryConn) SetWriteDeadline(time.Time) error      { return nil }
func (c *recoveryConn) SyscallConn() (syscall.RawConn, error) { return nil, errors.New("unused") }

func TestRelayUserspaceErrorUnblocksOppositeWrite(t *testing.T) {
	a, b := &recoveryConn{closed: make(chan struct{})}, &recoveryConn{closed: make(chan struct{})}
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	writing := make(chan struct{})
	first := errors.New("source failed while reverse relay was writing")
	a.read = func([]byte) (int, error) { <-writing; return 0, first }
	a.write = func([]byte) (int, error) { close(writing); <-a.closed; return 0, net.ErrClosed }
	b.read = func(p []byte) (int, error) { p[0] = 1; return 1, nil }
	b.write = func(p []byte) (int, error) { return len(p), nil }
	done := make(chan error, 1)
	go func() {
		done <- (&Runtime{idleTimeout: time.Second}).relayUserspace([2]*spliceDirectEdge{{src: a, dst: b}, {src: b, dst: a}})
	}()
	select {
	case err := <-done:
		if !errors.Is(err, first) {
			t.Fatalf("original failure lost: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("failed direction did not interrupt the opposite blocked write")
	}
}

func TestSpliceFailureKeepsEndpointAndLocalRuntimeSeparate(t *testing.T) {
	endpoint := netproxy.WrapFailure(errors.New("socket failed"), netproxy.Failure{Origin: netproxy.OriginTarget, Phase: netproxy.OpRead, Layer: netproxy.LayerTCP})
	local := errors.New("counter lookup failed")
	failures := netproxy.Failures(runtimeFailure(errors.Join(endpoint, local)))
	if len(failures) != 2 {
		t.Fatalf("failures = %+v", failures)
	}
	if failures[0].Origin != netproxy.OriginTarget || failures[0].Phase != netproxy.OpRead {
		t.Fatalf("endpoint changed: %+v", failures[0])
	}
	if failures[1].Origin != netproxy.OriginLocalProtocol || failures[1].Scope != netproxy.ScopeOperation {
		t.Fatalf("runtime failure blamed on transport: %+v", failures[1])
	}
}

func TestSpliceWriterEOFIsNotReadEOF(t *testing.T) {
	err := writeFullAndRecord(writeFunc(func([]byte) (int, error) { return 0, io.EOF }), []byte("request"), nil)
	if err == io.EOF || !errors.Is(err, io.EOF) || netproxy.ClassifyFailure(err).Phase != netproxy.OpWrite {
		t.Fatalf("writer EOF = %v", err)
	}
}
