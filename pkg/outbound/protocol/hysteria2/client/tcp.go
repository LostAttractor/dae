package client

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/hysteria2/internal/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/hysteria2/internal/utils"
)

type tcpConn struct {
	Orig             *utils.QStream
	PseudoLocalAddr  net.Addr
	PseudoRemoteAddr net.Addr

	readMu                sync.Mutex // one reader owns the response header
	mu                    sync.Mutex // state and deadline updates, never blocking I/O
	Established           bool
	responseErr           error
	readDeadline          time.Time
	responseDeadline      time.Time
	responseReading       bool
	expiredCallerDeadline bool
}

// TargetDialError is a rejection of one CONNECT request, not a failed QUIC
// connection. Fast-open reports it on the first read instead of DialContext.
type TargetDialError struct{ Message string }

func (e *TargetDialError) Error() string { return "hysteria2 target dial rejected: " + e.Message }
func targetDialError(stream *utils.QStream, message string) error {
	metadata := netproxy.Failure{Scope: netproxy.ScopeStream, Layer: netproxy.LayerProxy, Phase: netproxy.OpDial, Origin: netproxy.OriginTarget, Reason: netproxy.ReasonRejected}
	if stream.Lease != nil {
		metadata.Resource, metadata.Stream = stream.Lease.Resource(), stream.Lease.Stream()
	}
	err := netproxy.WrapFailure(&TargetDialError{Message: message}, metadata)
	stream.Abort(err)
	return err
}
func (c *tcpConn) DependencyLease() *netproxy.Lease { return c.Orig.DependencyLease() }

func responseError(stream *utils.QStream, err error) error {
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	err = stream.WrapError(err, netproxy.OpRead)
	failure := netproxy.ClassifyFailure(err)
	if failure.Scope == netproxy.ScopeUnknown || failure.Scope == "" {
		failure.Scope, failure.Layer, failure.Reason = netproxy.ScopeStream, netproxy.LayerProxy, netproxy.ReasonProtocol
		if stream.Lease != nil {
			failure.Resource, failure.Stream = stream.Lease.Resource(), stream.Lease.Stream()
		}
		err = netproxy.WrapFailure(err, failure)
	}
	// A failed response cannot be resumed, even when the underlying error is
	// an operation deadline. Terminate only this logical connection.
	stream.Abort(err)
	return err
}

func (c *tcpConn) Read(b []byte) (n int, err error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if err := c.readResponse(); err != nil {
		return 0, err
	}
	return c.Orig.Read(b)
}

func (c *tcpConn) readResponse() error {
	c.mu.Lock()
	if c.responseErr != nil {
		err := c.responseErr
		c.mu.Unlock()
		return err
	}
	if c.Established {
		c.mu.Unlock()
		return nil
	}
	c.responseDeadline = time.Now().Add(netproxy.DialTimeout)
	err := c.applyReadDeadlineLocked()
	c.mu.Unlock()

	var ok bool
	var msg string
	if err == nil {
		ok, msg, err = protocol.ReadTCPResponse(responseDeadlineReader{conn: c, reader: c.Orig})
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {

		c.responseErr = responseError(c.Orig, err)
	} else if !ok {
		c.responseErr = targetDialError(c.Orig, msg)
	} else {
		c.Established = true
		c.responseDeadline = time.Time{}
		if err := c.applyReadDeadlineLocked(); err != nil {
			c.responseErr = responseError(c.Orig, err)
		}
	}
	return c.responseErr
}

// Each underlying response read owns its deadline evidence. Successful reads
// discard it; later response reads cannot inherit an earlier caller timeout.
type responseDeadlineReader struct {
	conn   *tcpConn
	reader io.Reader
}

func (c *tcpConn) rememberCallerDeadlineLocked(now time.Time) {
	if c.responseReading && !c.readDeadline.IsZero() && !now.Before(c.readDeadline) && !c.readDeadline.After(c.responseDeadline) {
		c.expiredCallerDeadline = true
	}
}

func (r responseDeadlineReader) Read(p []byte) (int, error) {
	c := r.conn
	c.mu.Lock()
	c.responseReading, c.expiredCallerDeadline = true, false
	c.mu.Unlock()
	n, err := r.reader.Read(p)
	c.mu.Lock()
	now := time.Now()
	c.rememberCallerDeadlineLocked(now)
	failure := netproxy.ClassifyFailure(err)
	if failure.Reason == netproxy.ReasonDeadline && failure.Scope == netproxy.ScopeOperation {
		origin := netproxy.OriginUnknown
		if c.expiredCallerDeadline {
			origin = netproxy.OriginCaller
		} else if !now.Before(c.responseDeadline) {
			origin = netproxy.OriginLocalProtocol
		}
		err = netproxy.WrapFailure(err, netproxy.Failure{Origin: origin, Phase: netproxy.OpHandshake})
	}
	c.responseReading, c.expiredCallerDeadline = false, false
	c.mu.Unlock()
	return n, err
}

func (c *tcpConn) Write(b []byte) (n int, err error) {
	c.mu.Lock()
	err = c.responseErr
	c.mu.Unlock()
	if err != nil {
		return 0, err
	}
	n, err = c.Orig.Write(b)
	if err != nil {
		c.mu.Lock()
		if c.responseErr != nil {
			err = c.responseErr
		}
		c.mu.Unlock()
	}
	return n, err
}

func (c *tcpConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Orig.Close()
}

// CloseWrite sends a QUIC FIN while leaving the receive side open.
func (c *tcpConn) CloseWrite() error {
	return c.Orig.CloseWrite()
}

func (c *tcpConn) LocalAddr() net.Addr {
	return c.PseudoLocalAddr
}

func (c *tcpConn) RemoteAddr() net.Addr {
	return c.PseudoRemoteAddr
}

func (c *tcpConn) SetDeadline(t time.Time) error {
	return errors.Join(c.SetReadDeadline(t), c.SetWriteDeadline(t))
}

func (c *tcpConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	// A completed stream read may still be waiting to classify its error.
	// Preserve expired caller evidence before replacing the installed deadline.
	c.rememberCallerDeadlineLocked(time.Now())
	c.readDeadline = t
	return c.applyReadDeadlineLocked()
}

func (c *tcpConn) applyReadDeadlineLocked() error {
	deadline := c.readDeadline
	if !c.responseDeadline.IsZero() && (deadline.IsZero() || c.responseDeadline.Before(deadline)) {
		deadline = c.responseDeadline
	}
	return c.Orig.SetReadDeadline(deadline)
}

func (c *tcpConn) SetWriteDeadline(t time.Time) error {
	return c.Orig.SetWriteDeadline(t)
}
