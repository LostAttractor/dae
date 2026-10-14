package http

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"golang.org/x/net/http2"
)

// A proxy always opens a byte tunnel before returning the connection. The
// application payload is never inspected or consumed as an HTTP request.
func (p *HttpProxy) request(ctx context.Context, target string) *http.Request {
	request := &http.Request{Method: http.MethodConnect, URL: &url.URL{Host: target}, Host: target, Header: make(http.Header)}
	if p.transport {
		request.Method = http.MethodPut
		request.URL.Scheme = "http"
		request.URL.Path = p.Path
		request.Host = "www.example.com"
	}
	if p.Host != "" {
		request.Host = p.Host
	}
	if p.HaveAuth {
		request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(p.Username+":"+p.Password)))
	}
	return request.WithContext(ctx)
}
func proxyStatus(response *http.Response, scope netproxy.FailureScope) error {
	reason := netproxy.ReasonRejected
	if response.StatusCode == http.StatusProxyAuthRequired {
		reason = netproxy.ReasonAuth
	}
	return netproxy.WrapFailure(fmt.Errorf("proxy responded with status %s", response.Status), netproxy.Failure{Scope: scope, Layer: netproxy.LayerProxy, Origin: netproxy.OriginPeer, Phase: netproxy.OpHandshake, Reason: reason, Code: fmt.Sprint(response.StatusCode)})
}
func (p *HttpProxy) connectHTTP1(ctx context.Context, raw net.Conn, target string) (net.Conn, error) {
	var reader *bufio.Reader
	request := p.request(ctx, target)
	err := protocol.Handshake(ctx, raw, func() error {
		if err := request.WriteProxy(raw); err != nil {
			return err
		}
		response, buffered, err := protocol.ReadHTTPResponse(raw, request)
		if err != nil {
			return err
		}
		if response.StatusCode != http.StatusOK {
			return proxyStatus(response, netproxy.ScopeOperation)
		}
		reader = buffered
		// Successful CONNECT hands all following bytes to the tunnel, including
		// read-ahead retained by reader. Closing response.Body would drain them.
		return nil
	})
	if err != nil {
		return nil, err
	}
	tunnel := &bufferedHTTPConn{Conn: raw, reader: reader}
	if writer, ok := raw.(netproxy.CloseWriter); ok {
		return &netproxy.CloseWriteConn{Conn: tunnel, CloseWriter: writer}, nil
	}
	return tunnel, nil
}

func (p *HttpProxy) connectHTTP2(ctx context.Context, raw net.Conn, client *http2.ClientConn, target string) (net.Conn, error) {
	slot := raw.(*h2ObservedConn).slot
	lease := slot.lease.NewStream()
	lifetime, cancel := context.WithCancel(context.Background())
	stop := context.AfterFunc(ctx, cancel)
	requestBody, in := net.Pipe()
	request := p.request(lifetime, target)
	request.Body = requestBody
	response, err := client.RoundTrip(request)
	stop()
	if cause := ctx.Err(); cause != nil {
		err = errors.Join(err, cause)
	}
	if err == nil && !lease.Valid() {
		err = lease.Cause()
	}
	if err == nil && response.StatusCode != http.StatusOK {
		err = proxyStatus(response, netproxy.ScopeStream)
	}
	if err != nil {
		cancel()
		_ = in.Close()
		_ = requestBody.Close()
		if response != nil {
			_ = response.Body.Close()
		}
		err = wrapH2StreamError(err, slot, lease, netproxy.OpHandshake, false)
		lease.Invalidate(err)
		return nil, err
	}
	read, receive := net.Pipe()
	tunnel := &http2Conn{Conn: raw, in: in, read: read, receive: receive, out: response.Body, cancel: cancel, slot: slot, lease: lease}
	go tunnel.receiveLoop()
	return tunnel, nil
}

type http2Conn struct {
	net.Conn          // addresses only; deadlines and closure belong to this stream
	in, read, receive net.Conn
	out               io.ReadCloser
	cancel            context.CancelFunc
	slot              *h2Conn
	lease             *netproxy.Lease
	readMu            sync.Mutex
	readErr           error
	closeOnce         sync.Once
	closed            atomic.Bool
	closeErr          error
}

func (h *http2Conn) receiveLoop() {
	_, err := io.Copy(h.receive, h.out)
	if err == nil {
		err = io.EOF
	}
	h.readMu.Lock()
	h.readErr = err
	h.readMu.Unlock()
	_ = h.receive.Close()
}
func (h *http2Conn) DependencyLease() *netproxy.Lease { return h.lease }
func (h *http2Conn) Read(p []byte) (n int, err error) {
	n, err = h.read.Read(p)
	if err == io.EOF {
		h.readMu.Lock()
		err = h.readErr
		h.readMu.Unlock()
	}
	return n, wrapH2StreamError(err, h.slot, h.lease, netproxy.OpRead, h.closed.Load())
}
func (h *http2Conn) Write(p []byte) (n int, err error) {
	n, err = h.in.Write(p)
	return n, wrapH2StreamError(err, h.slot, h.lease, netproxy.OpWrite, h.closed.Load())
}
func (h *http2Conn) CloseWrite() error {
	return wrapH2StreamError(h.in.Close(), h.slot, h.lease, netproxy.OpCloseWrite, h.closed.Load())
}
func (h *http2Conn) SetDeadline(t time.Time) error {
	return errors.Join(h.SetReadDeadline(t), h.SetWriteDeadline(t))
}
func (h *http2Conn) SetReadDeadline(t time.Time) error  { return h.read.SetReadDeadline(t) }
func (h *http2Conn) SetWriteDeadline(t time.Time) error { return h.in.SetWriteDeadline(t) }
func (h *http2Conn) Close() error {
	h.closeOnce.Do(func() {
		h.closed.Store(true)
		h.lease.Invalidate(netproxy.WrapFailure(net.ErrClosed, netproxy.Failure{Resource: h.lease.Resource(), Stream: h.lease.Stream(), Scope: netproxy.ScopeStream, Layer: netproxy.LayerH2, Origin: netproxy.OriginLocalCleanup, Reason: netproxy.ReasonClosed}))
		h.cancel()
		h.closeErr = errors.Join(h.in.Close(), h.read.Close(), h.receive.Close(), h.out.Close())
	})
	return h.closeErr
}
func wrapH2StreamError(err error, slot *h2Conn, lease *netproxy.Lease, op netproxy.Operation, localClosed bool) error {
	if err == nil || err == io.EOF {
		return err
	}
	if !localClosed {
		slot.pool.refineFailure(slot, err, op)
	}
	var causes []error
	// The HTTP/2 library can replace a socket failure with its own error.
	// Retain the concrete owner's independent evidence of resource failure.
	if !localClosed && !slot.lease.Valid() {
		cause := slot.lease.Cause()
		if terminal := slot.terminal.Load(); terminal != nil {
			cause = terminal.cause
		}
		if cause != nil && errors.Is(cause, err) {
			f := netproxy.ClassifyFailure(cause)
			f.Stream, f.Phase = lease.Stream(), op
			return netproxy.WrapFailure(err, f)
		}
		if cause != nil && !errors.Is(err, cause) {
			for _, f := range netproxy.Failures(cause) {
				if f.Scope == netproxy.ScopeSharedResource {
					causes = append(causes, cause)
					break
				}
			}
		}
	}
	for _, failure := range netproxy.Failures(err) {
		if failure.Scope == netproxy.ScopeUnknown || failure.Scope == "" {
			failure.Scope = netproxy.ScopeStream
			if localClosed {
				failure.Origin, failure.Reason = netproxy.OriginLocalCleanup, netproxy.ReasonClosed
			}
		}
		if failure.Layer == netproxy.LayerUnknown || failure.Layer == "" {
			failure.Layer = netproxy.LayerH2
		}
		failure.Resource, failure.Stream, failure.Phase = slot.ref, lease.Stream(), op
		wrapped := netproxy.WrapFailure(failure.Cause, failure)
		if failure.Scope == netproxy.ScopeSharedResource {
			slot.pool.failSlot(slot, wrapped, op)
		} else if failure.Scope == netproxy.ScopeStream {
			lease.Invalidate(wrapped)
		}
		causes = append(causes, wrapped)
	}
	if len(causes) == 1 {
		return causes[0]
	}
	return errors.Join(causes...)
}

// bufferedHTTPConn retains bytes read past the CONNECT response headers.
type bufferedHTTPConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedHTTPConn) Read(p []byte) (int, error)       { return c.reader.Read(p) }
func (c *bufferedHTTPConn) DependencyLease() *netproxy.Lease { return netproxy.DependencyOf(c.Conn) }
