package meek

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
)

const maxWriteSize = 64 << 10
const maxResponseSize = 1 << 20

// Each logical connection owns one polling worker and bounded receive queue.
// An unsuccessful POST ends that connection: it may already have delivered
// application bytes, so retrying its body would silently replay traffic.
type clientSession struct {
	url, tag                    string
	transport                   http.RoundTripper
	ctx                         context.Context
	finish                      context.CancelCauseFunc
	done                        chan struct{}
	writerChan, readerChan      chan []byte
	readMu, writeMu, stateMu    sync.Mutex
	pending                     []byte
	readDeadline, writeDeadline protocol.Deadline
	closed                      bool
}

func newClientSession(ctx context.Context, transport http.RoundTripper, url string, workers *sync.WaitGroup) *clientSession {
	var id [16]byte
	_, _ = rand.Read(id[:])
	ctx, cancel := context.WithCancelCause(ctx)
	s := &clientSession{
		url: url, tag: base64.RawURLEncoding.EncodeToString(id[:]), transport: transport,
		ctx: ctx, finish: cancel, done: make(chan struct{}),
		writerChan: make(chan []byte), readerChan: make(chan []byte, 16),
		readDeadline: protocol.MakeDeadline(), writeDeadline: protocol.MakeDeadline(),
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		defer close(s.done)
		s.terminate(s.run())
	}()
	return s
}

func (s *clientSession) terminate(err error) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	if err == nil {
		err = context.Canceled
	}
	s.finish(err)
	s.readDeadline.Set(time.Time{})
	s.writeDeadline.Set(time.Time{})
}

func (s *clientSession) run() error {
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	wait := 100 * time.Millisecond
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for {
		buf.Reset()
		timer.Reset(wait)
	collect:
		for {
			select {
			case <-s.ctx.Done():
				return context.Cause(s.ctx)
			case data := <-s.writerChan:
				first := buf.Len() == 0
				buf.Write(data)
				if buf.Len() >= maxWriteSize {
					break collect
				}
				if first {
					timer.Reset(10 * time.Millisecond)
				}
			case <-timer.C:
				break collect
			}
		}
		timer.Stop()
		idle := buf.Len() == 0
		for first := true; first || buf.Len() > 0; first = false {
			data := buf.Next(min(buf.Len(), maxWriteSize))
			ctx, cancel := netproxy.NewDialTimeoutContextFrom(s.ctx)
			response, err := s.roundTrip(ctx, data)
			cancel()
			if err != nil {
				return err
			}
			if len(response) > 0 {
				idle = false
				select {
				case s.readerChan <- response:
				case <-s.ctx.Done():
					return context.Cause(s.ctx)
				}
			}
		}
		if idle {
			wait = min(max(wait*3/2, 10*time.Millisecond), time.Second)
		} else {
			wait = 0
		}
	}
}

func (s *clientSession) roundTrip(ctx context.Context, data []byte) ([]byte, error) {
	// RoundTrip may return an early response before it finishes reading or
	// closing the request body. That asynchronous reader owns immutable bytes.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(bytes.Clone(data)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Session-ID", s.tag)
	resp, err := s.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, netproxy.WrapFailure(fmt.Errorf("meek: rejected response %s", resp.Status), netproxy.Failure{Layer: netproxy.LayerProxy, Scope: netproxy.ScopeStream, Phase: netproxy.OpRead, Origin: netproxy.OriginPeer, Reason: netproxy.ReasonRejected, Code: strconv.Itoa(resp.StatusCode)})
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize+1))
	if len(body) > maxResponseSize {
		return nil, errors.New("meek response exceeds maximum size")
	}
	return body, err
}

func (s *clientSession) Read(p []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	select {
	case <-s.readDeadline.Wait():
		return 0, os.ErrDeadlineExceeded
	default:
	}
	if len(s.pending) == 0 {
		select {
		case s.pending = <-s.readerChan:
		default:
		}
	}
	if len(s.pending) == 0 {
		select {
		case <-s.ctx.Done():
			return 0, context.Cause(s.ctx)
		case <-s.readDeadline.Wait():
			return 0, os.ErrDeadlineExceeded
		case s.pending = <-s.readerChan:
		}
	}
	n := copy(p, s.pending)
	s.pending = s.pending[n:]
	if len(s.pending) == 0 {
		s.pending = nil
	}
	return n, nil
}

func (s *clientSession) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	written := 0
	for len(p) > 0 {
		if s.ctx.Err() != nil {
			return written, context.Cause(s.ctx)
		}
		select {
		case <-s.writeDeadline.Wait():
			return written, os.ErrDeadlineExceeded
		default:
		}
		n := min(len(p), maxWriteSize)
		data := bytes.Clone(p[:n])
		select {
		case <-s.ctx.Done():
			return written, context.Cause(s.ctx)
		case <-s.writeDeadline.Wait():
			return written, os.ErrDeadlineExceeded
		case s.writerChan <- data:
			written += n
			p = p[n:]
		}
	}
	return written, nil
}

func (s *clientSession) Close() error {
	s.terminate(context.Canceled)
	<-s.done
	s.readMu.Lock()
	s.pending = nil
	for {
		select {
		case <-s.readerChan:
		default:
			s.readMu.Unlock()
			return nil
		}
	}
}

func (s *clientSession) SetDeadline(deadline time.Time) error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	s.readDeadline.Set(deadline)
	s.writeDeadline.Set(deadline)
	return nil
}
func (s *clientSession) SetReadDeadline(deadline time.Time) error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	s.readDeadline.Set(deadline)
	return nil
}
func (s *clientSession) SetWriteDeadline(deadline time.Time) error {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	s.writeDeadline.Set(deadline)
	return nil
}
func (s *clientSession) LocalAddr() net.Addr  { return nil }
func (s *clientSession) RemoteAddr() net.Addr { return netproxy.NewAddr("meek", s.url) }
