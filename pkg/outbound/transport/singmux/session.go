package singmux

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	yamux "github.com/libp2p/go-yamux/v5"
)

// session is one multiplexed session over an outer connection.
type session interface {
	OpenStream(context.Context) (net.Conn, error)
	IsClosed() bool
	CloseChan() <-chan struct{}
	Close() error
	// closeErr reports why the library closed the session, if it records it.
	closeErr() error
	// saturated reports a session on which a new stream could not grow its
	// receive window to the full size.
	saturated() bool
}

func newSession(protocol Protocol, conn *monitoredConn) (session, error) {
	switch protocol {
	case ProtocolSmux:
		return newSmuxSession(conn), nil
	case ProtocolYAMux:
		// sing-box peers keep yamux keepalives, so both ends detect a dead peer.
		config := yamux.DefaultConfig()
		config.MaxStreamWindowSize = yamuxStreamWindow
		// sing-mux servers never open streams; reset any instead of
		// queueing it with a receive window nobody reads.
		config.MaxIncomingStreams = 0
		config.LogOutput = io.Discard
		budget := new(windowBudget)
		session, err := yamux.Client(conn, config, func() (yamux.MemoryManager, error) {
			return &windowSpan{budget: budget}, nil
		})
		if err != nil {
			return nil, err
		}
		return yamuxSession{Session: session, budget: budget, carrier: conn}, nil
	default:
		return nil, fmt.Errorf("unsupported multiplex %s", protocol)
	}
}

type yamuxSession struct {
	*yamux.Session
	budget  *windowBudget
	carrier *monitoredConn
}

func (s yamuxSession) OpenStream(ctx context.Context) (net.Conn, error) {
	stream, err := s.Session.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	return yamuxStream{stream}, nil
}

func (s yamuxSession) closeErr() error {
	if !s.IsClosed() {
		return nil
	}
	// A closed session fails every open with the reason it closed with.
	_, err := s.Session.OpenStream(context.Background())
	// The receive loop is the carrier's only reader. If it stopped without a
	// carrier error, and neither a GoAway (local Close included) nor the
	// keepalive closed the session, the library rejected a frame.
	var goAway *yamux.GoAwayError
	if !s.carrier.readFailed.Load() && !errors.As(err, &goAway) && !errors.Is(err, yamux.ErrKeepAliveTimeout) {
		return netproxy.WrapFailure(err, netproxy.Failure{Reason: netproxy.ReasonProtocol})
	}
	return err
}

func (s yamuxSession) saturated() bool {
	return s.budget.grown.Load() > yamuxSessionWindow-yamuxStreamWindow
}

// yamuxCloseTimeout is how long a closed stream waits for the peer's FIN
// before it is reset (sing-box's yamux client uses the same).
const yamuxCloseTimeout = 5 * time.Second

// yamuxStream closes like sing-box's yamux client. yamux's own Close also
// stops reading without telling the peer and then drops its data without
// window updates, so a sing-mux server writing into the stream blocks until
// the session ends. Close sends FIN instead, keeps the stream registered and
// resets it unless the peer has closed its half by yamuxCloseTimeout.
type yamuxStream struct{ *yamux.Stream }

func (s yamuxStream) Close() error {
	// Wake local readers; the stream is not read after Close.
	_ = s.SetReadDeadline(time.Now())
	err := s.CloseWrite()
	// A no-op once both halves are closed.
	time.AfterFunc(yamuxCloseTimeout, func() { _ = s.Reset() })
	return err
}

// idsExhausted reports an open that failed because the session ran out of
// stream IDs; the session stays open but cannot open another stream.
func idsExhausted(err error) bool {
	return errors.Is(err, yamux.ErrStreamsExhausted) || errors.Is(err, errSmuxStreamIDs)
}

// yamux grows a stream's receive window from 256 KiB, doubling it while the
// stream is read faster than 4 RTTs per window. yamuxStreamWindow caps one
// stream (measured ~330 Mbit/s at 100 ms RTT, ~170 Mbit/s at 200 ms); the
// streams of a session share yamuxSessionWindow of growth, so a session
// buffers at most that plus 256 KiB per stream. A stream keeps its growth
// until it closes, even while idle, so the budget covers the user streams a
// session carries before the pool adds another session, and a session with
// less than one full window left counts as loaded.
const (
	yamuxStreamWindow  = 8 << 20
	yamuxSessionWindow = expandStreams * yamuxStreamWindow
)

var errWindowBudget = errors.New("yamux session receive window budget exhausted")

type windowBudget struct{ grown atomic.Int64 }

// windowSpan accounts one stream's window growth against its session.
type windowSpan struct {
	budget *windowBudget
	mu     sync.Mutex
	grown  int64
	// done is set once the stream is gone: yamux may still try to grow it
	// from a Read that drains data left in its buffer.
	done bool
}

func (s *windowSpan) ReserveMemory(size int, priority uint8) error {
	// yamux reserves the initial window at the highest priority; it is
	// always granted so that opening a stream never fails here.
	if priority == math.MaxUint8 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return errWindowBudget
	}
	if s.budget.grown.Add(int64(size)) > yamuxSessionWindow {
		s.budget.grown.Add(-int64(size))
		return errWindowBudget
	}
	s.grown += int64(size)
	return nil
}

// ReleaseMemory is unused: yamux returns a span's memory only through Done.
func (*windowSpan) ReleaseMemory(int) {}

func (s *windowSpan) Done() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.done = true
	s.budget.grown.Add(-s.grown)
	s.grown = 0
}
