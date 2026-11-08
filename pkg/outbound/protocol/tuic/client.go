package tuic

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	mathrand "math/rand/v2"
	"net"
	"os"
	"sync"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/tuic/common"
	"github.com/daeuniverse/quic-go"
)

const Ver5 = 0x5

type ClientOption struct {
	TlsConfig             *tls.Config
	QuicConfig            *quic.Config
	Uuid                  [16]byte
	Password              string
	UdpRelayMode          common.UdpRelayMode
	MaxUdpRelayPacketSize int
	CongestionController  string
	ReduceRtt             bool
	CWND                  int
}

type clientImpl struct {
	*ClientOption
	udp bool

	underConn net.PacketConn
	transport *quic.Transport
	quicConn  *quic.Conn
	connMutex sync.Mutex
	uniMutex  sync.Mutex
	authReady chan struct{}

	closed bool

	udpIncomingPacketsMap sync.Map

	onClose   func()
	resource  netproxy.ResourceRef
	lease     *netproxy.Lease
	poolState *netproxy.PoolState
}

func (t *clientImpl) ConnectQUIC(ctx context.Context, dialer netproxy.Dialer, dialFn common.DialFunc) (*quic.Conn, error) {
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	if t.closed {
		return nil, common.ErrClientClosed
	}
	if t.quicConn != nil {
		if t.quicConn.Context().Err() != nil || !t.lease.Valid() {
			return nil, common.ErrClientClosed
		}
		return t.quicConn, nil
	}
	if t.resource == (netproxy.ResourceRef{}) {
		t.resource = netproxy.NewResourceRef()
	}
	deferAuth := false
	var authStream *quic.SendStream
	t.authReady = make(chan struct{})
	established, err := common.EstablishQUIC(ctx, dialer, dialFn, t.resource, common.QUICHooks{
		TLSConfig: t.TlsConfig, QUICConfig: t.QuicConfig,
		CongestionController: t.CongestionController, CWND: t.CWND,
		Early: t.ReduceRtt, AuthenticationError: ProtocolError,
		Authenticate: func(ctx context.Context, conn *quic.Conn) error {
			var err error
			authStream, err = conn.OpenUniStream()
			if errors.Is(err, quic.Err0RTTRejected) {
				if _, err = conn.NextConnection(ctx); err == nil {
					authStream, err = conn.OpenUniStream()
				}
			}
			if err != nil {
				return err
			}
			// The token needs the exporter of the completed handshake. A
			// server holds the commands sent in 0-RTT until it arrives.
			if deferAuth = !handshakeComplete(conn); deferAuth {
				return nil
			}
			return t.sendAuthentication(ctx, conn, authStream)
		},
	})
	if err != nil {
		return nil, err
	}
	quicConn := established.Conn
	t.lease = established.Lease
	t.transport = established.Transport
	t.underConn = established.Transport.Conn
	t.quicConn = quicConn
	if t.poolState != nil {
		t.poolState.Ready(t.resource)
	}
	established.WatchFailure(t.failConnection)
	if deferAuth {
		go func() {
			// WatchFailure reports a connection that ended first.
			if err := t.sendAuthentication(quicConn.Context(), quicConn, authStream); err != nil && quicConn.Context().Err() == nil {
				t.failConnection(err)
			}
		}()
	}

	if t.udp && t.UdpRelayMode == common.QUIC {
		go func() {
			_ = t.handleUniStream(quicConn)
		}()
	}
	go func() {
		_ = t.handleMessage(quicConn) // always handleMessage because tuicV5 using datagram to send the Heartbeat
	}()

	return quicConn, nil
}

// Authentication reserves its stream before publication; otherwise early UDP
// commands can consume all credit while the server holds them for authentication.
func (t *clientImpl) sendAuthentication(ctx context.Context, conn *quic.Conn, stream *quic.SendStream) error {
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-conn.Context().Done():
		return context.Cause(conn.Context())
	case <-conn.HandshakeComplete():
	}
	// No other caller enables the reset maps before this reservation is restored.
	t.uniMutex.Lock()
	_, err := conn.NextConnection(ctx)
	if err == nil && errors.Is(context.Cause(stream.Context()), quic.Err0RTTRejected) {
		stream, err = conn.OpenUniStream()
	}
	t.uniMutex.Unlock()
	if err != nil {
		return err
	}
	close(t.authReady)
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { stream.CancelWrite(0); close(done) })
	defer func() {
		if !stop() {
			<-done
		}
	}()
	if err = WriteAuthentication(stream, Ver5, conn.ConnectionState(), t.Uuid, t.Password); err != nil {
		stream.CancelWrite(0)
		return err
	}
	return stream.Close()
}

func (t *clientImpl) handleUniStream(conn *quic.Conn) error {
	for {
		stream, err := conn.AcceptUniStream(conn.Context())
		if errors.Is(err, quic.Err0RTTRejected) && waitAuthentication(conn.Context(), conn, t.authReady) == nil {
			continue
		}
		if err != nil {
			t.deferQuicConn(err)
			return err
		}
		go func() {
			defer stream.CancelRead(0)
			// packetFrame streams have a finite frame; a peer must not retain idle
			// receive workers forever by opening streams without a command.
			_ = stream.SetReadDeadline(time.Now().Add(5 * time.Second))
			t.receivePacket(stream, common.QUIC)
		}()
	}
}

func (t *clientImpl) handleMessage(conn *quic.Conn) error {
	for {
		data, err := conn.ReceiveDatagram(conn.Context())
		if err != nil {
			t.deferQuicConn(err)
			return err
		}
		// Datagram parsing does not block, so it needs no per-packet worker.
		t.receivePacket(bytes.NewReader(data), common.NATIVE)
	}
}

func (t *clientImpl) receivePacket(r io.Reader, mode common.UdpRelayMode) {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		t.deferQuicConn(err)
		return
	}
	if head[0] != Ver5 || head[1] != PacketType {
		return
	} // heartbeat has no payload
	packet, err := readPacket(r)
	if err != nil {
		t.deferQuicConn(err)
		return
	}
	if t.udp && t.UdpRelayMode == mode {
		if value, ok := t.udpIncomingPacketsMap.Load(packet.ASSOC_ID); ok {
			value.(*quicStreamPacketConn).incomingPackets.PushBack(packet)
		} else {
			netproxy.DropClosedStream.Add(1)
		}
	}
}

func (t *clientImpl) deferQuicConn(err error) {
	_ = common.WrapQUICError(err, t.resource, nil, netproxy.OpRead, t.failConnection)
}

func (t *clientImpl) failConnection(cause error) {
	if cause == nil {
		cause = net.ErrClosed
	}
	failure := netproxy.ClassifyFailure(common.WrapQUICError(cause, t.resource, nil, netproxy.OpRead, nil))
	failure.Scope = netproxy.ScopeSharedResource
	wrapped := netproxy.WrapFailure(cause, failure)
	if t.lease != nil {
		t.lease.Abort(wrapped)
	}
	if t.poolState != nil {
		t.poolState.Failed(t.resource, wrapped)
	}
	_ = t.forceClose(wrapped)
}

func (t *clientImpl) forceClose(cause error) error {
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	if t.lease != nil {
		t.lease.Invalidate(cause)
	}
	if t.poolState != nil {
		t.poolState.Failed(t.resource, cause)
	}
	if t.onClose != nil {
		go t.onClose()
		t.onClose = nil
	}
	quicConn := t.quicConn
	t.quicConn = nil

	var err error
	if quicConn != nil {
		message := ""
		if cause != nil {
			message = cause.Error()
		}
		err = errors.Join(err, quicConn.CloseWithError(ProtocolError, message))
	}
	if t.transport != nil {
		err = errors.Join(err, t.transport.Close())
		t.transport = nil
	}
	if t.underConn != nil {
		err = errors.Join(err, t.underConn.Close())
		t.underConn = nil
	}
	t.udpIncomingPacketsMap.Range(func(key, value any) bool {
		value.(*quicStreamPacketConn).shutdown(cause)
		t.udpIncomingPacketsMap.Delete(key)
		return true
	})
	return err
}

func (t *clientImpl) Close() error {
	return t.forceClose(netproxy.WrapFailure(common.ErrClientClosed, netproxy.Failure{Resource: t.resource, Scope: netproxy.ScopeSharedResource, Layer: netproxy.LayerQUIC, Phase: netproxy.OpClose, Origin: netproxy.OriginLocalCleanup, Reason: netproxy.ReasonClosed}))
}

func (t *clientImpl) DialContext(ctx context.Context, metadata *protocol.Metadata) (net.Conn, error) {
	quicConn, err := t.currentConn(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := func() (stream net.Conn, err error) {
		defer func() {
			t.deferQuicConn(err)
		}()
		address := addressFromMetadata(metadata)
		command := bytes.NewBuffer(make([]byte, 0, 2+address.BytesLen()))
		command.Write([]byte{Ver5, ConnectType})
		if err := address.appendTo(command); err != nil {
			return nil, err
		}

		// Checked before the open: the handshake may complete, and reject
		// the stream, right after it.
		early := !handshakeComplete(quicConn)
		quicStream, err := quicConn.OpenStream()
		if errors.Is(err, quic.Err0RTTRejected) {
			if err = waitAuthentication(ctx, quicConn, t.authReady); err == nil {
				early = false
				quicStream, err = quicConn.OpenStream()
			}
		}
		if err != nil {
			return nil, err
		}
		lease := t.lease.NewStream()
		if !lease.Valid() {
			quicStream.CancelRead(0)
			quicStream.CancelWrite(0)
			return nil, lease.Cause()
		}
		track := func(stream *quic.Stream) trackedStream {
			tracked := common.NewSafeStreamConn(stream, quicConn.LocalAddr(), quicConn.RemoteAddr())
			tracked.BindRecovery(lease, t.failConnection)
			return tracked
		}
		tracked := track(quicStream)
		if !early {
			return newConnectConn(tracked, command.Bytes()), nil
		}
		wrap := func(err error, op netproxy.Operation) error {
			return common.WrapQUICError(err, lease.Resource(), lease, op, t.failConnection)
		}
		return newConnectConn(newEarlyStream(quicStream.Context(), quicConn, tracked, func() (trackedStream, error) {
			if err := waitAuthentication(quicConn.Context(), quicConn, t.authReady); err != nil {
				return nil, wrap(err, netproxy.OpOpenStream)
			}
			stream, err := quicConn.OpenStream()
			if err != nil {
				return nil, wrap(err, netproxy.OpOpenStream)
			}
			return track(stream), nil
		}, wrap), command.Bytes()), nil
	}()
	if err != nil {
		return nil, common.WrapQUICError(err, t.resource, nil, netproxy.OpOpenStream, t.failConnection)
	}
	return stream, nil
}

type trackedStream interface {
	net.Conn
	netproxy.CloseWriter
	netproxy.DependencyProvider
}

// connectConn sends the CONNECT command in the same stream write as the
// first payload, so a lone fixed-size command never precedes it. A Read or
// CloseWrite before any Write sends the command alone; Close never sends it.
// On an earlyStream, that write returns once the server accepted or rejected
// the 0-RTT data.
type connectConn struct {
	trackedStream
	first   protocol.FirstWrite
	command []byte
}

func newConnectConn(stream trackedStream, command []byte) *connectConn {
	return &connectConn{trackedStream: stream, command: command}
}

func (c *connectConn) Write(b []byte) (int, error) {
	if c.first.Pending() {
		c.first.Lock()
		defer c.first.Unlock()
	}
	return c.first.Write(c.trackedStream, c.command, b)
}

// flush sends the command alone. The caller holds first.
func (c *connectConn) flush() error {
	_, err := c.first.Write(c.trackedStream, c.command, nil)
	return err
}

func (c *connectConn) Read(p []byte) (int, error) {
	if len(p) > 0 {
		if err := c.first.Flush(c.flush); err != nil {
			return 0, err
		}
	}
	return c.trackedStream.Read(p)
}

func (c *connectConn) CloseWrite() error {
	c.first.Lock()
	err := c.first.FlushLocked(c.flush)
	c.first.Unlock()
	if err != nil {
		return err
	}
	return c.trackedStream.CloseWrite()
}

// earlyStream is a stream opened while the handshake may still be incomplete,
// so its first carrier write may travel in 0-RTT. A server rejecting early
// data discards such a stream unread, and nothing is readable before the
// handshake, so settle resends that write on a stream of the 1-RTT
// connection, which then replaces the early stream. The embedded early stream
// supplies the addresses and lease, which its replacement shares.
type earlyStream struct {
	trackedStream
	conn    *quic.Conn
	ctx     context.Context // of the early stream, canceled by the rejection
	reopen  func() (trackedStream, error)
	wrap    func(error, netproxy.Operation) error
	settled chan struct{} // closed once current is final
	closed  chan struct{}
	timeout protocol.Deadline // the write deadline, for settle

	mu                          sync.Mutex // guards current, the deadlines and closing closed
	current                     trackedStream
	readDeadline, writeDeadline time.Time
}

func newEarlyStream(ctx context.Context, conn *quic.Conn, stream trackedStream, reopen func() (trackedStream, error), wrap func(error, netproxy.Operation) error) *earlyStream {
	return &earlyStream{trackedStream: stream, conn: conn, ctx: ctx, reopen: reopen, wrap: wrap, settled: make(chan struct{}), closed: make(chan struct{}), timeout: protocol.MakeDeadline(), current: stream}
}

func (s *earlyStream) stream() trackedStream {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current
}

// settle returns once the server accepted or rejected the 0-RTT data of buf,
// the first carrier write, whose write to the early stream returned err.
func (s *earlyStream) settle(buf []byte, err error) error {
	replacement, err := s.replace(err)
	close(s.settled)
	if replacement == nil {
		return err
	}
	_, err = replacement.Write(buf)
	return err
}

func (s *earlyStream) replace(err error) (trackedStream, error) {
	if err != nil && !errors.Is(err, quic.Err0RTTRejected) {
		return nil, err
	}
	select {
	case <-s.conn.HandshakeComplete():
	case <-s.conn.Context().Done():
		return nil, s.wrap(context.Cause(s.conn.Context()), netproxy.OpWrite)
	case <-s.closed:
		return nil, s.wrap(net.ErrClosed, netproxy.OpWrite)
	case <-s.timeout.Wait():
		return nil, s.wrap(os.ErrDeadlineExceeded, netproxy.OpWrite)
	}
	// The rejection resets the 0-RTT streams before the handshake completes.
	// A stream opened after another goroutine's NextConnection is a 1-RTT
	// stream that already carries the write.
	if !errors.Is(context.Cause(s.ctx), quic.Err0RTTRejected) {
		return nil, err
	}
	replacement, err := s.reopen()
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.closed:
		_ = replacement.Close()
		return nil, s.wrap(net.ErrClosed, netproxy.OpWrite)
	default:
	}
	_ = replacement.SetReadDeadline(s.readDeadline)
	_ = replacement.SetWriteDeadline(s.writeDeadline)
	s.current = replacement
	return replacement, nil
}

func (s *earlyStream) Read(p []byte) (int, error) {
	n, err := s.stream().Read(p)
	// The rejection reaches the first carrier write as it does this read;
	// settle replaces the stream as soon as the handshake completes.
	if len(p) > 0 && errors.Is(err, quic.Err0RTTRejected) {
		select {
		case <-s.settled:
		case <-s.closed:
		}
		return s.stream().Read(p)
	}
	return n, err
}

// Write settles the first write, which carries the command.
func (s *earlyStream) Write(b []byte) (int, error) {
	select {
	case <-s.settled:
		return s.stream().Write(b)
	default:
	}
	_, err := s.stream().Write(b)
	if err = s.settle(b, err); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (s *earlyStream) CloseWrite() error { return s.stream().CloseWrite() }

func (s *earlyStream) Close() error {
	s.mu.Lock()
	select {
	case <-s.closed:
	default:
		close(s.closed)
	}
	stream := s.current
	s.mu.Unlock()
	return stream.Close()
}

func (s *earlyStream) SetDeadline(t time.Time) error {
	return errors.Join(s.SetReadDeadline(t), s.SetWriteDeadline(t))
}

func (s *earlyStream) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.readDeadline = t
	return s.current.SetReadDeadline(t)
}

func (s *earlyStream) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.writeDeadline = t
	s.timeout.Set(t)
	return s.current.SetWriteDeadline(t)
}

func handshakeComplete(conn *quic.Conn) bool {
	select {
	case <-conn.HandshakeComplete():
		return true
	default:
		return false
	}
}

// waitAuthentication returns once a connection that refused a stream because
// the server rejected 0-RTT accepts streams again. A refused open sent
// nothing, so it can be retried.
func waitAuthentication(ctx context.Context, conn *quic.Conn, ready <-chan struct{}) error {
	select {
	case <-ready:
		return nil
	case <-conn.Context().Done():
		return context.Cause(conn.Context())
	case <-ctx.Done():
		return context.Cause(ctx)
	}
}

func (t *clientImpl) ListenPacket(ctx context.Context, metadata *protocol.Metadata) (*quicStreamPacketConn, error) {
	quicConn, err := t.currentConn(ctx)
	if err != nil {
		return nil, err
	}

	pc := &quicStreamPacketConn{
		lease: t.lease.NewStream(), fail: t.failConnection, quicConn: quicConn,
		authReady: t.authReady,
		openUniStream: func() (*quic.SendStream, error) {
			t.uniMutex.Lock()
			defer t.uniMutex.Unlock()
			return quicConn.OpenUniStream()
		},
		incomingPackets: newPacketQueue(), udpRelayMode: t.UdpRelayMode,
		maxUdpRelayPacketSize: t.MaxUdpRelayPacketSize, readDeadline: protocol.MakeDeadline(),
	}
	for attempts := 0; ; attempts++ {
		if attempts >= 65536 {
			pc.shutdown(common.ErrHoldOn)
			return nil, netproxy.WrapFailure(common.ErrHoldOn, netproxy.Failure{Scope: netproxy.ScopeOperation, Layer: netproxy.LayerQUIC, Phase: netproxy.OpOpenStream, Reason: netproxy.ReasonCapacity})
		}
		pc.connId = uint16(mathrand.Uint32())
		pc.closeDeferFn = func() { t.udpIncomingPacketsMap.CompareAndDelete(pc.connId, pc) }
		if _, loaded := t.udpIncomingPacketsMap.LoadOrStore(pc.connId, pc); !loaded {
			break
		}
	}

	if !pc.lease.Valid() || ctx.Err() != nil {
		cause := pc.terminalError(netproxy.OpOpenStream)
		_ = pc.Close()
		return nil, cause
	}
	return pc, nil
}

func (t *clientImpl) setOnClose(f func()) {
	t.onClose = f
}

// currentConn never establishes a transport on behalf of a relay.
func (t *clientImpl) currentConn(ctx context.Context) (*quic.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	if t.quicConn == nil || t.quicConn.Context().Err() != nil || !t.lease.Valid() {
		return nil, common.ErrClientClosed
	}
	return t.quicConn, nil
}

func (t *clientImpl) BindPool(state *netproxy.PoolState, ref netproxy.ResourceRef, onClose func()) {
	t.poolState, t.resource = state, ref
	t.setOnClose(onClose)
}

func (t *clientImpl) FailureCause() error { return t.lease.Cause() }

// HandshakePending leaves early stream admission to QUIC's restored limits.
func (t *clientImpl) HandshakePending() bool {
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	return t.quicConn != nil && !handshakeComplete(t.quicConn)
}
