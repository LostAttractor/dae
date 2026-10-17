package tuic

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pkg/fastrand"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
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
	established, err := common.EstablishQUIC(ctx, dialer, dialFn, t.resource, common.QUICHooks{
		TLSConfig: t.TlsConfig, QUICConfig: t.QuicConfig,
		CongestionController: t.CongestionController, CWND: t.CWND,
		Early: t.ReduceRtt, Authenticate: t.sendAuthentication, AuthenticationError: ProtocolError,
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

func (t *clientImpl) sendAuthentication(ctx context.Context, conn *quic.Conn) error {
	stream, err := conn.OpenUniStream()
	if err != nil {
		return err
	}
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
		buf := pool.GetBytesBuffer()
		defer pool.PutBytesBuffer(buf)
		buf.Write([]byte{Ver5, ConnectType})
		if err := addressFromMetadata(metadata).appendTo(buf); err != nil {
			return nil, err
		}

		quicStream, err := quicConn.OpenStream()
		if err != nil {
			return nil, err
		}
		lease := t.lease.NewStream()
		if !lease.Valid() {
			quicStream.CancelRead(0)
			quicStream.CancelWrite(0)
			return nil, lease.Cause()
		}
		tracked := common.NewSafeStreamConn(quicStream, quicConn.LocalAddr(), quicConn.RemoteAddr())
		tracked.BindRecovery(lease, t.failConnection)
		stream = tracked
		if err = protocol.Handshake(ctx, stream, func() error { _, err := stream.Write(buf.Bytes()); return err }); err != nil {
			_ = stream.Close()
			return nil, err
		}
		return stream, err
	}()
	if err != nil {
		return nil, common.WrapQUICError(err, t.resource, nil, netproxy.OpOpenStream, t.failConnection)
	}
	return stream, nil
}

func (t *clientImpl) ListenPacket(ctx context.Context, metadata *protocol.Metadata) (*quicStreamPacketConn, error) {
	quicConn, err := t.currentConn(ctx)
	if err != nil {
		return nil, err
	}

	pc := &quicStreamPacketConn{
		lease: t.lease.NewStream(), fail: t.failConnection, quicConn: quicConn,
		incomingPackets: newPacketQueue(), udpRelayMode: t.UdpRelayMode,
		maxUdpRelayPacketSize: t.MaxUdpRelayPacketSize, readDeadline: protocol.MakeDeadline(),
	}
	for attempts := 0; ; attempts++ {
		if attempts >= 65536 {
			pc.shutdown(common.ErrHoldOn)
			return nil, netproxy.WrapFailure(common.ErrHoldOn, netproxy.Failure{Scope: netproxy.ScopeOperation, Layer: netproxy.LayerQUIC, Phase: netproxy.OpOpenStream, Reason: netproxy.ReasonCapacity})
		}
		pc.connId = uint16(fastrand.Uint32())
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
