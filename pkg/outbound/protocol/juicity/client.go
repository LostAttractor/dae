package juicity

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/daeuniverse/dae/pkg/outbound/ciphers"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pkg/fastrand"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/tuic"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/tuic/common"
	"github.com/daeuniverse/quic-go"
)

var (
	CipherConf = ciphers.AeadCiphersConf["chacha20-poly1305"]
)

const (
	UnderlaySaltLen = 32
)

func init() {
	if CipherConf.SaltLen != UnderlaySaltLen {
		panic("CipherConf.SaltLen != IvSize")
	}
}

type UnderlayAuth struct {
	IV       []byte
	Psk      []byte
	Metadata *Metadata
	lease    *netproxy.Lease
}

type ClientOption struct {
	TlsConfig            *tls.Config
	QuicConfig           *quic.Config
	Uuid                 [16]byte
	Password             string
	CongestionController string
	CWND                 int
	Ctx                  context.Context
	Cancel               func()
	UnderlayAuth         chan *UnderlayAuth
}

type clientImpl struct {
	*ClientOption

	quicConn  *quic.Conn
	underConn net.PacketConn
	transport *quic.Transport
	connMutex sync.Mutex

	detachCallback func()
	resource       netproxy.ResourceRef
	lease          *netproxy.Lease
	poolState      *netproxy.PoolState
}

func (t *clientImpl) ConnectQUIC(ctx context.Context, dialer netproxy.Dialer, dialFn common.DialFunc) (*quic.Conn, error) {
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	if t.Ctx.Err() != nil {
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
	var authStream *quic.SendStream
	established, err := common.EstablishQUIC(ctx, dialer, dialFn, t.resource, common.QUICHooks{
		TLSConfig: t.TlsConfig, QUICConfig: t.QuicConfig,
		CongestionController: t.CongestionController, CWND: t.CWND,
		Authenticate: func(ctx context.Context, conn *quic.Conn) (err error) {
			authStream, err = t.openAuthentication(ctx, conn)
			return err
		}, AuthenticationError: tuic.ProtocolError,
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
	go func() {
		if err := t.sendAuthentication(authStream); err != nil {
			t.failConnection(err)
		}
	}()
	established.WatchFailure(t.failConnection)
	return quicConn, nil
}

func (t *clientImpl) openAuthentication(ctx context.Context, quicConn *quic.Conn) (*quic.SendStream, error) {
	uniStream, err := quicConn.OpenUniStream()
	if err != nil {
		return nil, err
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { uniStream.CancelWrite(0); close(done) })
	defer func() {
		if !stop() {
			<-done
		}
	}()
	if err = tuic.WriteAuthentication(uniStream, Version0, quicConn.ConnectionState(), t.Uuid, t.Password); err != nil {
		uniStream.CancelWrite(0)
		return nil, err
	}

	return uniStream, nil
}

func (t *clientImpl) sendAuthentication(uniStream *quic.SendStream) error {
	defer uniStream.Close()
	for {
		var auth *UnderlayAuth
		select {
		case <-t.Ctx.Done():
			return t.Ctx.Err()
		case auth = <-t.UnderlayAuth:
		}
		buf := pool.GetBytesBuffer()
		buf.Write(auth.IV)
		buf.Write(auth.Psk)
		err := auth.Metadata.appendTo(buf)
		if err == nil {
			_, err = buf.WriteTo(uniStream)
		}
		pool.PutBytesBuffer(buf)
		if err != nil {
			return err
		}
	}
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
	_ = t.Close()
}

func (t *clientImpl) Close() (err error) {
	t.connMutex.Lock()
	defer t.connMutex.Unlock()
	select {
	case <-t.Ctx.Done():
		return
	default:
	}
	if t.lease != nil {
		t.lease.Invalidate(netproxy.WrapFailure(net.ErrClosed, netproxy.Failure{Resource: t.resource, Scope: netproxy.ScopeSharedResource, Layer: netproxy.LayerQUIC, Origin: netproxy.OriginLocalCleanup, Reason: netproxy.ReasonClosed}))
	}
	t.Cancel()
	if t.poolState != nil {
		t.poolState.Failed(t.resource, net.ErrClosed)
	}
	if t.detachCallback != nil {
		go t.detachCallback()
		t.detachCallback = nil
	}
	if t.quicConn != nil {
		err = errors.Join(err, t.quicConn.CloseWithError(tuic.ProtocolError, common.ErrClientClosed.Error()))
		t.quicConn = nil
	}
	if t.transport != nil {
		err = errors.Join(err, t.transport.Close())
		t.transport = nil
	}
	if t.underConn != nil {
		err = errors.Join(err, t.underConn.Close())
		t.underConn = nil
	}
	return err
}

func (t *clientImpl) DialContext(ctx context.Context, metadata *Metadata) (*Conn, error) {
	select {
	case <-t.Ctx.Done():
		return nil, common.ErrClientClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	quicConn, err := t.currentConn(ctx)
	if err != nil {
		return nil, fmt.Errorf("ConnectQUIC: %w", err)
	}
	quicStream, err := quicConn.OpenStream()
	if err != nil {
		return nil, common.WrapQUICError(err, t.resource, nil, netproxy.OpOpenStream, t.failConnection)
	}

	stream := newConn(quicStream, metadata)
	stream.lease, stream.fail = t.lease.NewStream(), t.failConnection
	if !stream.lease.Valid() {
		quicStream.CancelRead(0)
		quicStream.CancelWrite(0)
		return nil, stream.lease.Cause()
	}
	stream.lAddr, stream.rAddr = quicConn.LocalAddr(), quicConn.RemoteAddr()
	return stream, nil
}
func (t *clientImpl) DialAuth(ctx context.Context, metadata *Metadata) (*UnderlayAuth, error) {
	if _, err := t.currentConn(ctx); err != nil {
		return nil, err
	}
	auth := &UnderlayAuth{IV: make([]byte, CipherConf.SaltLen), Psk: make([]byte, CipherConf.KeyLen), Metadata: metadata, lease: t.lease.NewStream()}
	if !auth.lease.Valid() {
		return nil, auth.lease.Cause()
	}
	_, _ = fastrand.Read(auth.IV[2:])
	_, _ = fastrand.Read(auth.Psk)
	select {
	case t.UnderlayAuth <- auth:
		if !auth.lease.Valid() {
			return nil, auth.lease.Cause()
		}
		return auth, nil
	case <-ctx.Done():
		auth.lease.Invalidate(ctx.Err())
		return nil, ctx.Err()
	case <-t.Ctx.Done():
		auth.lease.Invalidate(common.ErrClientClosed)
		return nil, common.ErrClientClosed
	}
}

func (t *clientImpl) setOnClose(f func()) {
	t.detachCallback = f
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
