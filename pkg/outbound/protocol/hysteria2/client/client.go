package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	P "github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/hysteria2/internal/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/hysteria2/internal/utils"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/hysteria2/udphop"
	tuiccommon "github.com/daeuniverse/dae/pkg/outbound/protocol/tuic/common"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/tuic/congestion"
	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
)

const (
	closeErrCodeProtocolError = 0x101 // HTTP3 ErrCodeGeneralProtocolError
)

type Client struct {
	config    *Config
	lifecycle *netproxy.SingleSession[*clientResource]
}

type clientResource struct {
	pktConn net.PacketConn
	http    *http3.Transport
	conn    *quic.Conn
	udpSM   *udpSessionManager
	ctx     context.Context
	cancel  context.CancelFunc
	credit  tuiccommon.StreamCredit
}

func (r *clientResource) close() error {
	if r.cancel != nil {
		r.cancel()
	}
	var err error
	if r.http != nil {
		err = errors.Join(err, r.http.Close())
	}
	if r.conn != nil {
		err = errors.Join(err, r.conn.CloseWithError(closeErrCodeProtocolError, ""))
	}
	if r.pktConn != nil {
		err = errors.Join(err, r.pktConn.Close())
	}
	if r.udpSM != nil && r.udpSM.done != nil {
		<-r.udpSM.done
	}
	return err
}

func NewClient(config *Config) (*Client, error) {
	if err := config.verifyAndFill(); err != nil {
		return nil, err
	}
	c := &Client{config: config}
	c.lifecycle = netproxy.NewSingleSession(netproxy.SingleSessionConfig[*clientResource]{
		Layer:     netproxy.LayerQUIC,
		Establish: c.establish,
		IsConnected: func(resource *clientResource) bool {
			return resource.conn != nil && resource.conn.Context().Err() == nil &&
				(resource.udpSM == nil || resource.udpSM.ctx.Err() == nil)
		},
		Observe: c.observe,
		Close:   (*clientResource).close,
	})
	return c, nil
}

func (c *Client) Snapshot() netproxy.StateEvent {
	return c.lifecycle.Snapshot()
}

func (c *Client) WatchState(ctx context.Context) <-chan netproxy.StateEvent {
	return c.lifecycle.WatchState(ctx)
}

func (c *Client) currentResource() (*clientResource, error) {
	return c.lifecycle.Current()
}

func (c *Client) openStream(ctx context.Context, resource *clientResource) (*utils.QStream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	handle, err := c.lifecycle.CurrentHandle()
	if err != nil {
		return nil, err
	}
	if handle.Resource() != resource {
		return nil, netproxy.ErrNotConnected
	}
	fail := func(err error) { handle.Abort(err) }
	stream, err := resource.conn.OpenStream()
	if err != nil {
		return nil, tuiccommon.WrapQUICError(err, handle.Ref(), nil, netproxy.OpOpenStream, fail)
	}
	lease := handle.NewStreamLease()
	if !lease.Valid() {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, lease.Cause()
	}
	return &utils.QStream{
		Stream: stream,
		LAddr:  resource.conn.LocalAddr(),
		RAddr:  resource.conn.RemoteAddr(),
		Lease:  lease,
		Fail:   fail,
	}, nil
}

// dialConn sends the request and waits for its response.
func (c *Client) dialConn(stream *utils.QStream, addr string) (net.Conn, error) {
	err := protocol.WriteTCPRequest(stream, addr)
	if err != nil {
		return nil, err
	}
	ok, msg, err := protocol.ReadTCPResponse(stream)
	if err != nil {
		return nil, responseError(stream, err)
	}
	if !ok {
		return nil, targetDialError(stream, msg)
	}
	return &tcpConn{
		Orig:             stream,
		PseudoLocalAddr:  stream.LocalAddr(),
		PseudoRemoteAddr: stream.RemoteAddr(),
		Established:      true,
	}, nil
}

func (c *Client) ListenPacket(ctx context.Context, _ string) (net.PacketConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	resource, err := c.currentResource()
	if err != nil {
		return nil, err
	}
	if resource.udpSM == nil {
		return nil, fmt.Errorf("Hysteria2 UDP not enabled: %w", netproxy.UnsupportedTunnelTypeError)
	}
	handle, err := c.lifecycle.CurrentHandle()
	if err != nil {
		return nil, err
	}
	if handle.Resource() != resource {
		return nil, netproxy.ErrNotConnected
	}
	return resource.udpSM.NewUDP(handle.NewStreamLease(), func(err error) { handle.Abort(err) })
}

func (c *Client) DialContext(ctx context.Context, network, address string) (conn net.Conn, err error) {
	if network == "udp" {
		packet, err := c.ListenPacket(ctx, address)
		if err != nil {
			return nil, err
		}
		return &netproxy.BindPacketConn{PacketConn: packet, Address: netproxy.NewAddr("udp", address)}, nil
	}
	if network != "tcp" {
		return nil, fmt.Errorf("%w: %s", netproxy.UnsupportedTunnelTypeError, network)
	}
	resource, err := c.currentResource()
	if err != nil {
		return nil, err
	}
	stream, err := c.openStream(ctx, resource)
	if err != nil {
		return nil, err
	}
	if c.config.FastOpen {
		// The request goes with the first Write and its response is parsed
		// on the first Read.
		var request bytes.Buffer
		_ = protocol.WriteTCPRequest(&request, address)
		return newFastOpenConn(stream, request.Bytes()), nil
	}
	err = P.Handshake(ctx, stream, func() error {
		var exchangeErr error
		conn, exchangeErr = c.dialConn(stream, address)
		return exchangeErr
	})
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (c *Client) Connect(ctx context.Context) error {
	return c.lifecycle.Connect(ctx)
}

func (c *Client) establish(ctx context.Context) (resource *clientResource, err error) {
	addr := c.config.Addr
	if c.config.ResolveAddr != nil {
		addr, err = c.config.ResolveAddr(ctx)
		if err != nil {
			return nil, err
		}
	}
	resourceCtx, resourceCancel := context.WithCancel(context.Background())
	resource = &clientResource{ctx: resourceCtx, cancel: resourceCancel}
	defer func(resource *clientResource) {
		if err != nil {
			_ = resource.close()
		}
	}(resource)

	if addr.Network() == "udphop" {
		// NextDialer.ListenPacket have to get a new lAddr every time.
		// Otherwise port hopping will not work.
		dialFunc := func(dialCtx context.Context, addr net.Addr) (net.Conn, error) {
			return c.config.NextDialer.DialContext(dialCtx, "udp", addr.String())
		}
		pktConn, err := udphop.NewUDPHopPacketConn(ctx, addr.(*udphop.UDPHopAddr), c.config.UDPHopInterval, dialFunc)
		if err != nil {
			return nil, err
		}
		resource.pktConn = pktConn
	} else {
		pktConn, err := c.config.NextDialer.ListenPacket(ctx, addr.String())
		if err != nil {
			return nil, err
		}
		resource.pktConn = pktConn
	}
	netproxy.CaptureDependency(ctx, resource.pktConn)

	// Prepare Transport
	quicConfig := c.config.QUICConfig
	quicConfig.CapabilityCallback = resource.credit.Report
	rt := &http3.Transport{
		TLSClientConfig: &c.config.TLSConfig,
		QUICConfig:      &quicConfig,
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			// Dial, not DialEarly: the auth request waits for the handshake
			// anyway, and 0-RTT on a resumed session only risks a rejection
			// that fails every later stream, as http3 never calls NextConnection.
			qc, err := quic.Dial(ctx, resource.pktConn, addr, tlsCfg, cfg)
			if err != nil {
				return nil, err
			}
			resource.conn = qc
			return qc, nil
		},
	}
	resource.http = rt
	// Send auth HTTP request
	u := &url.URL{
		Scheme: "https",
		Host:   protocol.URLHost,
		Path:   protocol.URLPath,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create HTTP3 handshake request: %w", err)
	}
	req.Header = make(http.Header)
	protocol.AuthRequestToHeader(req.Header, protocol.AuthRequest{
		Auth: c.config.Auth,
		Rx:   c.config.BandwidthConfig.MaxRx,
	})
	resp, err := rt.RoundTrip(req)
	if err != nil {
		_ = rt.Close()
		return nil, fmt.Errorf("HTTP3 handshake: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != protocol.StatusAuthOK {
		reason := netproxy.ReasonRejected
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			reason = netproxy.ReasonAuth
		}
		err = netproxy.WrapFailure(fmt.Errorf("Hysteria authentication endpoint returned HTTP status %d", resp.StatusCode), netproxy.Failure{
			Scope: netproxy.ScopeOperation, Layer: netproxy.LayerH3, Phase: netproxy.OpHandshake,
			Origin: netproxy.OriginPeer, Reason: reason, Code: strconv.Itoa(resp.StatusCode),
		})
		return nil, fmt.Errorf("HTTP3 handshake: %w", err)
	}
	// Auth OK
	authResp, err := protocol.AuthResponseFromHeader(resp.Header)
	if err != nil {
		return nil, netproxy.WrapFailure(err, netproxy.Failure{
			Scope: netproxy.ScopeOperation, Layer: netproxy.LayerH3, Phase: netproxy.OpHandshake,
			Origin: netproxy.OriginPeer, Reason: netproxy.ReasonProtocol,
		})
	}
	var actualTx uint64
	if authResp.RxAuto {
		// Server asks client to use bandwidth detection,
		// ignore local bandwidth config and use BBR
		congestion.UseBBR(resource.conn)
	} else {
		// actualTx = min(serverRx, clientTx)
		actualTx = authResp.Rx
		if actualTx == 0 || actualTx > c.config.BandwidthConfig.MaxTx {
			// Server doesn't have a limit, or our clientTx is smaller than serverRx
			actualTx = c.config.BandwidthConfig.MaxTx
		}
		if actualTx > 0 {
			if err := congestion.UseBrutal(resource.conn, actualTx); err != nil {
				return nil, err
			}
		} else {
			// We don't know our own bandwidth either, use BBR
			congestion.UseBBR(resource.conn)
		}
	}
	if authResp.UDPEnabled {
		resource.udpSM = newUDPSessionManager(resource.ctx, resource.conn)
	}
	return resource, nil
}

func (c *Client) observe(ctx context.Context, handle *netproxy.SingleSessionHandle[*clientResource]) {
	resource := handle.Resource()
	var udpDone <-chan struct{}
	if resource.udpSM != nil {
		udpDone = resource.udpSM.ctx.Done()
	}
	var cause error
	select {
	case <-ctx.Done():
		return
	case <-resource.conn.Context().Done():
		cause = context.Cause(resource.conn.Context())
	case <-udpDone:
		cause = context.Cause(resource.udpSM.ctx)
	}
	if ctx.Err() != nil {
		return
	}
	if cause == nil {
		cause = net.ErrClosed
	}
	cause = tuiccommon.WrapQUICError(cause, handle.Ref(), nil, netproxy.OpRead, nil)
	failure := netproxy.ClassifyFailure(cause)
	failure.Scope = netproxy.ScopeSharedResource
	cause = netproxy.WrapFailure(cause, failure)
	handle.Abort(cause)
}

// Close first lets the peer finish the streams it was sent, which returns
// their credit, for up to netproxy.CloseLinger: closing the QUIC connection
// discards what the peer has not read yet. A failed connection is cleaned
// up at once, without this wait.
func (c *Client) Close() error {
	if resource, err := c.lifecycle.Current(); err == nil && resource.conn != nil {
		ctx, cancel := context.WithTimeout(context.Background(), netproxy.CloseLinger)
		resource.credit.WaitReleased(ctx, resource.conn.Context().Done())
		cancel()
	}
	return c.lifecycle.Close()
}
