package httpupgrade

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
)

type Dialer struct {
	ParentDialer netproxy.Dialer
	address      string
	host         string
	path         *url.URL
	tlsConfig    *tls.Config
}

type Config struct {
	Address string
	Host    string
	Path    string
	// Nil uses plaintext; otherwise the upgrade uses TLS with HTTP/1.1.
	TLSConfig *tls.Config
}

func NewDialer(parent netproxy.Dialer, config Config) (*Dialer, error) {
	if config.Address == "" {
		return nil, errors.New("httpupgrade: proxy address is empty")
	}
	path := config.Path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	requestURL, err := url.ParseRequestURI(path)
	if err != nil {
		return nil, fmt.Errorf("httpupgrade path: %w", err)
	}
	d := &Dialer{ParentDialer: parent, address: config.Address, host: config.Host, path: requestURL}
	if d.host == "" {
		d.host = config.Address
	}
	if config.TLSConfig != nil {
		d.tlsConfig = config.TLSConfig.Clone()
		if d.tlsConfig.ServerName == "" {
			d.tlsConfig.ServerName, _, err = net.SplitHostPort(config.Address)
			if err != nil {
				return nil, fmt.Errorf("httpupgrade proxy address: %w", err)
			}
		}
		d.tlsConfig.NextProtos = []string{"http/1.1"}
	}
	return d, nil
}

func (d *Dialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("%w: httpupgrade+%s", netproxy.UnsupportedTunnelTypeError, network)
	}
	conn, err := d.ParentDialer.DialContext(ctx, "tcp", d.address)
	if err != nil {
		return nil, err
	}
	lease := netproxy.DependencyOf(conn)
	if d.tlsConfig != nil {
		conn = tls.Client(conn, d.tlsConfig)
	}
	c := &clientConn{Conn: conn, lease: lease}
	err = protocol.Handshake(ctx, c, func() error {
		req := &http.Request{Method: http.MethodGet, URL: d.path, Host: d.host, Header: make(http.Header)}
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		if err := req.Write(conn); err != nil {
			return err
		}
		resp, reader, err := protocol.ReadHTTPResponse(conn, req)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusSwitchingProtocols || !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") || !hasUpgradeToken(resp.Header.Values("Connection")) {
			return netproxy.WrapFailure(fmt.Errorf("httpupgrade: rejected response %s", resp.Status), netproxy.Failure{Layer: netproxy.LayerProxy, Scope: netproxy.ScopeOperation, Phase: netproxy.OpHandshake, Origin: netproxy.OriginPeer, Reason: netproxy.ReasonRejected, Code: strconv.Itoa(resp.StatusCode)})
		}
		c.reader = reader
		return nil
	})
	if err != nil {
		return nil, err
	}
	return c, nil
}

func hasUpgradeToken(values []string) bool {
	for _, value := range values {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return true
			}
		}
	}
	return false
}

func (*Dialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, fmt.Errorf("%w: httpupgrade+udp", netproxy.UnsupportedTunnelTypeError)
}

type clientConn struct {
	net.Conn
	reader *bufio.Reader
	lease  *netproxy.Lease
	readMu sync.Mutex
}

func (c *clientConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	return c.reader.Read(p)
}
func (c *clientConn) DependencyLease() *netproxy.Lease { return c.lease }
func (c *clientConn) CloseWrite() error {
	if cw, ok := c.Conn.(netproxy.CloseWriter); ok {
		return cw.CloseWrite()
	}
	return errors.ErrUnsupported
}
