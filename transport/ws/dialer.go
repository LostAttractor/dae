package ws

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	transportTls "github.com/daeuniverse/outbound/transport/tls"
)

func init() {
	dialer.FromLinkRegister("ws", NewWs)
	dialer.FromLinkRegister("wss", NewWs)
}

func parseRange(str string) (min, max int64, err error) {
	stringArr := strings.Split(str, "-")
	if len(stringArr) != 2 {
		return 0, 0, fmt.Errorf("invalid range: %s", str)
	}
	min, err = strconv.ParseInt(stringArr[0], 10, 64)
	if err != nil {
		return 0, 0, err
	}
	max, err = strconv.ParseInt(stringArr[1], 10, 64)
	if err != nil {
		return 0, 0, err
	}
	return min, max, nil
}

// Ws is a base Ws struct
type Ws struct {
	ParentDialer        netproxy.Dialer
	wsAddr              string
	host                string
	tlsClientConfig     *tls.Config
	passthroughUdp      bool
	tlsFragmentation    bool
	fragmentMinLength   int64
	fragmentMaxLength   int64
	fragmentMinInterval int64
	fragmentMaxInterval int64
}

type WsConfig struct {
	Scheme         string
	Host           string
	Path           string
	Hostname       string // Hostname in Http Header
	Alpn           string
	Sni            string
	AllowInsecure  bool
	PassthroughUdp bool
}

// NewWs returns a Ws infra.
func NewWs(link string) (dialer.Builder, *dialer.Property, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, nil, fmt.Errorf("NewWs: %w", err)
	}

	query := u.Query()

	t := &WsConfig{
		Scheme:   u.Scheme,
		Host:     u.Host,
		Hostname: query.Get("host"),
		Path:     u.Path,
		Alpn:     query.Get("alpn"),
		Sni:      query.Get("sni"),
	}

	if t.Hostname == "" {
		t.Hostname = u.Hostname()
	}
	t.PassthroughUdp, _ = strconv.ParseBool(u.Query().Get("passthroughUdp"))

	if u.Scheme == "wss" {
		t.AllowInsecure, _ = strconv.ParseBool(u.Query().Get("allowInsecure"))
		if !t.AllowInsecure {
			t.AllowInsecure, _ = strconv.ParseBool(u.Query().Get("allow_insecure"))
		}
		if !t.AllowInsecure {
			t.AllowInsecure, _ = strconv.ParseBool(u.Query().Get("allowinsecure"))
		}
		if !t.AllowInsecure {
			t.AllowInsecure, _ = strconv.ParseBool(u.Query().Get("skipVerify"))
		}
	}

	return t, &dialer.Property{
		Name:     u.Fragment,
		Address:  t.Host,
		Protocol: u.Scheme,
		Link:     link,
	}, nil
}

func (s *WsConfig) Build(option *dialer.ExtraOption, upstream dialer.Upstream) (netproxy.Layer, error) {
	if s.Alpn != "" {
		for _, alpn := range strings.Split(s.Alpn, ",") {
			if alpn != "http/1.1" {
				return netproxy.Layer{}, fmt.Errorf("unsupported WebSocket ALPN %q: only http/1.1 is supported", alpn)
			}
		}
	}
	wsUrl := url.URL{
		Scheme: s.Scheme,
		Host:   s.Host,
		Path:   s.Path,
	}
	ws := &Ws{
		ParentDialer:   upstream,
		wsAddr:         wsUrl.String(),
		passthroughUdp: s.PassthroughUdp,
		host:           s.Hostname,
		tlsClientConfig: &tls.Config{
			ServerName:         s.Sni,
			InsecureSkipVerify: s.AllowInsecure || option.AllowInsecure,
		},
	}
	if len(s.Alpn) > 0 {
		ws.tlsClientConfig.NextProtos = strings.Split(s.Alpn, ",")
	}
	if option.TlsFragment {
		ws.tlsFragmentation = true
		minLen, maxLen, err := parseRange(option.TlsFragmentLength)
		if err != nil {
			return netproxy.Layer{}, err
		}
		ws.fragmentMinLength = minLen
		ws.fragmentMaxLength = maxLen
		minInterval, maxInterval, err := parseRange(option.TlsFragmentInterval)
		if err != nil {
			return netproxy.Layer{}, err
		}
		ws.fragmentMinInterval = minInterval
		ws.fragmentMaxInterval = maxInterval
	}
	return netproxy.Layer{Data: ws}, nil
}

func (s *Ws) DialContext(ctx context.Context, network, addr string) (c net.Conn, err error) {
	switch network {
	case "tcp":
		endpoint, err := url.Parse(s.wsAddr)
		if err != nil {
			return nil, err
		}
		address := endpoint.Host
		if endpoint.Port() == "" {
			port := "80"
			if endpoint.Scheme == "wss" {
				port = "443"
			}
			address = net.JoinHostPort(endpoint.Hostname(), port)
		}
		raw, err := s.ParentDialer.DialContext(ctx, "tcp", address)
		if err != nil {
			return nil, err
		}
		netproxy.CaptureDependency(ctx, raw)
		dependency := netproxy.DependencyOf(raw)
		if endpoint.Scheme == "wss" {
			if s.tlsFragmentation {
				raw = transportTls.NewFragmentConn(raw, s.fragmentMinLength, s.fragmentMaxLength, s.fragmentMinInterval, s.fragmentMaxInterval)
			}
			config := s.tlsClientConfig.Clone()
			if config.ServerName == "" {
				config.ServerName = endpoint.Hostname()
			}
			raw = tls.Client(raw, config)
		}
		var reader *bufio.Reader
		err = protocol.Handshake(ctx, raw, func() error {
			var nonce [16]byte
			if _, err := rand.Read(nonce[:]); err != nil {
				return err
			}
			key := base64.StdEncoding.EncodeToString(nonce[:])
			request := &http.Request{Method: "GET", URL: endpoint, Host: endpoint.Host, Header: make(http.Header)}
			if s.host != "" {
				request.Host = s.host
			}
			request.Header.Set("Upgrade", "websocket")
			request.Header.Set("Connection", "Upgrade")
			request.Header.Set("Sec-WebSocket-Key", key)
			request.Header.Set("Sec-WebSocket-Version", "13")
			if err := request.Write(raw); err != nil {
				return err
			}
			response, buffered, err := protocol.ReadHTTPResponse(raw, request)
			if err != nil {
				return err
			}
			accept := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
			if response.StatusCode != http.StatusSwitchingProtocols || !strings.EqualFold(response.Header.Get("Upgrade"), "websocket") || !headerToken(response.Header.Get("Connection"), "upgrade") || response.Header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(accept[:]) || response.Header.Get("Sec-WebSocket-Extensions") != "" || response.Header.Get("Sec-WebSocket-Protocol") != "" {
				return netproxy.WrapFailure(fmt.Errorf("websocket upgrade rejected: %s", response.Status), netproxy.Failure{Layer: netproxy.LayerProxy, Scope: netproxy.ScopeOperation, Phase: netproxy.OpHandshake, Origin: netproxy.OriginPeer, Reason: netproxy.ReasonRejected, Code: strconv.Itoa(response.StatusCode)})
			}
			reader = buffered
			return nil
		})
		if err != nil {
			return nil, err
		}
		if !dependency.Valid() {
			_ = raw.Close()
			return nil, dependency.Cause()
		}
		return newConn(raw, reader, dependency), nil

	case "udp":
		if s.passthroughUdp {
			return s.ParentDialer.DialContext(ctx, network, addr)
		}
		return nil, fmt.Errorf("%w: ws+udp", netproxy.UnsupportedTunnelTypeError)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}
}

func (s *Ws) ListenPacket(ctx context.Context, addr string) (net.PacketConn, error) {
	if s.passthroughUdp {
		return s.ParentDialer.ListenPacket(ctx, addr)
	}
	return nil, fmt.Errorf("%w: ws+udp", netproxy.UnsupportedTunnelTypeError)
}
