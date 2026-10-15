package trojan

import (
	"context"
	cryptotls "crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/pkg/outbound/transport/tls"

	"github.com/daeuniverse/dae/pkg/outbound/common"
	"github.com/daeuniverse/dae/pkg/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/shadowsocks"
	"github.com/daeuniverse/dae/pkg/outbound/transport/grpc"
	"github.com/daeuniverse/dae/pkg/outbound/transport/httpupgrade"
	"github.com/daeuniverse/dae/pkg/outbound/transport/ws"
)

func init() {
	dialer.FromLinkRegister("trojan", NewTrojan)
	dialer.FromLinkRegister("trojan-go", NewTrojan)
}

type Trojan struct {
	Name          string `json:"name"`
	Server        string `json:"server"`
	Port          int    `json:"port"`
	Password      string `json:"password"`
	Sni           string `json:"sni"`
	Type          string `json:"type"`
	Encryption    string `json:"encryption"`
	Host          string `json:"host"`
	Path          string `json:"path"`
	ServiceName   string `json:"serviceName"`
	AllowInsecure bool   `json:"allowInsecure"`
	Protocol      string `json:"protocol"`
}

func NewTrojan(link string) (dialer.Builder, *dialer.Property, error) {
	s, err := ParseTrojanURL(link)
	if err != nil {
		return nil, nil, err
	}
	return s, &dialer.Property{
		Name:     s.Name,
		Address:  net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		Protocol: s.Protocol,
		Link:     s.ExportToURL(),
	}, nil
}

func (s *Trojan) Build(option *dialer.ExtraOption, upstream dialer.Upstream) (layer netproxy.Layer, err error) {
	layer.Data = upstream
	proxyAddress := net.JoinHostPort(s.Server, strconv.Itoa(s.Port))
	defer func() {
		if err != nil {
			err = errors.Join(err, layer.Close())
			layer = netproxy.Layer{}
		}
	}()

	switch s.Type {
	case "", "tcp", "ws", "grpc", "httpupgrade":
	default:
		err = fmt.Errorf("unsupported Trojan transport %q", s.Type)
		return
	}

	var encryption []string
	if s.Encryption != "" && s.Encryption != "none" {
		encryption = strings.SplitN(s.Encryption, ";", 3)
		if len(encryption) != 3 || encryption[0] != "ss" || encryption[1] == "" {
			err = fmt.Errorf("invalid Trojan encryption: expected ss;method;password")
			return
		}
	}

	if s.Type != "grpc" { // grpc contains tls
		tlsConfig := tls.TLSConfig{
			Host:          proxyAddress,
			Sni:           s.Sni,
			AllowInsecure: s.AllowInsecure,
		}
		if err = layer.AppendResult(tlsConfig.Build(option, dialer.NewUpstream(layer.Data))); err != nil {
			return
		}
	}
	switch s.Type {
	case "ws":
		host := s.Host
		if host == "" {
			host = s.Server
		}
		wsConfig := &ws.WsConfig{
			Scheme:   "ws",
			Host:     proxyAddress,
			Path:     s.Path,
			Hostname: host,
		}
		if err = layer.AppendResult(wsConfig.Build(option, dialer.NewUpstream(layer.Data))); err != nil {
			return
		}
	case "grpc":
		transport := &grpc.Dialer{
			ParentDialer: layer.Data,
			ServiceName:  s.ServiceName,
			Address:      proxyAddress,
			TLSConfig:    &cryptotls.Config{ServerName: s.Sni, InsecureSkipVerify: s.AllowInsecure || option.AllowInsecure},
		}
		layer.Data = transport
		layer.Sessions = append(layer.Sessions, transport)
		layer.Resources = append(layer.Resources, transport)
	case "httpupgrade":
		layer.Data, err = httpupgrade.NewDialer(layer.Data, httpupgrade.Config{
			Address: proxyAddress, Host: s.Host, Path: s.Path,
		})
		if err != nil {
			return
		}
	}
	if encryption != nil {
		var encrypted netproxy.Dialer
		encrypted, err = shadowsocks.NewDialer(layer.Data, protocol.Header{
			ProxyAddress: proxyAddress,
			Cipher:       encryption[1],
			Password:     encryption[2],
		})
		if err != nil {
			return
		}
		layer.Data = shadowsocksTransport{encrypted.(*shadowsocks.Dialer)}
	}
	err = layer.AppendResult(protocol.Build("trojanc", layer.Data, protocol.Header{
		ProxyAddress: proxyAddress,
		Password:     s.Password,
	}))
	return
}

// Trojan owns the destination header; this layer only encrypts its TCP carrier.
type shadowsocksTransport struct{ *shadowsocks.Dialer }

func (d shadowsocksTransport) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("%w: Trojan Shadowsocks transport: %s", netproxy.UnsupportedTunnelTypeError, network)
	}
	return d.DialTCPTransport(ctx)
}
func (shadowsocksTransport) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, fmt.Errorf("%w: Trojan Shadowsocks transport requires TCP", netproxy.UnsupportedTunnelTypeError)
}

func ParseTrojanURL(link string) (*Trojan, error) {
	u, err := url.Parse(link)
	if err != nil || (u.Scheme != "trojan" && u.Scheme != "trojan-go") {
		return nil, dialer.InvalidParameterErr
	}
	q := u.Query()
	for _, key := range []string{"allow_insecure", "allowinsecure", "skipVerify", "peer"} {
		if q.Has(key) {
			return nil, fmt.Errorf("unsupported Trojan option %q; use allowInsecure and sni", key)
		}
	}
	allowInsecure := false
	if q.Has("allowInsecure") {
		allowInsecure, err = strconv.ParseBool(q.Get("allowInsecure"))
		if err != nil {
			return nil, fmt.Errorf("invalid Trojan allowInsecure: %w", err)
		}
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, dialer.InvalidParameterErr
	}
	sni := q.Get("sni")
	if sni == "" {
		sni = u.Hostname()
	}
	data := &Trojan{
		Name: u.Fragment, Server: u.Hostname(), Port: port, Password: u.User.Username(), Sni: sni,
		AllowInsecure: allowInsecure, Protocol: u.Scheme, Encryption: q.Get("encryption"),
		Host: q.Get("host"), Path: q.Get("path"), Type: q.Get("type"), ServiceName: q.Get("serviceName"),
	}
	if data.Type == "grpc" && data.Path != "" {
		return nil, fmt.Errorf("Trojan gRPC uses serviceName, not path")
	}

	return data, nil
}

func (t *Trojan) ExportToURL() string {
	u := &url.URL{
		Scheme:   "trojan",
		User:     url.User(t.Password),
		Host:     net.JoinHostPort(t.Server, strconv.Itoa(t.Port)),
		Fragment: t.Name,
	}
	q := u.Query()
	if t.AllowInsecure {
		q.Set("allowInsecure", "1")
	}
	common.SetValue(&q, "sni", t.Sni)

	if t.Protocol == "trojan-go" {
		u.Scheme = "trojan-go"
	}
	common.SetValue(&q, "host", t.Host)
	common.SetValue(&q, "encryption", t.Encryption)
	common.SetValue(&q, "type", t.Type)
	common.SetValue(&q, "path", t.Path)
	common.SetValue(&q, "serviceName", t.ServiceName)

	u.RawQuery = q.Encode()
	return u.String()
}
