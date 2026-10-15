package shadowsocksr

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"github.com/daeuniverse/dae/pkg/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/transport/shadowsocksr/obfs"
	"github.com/daeuniverse/dae/pkg/outbound/transport/shadowsocksr/proto"
)

func init() {
	dialer.FromLinkRegister("ssr", NewShadowsocksR)
}

type ShadowsocksR struct {
	Name       string `json:"name"`
	Server     string `json:"server"`
	Port       int    `json:"port"`
	Password   string `json:"password"`
	Cipher     string `json:"cipher"`
	Proto      string `json:"proto"`
	ProtoParam string `json:"protoParam"`
	Obfs       string `json:"obfs"`
	ObfsParam  string `json:"obfsParam"`
	Protocol   string `json:"protocol"`
}

func NewShadowsocksR(link string) (dialer.Builder, *dialer.Property, error) {
	s, err := ParseSSRURL(link)
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

func (s *ShadowsocksR) Build(_ *dialer.ExtraOption, upstream dialer.Upstream) (netproxy.Layer, error) {
	if s.Port < 1 || s.Port > 65535 || s.Server == "" {
		return netproxy.Layer{}, fmt.Errorf("%w: invalid SSR proxy address", dialer.InvalidParameterErr)
	}
	layer := netproxy.Layer{Data: upstream}
	obfsDialer, err := obfs.NewDialer(layer.Data, &obfs.ObfsParam{
		ObfsHost:  s.Server,
		ObfsPort:  uint16(s.Port),
		Obfs:      s.Obfs,
		ObfsParam: s.ObfsParam,
	})
	if err != nil {
		return netproxy.Layer{}, err
	}
	layer.Data = obfsDialer
	err = layer.AppendResult(protocol.Build("shadowsocks_stream", layer.Data, protocol.Header{
		ProxyAddress: net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		Cipher:       s.Cipher,
		Password:     s.Password,
	}))
	if err != nil {
		return netproxy.Layer{}, err
	}
	layer.Data, err = proto.NewDialer(layer.Data, s.Proto, s.ProtoParam, obfsDialer.ObfsOverhead())
	if err != nil {
		return netproxy.Layer{}, err
	}
	return layer, nil
}

// ParseSSRURL accepts the standard ssr:// URL-safe Base64 payload.
// The server inside that payload is plain text, including IPv6.
func ParseSSRURL(link string) (*ShadowsocksR, error) {
	scheme, encoded, ok := strings.Cut(link, "://")
	if !ok || scheme != "ssr" {
		return nil, fmt.Errorf("%w: expected ssr:// link", dialer.InvalidParameterErr)
	}
	content, err := decodeURLBase64(encoded, "payload")
	if err != nil {
		return nil, err
	}
	address, query, _ := strings.Cut(content, "/?")
	// Read the five fixed fields from the right; IPv6 colons belong to server.
	fields := [6]string{}
	for i := 5; i > 0; i-- {
		split := strings.LastIndexByte(address, ':')
		if split < 0 {
			return nil, fmt.Errorf("%w: SSR requires server, port, protocol, cipher, obfuscation and password", dialer.InvalidParameterErr)
		}
		fields[i] = address[split+1:]
		address = address[:split]
	}
	fields[0] = address
	if strings.HasPrefix(address, "[") {
		if !strings.HasSuffix(address, "]") || !strings.Contains(address, ":") {
			return nil, fmt.Errorf("%w: invalid SSR bracketed IPv6 server", dialer.InvalidParameterErr)
		}
		fields[0] = address[1 : len(address)-1]
	}
	if fields[0] == "" || strings.ContainsAny(fields[0], "/?#@[]") || strings.ContainsFunc(fields[0], unicode.IsSpace) {
		return nil, fmt.Errorf("%w: invalid SSR server", dialer.InvalidParameterErr)
	}
	if strings.Contains(fields[0], ":") {
		if _, err := netip.ParseAddr(fields[0]); err != nil {
			return nil, fmt.Errorf("%w: invalid SSR IPv6 server", dialer.InvalidParameterErr)
		}
	}
	port, err := strconv.ParseUint(fields[1], 10, 16)
	if err != nil || port == 0 {
		return nil, fmt.Errorf("%w: SSR port must be 1..65535", dialer.InvalidParameterErr)
	}
	if fields[2] == "" || fields[3] == "" || fields[4] == "" {
		return nil, fmt.Errorf("%w: empty SSR protocol, cipher or obfuscation", dialer.InvalidParameterErr)
	}
	password, err := decodeURLBase64(fields[5], "password")
	if err != nil {
		return nil, err
	}
	params, err := url.ParseQuery(query)
	if err != nil {
		return nil, fmt.Errorf("%w: SSR query: %w", dialer.InvalidParameterErr, err)
	}
	result := &ShadowsocksR{Server: fields[0], Port: int(port), Proto: fields[2], Cipher: fields[3], Obfs: fields[4], Password: password, Protocol: "shadowsocksr"}
	for _, field := range []struct {
		name   string
		target *string
	}{{"remarks", &result.Name}, {"protoparam", &result.ProtoParam}, {"obfsparam", &result.ObfsParam}} {
		value, err := decodeURLBase64(params.Get(field.name), field.name)
		if err != nil {
			return nil, err
		}
		*field.target = value
	}
	return result, nil
}
func decodeURLBase64(value, field string) (string, error) {
	if strings.ContainsFunc(value, unicode.IsSpace) {
		return "", fmt.Errorf("%w: whitespace in SSR %s encoding", dialer.InvalidParameterErr, field)
	}
	encoding := base64.RawURLEncoding.Strict()
	if strings.Contains(value, "=") {
		encoding = base64.URLEncoding.Strict()
	}
	decoded, err := encoding.DecodeString(value)
	if err != nil {
		return "", fmt.Errorf("%w: SSR %s encoding: %w", dialer.InvalidParameterErr, field, err)
	}
	return string(decoded), nil
}
func (s *ShadowsocksR) ExportToURL() string {
	encode := func(value string) string { return base64.RawURLEncoding.EncodeToString([]byte(value)) }
	query := url.Values{"remarks": {encode(s.Name)}, "protoparam": {encode(s.ProtoParam)}, "obfsparam": {encode(s.ObfsParam)}}
	content := strings.Join([]string{s.Server, strconv.Itoa(s.Port), s.Proto, s.Cipher, s.Obfs, encode(s.Password)}, ":") + "/?" + query.Encode()
	return "ssr://" + encode(content)
}
