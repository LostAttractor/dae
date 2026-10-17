package v2ray

import (
	cryptotls "crypto/tls"
	"encoding/base64"
	jsonv1 "encoding/json"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/daeuniverse/dae/pkg/outbound/common"
	"github.com/daeuniverse/dae/pkg/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/http"
	"github.com/daeuniverse/dae/pkg/outbound/transport/grpc"
	"github.com/daeuniverse/dae/pkg/outbound/transport/httpupgrade"
	"github.com/daeuniverse/dae/pkg/outbound/transport/meek"
	"github.com/daeuniverse/dae/pkg/outbound/transport/tls"
	"github.com/daeuniverse/dae/pkg/outbound/transport/ws"
	"github.com/daeuniverse/dae/pkg/proxylink"
)

func init() {
	dialer.FromLinkRegister("vmess", NewV2Ray)
	dialer.FromLinkRegister("vless", NewV2Ray)
}

type V2Ray struct {
	Ps            string `json:"ps"`
	Add           string `json:"add"`
	Port          string `json:"port"`
	ID            string `json:"id"`
	Aid           string `json:"aid"`
	Cipher        string `json:"scy,omitempty"`
	Encryption    string `json:"encryption,omitempty"`
	Net           string `json:"net"`
	Type          string `json:"type"`
	Host          string `json:"host"`
	SNI           string `json:"sni"`
	Path          string `json:"path"`
	TLS           string `json:"tls"`
	Flow          string `json:"flow,omitempty"`
	Alpn          string `json:"alpn,omitempty"`
	AllowInsecure bool   `json:"allowInsecure"`
	Fingerprint   string `json:"fp,omitempty"`
	PublicKey     string `json:"pbk,omitempty"`
	ShortId       string `json:"sid,omitempty"`
	SpiderX       string `json:"spx,omitempty"`
	V             string `json:"v"`
	Protocol      string `json:"protocol"`
}

func NewV2Ray(link string) (dialer.Builder, *dialer.Property, error) {
	var (
		s   *V2Ray
		err error
	)
	switch {
	case strings.HasPrefix(link, "vmess://"):
		s, err = ParseVmessURL(link)
		if err != nil {
			return nil, nil, err
		}
	case strings.HasPrefix(link, "vless://"):
		s, err = ParseVlessURL(link)
		if err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, dialer.InvalidParameterErr
	}
	if _, err := s.dataCipher(); err != nil {
		return nil, nil, err
	}
	return s, &dialer.Property{
		Name:     s.Ps,
		Address:  net.JoinHostPort(s.Add, s.Port),
		Protocol: s.Protocol,
		Link:     s.ExportToURL(),
	}, nil
}

func (s *V2Ray) Build(option *dialer.ExtraOption, upstream dialer.Upstream) (layer netproxy.Layer, err error) {
	layer.Data = upstream
	proxyAddress := net.JoinHostPort(s.Add, s.Port)
	defer func() {
		if err != nil {
			err = errors.Join(err, layer.Close())
			layer = netproxy.Layer{}
		}
	}()

	switch s.Protocol {
	case "vmess", "vless":
	default:
		err = fmt.Errorf("V2Ray.Build: unexpected protocol: %v", s.Protocol)
		return
	}

	dataCipher, cipherErr := s.dataCipher()
	if cipherErr != nil {
		err = cipherErr
		return
	}

	switch s.TLS {
	case "", "none", "tls":
	case "reality":
		if s.Protocol != "vless" || strings.ToLower(s.Net) != "tcp" {
			err = fmt.Errorf("REALITY requires VLESS over TCP")
			return
		}
	default:
		err = fmt.Errorf("%w: security: %s", dialer.UnexpectedFieldErr, s.TLS)
		return
	}
	sni := s.SNI
	if sni == "" {
		sni = s.Host
	}

	switch strings.ToLower(s.Net) {
	case "ws":
		scheme := "ws"
		if s.TLS == "tls" {
			scheme = "wss"
		}
		host := s.Host
		if host == "" {
			host = s.Add
		}
		wsBuilder := &ws.WsConfig{
			Scheme:        scheme,
			Host:          proxyAddress,
			Path:          s.Path,
			Hostname:      host,
			Sni:           sni,
			Alpn:          s.Alpn,
			AllowInsecure: s.AllowInsecure,
		}
		if err = layer.AppendResult(wsBuilder.Build(option, dialer.NewUpstream(layer.Data))); err != nil {
			return
		}
	case "tcp":
		if s.Type != "none" && s.Type != "" {
			err = fmt.Errorf("%w: type: %v", dialer.UnexpectedFieldErr, s.Type)
			return
		}
		if s.TLS == "tls" || s.TLS == "reality" {
			if s.TLS == "reality" {
				u := url.URL{
					Scheme: "reality",
					Host:   proxyAddress,
					RawQuery: url.Values{
						"sni": []string{sni},
						"fp":  []string{s.Fingerprint},
						"sid": []string{s.ShortId},
						"pbk": []string{s.PublicKey},
						"spx": []string{s.SpiderX},
					}.Encode(),
				}
				var reality *tls.Reality
				reality, err = tls.NewReality(u.String(), layer.Data)
				if err == nil {
					layer.Data = reality
					layer.Resources = append(layer.Resources, reality)
				}
			} else {
				tlsConfig := tls.TLSConfig{
					Host:          proxyAddress,
					Sni:           sni,
					Alpn:          s.Alpn,
					AllowInsecure: s.AllowInsecure,
				}
				err = layer.AppendResult(tlsConfig.Build(option, dialer.NewUpstream(layer.Data)))
			}
			if err != nil {
				return
			}
		}
	case "grpc":
		transport := &grpc.Dialer{
			ParentDialer: layer.Data,
			ServiceName:  s.Path,
			Address:      proxyAddress,
		}
		if s.TLS == "tls" {
			transport.TLSConfig = &cryptotls.Config{ServerName: sni, InsecureSkipVerify: s.AllowInsecure || option.AllowInsecure}
		}
		layer.Data = transport
		layer.Sessions = append(layer.Sessions, transport)
		layer.Resources = append(layer.Resources, transport)
	case "http", "h2":
		sni := s.SNI
		if sni == "" {
			sni = s.Add
		}
		scheme := "http"
		if s.TLS == "tls" {
			scheme = "https"
		}
		u := url.URL{
			Scheme: scheme,
			Host:   proxyAddress,
			Path:   s.Path,
			RawQuery: url.Values{
				"sni":           []string{sni},
				"allowInsecure": []string{common.BoolToString(s.AllowInsecure)},
				"host":          []string{s.Host},
				"alpn":          []string{s.Alpn},
				"transport":     []string{"1"},
			}.Encode(),
		}
		if err = layer.AppendResult(http.BuildHTTPProxy(&u, option, layer.Data)); err != nil {
			return
		}
	case "meek":
		if strings.HasPrefix(s.Path, "https://") && s.TLS != "tls" {
			err = fmt.Errorf("%w: meek: tls should be enabled", dialer.InvalidParameterErr)
			return
		}

		tlsConfig := &cryptotls.Config{ServerName: s.SNI, InsecureSkipVerify: s.AllowInsecure || option.AllowInsecure}
		if s.Alpn != "" {
			tlsConfig.NextProtos = strings.Split(s.Alpn, ",")
		}
		transport, buildErr := meek.NewDialer(layer.Data, meek.Config{URL: s.Path, TLSConfig: tlsConfig})
		err = buildErr
		if err != nil {
			return
		}
		layer.Data = transport
		layer.Resources = append(layer.Resources, transport)
	case "httpupgrade":
		config := httpupgrade.Config{Address: proxyAddress, Host: s.Host, Path: s.Path}
		if s.TLS == "tls" {
			config.TLSConfig = &cryptotls.Config{ServerName: s.SNI, InsecureSkipVerify: s.AllowInsecure || option.AllowInsecure}
		}
		layer.Data, err = httpupgrade.NewDialer(layer.Data, config)
		if err != nil {
			return
		}
	default:
		err = fmt.Errorf("%w: network: %v", dialer.UnexpectedFieldErr, s.Net)
		return
	}

	err = layer.AppendResult(protocol.Build(s.Protocol, layer.Data, protocol.Header{
		ProxyAddress: proxyAddress,
		Cipher:       dataCipher,
		Password:     s.ID,
		Feature1:     s.Flow,
	}))
	return
}

func ParseVlessURL(vless string) (data *V2Ray, err error) {
	u, err := url.Parse(vless)
	if err != nil {
		return nil, fmt.Errorf("parse VLESS proxy URL: %w", err.(*url.Error).Err)
	}
	data = &V2Ray{
		Ps:            u.Fragment,
		Add:           u.Hostname(),
		Port:          u.Port(),
		ID:            u.User.String(),
		Net:           u.Query().Get("type"),
		Type:          u.Query().Get("headerType"),
		Host:          u.Query().Get("host"),
		SNI:           u.Query().Get("sni"),
		Path:          u.Query().Get("path"),
		TLS:           u.Query().Get("security"),
		Flow:          u.Query().Get("flow"),
		Encryption:    u.Query().Get("encryption"),
		Alpn:          u.Query().Get("alpn"),
		AllowInsecure: false,
		Fingerprint:   u.Query().Get("fp"),
		PublicKey:     u.Query().Get("pbk"),
		ShortId:       u.Query().Get("sid"),
		SpiderX:       u.Query().Get("spx"),
		V:             "2",
		Protocol:      "vless",
	}
	if data.Net == "" {
		data.Net = "tcp"
	}
	if data.Net == "grpc" {
		data.Path = u.Query().Get("serviceName")
	}
	if data.Net == "meek" {
		data.Path = u.Query().Get("url")
	}
	if data.Type == "" {
		data.Type = "none"
	}
	if data.TLS == "" {
		data.TLS = "none"
	}
	return data, nil
}

func ParseVmessURL(link string) (*V2Ray, error) {
	payload, ok := strings.CutPrefix(link, "vmess://")
	if !ok {
		return nil, dialer.InvalidParameterErr
	}
	encoded, query, _ := strings.Cut(payload, "?")
	raw, err := proxylink.DecodeBase64(encoded)
	if err != nil {
		raw, err = proxylink.DecodeBase64URL(encoded)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: VMess payload encoding", dialer.InvalidParameterErr)
	}
	var info V2Ray
	if strings.HasPrefix(strings.TrimSpace(raw), "{") {
		if err := json.Unmarshal([]byte(raw), &info, jsonv1.DefaultOptionsV1(), json.WithUnmarshalers(vmessUnmarshalers)); err != nil {
			return nil, err
		}
	} else {
		// Compact form: BASE64(cipher:UUID@server:port)?obfs=... .
		credentials, server, ok := strings.Cut(raw, "@")
		if !ok {
			return nil, fmt.Errorf("%w: VMess credentials/address", dialer.InvalidParameterErr)
		}
		info.Cipher, info.ID, ok = strings.Cut(credentials, ":")
		if !ok {
			return nil, fmt.Errorf("%w: VMess cipher/UUID", dialer.InvalidParameterErr)
		}
		info.Add, info.Port, err = net.SplitHostPort(server)
		if err != nil {
			return nil, fmt.Errorf("%w: VMess server address", dialer.InvalidParameterErr)
		}
		q, err := url.ParseQuery(query)
		if err != nil {
			return nil, err
		}
		if q.Has("remark") || q.Has("aid") {
			return nil, fmt.Errorf("%w: compact VMess uses remarks and alterId", dialer.UnexpectedFieldErr)
		}
		info.Ps = q.Get("remarks")
		info.Net = q.Get("obfs")
		info.Host = vmessObfsHost(q.Get("obfsParam"))
		info.Path = q.Get("path")
		info.Aid = q.Get("alterId")
		info.SNI = q.Get("peer")
		switch q.Get("tls") {
		case "", "0":
		case "1":
			info.TLS = "tls"
		default:
			return nil, fmt.Errorf("%w: VMess TLS option", dialer.UnexpectedFieldErr)
		}
	}
	if info.Aid == "" {
		info.Aid = "0"
	}
	if info.Net == "" {
		info.Net = "tcp"
	}
	info.Protocol = "vmess"
	return &info, nil
}

func (s *V2Ray) ExportToURL() string {
	switch s.Protocol {
	case "vless":
		// https://github.com/reality/Xray-core/issues/91
		var query = make(url.Values)
		common.SetValue(&query, "type", s.Net)
		common.SetValue(&query, "security", s.TLS)
		common.SetValue(&query, "encryption", s.Encryption)
		switch s.Net {
		case "ws", "http", "h2", "httpupgrade":
			common.SetValue(&query, "path", s.Path)
			common.SetValue(&query, "host", s.Host)
		case "tcp":
			common.SetValue(&query, "headerType", s.Type)
			common.SetValue(&query, "host", s.Host)
			common.SetValue(&query, "path", s.Path)
		case "grpc":
			common.SetValue(&query, "serviceName", s.Path)
		case "meek":
			common.SetValue(&query, "url", s.Host)
		}

		if s.TLS != "none" {
			common.SetValue(&query, "sni", s.SNI)
			common.SetValue(&query, "alpn", s.Alpn)
			common.SetValue(&query, "flow", s.Flow)
			common.SetValue(&query, "fp", s.Fingerprint)
		}

		U := url.URL{
			Scheme:   "vless",
			User:     url.User(s.ID),
			Host:     net.JoinHostPort(s.Add, s.Port),
			RawQuery: query.Encode(),
			Fragment: s.Ps,
		}
		return U.String()
	case "vmess":
		s.V = "2"
		b, _ := json.Marshal(s, jsonv1.DefaultOptionsV1())
		return "vmess://" + strings.TrimSuffix(base64.StdEncoding.EncodeToString(b), "=")
	}
	return ""
}
