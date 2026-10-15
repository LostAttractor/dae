package shadowsocks

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/pkg/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/transport/mux"
	"github.com/daeuniverse/dae/pkg/outbound/transport/simpleobfs"
	"github.com/daeuniverse/dae/pkg/outbound/transport/tls"
	"github.com/daeuniverse/dae/pkg/outbound/transport/ws"
	"github.com/daeuniverse/dae/pkg/proxylink"
)

func init() {
	dialer.FromLinkRegister("shadowsocks", NewShadowsocks)
	dialer.FromLinkRegister("ss", NewShadowsocks)
}

type Shadowsocks struct {
	Name     string `json:"name"`
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Password string `json:"password"`
	Cipher   string `json:"cipher"`
	Plugin   Sip003 `json:"plugin"`
	UDP      bool   `json:"udp"`
}

func NewShadowsocks(link string) (dialer.Builder, *dialer.Property, error) {
	s, err := ParseSSURL(link)
	if err != nil {
		return nil, nil, err
	}
	return s, &dialer.Property{
		Name:     s.Name,
		Address:  net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		Protocol: "shadowsocks",
		Link:     s.ExportToURL(),
	}, nil
}

func (s *Shadowsocks) Build(option *dialer.ExtraOption, upstream dialer.Upstream) (layer netproxy.Layer, err error) {
	layer.Data = upstream
	proxyAddress := net.JoinHostPort(s.Server, strconv.Itoa(s.Port))
	opts := s.Plugin.Opts
	defer func() {
		if err != nil {
			err = errors.Join(err, layer.Close())
			layer = netproxy.Layer{}
		}
	}()

	switch s.Plugin.Name {
	case "simple-obfs":
		obfsType, obfsErr := simpleobfs.NewObfsType(opts.Obfs)
		if obfsErr != nil {
			err = obfsErr
			return
		}
		host := opts.Host
		if host == "" {
			host = "cloudflare.com"
		}
		layer.Data = &simpleobfs.SimpleObfs{
			ParentDialer: layer.Data,
			Addr:         proxyAddress,
			ObfsType:     obfsType,
			Host:         host,
			Path:         opts.Path,
		}
	case "v2ray-plugin":
		// https://github.com/teddysun/v2ray-plugin
		switch opts.Obfs {
		case "":
			if opts.Tls == "tls" {
				tlsConfig := tls.TLSConfig{
					Host:           proxyAddress,
					Sni:            opts.Host,
					PassthroughUdp: true,
				}
				if err = layer.AppendResult(tlsConfig.Build(option, dialer.NewUpstream(layer.Data))); err != nil {
					return
				}
			}
			wsConfig := ws.WsConfig{
				Scheme:         "ws",
				Host:           proxyAddress,
				Path:           "/",
				Hostname:       opts.Host,
				PassthroughUdp: true,
			}
			if err = layer.AppendResult(wsConfig.Build(option, dialer.NewUpstream(layer.Data))); err != nil {
				return
			}
			layer.Data = &mux.Mux{
				ParentDialer:   layer.Data,
				Addr:           proxyAddress,
				PassthroughUdp: true,
			}
		default:
			err = fmt.Errorf("unsupported mode %v of plugin %v", opts.Obfs, s.Plugin.Name)
			return
		}
	}

	var typeName string
	switch s.Cipher {
	case "aes-256-gcm", "aes-128-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305":
		typeName = "shadowsocks"
	case "2022-blake3-aes-256-gcm", "2022-blake3-aes-128-gcm":
		typeName = "shadowsocks_2022"
	case "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "aes-128-ofb", "aes-192-ofb", "aes-256-ofb", "des-cfb", "bf-cfb", "cast5-cfb", "rc4-md5", "rc4-md5-6", "chacha20", "chacha20-ietf", "salsa20", "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb", "idea-cfb", "rc2-cfb", "seed-cfb", "rc4", "none", "plain":
		typeName = "shadowsocks_stream"
	default:
		err = fmt.Errorf("unsupported shadowsocks encryption method: %v", s.Cipher)
		return
	}
	err = layer.AppendResult(protocol.Build(typeName, layer.Data, protocol.Header{
		ProxyAddress: proxyAddress,
		Cipher:       s.Cipher,
		Password:     s.Password,
	}))
	return
}

func ParseSSURL(ssurl string) (data *Shadowsocks, err error) {
	// parse attempts to parse ss:// links
	parse := func(content string) (v *Shadowsocks, ok bool) {
		// semicolon is not allowed in query, otherwise u.Query() will return empty map.
		content = strings.Replace(content, ";", "%3B", -1)
		// try to parse in the format of ss://BASE64(method:password)@server:port/?plugin=xxxx#name
		u, err := url.Parse(content)
		if err != nil {
			return nil, false
		}
		username := u.User.String()
		username, _ = proxylink.DecodeBase64URL(username)
		arr := strings.SplitN(username, ":", 2)
		if len(arr) != 2 {
			return nil, false
		}
		cipher := arr[0]
		password := arr[1]
		var sip003 Sip003
		plugin := u.Query().Get("plugin")
		if len(plugin) > 0 {
			sip003 = ParseSip003(plugin)
		}
		port, err := strconv.Atoi(u.Port())
		if err != nil {
			return nil, false
		}
		ss := Shadowsocks{
			Cipher:   strings.ToLower(cipher),
			Password: password,
			Server:   u.Hostname(),
			Port:     port,
			Name:     u.Fragment,
			Plugin:   sip003,
			UDP:      sip003.Name == "",
		}
		return &ss, true
	}
	var (
		v  *Shadowsocks
		ok bool
	)
	content := ssurl
	// try to parse the ss:// link, if it fails, base64 decode first
	if v, ok = parse(content); !ok {
		// 进行base64解码，并unmarshal到VmessInfo上
		t := content[5:]
		var l, r string
		if ind := strings.Index(t, "#"); ind > -1 {
			l = t[:ind]
			r = t[ind+1:]
		} else {
			l = t
		}
		l, err = proxylink.DecodeBase64(l)
		if err != nil {
			l, err = proxylink.DecodeBase64URL(l)
			if err != nil {
				return
			}
		}
		t = "ss://" + l
		if len(r) > 0 {
			t += "#" + r
		}
		v, ok = parse(t)
	}
	if !ok {
		return nil, fmt.Errorf("%w: unrecognized ss address", dialer.InvalidParameterErr)
	}
	return v, nil
}

type Sip003 struct {
	Name string     `json:"name"`
	Opts Sip003Opts `json:"opts"`
}
type Sip003Opts struct {
	Tls  string `json:"tls"`  // for v2ray-plugin
	Obfs string `json:"obfs"` // mode for v2ray-plugin
	Host string `json:"host"`
	Path string `json:"uri"`
}

func ParseSip003Opts(opts string) Sip003Opts {
	var sip003Opts Sip003Opts
	fields := strings.Split(opts, ";")
	for i := range fields {
		a := strings.Split(fields[i], "=")
		if len(a) == 1 {
			// to avoid panic
			a = append(a, "")
		}
		switch a[0] {
		case "tls":
			sip003Opts.Tls = "tls"
		case "obfs", "mode":
			sip003Opts.Obfs = a[1]
		case "obfs-path", "obfs-uri", "path":
			if !strings.HasPrefix(a[1], "/") {
				a[1] += "/"
			}
			sip003Opts.Path = a[1]
		case "obfs-host", "host":
			sip003Opts.Host = a[1]
		}
	}
	return sip003Opts
}
func ParseSip003(plugin string) Sip003 {
	var sip003 Sip003
	fields := strings.SplitN(plugin, ";", 2)
	switch fields[0] {
	case "obfs-local", "simpleobfs", "obfs":
		sip003.Name = "simple-obfs"
	default:
		sip003.Name = fields[0]
	}
	sip003.Opts = ParseSip003Opts(fields[1])
	return sip003
}

func (s *Sip003) String() string {
	list := []string{s.Name}
	if s.Opts.Obfs != "" {
		list = append(list, "obfs="+s.Opts.Obfs)
	}
	if s.Opts.Host != "" {
		list = append(list, "obfs-host="+s.Opts.Host)
	}
	if s.Opts.Path != "" {
		list = append(list, "obfs-uri="+s.Opts.Path)
	}
	return strings.Join(list, ";")
}

func (s *Shadowsocks) ExportToURL() string {
	// sip002
	u := &url.URL{
		Scheme:   "ss",
		User:     url.User(strings.TrimSuffix(base64.URLEncoding.EncodeToString([]byte(s.Cipher+":"+s.Password)), "=")),
		Host:     net.JoinHostPort(s.Server, strconv.Itoa(s.Port)),
		Fragment: s.Name,
	}
	if s.Plugin.Name != "" {
		q := u.Query()
		q.Set("plugin", s.Plugin.String())
		u.RawQuery = q.Encode()
	}
	return u.String()
}
