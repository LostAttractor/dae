package anytls

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"strings"

	"github.com/daeuniverse/dae/pkg/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
)

func init() {
	dialer.FromLinkRegister("anytls", NewAnytls)
}

type Anytls struct {
	link     string
	Auth     string
	Host     string
	Sni      string
	Insecure bool
}

func NewAnytls(link string) (dialer.Builder, *dialer.Property, error) {
	switch {
	case strings.HasPrefix(link, "anytls://"):
		s, err := parseAnytlsURL(link)
		if err != nil {
			return nil, nil, err
		}
		return s, &dialer.Property{
			Name:     "anytls",
			Protocol: "anytls",
			Address:  s.Host,
			Link:     s.link,
		}, nil
	default:
		return nil, nil, dialer.InvalidParameterErr
	}
}

func parseAnytlsURL(link string) (*Anytls, error) {
	u, err := url.ParseRequestURI(link)
	if err != nil {
		return nil, fmt.Errorf("parse AnyTLS proxy URL: %w", err.(*url.Error).Err)
	}
	antls := &Anytls{
		link:     link,
		Auth:     u.User.Username(),
		Host:     u.Host,
		Sni:      u.Query().Get("sni"),
		Insecure: u.Query().Get("insecure") == "1",
	}

	return antls, nil
}

func (s *Anytls) Build(_ *dialer.ExtraOption, upstream dialer.Upstream) (netproxy.Layer, error) {
	tlsConfig := &tls.Config{
		ServerName:         s.Sni,
		InsecureSkipVerify: s.Insecure,
	}
	if tlsConfig.ServerName == "" {
		// disable the SNI
		tlsConfig.ServerName = "127.0.0.1"
	}
	return protocol.Build("anytls", upstream, protocol.Header{
		ProxyAddress: s.Host,
		Password:     s.Auth,
		TlsConfig:    tlsConfig,
	})
}
