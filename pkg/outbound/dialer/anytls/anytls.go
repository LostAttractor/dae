package anytls

import (
	"cmp"
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
		s, name, err := parseAnytlsURL(link)
		if err != nil {
			return nil, nil, err
		}
		return s, &dialer.Property{
			Name:     name,
			Protocol: "anytls",
			Address:  s.Host,
			Link:     s.link,
		}, nil
	default:
		return nil, nil, dialer.InvalidParameterErr
	}
}

// parseAnytlsURL also returns the node name carried in the link's fragment.
func parseAnytlsURL(link string) (*Anytls, string, error) {
	u, err := url.Parse(link)
	if err != nil {
		return nil, "", fmt.Errorf("parse AnyTLS proxy URL: %w", err.(*url.Error).Err)
	}
	q := u.Query()
	antls := &Anytls{
		link:     link,
		Auth:     u.User.Username(),
		Host:     u.Host,
		Sni:      cmp.Or(q.Get("sni"), u.Hostname()),
		Insecure: q.Get("insecure") == "1",
	}
	return antls, u.Fragment, nil
}

func (s *Anytls) Build(option *dialer.ExtraOption, upstream dialer.Upstream) (netproxy.Layer, error) {
	tlsConfig := &tls.Config{
		ServerName:         s.Sni,
		InsecureSkipVerify: s.Insecure || option.AllowInsecure,
	}
	return protocol.Build("anytls", upstream, protocol.Header{
		ProxyAddress: s.Host,
		Password:     s.Auth,
		TlsConfig:    tlsConfig,
	})
}
