package shadowsocks

import "github.com/daeuniverse/dae/pkg/outbound/dialer"

func (s *Shadowsocks) ConnectionIdentity() string {
	config := *s
	config.Name = ""
	return dialer.ConfigIdentity("shadowsocks", config)
}
