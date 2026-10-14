package shadowsocks

import "github.com/daeuniverse/outbound/dialer"

func (s *Shadowsocks) ConnectionIdentity() string {
	config := *s
	config.Name = ""
	return dialer.ConfigIdentity("shadowsocks", config)
}
