package shadowsocksr

import "github.com/daeuniverse/outbound/dialer"

func (s *ShadowsocksR) ConnectionIdentity() string {
	config := *s
	config.Name = ""
	return dialer.ConfigIdentity("shadowsocksr", config)
}
