package shadowsocksr

import "github.com/daeuniverse/dae/pkg/outbound/dialer"

func (s *ShadowsocksR) ConnectionIdentity() string {
	config := *s
	config.Name = ""
	return dialer.ConfigIdentity("shadowsocksr", config)
}
