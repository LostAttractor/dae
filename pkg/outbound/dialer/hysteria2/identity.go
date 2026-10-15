package hysteria2

import "github.com/daeuniverse/dae/pkg/outbound/dialer"

func (s *Hysteria2) ConnectionIdentity() string {
	config := *s
	config.Name = ""
	return dialer.ConfigIdentity("hysteria2", config)
}
