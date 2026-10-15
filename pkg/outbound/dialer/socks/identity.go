package socks

import "github.com/daeuniverse/dae/pkg/outbound/dialer"

func (s *Socks) ConnectionIdentity() string {
	config := *s
	config.Name = ""
	return dialer.ConfigIdentity("socks", config)
}
