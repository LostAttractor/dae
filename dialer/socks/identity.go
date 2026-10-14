package socks

import "github.com/daeuniverse/outbound/dialer"

func (s *Socks) ConnectionIdentity() string {
	config := *s
	config.Name = ""
	return dialer.ConfigIdentity("socks", config)
}
