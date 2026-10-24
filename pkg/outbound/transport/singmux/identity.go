package singmux

import "github.com/daeuniverse/dae/pkg/outbound/dialer"

func (s *Config) ConnectionIdentity() string {
	return dialer.ConfigIdentity("singmux", s)
}
