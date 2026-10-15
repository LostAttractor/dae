package smux

import "github.com/daeuniverse/dae/pkg/outbound/dialer"

func (s *SmuxConfig) ConnectionIdentity() string {
	return dialer.ConfigIdentity("smux", s)
}
