package smux

import "github.com/daeuniverse/outbound/dialer"

func (s *SmuxConfig) ConnectionIdentity() string {
	return dialer.ConfigIdentity("smux", s)
}
