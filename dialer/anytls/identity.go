package anytls

import "github.com/daeuniverse/outbound/dialer"

func (s *Anytls) ConnectionIdentity() string {
	// The original link is private; all parsed connection options are exported.
	return dialer.ConfigIdentity("anytls", s)
}
