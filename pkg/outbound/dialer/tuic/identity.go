package tuic

import "github.com/daeuniverse/dae/pkg/outbound/dialer"

func (s *Tuic) ConnectionIdentity() string {
	config := *s
	config.Name = ""
	return dialer.ConfigIdentity("tuic", config)
}
