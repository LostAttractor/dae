package juicity

import "github.com/daeuniverse/outbound/dialer"

func (s *Juicity) ConnectionIdentity() string {
	config := *s
	config.Name = ""
	return dialer.ConfigIdentity("juicity", config)
}
