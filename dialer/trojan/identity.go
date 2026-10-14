package trojan

import "github.com/daeuniverse/outbound/dialer"

func (s *Trojan) ConnectionIdentity() string {
	config := *s
	config.Name = ""
	return dialer.ConfigIdentity("trojan", config)
}
