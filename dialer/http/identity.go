package http

import "github.com/daeuniverse/outbound/dialer"

func (s *HTTP) ConnectionIdentity() string {
	config := *s
	config.Name = ""
	return dialer.ConfigIdentity("http", config)
}
