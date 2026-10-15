package http

import "github.com/daeuniverse/dae/pkg/outbound/dialer"

func (s *HTTP) ConnectionIdentity() string {
	config := *s
	config.Name = ""
	return dialer.ConfigIdentity("http", config)
}
