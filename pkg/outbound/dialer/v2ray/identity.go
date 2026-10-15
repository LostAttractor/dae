package v2ray

import (
	"github.com/daeuniverse/dae/pkg/outbound/dialer"
	"strings"
)

func (s *V2Ray) ConnectionIdentity() string {
	config := *s
	config.Ps, config.V = "", ""
	config.Net = strings.ToLower(config.Net)
	return dialer.ConfigIdentity("v2ray", config)
}
