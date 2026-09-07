// SPDX-License-Identifier: AGPL-3.0-only
package control

import (
	"net/http"
	"net/netip"

	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/component/api"
)

func (c *ControlPlane) APIHandler() http.Handler {
	return c.apiHandler(func(ip netip.Addr) ([6]byte, error) {
		return netutils.ResolveClientMAC(ip, c.lanInterface)
	})
}

func (c *ControlPlane) apiHandler(resolve func(netip.Addr) ([6]byte, error)) http.Handler {
	options := api.Options{Selectors: c, Devices: c, ResolveClient: resolve, Token: c.apiToken}
	if authority := c.mitmAuthority(); authority != nil {
		options.Certificates = &api.Certificates{Fingerprint: authority.Fingerprint(), Handler: authority.Handler()}
	}
	return api.NewHandler(options)
}
