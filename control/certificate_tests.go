// SPDX-License-Identifier: AGPL-3.0-only

package control

import "github.com/daeuniverse/dae/component/mitm/certtest"

// CertificateTests belongs to the current immutable host generation. API owners
// drain requests before replacing that host, just as for its public CA handler.
func (c *ControlPlane) CertificateTests() *certtest.Service {
	if host := c.MITMHost(); host != nil {
		for _, instance := range host.Instances() {
			if tests, ok := instance.Plugin.(*certtest.Service); ok {
				return tests
			}
		}
	}
	return nil
}
