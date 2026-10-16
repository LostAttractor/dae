// SPDX-License-Identifier: AGPL-3.0-only

package control

import "github.com/daeuniverse/dae/component/mitm/verify"

// MITMTests belongs to the current immutable host generation. API owners
// drain requests before replacing that host.
func (c *ControlPlane) MITMTests() *mitmverify.Service {
	if host := c.MITMHost(); host != nil {
		for _, instance := range host.Instances() {
			if tests, ok := instance.Plugin.(*mitmverify.Service); ok {
				return tests
			}
		}
	}
	return nil
}
