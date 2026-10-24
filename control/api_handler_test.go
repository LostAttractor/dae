// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	contract "github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/internal/apiserver"
)

// apiHandler supplies the HTTP fixture for control-plane behavior tests.
func (c *ControlPlane) apiHandler(version string, resolve apiserver.ClientResolver, operations apiserver.OperationStore, certificates *apiserver.Certificates) *apiserver.Handler {
	return c.apiHandlerWithPolicy(config.API{AdminKey: "test-secret", AllowLANAnonymous: true}, version, resolve, operations, certificates)
}
func (c *ControlPlane) apiHandlerWithPolicy(policy config.API, version string, resolve apiserver.ClientResolver, operations apiserver.OperationStore, certificates *apiserver.Certificates) *apiserver.Handler {
	if resolve == nil {
		resolve = c.ResolveAPIClient
	}
	options := apiserver.Options{Selectors: c, Probes: c, Devices: c, ResolveClient: resolve, UserKey: policy.UserKey, AdminKey: policy.AdminKey, AllowLANAnonymous: policy.AllowLANAnonymous, WebOrigins: policy.WebOrigins, Operations: operations, Diagnostics: c}
	options.Status = func() *contract.StatusSnapshot { return c.StatusSnapshot(version) }
	options.DeviceStatus = c.DeviceStatus
	if host := c.MITMHost(); host != nil {
		options.Scripts = host
	}
	options.Certificates = certificates
	if tests := c.MITMTests(); tests != nil {
		options.MITMTests = tests
		if certificates != nil {
			copy := *certificates
			copy.Identity.MITMTestGeneration = tests.Generation()
			copy.Identity.MITMTestOrigins = tests.Origins()
			options.Certificates = &copy
		}
	}
	return apiserver.NewHandler(options)
}
