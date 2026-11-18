// SPDX-License-Identifier: AGPL-3.0-only
package daemon

import (
	"fmt"
	"net/http"
	"net/netip"
	"os"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/network"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/internal/apiserver"
	"github.com/daeuniverse/dae/internal/webui"
)

func prepareAPIServer(current *apiserver.Server, api config.API, interfaces []string, manager *network.InterfaceManager, hold bool) (*apiserver.Server, *apiserver.InterfaceUpdate, error) {
	address, _, lan, err := api.Endpoint()
	if err != nil {
		return nil, nil, err
	}
	if address == "" {
		return nil, nil, nil
	}
	binding := "tcp " + address
	if lan {
		binding = apiserver.InterfaceBinding(address, interfaces)
	}
	if current != nil && current.Binding() == binding {
		return current, nil, nil
	}
	var server *apiserver.Server
	var update *apiserver.InterfaceUpdate
	if lan {
		server, update, err = apiserver.PrepareInterfaces(current, address, interfaces, manager)
	} else {
		listen := apiserver.Listen
		if hold {
			listen = apiserver.ListenHeld
		}
		server, err = listen("tcp", address)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("api.listen: %w", err)
	}
	return server, update, nil
}

func daemonAPIHandler(api *apiserver.Handler, enabled bool, testTargets ...netip.AddrPort) http.Handler {
	if !enabled {
		return api.WithWeb(http.NotFoundHandler())
	}
	return api.WithWeb(webui.Handler(os.Getenv("DAE_WEB_ROOT"), testTargets...))
}

func (a *application) apiHandler() *apiserver.Handler {
	c, policy := a.plane, a.conf.API
	options := apiserver.Options{
		Status:    func() *api.StatusSnapshot { return c.StatusSnapshot(a.options.Version) },
		Selectors: c, Probes: c, Devices: c, DeviceStatus: c.DeviceStatus,
		ResolveClient: c.ResolveAPIClient, Diagnostics: c, Operations: a.operations,
		UserKey: policy.UserKey, AdminKey: policy.AdminKey,
		AllowLANAnonymous: policy.AllowLANAnonymous, WebOrigins: policy.WebOrigins,
		Certificates: a.certificates.Public(), Metrics: a.metrics, Pprof: policy.Pprof,
	}
	if host := c.MITMHost(); host != nil {
		options.Scripts = host
		options.ScriptStorage = host
	}
	if tests := c.MITMTests(); tests != nil {
		options.MITMTests = tests
		if options.Certificates != nil {
			options.Certificates.Identity.MITMTestGeneration = tests.Generation()
			options.Certificates.Identity.MITMTestOrigins = tests.Origins()
		}
	}
	return apiserver.NewHandler(options)
}
