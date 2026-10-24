// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"

	"github.com/daeuniverse/dae/common"
	localca "github.com/daeuniverse/dae/component/ca"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/mitm/verify"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/pluginhost"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	log "github.com/sirupsen/logrus"
)

func configuredPluginSpecs(conf *config.Config) []plugin.Spec {
	specs := make([]plugin.Spec, 0, len(conf.Plugins))
	for _, p := range conf.Plugins {
		if p.Enabled {
			specs = append(specs, plugin.Spec{ID: p.Name, Type: p.Type, Config: p.Config})
		}
	}
	return specs
}

func logStartupMITMStatus(instances []plugin.InstanceStatus) {
	for _, instance := range instances {
		log.WithFields(log.Fields{"plugin_instance": instance.ID, "type": instance.Type,
			"state": instance.State, "scopes": instance.Scopes, "destination_rules": instance.DestinationRules,
		}).Debug("Plugin prepared")
	}
}

func configurePlugins(conf *config.Config, definitions map[string]plugin.Definition) (*pluginhost.Configuration, error) {
	for _, spec := range conf.Plugins {
		if spec.Name == mitmverify.InstanceID {
			return nil, fmt.Errorf("plugin ID %q is reserved for MITM verification", spec.Name)
		}
	}
	if conf.MITM.Enabled && conf.API.Port() != 0 {
		if _, err := mitmverify.ParseTargets(conf.API.MITMTestIPv4, conf.API.MITMTestIPv6); err != nil {
			return nil, err
		}
	}
	return pluginhost.Configure(definitions, configuredPluginSpecs(conf))
}

func loadMITM(ctx context.Context, conf *config.Config, authority *localca.Authority, client *http.Client, background *http.Client, plugins *pluginhost.Configuration, previous *mitm.Host, geoDirs []string, runtime *control.Runtime) (control.PreparedMITM, error) {
	m := conf.MITM
	if len(conf.Plugins) == 0 && !(m.Enabled && conf.API.Port() != 0) {
		return control.PreparedMITM{}, nil
	}
	base := common.CacheDirectory()
	if !m.Enabled {
		authority = nil
	}
	var err error

	options := mitm.Options{DisableHTTP: !m.Enabled, BufferMemoryLimit: m.BufferMemoryLimit, Authority: authority, HTTPClient: background, Logger: log.NewEntry(log.StandardLogger()), Metrics: &pluginMetrics}
	var diagnosticPlan plugin.Plan
	var targets [2]netip.Addr
	var addresses []net.Addr
	if authority != nil && conf.API.Port() != 0 {
		targets, err = mitmverify.ParseTargets(conf.API.MITMTestIPv4, conf.API.MITMTestIPv6)
		if err != nil {
			return control.PreparedMITM{}, err
		}
		addresses, err = net.InterfaceAddrs()
		if err != nil {
			return control.PreparedMITM{}, err
		}
		diagnosticPlan, err = mitmverify.PreparePlan(targets, addresses)
		if err != nil {
			return control.PreparedMITM{}, err
		}
	}

	services := plugin.Services{BaseDir: base, PrepareClient: client, Logger: log.NewEntry(log.StandardLogger())}
	if runtime != nil {
		services.Devices = runtime
		services.SharedStates = runtime.SharedStates()
		services.Interfaces, err = runtime.Interfaces()
		if err != nil {
			return control.PreparedMITM{}, err
		}
	}
	if conf.Global.ResourceCache {
		services.ResourceCacheDir = filepath.Join(base, "resources")
	}
	resources, err := plugins.LoadResources(ctx, services)
	if err != nil {
		return control.PreparedMITM{}, err
	}
	plan, err := mitm.PreparePlan(options, diagnosticPlan, resources.Plan())
	if err != nil {
		return control.PreparedMITM{}, err
	}
	prepared, err := control.PrepareMITMPlan(ctx, plan, geoDirs)
	if err != nil {
		return control.PreparedMITM{}, err
	}
	// The preparation client is joined before final routing is installed. Live
	// factories receive no download transport or expired resource-load context.
	services.PrepareClient = nil
	prepared.BuildHost = func(liveCtx context.Context) (*mitm.Host, error) {
		options := options
		if len(diagnosticPlan.Scopes) != 0 {
			diagnostic, err := mitmverify.New(authority.Fingerprint(), targets, addresses)
			if err != nil {
				return nil, err
			}
			for _, instance := range previous.Instances() {
				if service, ok := instance.Plugin.(*mitmverify.Service); ok && service.SameConfiguration(diagnostic) {
					options.Diagnostic = instance
					break
				}
			}
			if options.Diagnostic == nil {
				options.Diagnostic = pluginhost.Adopt(mitmverify.InstanceID, "mitm-test", diagnostic)
				defer options.Diagnostic.Release()
			}
		}
		return mitm.Build(liveCtx, resources, options, services, previous)
	}
	return prepared, nil
}
