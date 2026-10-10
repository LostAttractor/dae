// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"path/filepath"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/mitm/ca"
	"github.com/daeuniverse/dae/component/mitm/certtest"
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
	for _, spec := range configuredPluginSpecs(conf) {
		if spec.ID == certtest.InstanceID {
			return nil, fmt.Errorf("plugin ID %q is reserved for certificate diagnostics", spec.ID)
		}
	}
	if conf.MITM.Enabled && conf.MITM.CACert != "" {
		if _, err := certtest.ParseTargets(conf.Global.APIMITMTestIPv4, conf.Global.APIMITMTestIPv6); err != nil {
			return nil, err
		}
	}
	return pluginhost.Configure(definitions, configuredPluginSpecs(conf))
}

func loadMITM(ctx context.Context, conf *config.Config, client *http.Client, background *http.Client, plugins *pluginhost.Configuration, previous *mitm.Host, geoDirs []string) (control.PreparedMITM, error) {
	m := conf.MITM
	if len(conf.Plugins) == 0 && !(m.Enabled && m.CACert != "" && conf.Global.APIPort != 0) {
		return control.PreparedMITM{}, nil
	}
	base := common.CacheDirectory()
	resolve := func(path string) string {
		if path == "" || filepath.IsAbs(path) {
			return path
		}
		return filepath.Join(base, path)
	}
	var authority *mitmca.Authority
	var err error
	if m.Enabled && m.CACert != "" {
		authority, err = mitmca.Load(resolve(m.CACert), resolve(m.CAKey))
		if err != nil {
			return control.PreparedMITM{}, fmt.Errorf("mitm CA: %w", err)
		}
	}
	if authority != nil {
		log.WithField("fingerprint", authority.Fingerprint()).Info("Loaded MITM CA")
	}

	options := mitm.Options{DisableHTTP: !m.Enabled, BufferMemoryLimit: m.BufferMemoryLimit, Authority: authority, HTTPClient: background, Logger: log.NewEntry(log.StandardLogger()), Metrics: &pluginMetrics}
	if authority != nil && conf.Global.APIPort != 0 {
		targets, err := certtest.ParseTargets(conf.Global.APIMITMTestIPv4, conf.Global.APIMITMTestIPv6)
		if err != nil {
			return control.PreparedMITM{}, err
		}
		addresses, err := net.InterfaceAddrs()
		if err != nil {
			return control.PreparedMITM{}, err
		}
		options.Diagnostic, err = certtest.New(authority, conf.Global.APIPort, targets, addresses)
		if err != nil {
			return control.PreparedMITM{}, err
		}
	}

	services := plugin.Services{BaseDir: base, PrepareClient: client, Logger: log.NewEntry(log.StandardLogger())}
	if conf.Global.ResourceCache {
		services.ResourceCacheDir = filepath.Join(base, "resources")
	}
	host, err := mitm.Load(ctx, plugins, options, services, previous)
	if err != nil {
		return control.PreparedMITM{}, err
	}
	return control.PrepareMITM(ctx, host, geoDirs)
}
