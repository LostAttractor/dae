// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/mitm/ca"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/config"
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

func configurePlugins(conf *config.Config, definitions map[string]plugin.Definition) (*mitm.Configuration, error) {
	return mitm.Configure(definitions, configuredPluginSpecs(conf))
}

func loadMITM(ctx context.Context, conf *config.Config, client *http.Client, background *http.Client, plugins *mitm.Configuration) (host *mitm.Host, err error) {
	m := conf.MITM
	if len(conf.Plugins) == 0 {
		return nil, nil
	}
	base := cacheDirectory()
	resolve := func(path string) string {
		if path == "" || filepath.IsAbs(path) {
			return path
		}
		return filepath.Join(base, path)
	}
	var authority *mitmca.Authority
	if m.Enabled && m.CACert != "" {
		authority, err = mitmca.Load(resolve(m.CACert), resolve(m.CAKey))
		if err != nil {
			return nil, fmt.Errorf("mitm CA: %w", err)
		}
	}
	if authority != nil {
		log.WithField("fingerprint", authority.Fingerprint()).Info("Loaded MITM CA")
	}

	options := mitm.Options{DisableHTTP: !m.Enabled, BufferMemoryLimit: m.BufferMemoryLimit, Authority: authority, HTTPClient: background, Logger: log.NewEntry(log.StandardLogger())}

	services := plugin.Services{BaseDir: base, PrepareClient: client, Logger: log.NewEntry(log.StandardLogger())}
	return plugins.Load(ctx, options, services)
}
