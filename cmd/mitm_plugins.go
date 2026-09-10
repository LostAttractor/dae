// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"

	"github.com/daeuniverse/dae/component/mitm"
	"github.com/daeuniverse/dae/component/mitm/ca"
	"github.com/daeuniverse/dae/component/mitm/plugin"
	"github.com/daeuniverse/dae/config"
	log "github.com/sirupsen/logrus"
)

func loadMITM(ctx context.Context, conf *config.Config, client *http.Client, background *http.Client, setups map[string]plugin.Setup) (host *mitm.Host, err error) {
	m := conf.MITM
	if !m.Enabled {
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
	if m.CACert != "" {
		authority, err = mitmca.Load(resolve(m.CACert), resolve(m.CAKey))
		if err != nil {
			return nil, fmt.Errorf("mitm CA: %w", err)
		}
	}
	if authority != nil {
		log.WithField("fingerprint", authority.Fingerprint()).Info("Loaded MITM CA")
	}

	options := mitm.Options{BufferMemoryLimit: m.BufferMemoryLimit, Authority: authority, HTTPClient: background, Log: func(message string) { log.Warn(message) }}

	services := plugin.Services{BaseDir: base, PrepareClient: client, Logger: log.NewEntry(log.StandardLogger())}
	var specs []plugin.Spec
	for _, p := range m.Plugins {
		if !p.Enabled {
			continue
		}

		specs = append(specs, plugin.Spec{ID: p.Name, Type: p.Type, Config: p.Config})
	}
	return mitm.Load(ctx, setups, specs, options, services)
}
