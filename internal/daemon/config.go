// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/config"
)

// ValidateConfig shares startup's plugin and MITM target checks without preparing
// resources, generating certificates, or changing the host network.
func ValidateConfig(ctx context.Context, conf *config.Config, definitions map[string]plugin.Definition) error {
	plugins, err := configurePlugins(conf, definitions)
	if err != nil {
		return err
	}
	return plugins.Preflight(ctx)
}

// LoadReloadConfig uses the accepted configuration for suspend, even if the
// file on disk is invalid.
func LoadReloadConfig(path string, current *config.Config, suspend bool) (*config.Config, []string, error) {
	if !suspend {
		return config.Load(path)
	}
	next := new(*current)
	next.Global.WanInterface, next.Global.LanInterface = nil, nil
	next.Global.LogLevel = "warning"
	return next, nil, nil
}
