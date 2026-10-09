// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import "github.com/daeuniverse/dae/config"

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
