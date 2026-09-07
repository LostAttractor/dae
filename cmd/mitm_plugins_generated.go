// Code generated from mitm_plugins.cfg; DO NOT EDIT.
//go:build linux

package cmd

import (
	"github.com/daeuniverse/dae/component/mitm/plugin"
	plugin2 "github.com/daeuniverse/dae/component/mitm/surge"
)

func compiledMITMPlugins() map[string]plugin.Definition {
	return map[string]plugin.Definition{
		"surge": plugin2.Plugin,
	}
}
