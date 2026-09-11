// Code generated from plugins.cfg; DO NOT EDIT.
//go:build linux

package cmd

import (
	plugin2 "github.com/daeuniverse/dae/component/mitm/surge"
	"github.com/daeuniverse/dae/component/plugin"
)

func compiledPlugins() map[string]plugin.Definition {
	return map[string]plugin.Definition{
		"surge": plugin2.Plugin,
	}
}
