// SPDX-License-Identifier: AGPL-3.0-only

package dns

import (
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

type RequestRouting struct {
	Rules    []*config_parser.RoutingRule `mapstructure:"_"`
	Fallback config.FunctionOrString      `mapstructure:"fallback"`
}

type ResponseRouting struct {
	Rules    []*config_parser.RoutingRule `mapstructure:"_"`
	Fallback config.FunctionOrString      `mapstructure:"fallback"`
}

type Routing struct {
	Request  RequestRouting  `mapstructure:"request"`
	Response ResponseRouting `mapstructure:"response"`
}

type Config struct {
	IPVersionPrefer int                    `mapstructure:"ipversion_prefer"`
	Upstream        []config.KeyableString `mapstructure:"upstream"`
	Routing         Routing                `mapstructure:"routing"`
}
