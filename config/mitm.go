// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strconv"

	"github.com/daeuniverse/dae/common/clientmatch"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

// MITM owns HTTP interception settings. Plugin instances live in plugins{}.
type MITM struct {
	BufferMemoryLimit   int64    `mapstructure:"buffer_memory_limit" default:"0"`
	Enabled             bool     `mapstructure:"enabled" default:"false"`
	ClientSourceAddress []string `mapstructure:"client_source_address"`
}

type Plugins []PluginSpec

type PluginSpec struct {
	Name    string                 `mapstructure:"_"`
	Type    string                 `mapstructure:"type"`
	Enabled bool                   `mapstructure:"enabled" default:"true"`
	Config  *config_parser.Section `mapstructure:"_"`
}

var pluginIdentifier = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_-]*$`)

func parseMITM(to *MITM, section *config_parser.Section) error {
	*to = MITM{}
	if err := ParamParser(reflect.ValueOf(to), section); err != nil {
		return fmt.Errorf("mitm: %w", err)
	}
	bufferLimitSet := slices.ContainsFunc(section.Items, func(item *config_parser.Item) bool {
		param, ok := item.Value.(*config_parser.Param)
		return ok && param.Key == "buffer_memory_limit"
	})
	if to.BufferMemoryLimit < 0 || bufferLimitSet && to.BufferMemoryLimit == 0 {
		return fmt.Errorf("mitm.buffer_memory_limit: expected a positive byte count")
	}
	if _, err := clientmatch.Parse(to.ClientSourceAddress); err != nil {
		return fmt.Errorf("mitm.client_source_address: %w", err)
	}
	return nil
}

func parsePlugins(to *Plugins, section *config_parser.Section) error {
	*to = nil
	names := make(map[string]bool)
	for _, item := range section.Items {
		var value *config_parser.Section
		switch v := item.Value.(type) {
		case *config_parser.Section:
			value = v
		case *config_parser.Param:
			enabled := *v
			enabled.Key = "enabled"
			value = &config_parser.Section{Name: v.Key, Items: []*config_parser.Item{{Value: &enabled}}}
		default:
			return fmt.Errorf("plugins: expected a named plugin section or boolean")
		}
		if !pluginIdentifier.MatchString(value.Name) {
			return fmt.Errorf("invalid plugin instance name %q", value.Name)
		}
		if names[value.Name] {
			return fmt.Errorf("duplicate plugin instance %q", value.Name)
		}
		names[value.Name] = true
		p := PluginSpec{Name: value.Name, Type: value.Name, Enabled: true, Config: &config_parser.Section{Name: value.Name}}
		seen := make(map[string]bool)
		for _, child := range value.Items {
			param, ok := child.Value.(*config_parser.Param)
			if !ok || param.Key != "type" && param.Key != "enabled" {
				p.Config.Items = append(p.Config.Items, child)
				continue
			}
			if seen[param.Key] || param.AndFunctions != nil || len(param.Annotation) != 0 {
				return fmt.Errorf("plugins.%s: invalid or duplicate %s", p.Name, param.Key)
			}
			seen[param.Key] = true
			if param.Key == "type" {
				if param.Val == "" {
					return fmt.Errorf("plugins.%s: empty plugin type", p.Name)
				}
				p.Type = param.Val
				if !pluginIdentifier.MatchString(p.Type) {
					return fmt.Errorf("plugins.%s: invalid plugin type", p.Name)
				}
			} else {
				var err error
				p.Enabled, err = strconv.ParseBool(param.Val)
				if err != nil {
					return fmt.Errorf("plugins.%s.enabled: expected boolean", p.Name)
				}
			}
		}
		*to = append(*to, p)
	}
	return nil
}

func (m *Marshaller) marshalMITM(conf MITM, depth int) error {
	m.writeLine(depth, "enabled:"+strconv.FormatBool(conf.Enabled))
	if conf.BufferMemoryLimit > 0 {
		m.writeLine(depth, "buffer_memory_limit:"+strconv.FormatInt(conf.BufferMemoryLimit, 10))
	}
	for _, value := range conf.ClientSourceAddress {
		m.writeLine(depth, "client_source_address:"+strconv.Quote(value))
	}
	return nil
}

func (m *Marshaller) marshalPlugins(conf Plugins, depth int) error {
	for _, p := range conf {
		if p.Name == p.Type && (p.Config == nil || len(p.Config.Items) == 0) {
			m.writeLine(depth, p.Name+":"+strconv.FormatBool(p.Enabled))
			continue
		}
		m.writeLine(depth, p.Name+" {")
		if p.Type != p.Name {
			m.writeLine(depth+1, "type:"+strconv.Quote(p.Type))
		}
		if !p.Enabled {
			m.writeLine(depth+1, "enabled:false")
		}
		if p.Config != nil {
			if err := m.marshalRawItems(p.Config.Items, depth+1); err != nil {
				return err
			}
		}
		m.writeLine(depth, "}")
	}
	return nil
}

func (m *Marshaller) marshalRawItems(items []*config_parser.Item, depth int) error {
	for _, item := range items {
		switch value := item.Value.(type) {
		case *config_parser.Param:
			m.writeLine(depth, value.String(true, true))
		case *config_parser.RoutingRule:
			m.writeLine(depth, value.String(false, true, true))
		case *config_parser.Section:
			m.writeLine(depth, value.Name+" {")
			if err := m.marshalRawItems(value.Items, depth+1); err != nil {
				return err
			}
			m.writeLine(depth, "}")
		default:
			return fmt.Errorf("unsupported plugin configuration item %T", value)
		}
	}
	return nil
}
