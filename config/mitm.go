// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"fmt"
	"reflect"
	"regexp"
	"strconv"

	"github.com/daeuniverse/dae/common/clientmatch"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

// MITM owns transport settings and ordered, independently configured plugins.
type MITM struct {
	Enabled             bool         `mapstructure:"enabled" default:"false"`
	ClientSourceAddress []string     `mapstructure:"client_source_address"`
	CACert              string       `mapstructure:"ca_cert"`
	CAKey               string       `mapstructure:"ca_key"`
	Plugins             []PluginSpec `mapstructure:"_"`
}

type PluginSpec struct {
	Name    string                 `mapstructure:"_"`
	Type    string                 `mapstructure:"type"`
	Enabled bool                   `mapstructure:"enabled" default:"true"`
	Config  *config_parser.Section `mapstructure:"_" outline:"-"`
}

var mitmHostKeys = map[string]bool{
	"enabled": true, "client_source_address": true, "ca_cert": true, "ca_key": true,
}

var pluginIdentifier = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_-]*$`)

func parseMITM(to *MITM, section *config_parser.Section) error {
	*to = MITM{}
	host := &config_parser.Section{Name: section.Name}
	names := make(map[string]bool)
	for _, item := range section.Items {
		switch value := item.Value.(type) {
		case *config_parser.Param:
			if !mitmHostKeys[value.Key] {
				return fmt.Errorf("unknown mitm setting %q", value.Key)
			}
			host.Items = append(host.Items, item)
		case *config_parser.Section:
			if !pluginIdentifier.MatchString(value.Name) {
				return fmt.Errorf("invalid mitm instance name %q", value.Name)
			}
			if mitmHostKeys[value.Name] || value.Name == "type" {
				return fmt.Errorf("reserved plugin instance name %q", value.Name)
			}
			if names[value.Name] {
				return fmt.Errorf("duplicate mitm plugin instance %q", value.Name)
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
					return fmt.Errorf("mitm.%s: invalid or duplicate %s", p.Name, param.Key)
				}
				seen[param.Key] = true
				if param.Key == "type" {
					if param.Val == "" {
						return fmt.Errorf("mitm.%s: empty plugin type", p.Name)
					}
					p.Type = param.Val
					if !pluginIdentifier.MatchString(p.Type) {
						return fmt.Errorf("mitm.%s: invalid plugin type", p.Name)
					}
				} else {
					var err error
					p.Enabled, err = strconv.ParseBool(param.Val)
					if err != nil {
						return fmt.Errorf("mitm.%s.enabled: expected boolean", p.Name)
					}
				}
			}
			to.Plugins = append(to.Plugins, p)
		default:
			return fmt.Errorf("mitm: expected a setting or named plugin section")
		}
	}
	if err := ParamParser(reflect.ValueOf(to), host, nil); err != nil {
		return err
	}
	if (to.CACert == "") != (to.CAKey == "") {
		return fmt.Errorf("mitm: ca_cert and ca_key must be configured together")
	}
	if _, err := clientmatch.Parse(to.ClientSourceAddress); err != nil {
		return fmt.Errorf("mitm.client_source_address: %w", err)
	}
	return nil
}

// DecodeSurgePlugin keeps the module format's settings out of the host schema.
func DecodeSurgePlugin(section *config_parser.Section) (Surge, error) {
	var conf Surge
	if err := SectionParser(reflect.ValueOf(&conf), section); err != nil {
		return conf, err
	}
	return conf, conf.Validate()
}

func (m *Marshaller) marshalMITM(conf MITM, depth int) error {
	m.writeLine(depth, "enabled:"+strconv.FormatBool(conf.Enabled))
	for _, value := range conf.ClientSourceAddress {
		m.writeLine(depth, "client_source_address:"+strconv.Quote(value))
	}
	if conf.CACert != "" {
		m.writeLine(depth, "ca_cert:"+strconv.Quote(conf.CACert))
	}
	if conf.CAKey != "" {
		m.writeLine(depth, "ca_key:"+strconv.Quote(conf.CAKey))
	}
	for _, p := range conf.Plugins {
		m.writeLine(depth, p.Name+" {")
		m.writeLine(depth+1, "type:"+strconv.Quote(p.Type))
		m.writeLine(depth+1, "enabled:"+strconv.FormatBool(p.Enabled))
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
