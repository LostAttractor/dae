// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/daeuniverse/dae/pkg/config_parser"
)

// ModuleSource names a module source without changing its download identity.
// Name is optional and only overrides the module's display name.
type ModuleSource struct {
	Name string `mapstructure:"_"`
	Link string `mapstructure:"link"`
	// Arguments override module defaults using raw string values, including empty values.
	Arguments map[string]string `mapstructure:"arguments"`
}

// Surge configures modules for HTTP processing, routing and IP rewrites. Sizes are bytes.
type Surge struct {
	Modules              []ModuleSource `mapstructure:"module"`
	Store                string         `mapstructure:"store"`
	ScriptTimeout        time.Duration  `mapstructure:"script_timeout" default:"5s"`
	MemoryLimit          int64          `mapstructure:"memory_limit" default:"134217728"`
	MaxBodySize          int64          `mapstructure:"max_body_size" default:"33554432"`
	MaxConcurrentScripts int            `mapstructure:"max_concurrent_scripts" default:"16"`
}

func parseModuleSources(modules *[]ModuleSource, section *config_parser.Section) error {
	names := make(map[string]struct{}, len(*modules))
	for _, module := range *modules {
		if module.Name != "" {
			names[module.Name] = struct{}{}
		}
	}
	for _, item := range section.Items {
		var source ModuleSource
		switch value := item.Value.(type) {
		case *config_parser.Param:
			if value.AndFunctions != nil || len(value.Annotation) != 0 {
				return fmt.Errorf("module %q must be a literal source without annotations", value.Key)
			}
			source = ModuleSource{Name: value.Key, Link: value.Val}
		case *config_parser.Section:
			var err error
			source, err = parseExpandedModuleSource(value)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("module section requires literal sources or named sections, got %s", item.TypeName())
		}
		if strings.TrimSpace(source.Link) == "" {
			return fmt.Errorf("module %q requires a non-empty source", source.Name)
		}
		if source.Name != "" {
			if _, exists := names[source.Name]; exists {
				return fmt.Errorf("duplicate module name %q", source.Name)
			}
			names[source.Name] = struct{}{}
		}
		*modules = append(*modules, source)
	}
	return nil
}

func parseExpandedModuleSource(section *config_parser.Section) (ModuleSource, error) {
	source := ModuleSource{Name: section.Name}
	var linkSet, argumentsSet bool
	for _, item := range section.Items {
		switch value := item.Value.(type) {
		case *config_parser.Param:
			if value.Key != "link" || value.AndFunctions != nil || len(value.Annotation) != 0 {
				return ModuleSource{}, fmt.Errorf("module %q: expected a literal link without annotations", section.Name)
			}
			if linkSet {
				return ModuleSource{}, fmt.Errorf("module %q: duplicate link", section.Name)
			}
			source.Link = value.Val
			linkSet = true
		case *config_parser.Section:
			if value.Name != "arguments" {
				return ModuleSource{}, fmt.Errorf("module %q: unknown section %q", section.Name, value.Name)
			}
			if argumentsSet {
				return ModuleSource{}, fmt.Errorf("module %q: duplicate arguments section", section.Name)
			}
			arguments, err := parseModuleArguments(value)
			if err != nil {
				return ModuleSource{}, fmt.Errorf("module %q: %w", section.Name, err)
			}
			source.Arguments = arguments
			argumentsSet = true
		default:
			return ModuleSource{}, fmt.Errorf("module %q: expected link or arguments section, got %s", section.Name, item.TypeName())
		}
	}
	if !linkSet {
		return ModuleSource{}, fmt.Errorf("module %q: missing link", section.Name)
	}
	return source, nil
}

func parseModuleArguments(section *config_parser.Section) (map[string]string, error) {
	var arguments map[string]string
	for _, item := range section.Items {
		param, ok := item.Value.(*config_parser.Param)
		if !ok || param.Key != "" || param.AndFunctions != nil || len(param.Annotation) != 0 {
			return nil, fmt.Errorf("arguments require literal 'name=value' entries without annotations")
		}
		name, value, found := strings.Cut(param.Val, "=")
		name = strings.TrimSpace(name)
		if !found || name == "" {
			return nil, fmt.Errorf("arguments require literal 'name=value' entries with a non-empty name")
		}
		if _, exists := arguments[name]; exists {
			return nil, fmt.Errorf("duplicate argument %q", name)
		}
		if arguments == nil {
			arguments = make(map[string]string, len(section.Items))
		}
		arguments[name] = value
	}
	return arguments, nil
}

func (s Surge) Validate() error {
	if len(s.Modules) == 0 {
		return fmt.Errorf("surge: at least one module is required when enabled")
	}
	if s.ScriptTimeout <= 0 || s.ScriptTimeout > time.Minute {
		return fmt.Errorf("surge: script_timeout must be between 0 and 1 minute")
	}
	if s.MemoryLimit < 16<<20 || s.MemoryLimit > 1<<30 {
		return fmt.Errorf("surge: memory_limit must be between 16 MiB and 1 GiB")
	}
	if s.MaxBodySize <= 0 || s.MaxBodySize > 256<<20 {
		return fmt.Errorf("surge: max_body_size must be between 0 and 256 MiB")
	}
	if s.MaxConcurrentScripts < 1 || s.MaxConcurrentScripts > 256 {
		return fmt.Errorf("surge: max_concurrent_scripts must be between 1 and 256")
	}
	return nil
}
