// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

// ModuleSource names a module source without changing its download identity.
// Name is optional and only overrides the module's display name.
type ModuleSource struct {
	Name string
	Link string
	// Arguments override module defaults using raw string values, including empty values.
	Arguments                 map[string]string
	IsolateLAN, IsolateLANSet bool
	ScriptIsolation           map[string]bool
}

// Config configures modules for HTTP processing, routing and IP rewrites. Sizes are bytes.
type Config struct {
	Modules              []ModuleSource `mapstructure:"_"`
	Store                bool           `mapstructure:"store"`
	IsolateLAN           bool           `mapstructure:"isolate_lan"`
	NodePath             string         `mapstructure:"node_path"`
	ScriptTimeout        time.Duration  `mapstructure:"script_timeout"`
	MemoryLimit          int64          `mapstructure:"memory_limit"`
	MaxBodySize          int64          `mapstructure:"max_body_size"`
	MaxConcurrentScripts int            `mapstructure:"max_concurrent_scripts"`
	HTTPPolicies         []string       `mapstructure:"http_policies"`
}

const (
	defaultMemoryLimit          = 128 << 20
	defaultMaxBodySize          = 32 << 20
	defaultMaxConcurrentScripts = 16
)

// ParseConfig interprets only the settings owned by a Surge instance.
func ParseConfig(section *config_parser.Section) (Config, error) {
	if section == nil {
		return Config{}, fmt.Errorf("surge configuration is required")
	}
	c := Config{
		Store:                true,
		IsolateLAN:           true,
		NodePath:             "node",
		ScriptTimeout:        DefaultScriptTimeout,
		MemoryLimit:          defaultMemoryLimit,
		MaxBodySize:          defaultMaxBodySize,
		MaxConcurrentScripts: defaultMaxConcurrentScripts,
	}
	settings := &config_parser.Section{Name: section.Name}
	for _, item := range section.Items {
		if p, ok := item.Value.(*config_parser.Param); ok && p.Key == "node_path" && compiledJSRuntime != "nodejs" {
			return c, fmt.Errorf("unknown setting %q", p.Key)
		}
		if child, ok := item.Value.(*config_parser.Section); ok && child.Name == "module" {
			if err := parseModuleSources(&c.Modules, child); err != nil {
				return c, err
			}
		} else if p, ok := item.Value.(*config_parser.Param); ok && p.Key == "module" {
			return c, fmt.Errorf("module requires a section")
		} else {
			settings.Items = append(settings.Items, item)
		}
	}
	err := plugin.DecodeSettings(settings, &c)
	if err != nil {
		return c, err
	}
	for i, name := range c.HTTPPolicies {
		name = strings.TrimSpace(name)
		switch strings.ToUpper(name) {
		case "DIRECT":
			name = "direct"
		case "REJECT":
			name = "block"
		}
		if name == "" {
			return c, fmt.Errorf("surge: http_policies requires non-empty outbound names")
		}
		c.HTTPPolicies[i] = name
	}
	return c, c.Validate()
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
	settings := &config_parser.Section{Name: section.Name}
	var linkSet bool
	for _, item := range section.Items {
		if script, ok := item.Value.(*config_parser.Section); ok && script.Name == "script" {
			var name string
			var isolate bool
			if err := plugin.DecodeSettingsFields(script, map[string]any{"name": &name, "isolate_lan": &isolate}); err != nil {
				return ModuleSource{}, fmt.Errorf("module %q script: %w", section.Name, err)
			}
			if strings.TrimSpace(name) == "" || len(script.Items) != 2 {
				return ModuleSource{}, fmt.Errorf("module %q: script requires name and isolate_lan", section.Name)
			}
			if _, exists := source.ScriptIsolation[name]; exists {
				return ModuleSource{}, fmt.Errorf("module %q: duplicate script override %q", section.Name, name)
			}
			if source.ScriptIsolation == nil {
				source.ScriptIsolation = make(map[string]bool)
			}
			source.ScriptIsolation[name] = isolate
			continue
		}
		if param, ok := item.Value.(*config_parser.Param); ok {
			linkSet = linkSet || param.Key == "link"
			source.IsolateLANSet = source.IsolateLANSet || param.Key == "isolate_lan"
		}
		settings.Items = append(settings.Items, item)
	}
	if err := plugin.DecodeSettingsFields(settings, map[string]any{
		"link":        &source.Link,
		"isolate_lan": &source.IsolateLAN,
		"arguments": func(section *config_parser.Section) error {
			var err error
			source.Arguments, err = parseModuleArguments(section)
			return err
		},
	}); err != nil {
		return ModuleSource{}, fmt.Errorf("module %q: %w", section.Name, err)
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

func (s Config) Validate() error {
	if compiledJSRuntime == "nodejs" && strings.TrimSpace(s.NodePath) == "" {
		return fmt.Errorf("surge: node_path must be non-empty")
	}
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

var moduleIdentifier = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// FormatModuleSource produces a module block for the configure command.
func FormatModuleSource(source ModuleSource) (string, error) {
	if source.Name != "" && !moduleIdentifier.MatchString(source.Name) {
		return "", fmt.Errorf("invalid module name %q", source.Name)
	}
	if strings.TrimSpace(source.Link) == "" {
		return "", fmt.Errorf("module requires a non-empty source")
	}
	var b strings.Builder
	line := func(depth int, value string) { b.WriteString(strings.Repeat("  ", depth) + value + "\n") }
	line(0, "module {")
	if len(source.Arguments) == 0 && !source.IsolateLANSet && len(source.ScriptIsolation) == 0 {
		line(1, (&config_parser.Param{Key: source.Name, Val: source.Link}).String(true, true))
	} else {
		if source.Name == "" {
			return "", fmt.Errorf("module settings require a module name")
		}
		line(1, source.Name+" {")
		line(2, (&config_parser.Param{Key: "link", Val: source.Link}).String(true, true))
		if len(source.Arguments) != 0 {
			line(2, "arguments {")
			names := make([]string, 0, len(source.Arguments))
			for name := range source.Arguments {
				if strings.TrimSpace(name) == "" || strings.Contains(name, "=") {
					return "", fmt.Errorf("argument name must be non-empty and cannot contain '='")
				}
				if name != strings.TrimSpace(name) {
					return "", fmt.Errorf("argument name cannot have leading or trailing whitespace")
				}
				names = append(names, name)
			}
			slices.Sort(names)
			for _, name := range names {
				line(3, (&config_parser.Param{Val: name + "=" + source.Arguments[name]}).String(true, true))
			}
			line(2, "}")
		}
		if source.IsolateLANSet {
			line(2, "isolate_lan: "+strconv.FormatBool(source.IsolateLAN))
		}
		names := make([]string, 0, len(source.ScriptIsolation))
		for name := range source.ScriptIsolation {
			if strings.TrimSpace(name) == "" {
				return "", fmt.Errorf("script name must be non-empty")
			}
			names = append(names, name)
		}
		slices.Sort(names)
		for _, name := range names {
			line(2, "script {")
			line(3, (&config_parser.Param{Key: "name", Val: name}).String(true, true))
			line(3, "isolate_lan: "+strconv.FormatBool(source.ScriptIsolation[name]))
			line(2, "}")
		}
		line(1, "}")
	}
	line(0, "}")
	return b.String(), nil
}
