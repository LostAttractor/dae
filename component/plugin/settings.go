// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"fmt"
	"reflect"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

// DecodeSettings applies default tags and settings to a struct pointer.
// Fields declare configuration names with mapstructure tags; "_" skips fields
// parsed by the caller. Validation belongs to the caller. Errors never include
// values, since plugin configuration may contain credentials.
func DecodeSettings(section *config_parser.Section, target any) error {
	if section == nil {
		return fmt.Errorf("plugin configuration is required")
	}
	value := reflect.ValueOf(target)
	if value.Kind() != reflect.Pointer || value.IsNil() || value.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("plugin settings target must be a non-nil struct pointer")
	}
	value = value.Elem()
	fields := make(map[string]any, value.NumField())
	for i := range value.NumField() {
		field := value.Field(i)
		definition := value.Type().Field(i)
		key := definition.Tag.Get("mapstructure")
		if key == "_" {
			continue
		}
		if key == "" || !field.CanSet() {
			return fmt.Errorf("settings field %q requires an exported field and a mapstructure tag", definition.Name)
		}
		if _, exists := fields[key]; exists {
			return fmt.Errorf("duplicate settings field %q", key)
		}
		fields[key] = field.Addr().Interface()
		if initial, ok := definition.Tag.Lookup("default"); ok {
			if !config.FuzzyDecode(fields[key], initial) {
				return fmt.Errorf("invalid default for setting %q", key)
			}
		}
	}
	return DecodeSettingsFields(section, fields)
}

// DecodeSettingsFields decodes unique settings into scalar pointers, nested section
// decoders (func(*config_parser.Section) error), or parameter decoders
// (func(*config_parser.Param) error). String slices also accept list sections.
// A "_" entry may receive routing rules.
// Custom decoders must also omit configuration values from their errors.
// Defaults and validation belong to the caller. Errors never include values,
// since plugin configuration may contain credentials.
func DecodeSettingsFields(section *config_parser.Section, fields map[string]any) error {
	if section == nil {
		return fmt.Errorf("plugin configuration is required")
	}
	seen := make(map[string]bool)
	for _, item := range section.Items {
		var key string
		switch value := item.Value.(type) {
		case *config_parser.Param:
			if value.Key == "" || len(value.Annotation) != 0 {
				return fmt.Errorf("expected settings without annotations")
			}
			key = value.Key
		case *config_parser.Section:
			key = value.Name
		case *config_parser.RoutingRule:
			rules, ok := fields["_"].(*[]*config_parser.RoutingRule)
			if !ok {
				return fmt.Errorf("routing rules are not allowed in this section")
			}
			*rules = append(*rules, value)
			continue
		default:
			return fmt.Errorf("unsupported setting type")
		}
		if seen[key] {
			return fmt.Errorf("duplicate setting %q", key)
		}
		seen[key] = true
		field, ok := fields[key]
		if !ok || key == "_" {
			return fmt.Errorf("unknown setting %q", key)
		}
		switch value := item.Value.(type) {
		case *config_parser.Section:
			if list, ok := field.(*[]string); ok {
				values, err := DecodeStringList(value)
				if err != nil {
					return fmt.Errorf("setting %q: %w", key, err)
				}
				*list = values
				continue
			}
			decode, ok := field.(func(*config_parser.Section) error)
			if !ok {
				return fmt.Errorf("setting %q does not accept a section", key)
			}
			if err := decode(value); err != nil {
				return fmt.Errorf("setting %q: %w", key, err)
			}
		case *config_parser.Param:
			if decode, ok := field.(func(*config_parser.Param) error); ok {
				if err := decode(value); err != nil {
					return fmt.Errorf("setting %q: %w", key, err)
				}
				continue
			}
			if _, section := field.(func(*config_parser.Section) error); section {
				return fmt.Errorf("setting %q requires a section", key)
			}
			if value.AndFunctions != nil || !config.FuzzyDecode(field, value.Val) {
				return fmt.Errorf("invalid value for setting %q", key)
			}
		}
	}
	return nil
}

// DecodeStringList reads a section of optionally keyed strings without exposing
// values in structural errors. Defaults and value validation belong to the caller.
func DecodeStringList(section *config_parser.Section) ([]string, error) {
	var values []string
	for _, item := range section.Items {
		param, ok := item.Value.(*config_parser.Param)
		if !ok || param.AndFunctions != nil || len(param.Annotation) != 0 {
			return nil, fmt.Errorf("expected a list of strings without annotations")
		}
		values = append(values, param.String(true, false))
	}
	return values, nil
}
