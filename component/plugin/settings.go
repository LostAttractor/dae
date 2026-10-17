// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"fmt"
	"reflect"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

// DecodeSettings applies default tags and unique scalar settings to a struct
// pointer. Fields declare configuration names with mapstructure tags; "_" skips
// fields parsed by the caller. Validation belongs to the caller. Errors never
// include values, since plugin configuration may contain credentials.
func DecodeSettings(section *config_parser.Section, target any) error {
	if section == nil {
		return fmt.Errorf("plugin configuration is required")
	}
	value := reflect.ValueOf(target)
	if value.Kind() != reflect.Pointer || value.IsNil() || value.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("plugin settings target must be a non-nil struct pointer")
	}
	value = value.Elem()
	fields := make(map[string]reflect.Value, value.NumField())
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
		fields[key] = field
		if initial, ok := definition.Tag.Lookup("default"); ok {
			if !common.FuzzyDecode(field.Addr().Interface(), initial) {
				return fmt.Errorf("invalid default for setting %q", key)
			}
		}
	}
	seen := make(map[string]bool)
	for _, item := range section.Items {
		p, ok := item.Value.(*config_parser.Param)
		if !ok || p.Key == "" || p.AndFunctions != nil || len(p.Annotation) != 0 {
			return fmt.Errorf("expected scalar settings without annotations")
		}
		if seen[p.Key] {
			return fmt.Errorf("duplicate setting %q", p.Key)
		}
		seen[p.Key] = true
		field, ok := fields[p.Key]
		if !ok {
			return fmt.Errorf("unknown setting %q", p.Key)
		}
		if !common.FuzzyDecode(field.Addr().Interface(), p.Val) {
			return fmt.Errorf("invalid value for setting %q", p.Key)
		}
	}
	return nil
}
