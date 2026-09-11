// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"fmt"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

// DecodeSettings decodes unique scalar settings into the supplied pointers.
// Defaults and validation belong to the caller. Errors never include values,
// since plugin configuration may contain credentials.
func DecodeSettings(section *config_parser.Section, fields map[string]any) error {
	if section == nil {
		return fmt.Errorf("plugin configuration is required")
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
		if !common.FuzzyDecode(field, p.Val) {
			return fmt.Errorf("invalid value for setting %q", p.Key)
		}
	}
	return nil
}
