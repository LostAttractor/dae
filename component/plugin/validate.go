// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"errors"
	"fmt"
)

// ValidateSpecs preflights active instances. Check the complete type list first
// so an unavailable type never starts validation or setup of preceding plugins.
// A missing optional validator leaves plugin-specific checks to Setup.
func ValidateSpecs(definitions map[string]Definition, specs []Spec) error {
	var errs []error
	for _, spec := range specs {
		if definitions[spec.Type].Setup == nil {
			errs = append(errs, fmt.Errorf("plugins.%s: plugin type %q is not compiled into this binary", spec.ID, spec.Type))
		}
	}
	if len(errs) != 0 {
		return errors.Join(errs...)
	}
	for _, spec := range specs {
		if validate := definitions[spec.Type].Validate; validate != nil {
			if err := validate(spec); err != nil {
				errs = append(errs, fmt.Errorf("plugins.%s: %w", spec.ID, err))
			}
		}
	}
	return errors.Join(errs...)
}
