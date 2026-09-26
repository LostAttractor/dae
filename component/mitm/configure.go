// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"errors"
	"fmt"

	"github.com/daeuniverse/dae/component/plugin"
)

// Configuration contains parsed plugin configurations, without runtime resources.
// Configure once before preparing any daemon resources, then call Load to build
// a host. Factories are evaluated in declaration order; they do not reparse specs.
type Configuration struct{ instances []configuredPlugin }

type configuredPlugin struct {
	id, typ string
	factory plugin.Factory
}

func Configure(definitions map[string]plugin.Definition, specs []plugin.Spec) (*Configuration, error) {
	var errs []error
	for _, spec := range specs {
		if definitions[spec.Type].Configure == nil {
			errs = append(errs, fmt.Errorf("plugins.%s: plugin type %q is not compiled into this binary", spec.ID, spec.Type))
		}
	}
	if len(errs) != 0 {
		return nil, errors.Join(errs...)
	}
	configuration := &Configuration{}
	for _, spec := range specs {
		factory, err := definitions[spec.Type].Configure(spec)
		if err == nil && factory == nil {
			err = errors.New("Configure returned a nil factory")
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("plugins.%s: %w", spec.ID, err))
			continue
		}
		configuration.instances = append(configuration.instances, configuredPlugin{id: spec.ID, typ: spec.Type, factory: factory})
	}
	if len(errs) != 0 {
		return nil, errors.Join(errs...)
	}
	return configuration, nil
}
