// SPDX-License-Identifier: AGPL-3.0-only

package pluginhost

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/membuffer"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

type Configuration struct{ instances []configuredPlugin }
type configuredPlugin struct {
	spec      plugin.Spec
	factory   plugin.Factory
	preflight func(context.Context, plugin.Spec) error
	resources func(context.Context, plugin.Spec, plugin.Services) (plugin.Resources, error)
}
type instanceInput struct {
	config     any
	resources  string
	baseDir    string
	bodyMemory *membuffer.Budget
}

// Configure validates every enabled instance before any external I/O.
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
		definition := definitions[spec.Type]
		factory, err := definition.Configure(spec)
		if err == nil && factory == nil {
			err = errors.New("Configure returned a nil factory")
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("plugins.%s: %w", spec.ID, err))
			continue
		}
		configuration.instances = append(configuration.instances, configuredPlugin{spec, factory, definition.Preflight, definition.Resources})
	}
	if len(errs) != 0 {
		return nil, errors.Join(errs...)
	}
	return configuration, nil
}

// Preflight checks local runtime dependencies without preparing plugin resources.
func (c *Configuration) Preflight(ctx context.Context) error {
	for _, configured := range c.instances {
		if err := ctx.Err(); err != nil {
			return err
		}
		if configured.preflight != nil {
			if err := configured.preflight(ctx, configured.spec); err != nil {
				return fmt.Errorf("plugins.%s preflight: %w", configured.spec.ID, err)
			}
		}
	}
	return nil
}

// Prepare refreshes resources and borrows unchanged instances. On success the
// caller owns one reference per result; errors release only candidate references.
func (c *Configuration) Prepare(ctx context.Context, services plugin.Services, previous []*Instance) (instances []*Instance, err error) {
	defer func() {
		if err != nil {
			for _, instance := range instances {
				err = errors.Join(err, instance.Release())
			}
			instances = nil
		}
	}()
	if c == nil {
		return nil, nil
	}
	old := make(map[string]*Instance, len(previous))
	for _, instance := range previous {
		old[instance.ID] = instance
	}
	for _, configured := range c.instances {
		if err = ctx.Err(); err != nil {
			return instances, err
		}
		spec := configured.spec
		local := services
		if local.Logger == nil {
			local.Logger = log.NewEntry(log.StandardLogger())
		}
		local.Logger = local.Logger.WithField("plugin_instance", spec.ID)
		var resources plugin.Resources
		if configured.resources != nil {
			resources, err = configured.resources(ctx, spec, local)
			if err != nil {
				return instances, fmt.Errorf("plugins.%s resources: %w", spec.ID, err)
			}
		}
		configuration := resources.Config
		if configuration == nil {
			configuration = spec.Config
		}
		input := instanceInput{configuration, resources.Key, services.BaseDir, services.BodyMemory}
		if existing := old[spec.ID]; existing != nil && existing.Type == spec.Type && existing.input.bodyMemory == input.bodyMemory && existing.input.baseDir == input.baseDir && existing.input.resources == input.resources && reflect.DeepEqual(existing.input.config, input.config) && existing.Retain() {
			instances = append(instances, existing)
			continue
		}
		local.Prepared = resources.Value
		local.Storage, err = newPluginStorage(local.BaseDir, spec)
		if err != nil {
			return instances, fmt.Errorf("plugins.%s storage: %w", spec.ID, err)
		}
		registry := prometheus.NewRegistry()
		local.Metrics = prometheus.WrapRegistererWithPrefix("dae_plugin_", prometheus.WrapRegistererWith(prometheus.Labels{
			"plugin_type": spec.Type, "plugin_instance": spec.ID,
		}, registry))
		implementation, buildErr := configured.factory(ctx, local)
		if buildErr != nil {
			return instances, fmt.Errorf("plugins.%s: %w", spec.ID, buildErr)
		}
		if implementation == nil {
			return instances, fmt.Errorf("plugins.%s: factory returned a nil plugin", spec.ID)
		}
		instance := Adopt(spec.ID, spec.Type, implementation)
		instance.input, instance.Metrics, instance.logger = input, registry, local.Logger
		instances = append(instances, instance)
	}
	return instances, nil
}
