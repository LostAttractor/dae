// SPDX-License-Identifier: AGPL-3.0-only

package pluginhost

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/daeuniverse/dae/component/network"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/membuffer"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

const maxConcurrentResourceLoads = 4

type Configuration struct{ instances []configuredPlugin }
type configuredPlugin struct {
	spec      plugin.Spec
	factory   plugin.Factory
	preflight func(context.Context, plugin.Spec) error
	resources func(context.Context, plugin.Spec, plugin.Services) (plugin.Resources, error)
}
type instanceInput struct {
	interfaces   *network.InterfaceManager
	config       any
	resources    string
	baseDir      string
	bodyMemory   *membuffer.Budget
	sharedStates plugin.SharedStates
	devices      plugin.DeviceService
}

func sameService(a, b any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return reflect.ValueOf(a).Comparable() && reflect.ValueOf(b).Comparable() && a == b
}

// PreparedInstance owns a reference and candidate-local resource metadata.
// Sharing a runtime does not publish the candidate's latest check prematurely.
type PreparedInstance struct {
	*Instance
	Resources any
}

func (p PreparedInstance) CommitResources() {
	if observer, ok := p.Plugin.(plugin.ResourceObserver); ok {
		observer.AcceptResources(p.Resources)
	}
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

// PreparedResources contains immutable, process-local inputs, not runtime state
// or loading contexts. It can build multiple candidates with their own services.
type PreparedResources struct {
	configuration *Configuration
	resources     []plugin.Resources
}

// Plan returns the complete static declaration without constructing instances.
func (p *PreparedResources) Plan() plugin.Plan {
	if p == nil {
		return plugin.Plan{}
	}
	plans := make([]plugin.Plan, len(p.resources))
	for i, resource := range p.resources {
		plans[i] = *resource.Plan
	}
	return plugin.MergePlans(plans...)
}

func instanceServices(services plugin.Services, spec plugin.Spec) (plugin.Services, error) {
	if services.Logger == nil {
		services.Logger = log.NewEntry(log.StandardLogger())
	}
	services.Logger = services.Logger.WithField("plugin_instance", spec.ID)
	var err error
	services.SharedStates, err = scopeStates(services.SharedStates, services.BaseDir, spec)
	if err != nil {
		return plugin.Services{}, fmt.Errorf("plugins.%s shared states: %w", spec.ID, err)
	}
	return services, nil
}

// LoadResources refreshes and validates all static declarations concurrently.
// No factory runs; failed loads cancel and join all admitted resource work.
func (c *Configuration) LoadResources(ctx context.Context, services plugin.Services) (*PreparedResources, error) {
	if c == nil {
		return &PreparedResources{}, nil
	}
	prepared := &PreparedResources{configuration: c, resources: make([]plugin.Resources, len(c.instances))}
	group, loadCtx := errgroup.WithContext(ctx)
	group.SetLimit(maxConcurrentResourceLoads)
	for i, configured := range c.instances {
		group.Go(func() error {
			if err := loadCtx.Err(); err != nil {
				return err
			}
			if configured.resources == nil {
				return fmt.Errorf("plugins.%s: static Plan declaration is required; plugin must implement Resources", configured.spec.ID)
			}
			local, err := instanceServices(services, configured.spec)
			if err != nil {
				return err
			}
			resource, err := configured.resources(loadCtx, configured.spec, local)
			if err != nil {
				return fmt.Errorf("plugins.%s resources: %w", configured.spec.ID, err)
			}
			if resource.Plan == nil {
				return fmt.Errorf("plugins.%s: Resources returned no static Plan declaration", configured.spec.ID)
			}
			prepared.resources[i] = resource
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	return prepared, nil
}

// Prepare composes resource loading and instance construction for ordinary reload.
func (c *Configuration) Prepare(ctx context.Context, services plugin.Services, previous []*Instance) ([]PreparedInstance, error) {
	prepared, err := c.LoadResources(ctx, services)
	if err != nil {
		return nil, err
	}
	return prepared.BuildInstances(ctx, services, previous)
}

// BuildInstances borrows unchanged instances or builds in declaration order using
// the caller's live context and services, never the resource group's context.
// The caller owns one reference per result; errors release candidate references.
func (p *PreparedResources) BuildInstances(ctx context.Context, services plugin.Services, previous []*Instance) (instances []PreparedInstance, err error) {
	defer func() {
		if err != nil {
			for _, instance := range instances {
				err = errors.Join(err, instance.Release())
			}
			instances = nil
		}
	}()
	if p == nil || p.configuration == nil {
		return nil, nil
	}
	old := make(map[string]*Instance, len(previous))
	for _, instance := range previous {
		old[instance.ID] = instance
	}
	for i, configured := range p.configuration.instances {
		if err = ctx.Err(); err != nil {
			return instances, err
		}
		spec := configured.spec
		resource := p.resources[i]
		local, localErr := instanceServices(services, spec)
		if localErr != nil {
			return instances, localErr
		}
		configuration := resource.Config
		if configuration == nil {
			configuration = spec.Config
		}
		input := instanceInput{services.Interfaces, configuration, resource.Key, services.BaseDir, services.BodyMemory, services.SharedStates, services.Devices}
		if existing := old[spec.ID]; existing != nil && existing.Type == spec.Type && existing.input.interfaces == input.interfaces && existing.input.bodyMemory == input.bodyMemory && sameService(existing.input.sharedStates, input.sharedStates) && sameService(existing.input.devices, input.devices) && existing.input.baseDir == input.baseDir && existing.input.resources == input.resources && reflect.DeepEqual(existing.input.config, input.config) && existing.Retain() {
			instances = append(instances, PreparedInstance{existing, resource.Value})
			continue
		}
		local.Prepared = resource.Value
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
		instance := adopt(spec.ID, spec.Type, implementation, *resource.Plan)
		instance.input, instance.Metrics, instance.logger = input, registry, local.Logger
		instances = append(instances, PreparedInstance{instance, resource.Value})
	}
	return instances, nil
}
