// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/component/plugin"
	log "github.com/sirupsen/logrus"
)

var Plugin = plugin.Definition{Configure: Configure, Resources: prepareResources, Commands: Commands}

func prepareModules(ctx context.Context, conf Config, services plugin.Services) (modules []*Module, err error) {
	logger := services.Logger
	client := services.PrepareClient
	status := api.SurgeStatus{Enabled: true, Modules: make([]api.ModuleStatus, len(conf.Modules))}
	for i, source := range conf.Modules {
		name := source.Name
		if name == "" {
			name = resource.RedactURL(source.Link)
		}
		status.Modules[i] = api.ModuleStatus{Name: name, Source: resource.RedactURL(source.Link), State: "not loaded"}
	}
	defer func() {
		if err != nil {
			for _, module := range status.Modules {
				logger.WithFields(log.Fields{"module": module.Name, "state": module.State}).Debug("Surge module load status")
			}
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if client == nil {
		return nil, fmt.Errorf("surge: routed download client is required")
	}
	logger.WithField("modules", len(conf.Modules)).Debug("Loading Surge modules")
	baseDir := services.BaseDir
	// Bound remote refreshes across the module list, while allowing remaining
	// modules to use their complete snapshots after the network budget expires.
	refreshDeadline := time.Now().Add(2 * time.Minute)
	var moduleCache string
	if services.ResourceCacheDir != "" {
		moduleCache = filepath.Join(services.ResourceCacheDir, "surge")
	}
	modules = make([]*Module, 0, len(conf.Modules))
	for i, source := range conf.Modules {
		module, err := Load(ctx, source.Link, client, LoadOptions{
			BaseDir:         baseDir,
			CacheDir:        moduleCache,
			Arguments:       source.Arguments,
			RefreshDeadline: refreshDeadline,
		})
		if err != nil {
			status.Modules[i].State = "failed"
			return nil, fmt.Errorf("surge module %q (%s): %w", source.Name, resource.RedactURL(source.Link), err)
		}
		if source.Name != "" {
			module.Name = source.Name
		}
		for _, warning := range module.Warnings {
			logger.WithField("module", module.Name).Warn(resource.RedactText(warning))
		}
		for _, ignored := range module.Ignored {
			logger.WithField("module", module.Name).Trace(ignored)
		}
		status.Modules[i] = module.Status()
		modules = append(modules, module)
	}
	return modules, nil
}

func prepareResources(ctx context.Context, spec plugin.Spec, services plugin.Services) (plugin.Resources, error) {
	conf, err := ParseConfig(spec.Config)
	if err != nil {
		return plugin.Resources{}, err
	}
	modules, err := prepareModules(ctx, conf, services)
	if err != nil {
		return plugin.Resources{}, err
	}
	var key strings.Builder
	for _, module := range modules {
		key.WriteString(module.contentKey)
	}
	return plugin.Resources{Config: conf, Key: key.String(), Value: modules}, nil
}

func prepare(ctx context.Context, conf Config, services plugin.Services, instanceID string) (*Engine, error) {
	modules, ok := services.Prepared.([]*Module)
	if !ok {
		var err error
		modules, err = prepareModules(ctx, conf, services)
		if err != nil {
			return nil, err
		}
	}
	var storePath string
	if conf.Store {
		if services.BaseDir == "" || instanceID == "" || instanceID == "." || instanceID == ".." || filepath.Base(instanceID) != instanceID {
			return nil, fmt.Errorf("surge: persistent store requires a base directory and a valid plugin instance ID")
		}
		storePath = filepath.Join(services.BaseDir, "plugins", instanceID, "surge-store.json")
	}
	runtime, err := NewRuntime(RuntimeOptions{
		MemoryLimit: conf.MemoryLimit, Timeout: conf.ScriptTimeout,
		StorePath: storePath,
		Logger:    services.Logger,
	})
	if err != nil {
		return nil, err
	}
	return NewEngine(EngineOptions{
		Modules: modules, Runtime: runtime,
		BodyMemory:  services.BodyMemory,
		MaxBodySize: conf.MaxBodySize, MaxConcurrentScripts: conf.MaxConcurrentScripts,
		ScriptTimeout: conf.ScriptTimeout, Logger: services.Logger,
	})
}

func Configure(spec plugin.Spec) (plugin.Factory, error) {
	conf, err := ParseConfig(spec.Config)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, services plugin.Services) (plugin.Plugin, error) {
		engine, err := prepare(ctx, conf, services, spec.ID)
		if err != nil {
			return nil, err
		}
		if services.Metrics != nil {
			if err := services.Metrics.Register(engine.metrics); err != nil {
				return nil, fmt.Errorf("surge metrics: %w", err)
			}
		}
		logModuleStatus(engine.Status(), services.Logger, spec.ID)
		return engine, nil
	}, nil
}
