// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/component/mitm/plugin"
	log "github.com/sirupsen/logrus"
)

var Plugin = plugin.Definition{Setup: Setup, Commands: Commands}

func prepare(ctx context.Context, conf Config, services plugin.Services, instanceID string) (engine *Engine, err error) {
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
	resolve := func(path string) string {
		if path == "" || filepath.IsAbs(path) {
			return path
		}
		return filepath.Join(baseDir, path)
	}
	// Bound remote refreshes across the module list, while allowing remaining
	// modules to use their complete snapshots after the network budget expires.
	refreshDeadline := time.Now().Add(2 * time.Minute)
	moduleCache := filepath.Join(baseDir, "mitm", instanceID, "surge-cache")
	modules := make([]*Module, 0, len(conf.Modules))
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
	runtime, err := NewRuntime(RuntimeOptions{
		MemoryLimit: conf.MemoryLimit, Timeout: conf.ScriptTimeout,
		StorePath: resolve(conf.Store),
		Logger:    logger,
	})
	if err != nil {
		return nil, err
	}
	return NewEngine(EngineOptions{
		Modules: modules, Runtime: runtime,
		MaxBodySize: conf.MaxBodySize, MaxConcurrentScripts: conf.MaxConcurrentScripts,
		ScriptTimeout: conf.ScriptTimeout, Logger: logger,
	})
}

// Setup decodes and prepares one complete Surge compatibility engine.
func Setup(ctx context.Context, spec plugin.Spec, services plugin.Services) (plugin.Plugin, error) {
	conf, err := ParseConfig(spec.Config)
	if err != nil {
		return nil, err
	}
	engine, err := prepare(ctx, conf, services, spec.ID)
	if err != nil {
		return nil, err
	}
	logModuleStatus(engine.Status(), services.Logger, spec.ID)
	return engine, nil
}
