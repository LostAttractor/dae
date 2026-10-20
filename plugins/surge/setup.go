// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/component/plugin"
	surgeapi "github.com/daeuniverse/dae/plugins/surge/api"
	"github.com/daeuniverse/dae/plugins/surge/internal/jq"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

const maxConcurrentModuleLoads = 4

var Plugin = plugin.Definition{Configure: Configure, Resources: prepareResources, Commands: Commands}

func prepareModules(ctx context.Context, conf Config, services plugin.Services) (modules []*Module, err error) {
	started := time.Now()
	logger := services.Logger
	client := services.PrepareClient
	status := surgeapi.SurgeStatus{Enabled: true, Modules: make([]surgeapi.ModuleStatus, len(conf.Modules))}
	for i, source := range conf.Modules {
		name := source.Name
		if name == "" {
			name = resource.RedactURL(source.Link)
		}
		status.Modules[i] = surgeapi.ModuleStatus{Name: name, Source: resource.RedactURL(source.Link), State: "not loaded"}
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
	// Downloads are independent, but module order determines rule priority.
	// Keep each complete module in its declaration slot and cancel outstanding
	// work on failure; the resource session is only committed by the caller.
	modules = make([]*Module, len(conf.Modules))
	group, loadCtx := errgroup.WithContext(ctx)
	group.SetLimit(maxConcurrentModuleLoads)
	for i, source := range conf.Modules {
		group.Go(func() error {
			if err := loadCtx.Err(); err != nil {
				return err
			}
			moduleStarted := time.Now()
			module, err := Load(loadCtx, source.Link, client, LoadOptions{
				BaseDir:         baseDir,
				CacheDir:        moduleCache,
				Arguments:       source.Arguments,
				RefreshDeadline: refreshDeadline,
			})
			if err != nil {
				// Modules canceled by another failure remain "not loaded".
				if loadCtx.Err() == nil || !errors.Is(err, context.Canceled) {
					status.Modules[i].State = "failed"
				}
				return fmt.Errorf("surge module %q (%s): %w", source.Name, resource.RedactURL(source.Link), err)
			}
			if source.Name != "" {
				module.Name = source.Name
			}
			status.Modules[i] = module.Status()
			modules[i] = module
			logger.WithFields(log.Fields{"module": module.Name, "duration": time.Since(moduleStarted)}).Debug("Loaded Surge module")
			return nil
		})
	}
	if err := group.Wait(); err != nil {
		return nil, err
	}
	var jqPool *jq.Pool
	var releaseJQ func() error
	defer func() {
		if releaseJQ != nil {
			_ = releaseJQ()
		}
	}()
	for i, module := range modules {
		if slices.ContainsFunc(module.BodyRewrites, func(rule BodyRewrite) bool { return rule.expression != "" }) {
			if jqPool == nil {
				jqPool, releaseJQ, err = jq.Acquire()
				if err != nil {
					return nil, err
				}
			}
			prepared, err := prepareBodyRewrites(ctx, []*Module{module}, jqPool)
			if err != nil {
				return nil, err
			}
			module = prepared[0]
			// Prepared resources own immutable expressions; the runtime binds a
			// live pool after it acquires its own lifetime reference.
			for j := range module.BodyRewrites {
				module.BodyRewrites[j].jq = nil
			}
			modules[i] = module
		}
		for _, warning := range module.Warnings {
			logger.WithField("module", module.Name).Warn(resource.RedactText(warning))
		}
		for _, ignored := range module.Ignored {
			logger.WithField("module", module.Name).Trace(ignored)
		}
		status.Modules[i] = module.Status()
	}
	logger.WithFields(log.Fields{"modules": len(modules), "duration": time.Since(started)}).Debug("Loaded Surge modules")
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
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	modules, ok := services.Prepared.([]*Module)
	if !ok {
		var err error
		modules, err = prepareModules(ctx, conf, services)
		if err != nil {
			return nil, err
		}
	}
	var runtime *Runtime
	needsRuntime := slices.ContainsFunc(modules, func(module *Module) bool {
		return len(module.Scripts)+len(module.TaskScripts) != 0
	})
	if needsRuntime {
		var storePath string
		if conf.Store {
			if services.BaseDir == "" || instanceID == "" || instanceID == "." || instanceID == ".." || filepath.Base(instanceID) != instanceID {
				return nil, fmt.Errorf("surge: persistent store requires a base directory and a valid plugin instance ID")
			}
			storePath = filepath.Join(services.BaseDir, "plugins", instanceID, "surge-store.json")
		}
		var err error
		runtime, err = NewRuntime(ctx, RuntimeOptions{
			NodePath: conf.NodePath, NodeWorkers: conf.MaxConcurrentScripts,
			MemoryLimit: conf.MemoryLimit, Timeout: conf.ScriptTimeout,
			StorePath: storePath,
			Logger:    services.Logger,
		})
		if err != nil {
			return nil, err
		}
		// Warm before publication: failure rejects this candidate, not the
		// running generation.
		if err := runtime.Warm(ctx); err != nil {
			_ = runtime.Close()
			return nil, err
		}
	}
	engine, err := newEngine(ctx, EngineOptions{
		Modules: modules, Runtime: runtime,
		HTTPPolicies: conf.HTTPPolicies,
		BodyMemory:   services.BodyMemory,
		MaxBodySize:  conf.MaxBodySize, MaxConcurrentScripts: conf.MaxConcurrentScripts,
		ScriptTimeout: conf.ScriptTimeout, Logger: services.Logger,
	})
	if err != nil {
		_ = runtime.Close()
	}
	return engine, err
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
				_ = engine.Close()
				return nil, fmt.Errorf("surge metrics: %w", err)
			}
		}
		logModuleStatus(engine.Status(), services.Logger, spec.ID)
		return engine, nil
	}, nil
}
