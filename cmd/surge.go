// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/component/surgemodule"
	"github.com/daeuniverse/dae/config"
	log "github.com/sirupsen/logrus"
)

func loadSurge(ctx context.Context, conf config.Surge, client *http.Client, instanceID string) (engine *surgemodule.Engine, err error) {
	logger := log.WithField("mitm_instance", instanceID)
	status := surgemodule.Status{Enabled: true, Modules: make([]surgemodule.ModuleStatus, len(conf.Modules))}
	for i, source := range conf.Modules {
		name := source.Name
		if name == "" {
			name = resource.RedactURL(source.Link)
		}
		status.Modules[i] = surgemodule.ModuleStatus{Name: name, Source: resource.RedactURL(source.Link), State: "not loaded"}
	}
	defer func() {
		if err != nil {
			logger.Info("Surge module initialization failed; resource load status follows")
			logStartupSurgeStatus(status)
		}
	}()
	if err := conf.Validate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if client == nil {
		return nil, fmt.Errorf("surge: routed download client is required")
	}
	logger.Info("Loading Surge modules using routing rules after initial connectivity checks")
	baseDir := cacheDirectory()
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
	modules := make([]*surgemodule.Module, 0, len(conf.Modules))
	for i, source := range conf.Modules {
		module, err := surgemodule.Load(ctx, source.Link, client, surgemodule.LoadOptions{
			BaseDir:         baseDir,
			CacheDir:        moduleCache,
			Arguments:       source.Arguments,
			RefreshDeadline: refreshDeadline,
		})
		if err != nil {
			status.Modules[i].State = "failed"
			status.Modules[i].Error = resource.RedactText(err.Error())
			return nil, fmt.Errorf("surge module %q (%s): %w", source.Name, resource.RedactURL(source.Link), err)
		}
		if source.Name != "" {
			module.Name = source.Name
		}
		for _, warning := range module.Warnings {
			logger.Warnf("Surge module %s: %s", module.Name, warning)
		}
		for _, ignored := range module.Ignored {
			logger.Tracef("Surge module %s: %s", module.Name, ignored)
		}
		status.Modules[i] = module.Status()
		modules = append(modules, module)
	}
	runtime, err := surgemodule.NewRuntime(surgemodule.RuntimeOptions{
		MemoryLimit: conf.MemoryLimit, Timeout: conf.ScriptTimeout,
		StorePath: resolve(conf.Store),
		Log: func(level, message string) {
			switch level {
			case "debug":
				logger.Debug(message)
			case "info":
				logger.Info(message)
			case "warn":
				logger.Warn(message)
			case "error":
				logger.Error(message)
			}
		},
	})
	if err != nil {
		return nil, err
	}
	return surgemodule.NewEngine(surgemodule.EngineOptions{
		Modules: modules, Runtime: runtime,
		MaxBodySize: conf.MaxBodySize, MaxConcurrentScripts: conf.MaxConcurrentScripts,
		ScriptTimeout: conf.ScriptTimeout, Log: func(s string) { logger.Warn(s) },
		Trace:        func(s string) { logger.Info(s) },
		TraceEnabled: func() bool { return log.IsLevelEnabled(log.InfoLevel) },
	})
}
