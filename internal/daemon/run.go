// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/filewatch"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/settings"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/internal/apiserver"
	"github.com/okzk/sdnotify"
	log "github.com/sirupsen/logrus"
)

const (
	PidFilePath      = "/var/run/dae.pid"
	StatusSocketPath = "/var/run/dae.sock"
	shutdownTimeout  = 15 * time.Second
)

type Options struct {
	ConfigFile       string
	Version          string
	DisableTimestamp bool
	DisablePidFile   bool
}

// Run owns daemon startup, serialized configuration changes and shutdown.
// The caller installs process-wide name resolution before concurrent work.
func Run(conf *config.Config, geoDirs []string, definitions map[string]plugin.Definition, resolver *netutils.InternalResolver, options Options) error {
	plugins, err := configurePlugins(conf, definitions)
	if err != nil {
		return fmt.Errorf("configure plugins: %w", err)
	}
	if resolver == nil {
		return errors.New("daemon requires an installed internal resolver")
	}
	ctx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer stopSignals()
	if err := plugins.Preflight(ctx); err != nil {
		return err
	}
	if err := control.CheckKernelFeatures(ctx); err != nil {
		return err
	}
	certificates, err := prepareCertificates(conf, nil)
	if err != nil {
		return err
	}
	stopWatchdog := watchShutdown(ctx, shutdownTimeout, func() {
		log.WithField("timeout", shutdownTimeout).Error("Shutdown timed out; forcing process exit")
		os.Exit(1)
	})
	defer stopWatchdog()
	startPprofServer(conf.Global.PprofPort)
	defer startPprofServer(0)
	settingsPath := filepath.Join(common.CacheDirectory(), "runtime-state.json")
	runtimeSettings, err := settings.Open(settingsPath)
	if err != nil {
		return fmt.Errorf("runtime settings: %w", err)
	}
	watcher, err := filewatch.New(settingsPath, 100*time.Millisecond)
	if err != nil {
		return fmt.Errorf("watch runtime settings: %w", err)
	}
	defer watcher.Close()

	started := time.Now()
	defer cleanupKernelResources()
	datapath := control.NewRuntime()
	defer datapath.Close()
	worker, closeWorker := datapath.NewWorkerClient()
	defer closeWorker()
	var resources resource.RefreshStore
	loadCtx, refresh := resources.Begin(ctx, conf.Global.ResourceUpdateInterval, false)
	inputs, err := loadControlInputs(loadCtx, conf, false, geoDirs, options.ConfigFile, nil)
	var plane *control.ControlPlane
	if err == nil {
		plane, err = newControlPlane(loadCtx, datapath, conf, inputs, runtimeSettings, func(client *http.Client) (control.PreparedMITM, error) {
			return loadMITM(loadCtx, conf, certificates.Authority(), client, worker, plugins, nil, geoDirs, datapath)
		})
	}
	if err == nil && ctx.Err() != nil {
		err = errors.Join(ctx.Err(), plane.Close())
	}
	if err != nil {
		if errors.Is(err, context.Canceled) {
			log.Info("Startup canceled")
			return nil
		}
		return err
	}
	management, err := prepareAPIServer(nil, conf.Global.APIPort)
	if err != nil {
		return errors.Join(err, plane.Close())
	}
	local, err := apiserver.Listen("unix", StatusSocketPath)
	if err != nil {
		management.Close()
		return errors.Join(fmt.Errorf("local API: %w", err), plane.Close())
	}
	if err := datapath.Publish(plane, false); err != nil {
		local.Close()
		management.Close()
		return errors.Join(err, datapath.Close(), plane.Close())
	}
	datapath.RefreshTCPIdleTimeouts()
	refresh.Commit()
	app := &application{
		options: options, conf: conf, inputs: inputs, plane: plane, datapath: datapath,
		settings: runtimeSettings, definitions: definitions, resolver: resolver, workerClient: worker,
		geoDirs: geoDirs, localAPI: local, managementAPI: management,
		resources: resources, operations: newOperations(),
	}
	app.setCertificates(certificates)
	local.SetOperations(app.operations)
	stopOperations := context.AfterFunc(ctx, app.operations.stop)
	defer stopOperations()
	defer func() {
		app.operations.stop()
		stopSignals()
		log.Info("Shutting down")
		resolver.SetRoute(nil)
		exit(datapath, app.localAPI, app.managementAPI)
	}()
	pruneSubscriptions(conf, filepath.Dir(options.ConfigFile))
	logStartupNodeStatus(plane.GroupsStatus())
	startMetricsServer(conf.Global.MetricsPort)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGHUP, syscall.SIGILL, syscall.SIGUSR1, syscall.SIGUSR2)
	defer signal.Stop(sigs)
	ingressErrors := make(chan error, 1)
	ready := make(chan bool, 1)
	go func() {
		_, err := control.GetDaeNetns().With(func() (*control.Listener, error) {
			return datapath.ListenAndServe(ready, conf.Global.TproxyPort)
		})
		if err == nil {
			err = errors.New("datapath ingress stopped")
		}
		ingressErrors <- err
	}()
	select {
	case started := <-ready:
		if !started {
			return <-ingressErrors
		}
	case err := <-ingressErrors:
		return err
	case <-ctx.Done():
		return nil
	}
	resolver.SetRoute(plane.DNSResolverDialer())
	app.publishAPI()
	if management != nil {
		log.Infof("Configuration page and API listening on port %d", conf.Global.APIPort)
	}
	sdnotify.Ready()
	log.WithFields(log.Fields{"duration": time.Since(started), "targets": len(plane.GroupsStatus()), "plugins": len(plane.MITMStatus())}).Info("Startup completed")
	if !options.DisablePidFile {
		_ = os.WriteFile(PidFilePath, []byte(strconv.Itoa(os.Getpid())), 0644)
	}
	refreshTimer := time.NewTimer(time.Hour)
	defer refreshTimer.Stop()
	var retryAfter time.Time
	runOperation := func(id string) error {
		err := app.executeOperation(ctx, id)
		status, _ := app.operations.Operation(id)
		if status.Kind == "refresh" && err != nil {
			retryAfter = time.Now().Add(5 * time.Minute)
		} else if err == nil {
			retryAfter = time.Time{}
		}
		if _, fatal := errors.AsType[*activationError](err); fatal {
			sdnotify.Stopping()
			return err
		}
		return nil
	}
	for {
		var refreshC <-chan time.Time
		next := app.resources.Next()
		refreshStatus := app.operations.ResourceRefreshStatus()
		refreshPending := refreshStatus.Operation != nil && refreshStatus.Operation.FinishedAt.IsZero()
		if !next.IsZero() && !refreshPending {
			if next.Before(retryAfter) {
				next = retryAfter
			}
			refreshTimer.Reset(max(time.Until(next), 0))
			refreshC = refreshTimer.C
		}
		app.operations.setNext(next)
		select {
		case <-ctx.Done():
			return nil
		case err := <-ingressErrors:
			return err
		case <-refreshC:
			if _, err := app.operations.submit(api.OperationRequest{Kind: "refresh"}, "automatic"); err != nil {
				retryAfter = time.Now().Add(time.Second)
			}
		case id := <-app.operations.requests:
			if err := runOperation(id); err != nil {
				return err
			}
		case err := <-watcher.Errors:
			log.WithError(err).Warn("Runtime settings watcher error")
		case <-watcher.Changes:
			changed, err := app.plane.ReloadRuntimeSettings()
			if err != nil {
				log.WithError(err).Warn("Could not reload runtime-state.json; keeping previous settings")
			} else if changed {
				log.Info("Reloaded runtime-state.json")
			}
		case sig := <-sigs:
			switch sig {
			case syscall.SIGUSR1, syscall.SIGUSR2:
				kind := "reload"
				if sig == syscall.SIGUSR2 {
					kind = "suspend"
				}
				if _, err := app.operations.submit(api.OperationRequest{Kind: kind}, "signal"); err != nil {
					log.WithError(err).Warn("Could not enqueue signal operation")
				}
			case syscall.SIGHUP:
				continue
			default:
				log.WithField("signal", sig).Info("Received signal")
				return nil
			}
		}
	}
}

// Bound terminal shutdown even when a worker cannot be canceled. Shared state
// stays alive until its users finish; the deadline forces process exit.
func watchShutdown(ctx context.Context, timeout time.Duration, forceExit func()) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case <-done:
		case <-timer.C:
			forceExit()
		}
	})
	return func() { close(done); stop() }
}

func exit(datapath *control.Runtime, servers ...*apiserver.Server) {
	startPprofServer(0)
	startMetricsServer(0)
	for _, server := range servers {
		server.Stop()
	}
	for _, server := range servers {
		server.Close()
	}
	if err := datapath.Close(); err != nil {
		log.WithError(err).Error("Could not stop control plane ingress")
	}
	if err := os.Remove(PidFilePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.WithError(err).Warn("Could not remove PID file")
	}
}
