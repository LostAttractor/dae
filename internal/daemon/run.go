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
	"runtime/debug"
	"slices"
	"syscall"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/filewatch"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/settings"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/internal/apiserver"
	"github.com/daeuniverse/dae/internal/handoff"
	log "github.com/sirupsen/logrus"
)

const (
	StatusSocketPath = "/var/run/dae.sock"
	shutdownTimeout  = 15 * time.Second
)

type Options struct {
	ConfigFile       string
	Version          string
	DisableTimestamp bool
	LaunchArgs       []string
	Startup          *Startup
}

// Run handles daemon startup, serialized configuration changes, and shutdown.
// The caller owns Startup and installs the process-wide resolver.
func Run(conf *config.Config, geoDirs []string, definitions map[string]plugin.Definition, resolver *netutils.InternalResolver, options Options) (runErr error) {
	if options.Startup == nil || options.Startup.lock == nil {
		return errors.New("daemon requires startup resources and the instance lock")
	}
	startup := options.Startup
	ctx := startup.ctx
	defer startup.cancel(context.Canceled)
	defer func() {
		if errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
			runErr = errors.Join(runErr, fmt.Errorf("replacement startup deadline exceeded: %w", context.Cause(ctx)))
		}
		if _, reserved := errors.AsType[*exemptionError](runErr); !reserved {
			cleanupCtx, stop := context.WithTimeout(context.Background(), shutdownTimeout)
			runErr = errors.Join(runErr, handoff.DrainChildren(cleanupCtx))
			stop()
		}
	}()
	incoming := startup.incoming
	if incoming != nil {
		manifest := incoming.manifest
		if !slices.Equal(conf.Global.LanInterface, manifest.LAN) || !slices.Equal(conf.Global.WanInterface, manifest.WAN) {
			return errors.New("interception interfaces changed during replacement")
		}
		hostns := incoming.take("hostns")
		daens := incoming.take("daens")
		err := control.BorrowDaeNetns(int(hostns.Fd()), int(daens.Fd()), manifest.HostIndex, manifest.PeerIndex)
		_ = hostns.Close()
		_ = daens.Close()
		if err != nil {
			return err
		}
	}
	startup.stage("Initializing plugins and runtime services...")
	plugins, err := configurePlugins(conf, definitions)
	if err != nil {
		return fmt.Errorf("configure plugins: %w", err)
	}
	if resolver == nil {
		return errors.New("daemon requires an installed internal resolver")
	}
	if err := plugins.Preflight(ctx); err != nil {
		return err
	}
	// A validated exec state is issued only after this ELF passes kernel preflight.
	if incoming == nil {
		if err := control.CheckKernelFeatures(ctx); err != nil {
			return err
		}
	}
	if err := control.RegisterDaemonIdentity(); err != nil {
		return fmt.Errorf("register daemon socket identity: %w", err)
	}
	certificates, err := prepareCertificates(conf, nil)
	if err != nil {
		return err
	}
	stopSampling, err := stats.DefaultStore.StartSampling()
	if err != nil {
		return fmt.Errorf("start traffic sampling: %w", err)
	}
	// Keep sampling through reloads and until all traffic producers have drained.
	defer stopSampling()
	var inheritedAPI *apiserver.Server
	if incoming != nil {
		inheritedAPI, err = incoming.takeManagement(conf.API, conf.Global.LanInterface)
		if err != nil {
			return err
		}
		defer inheritedAPI.Close()
	}
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
	datapath := control.NewRuntime()
	defer func() {
		if closeErr := datapath.Close(); closeErr != nil && !errors.Is(runErr, closeErr) {
			runErr = errors.Join(runErr, closeErr)
		}
	}()
	defer exitOnPanic(startup)
	if incoming != nil {
		files, err := incoming.takeLinks(len(incoming.manifest.Links))
		if err != nil {
			return err
		}
		importErr := datapath.ImportReplacement(incoming.manifest.Links, files)
		for _, file := range files {
			_ = file.Close()
		}
		if importErr != nil {
			return importErr
		}
	}
	worker, closeWorker := datapath.NewWorkerClient()
	defer closeWorker()
	app := &application{
		staging: incoming != nil, beginShutdown: startup.beginShutdown,
		options: options, conf: conf, datapath: datapath,
		settings: runtimeSettings, definitions: definitions, resolver: resolver, workerClient: worker,
		geoDirs: geoDirs, operations: newOperations(), managementAPI: inheritedAPI,
		metrics: newRuntimeMetricsHandler(datapath.DomainRegistryUsage),
	}
	if incoming != nil {
		op := incoming.manifest.Operation
		app.operations.records[op.ID] = &operationRecord{status: op, request: api.OperationRequest{Kind: "reload"}}
		app.operations.active = op.ID
		app.operations.replacing = true
	}
	startup.stage("Preparing routing and listeners...")
	loadCtx, refresh := app.resources.Begin(startup.InitializationContext(), conf.Global.ResourceUpdateInterval, false)
	inputs, err := loadControlInputs(loadCtx, conf, false, geoDirs, options.ConfigFile, nil)
	var candidate *preparedPlane
	if err == nil {
		candidate, err = app.assemblePlane(ctx, conf, inputs, func(client *http.Client) (control.PreparedMITM, error) {
			return loadMITM(loadCtx, conf, certificates.Authority(), client, worker, plugins, nil, geoDirs, datapath)
		})
	}
	if err != nil {
		if errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
			return fmt.Errorf("replacement startup: %w", context.Cause(ctx))
		}
		if errors.Is(err, context.Canceled) {
			log.Info("Startup canceled")
			return nil
		}
		return err
	}
	startup.inputs = nil
	var local *apiserver.Server
	if incoming != nil {
		file := incoming.take("local")
		local, err = apiserver.FromFile(file, "unix")
		_ = file.Close()
	} else {
		local, err = apiserver.Listen("unix", StatusSocketPath)
	}
	if err != nil {
		return errors.Join(fmt.Errorf("local API: %w", err), candidate.discard())
	}
	// Register both transparent sockets and start their readers before any
	// host program can hand traffic to this generation.
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
			local.Close()
			return errors.Join(<-ingressErrors, candidate.discard())
		}
	case err := <-ingressErrors:
		local.Close()
		return errors.Join(err, candidate.discard())
	case <-ctx.Done():
		local.Close()
		if errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
			return errors.Join(context.Cause(ctx), candidate.discard())
		}
		return candidate.discard()
	}
	if err := app.publishPlane(candidate, false); err != nil {
		local.Close()
		return errors.Join(err, datapath.Close(), candidate.plane.Close())
	}
	app.localAPI, app.inputs = local, inputs
	plane, management := app.plane, app.managementAPI
	datapath.RefreshTCPIdleTimeouts()
	refresh.Commit()
	app.setCertificates(certificates)
	local.SetLocalServices(apiserver.LocalServices{Operations: app.operations, Metrics: app.metrics, Pprof: conf.API.Pprof})
	stopOperations := context.AfterFunc(ctx, app.operations.stop)
	defer stopOperations()
	defer func() {
		app.operations.stop()
		startup.cancel(context.Canceled)
		log.Info("Shutting down")
		if !app.staging {
			runErr = errors.Join(runErr, notifyService(context.Background(), "stopping"))
		}
		resolver.SetRoute(nil)
		runErr = errors.Join(runErr, exit(datapath, app.localAPI, app.managementAPI))
	}()
	defer exitOnPanic(startup)
	app.publishAPI()
	if incoming != nil {
		startup.stage("Activating replacement datapath...")
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := datapath.CommitReplacement(ctx); err != nil {
			return err
		}
		log.WithField("cutover", time.Since(incoming.manifest.CutoverAt)).Info("Replacement datapath ready")
		app.localAPI.Activate()
		app.managementAPI.Activate()
		candidate.apiUpdate.Commit()
		incoming.close()
	}
	pruneSubscriptions(conf, filepath.Dir(options.ConfigFile))
	logStartupNodeStatus(plane.GroupsStatus())
	// A daemon survives the loss of its controlling terminal.
	signal.Ignore(syscall.SIGHUP)
	resolver.SetRoute(plane.DNSResolverDialer())
	if management != nil {
		log.Infof("API listening at %s", conf.API.Listen)
	}
	if err := app.finishStartup(ctx); err != nil {
		return err
	}
	log.WithFields(log.Fields{"duration": time.Since(started), "targets": len(plane.GroupsStatus()), "plugins": len(plane.MITMStatus().Plugins)}).Info("Startup completed")
	if incoming != nil {
		startup.closeLogPipe()
		app.operations.finish(incoming.manifest.Operation.ID, fmt.Sprintf("Replaced daemon; PID %d, version %s", os.Getpid(), options.Version), nil)
		app.operations.endReplacement()
	}
	refreshTimer := time.NewTimer(time.Hour)
	defer refreshTimer.Stop()
	apiRoutingTimer := time.NewTimer(time.Hour)
	apiRoutingTimer.Stop()
	defer apiRoutingTimer.Stop()
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
		case <-app.managementAPI.InterfaceChanges():
			apiRoutingTimer.Reset(0)
		case <-app.plane.APIAddressChanges():
			apiRoutingTimer.Reset(0)
		case <-apiRoutingTimer.C:
			if err := app.refreshAPIRouting(ctx); err != nil {
				log.WithError(resource.RedactError(err)).Warn("Could not refresh API routing after address or listener changes; retrying")
				apiRoutingTimer.Reset(time.Second)
			}
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
		}
	}
}

// Bound terminal shutdown even when a worker cannot be canceled. Shared state
// stays alive until its users finish; the deadline forces process exit.
func watchShutdown(ctx context.Context, timeout time.Duration, forceExit func()) (start, finish func()) {
	ctx, cancel := context.WithCancel(ctx)
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
	return cancel, func() { close(done); stop(); cancel() }
}

// exitOnPanic makes a panic on the daemon goroutine an unexpected exit: like
// SIGKILL, it skips cleanup, so unexpected_exit_behavior governs the retained
// datapath. Defer it after each cleanup it must skip.
func exitOnPanic(startup *Startup) {
	if recovered := recover(); recovered != nil {
		if startup != nil && startup.logPipe != nil {
			writeReplacementError(startup.logPipe, "Initialization failed", fmt.Errorf("panic: %v", recovered))
		}
		fmt.Fprintf(os.Stderr, "panic: %v\n\n%s", recovered, debug.Stack())
		os.Exit(2)
	}
}

func exit(datapath *control.Runtime, servers ...*apiserver.Server) error {
	var err error
	if offlineErr := datapath.GoOffline(); offlineErr != nil {
		err = fmt.Errorf("mark kernel datapath offline: %w", offlineErr)
	}
	for _, server := range servers {
		server.Stop()
	}
	for _, server := range servers {
		server.Close()
	}
	return errors.Join(err, datapath.Close())
}
