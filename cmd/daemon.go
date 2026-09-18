// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/filewatch"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/component/settings"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/internal/apiserver"
	"github.com/daeuniverse/dae/pkg/logger"
	"github.com/okzk/sdnotify"
	log "github.com/sirupsen/logrus"
)

const (
	PidFilePath      = "/var/run/dae.pid"
	StatusSocketPath = "/var/run/dae.sock"
)

type reloadControlPlaneRetirer interface {
	StopAndAbortConnections() error
	Close() error
}

func retireControlPlaneForReload(c reloadControlPlaneRetirer, abortConnections bool) error {
	var abortErr error
	if abortConnections {
		abortErr = c.StopAndAbortConnections()
	}
	return errors.Join(abortErr, c.Close())
}

// Run starts dae after command startup has configured process-wide name
// resolution. Embedders install and pass the resolver before concurrent work.
// Run starts the daemon with the binary's complete set of plugin types.
func Run(conf *config.Config, externGeoDataDirs []string, definitions map[string]plugin.Definition, resolver *netutils.InternalResolver) error {
	shutdownCtx, stopShutdownSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	defer stopShutdownSignals()
	stopWatchdog := watchShutdown(shutdownCtx, shutdownTimeout, func() {
		log.WithField("timeout", shutdownTimeout).Error("Shutdown timed out; forcing process exit")
		os.Exit(1)
	})
	defer stopWatchdog()
	// Remove AbortFile at beginning.
	_ = os.Remove(AbortFile)
	startPprofServer(conf.Global.PprofPort)
	defer startPprofServer(0)

	runtimeSettingsPath := filepath.Join(cacheDirectory(), "runtime-state.json")
	runtimeSettings, err := settings.Open(runtimeSettingsPath)
	if err != nil {
		return fmt.Errorf("runtime settings: %w", err)
	}
	settingsWatcher, err := filewatch.New(runtimeSettingsPath, 100*time.Millisecond)
	if err != nil {
		return fmt.Errorf("watch runtime settings: %w", err)
	}
	defer settingsWatcher.Close()

	// New ControlPlane.
	startupStarted := time.Now()
	c, err := newControlPlane(shutdownCtx, nil, conf, externGeoDataDirs, runtimeSettings, definitions)
	startupErr := shutdownCtx.Err()
	if err == nil && startupErr != nil {
		err = errors.Join(startupErr, cleanupStartup(c))
		c = nil
	}
	if err != nil {
		if errors.Is(err, context.Canceled) {
			log.Info("Startup canceled")
			return nil
		}
		return err
	}
	managementAPI, err := prepareAPIServer(nil, conf.Global.APIPort)
	if err != nil {
		return errors.Join(err, cleanupStartup(c))
	}
	localAPI, err := apiserver.Listen("unix", StatusSocketPath)
	if err != nil {
		managementAPI.Close()
		return errors.Join(fmt.Errorf("local API: %w", err), cleanupStartup(c))
	}
	if err = c.Activate(); err != nil {
		localAPI.Close()
		managementAPI.Close()
		return errors.Join(err, cleanupStartup(c))
	}
	logStartupNodeStatus(c.GroupsStatus())

	startMetricsServer(conf.Global.MetricsPort)

	// Serve tproxy TCP/UDP server util signals.
	var listener *control.Listener
	sigs := make(chan os.Signal, 1)
	errCh := make(chan error, 1)
	signal.Notify(sigs, syscall.SIGHUP, syscall.SIGILL, syscall.SIGUSR1, syscall.SIGUSR2)
	defer signal.Stop(sigs)
	startupPlane := c
	startupPort := conf.Global.TproxyPort
	readyChan := make(chan bool, 1)
	go func() {
		startedListener, err := control.GetDaeNetns().With(func() (*control.Listener, error) {
			startedListener, err := startupPlane.ListenAndServe(readyChan, startupPort)
			if err != nil {
				return nil, fmt.Errorf("ListenAndServe: %w", err)
			}
			return startedListener, nil
		})
		listener = startedListener
		if err != nil {
			errCh <- err
		} else {
			sigs <- nil
		}
	}()

	// Close the CURRENT plane on exit: c is re-assigned on every reload, and
	// a deferred exit(c) would capture the startup plane, closing the retired
	// plane a second time while the final, bpf-owning plane is never closed.
	defer func() {
		// Cancel even on an internal error, arming the shutdown deadline and
		// restoring default handling for any further termination signals.
		stopShutdownSignals()
		log.Info("Shutting down")
		resolver.SetRoute(nil)
		exit(c, localAPI, managementAPI)
	}()
	select {
	case ready := <-readyChan:
		if !ready {
			return <-errCh
		}
	case startupErr := <-errCh:
		return startupErr
	}
	resolver.SetRoute(startupPlane.DNSResolverDialer())
	handler := startupPlane.APIHandler(Version)
	localAPI.SetHandler(handler)
	managementAPI.SetHandler(daemonAPIHandler(handler))
	if managementAPI != nil {
		log.Infof("Configuration page and API listening on port %d", conf.Global.APIPort)
	}
	sdnotify.Ready()
	log.WithFields(log.Fields{
		"duration": time.Since(startupStarted), "targets": len(startupPlane.GroupsStatus()),
		"plugins": len(startupPlane.MITMStatus()),
	}).Info("Startup completed")
	if !disablePidFile {
		_ = os.WriteFile(PidFilePath, []byte(strconv.Itoa(os.Getpid())), 0644)
	}
	writeReloadState(consts.ReloadDone, "")

	pendingReload := false
	isSuspend := false
	abortConnections := false
loop:
	for {
		select {
		case <-shutdownCtx.Done():
			return nil
		case err := <-settingsWatcher.Errors:
			log.WithError(err).Warn("Runtime settings watcher error")
		case <-settingsWatcher.Changes:
			changed, err := c.ReloadRuntimeSettings()
			if err != nil {
				log.WithError(err).Warn("Could not reload runtime-state.json; keeping previous settings")
			} else if changed {
				log.Info("Reloaded runtime-state.json")
			}
		case sig := <-sigs:
			switch sig {
			case nil:
				if listener == nil {
					// Failed to listen. Exit.
					return errors.New("control plane stopped without a reusable listener")
				}
				// Serve.
				log.Debug("Starting replacement control plane listener")
				readyChan := make(chan bool, 1)
				go func() {
					if err := c.Serve(readyChan, listener); err != nil {
						errCh <- fmt.Errorf("Serve: %w", err)
					} else {
						sigs <- nil
					}
				}()
				if ready := <-readyChan; !ready {
					serveErr := <-errCh
					writeReloadState(consts.ReloadError, serveErr.Error())
					return serveErr
				}
				if pendingReload {
					resolver.SetRoute(c.DNSResolverDialer())
					reconfigureObservabilityServers(conf.Global.PprofPort, conf.Global.MetricsPort)
					stats.DefaultStore.RecordReload()
					handler := c.APIHandler(Version)
					localAPI.SetHandler(handler)
					managementAPI.SetHandler(daemonAPIHandler(handler))
					if managementAPI != nil {
						log.Infof("Configuration page and API listening on port %d", conf.Global.APIPort)
					}
					pendingReload = false
				}
				sdnotify.Ready()
				writeReloadState(consts.ReloadDone, "OK")
				log.Info("Reload completed")
			case syscall.SIGUSR2:
				if pendingReload {
					log.Debug("Ignoring suspend signal while reload is in progress")
					continue
				}
				isSuspend = true
				fallthrough
			case syscall.SIGUSR1:
				if pendingReload {
					log.Debug("Ignoring reload signal while reload is in progress")
					continue
				}
				// Reload signal.
				if isSuspend {
					log.Info("Suspending traffic interception")
				} else {
					log.Info("Reload requested")
				}
				sdnotify.Reloading()
				writeReloadState(consts.ReloadProcessing, "")

				// On failure keep the current control plane running and
				// report the error through the log and the progress file.
				reloadFailed := func(step string, err error) {
					err = resource.RedactError(err)
					log.WithError(err).WithField("step", step).Warn("Reload rejected; current configuration remains active")
					sdnotify.Ready()
					writeReloadState(consts.ReloadError, err.Error())
				}

				// Load new config.
				abortConnections = os.Remove(AbortFile) == nil
				log.Debug("Reading replacement configuration")
				newConf, includes, err := loadReloadConfig(cfgFile, conf, isSuspend)
				isSuspend = false
				if err != nil {
					reloadFailed("Failed to load config", err)
					continue
				}
				if includes != nil {
					log.WithField("files", includes).Debug("Loaded configuration files")
				}
				if err := validatePlugins(newConf, definitions); err != nil {
					reloadFailed("Failed to validate plugins", err)
					continue
				}
				resolverServer, err := netutils.ParseDNSServer(newConf.Global.DNSResolver)
				if err != nil {
					reloadFailed("Failed to configure DNS resolver", err)
					continue
				}
				// The tproxy listener is reused across reloads, so a port
				// change cannot take effect without a restart.
				if newConf.Global.TproxyPort != conf.Global.TproxyPort {
					reloadFailed("Failed to reload",
						fmt.Errorf("tproxy_port (%v -> %v) cannot be changed by reload; restart dae to apply it", conf.Global.TproxyPort, newConf.Global.TproxyPort))
					continue
				}
				oldSoMark := common.EffectiveSoMarkFromDae(conf.Global.SoMarkFromDae)
				newSoMark := common.EffectiveSoMarkFromDae(newConf.Global.SoMarkFromDae)
				if newSoMark != oldSoMark {
					reloadFailed("Failed to reload",
						fmt.Errorf("so_mark_from_dae (%#x -> %#x) cannot be changed by reload; restart dae to apply it", oldSoMark, newSoMark))
					continue
				}
				// Phase 1: build the new control plane in memory. This step
				// loads external resources (e.g. geoip) and validates the
				// configuration without touching shared BPF maps or interface
				// bindings, so the existing plane keeps serving traffic if it
				// fails.
				log.Debug("Building replacement control plane")
				writeReloadProgress("Building new control plane...")
				obj := c.EjectBpf()
				newC, err := newControlPlane(shutdownCtx, obj, newConf, externGeoDataDirs, runtimeSettings, definitions)
				reloadErr := shutdownCtx.Err()
				if err == nil && reloadErr != nil {
					err = errors.Join(reloadErr, newC.Close())
				}
				if err != nil {
					// Restore BPF ownership on the old plane and keep it running.
					c.InjectBpf()
					if reloadErr != nil {
						return nil // The terminating signal also cancels candidate preparation.
					}
					reloadFailed("Failed to build new control plane", err)
					continue
				}
				nextAPI, err := prepareAPIServer(managementAPI, newConf.Global.APIPort)
				if err != nil {
					_ = newC.Close()
					c.InjectBpf()
					reloadFailed("Failed to bind HTTP API port", err)
					continue
				}

				// Phase 2a: retire the old plane BEFORE the new plane pushes
				// rules into the kernel. Once BuildKernspace runs, the shared
				// routing maps carry the new config's outbound ids; the old
				// plane must not accept connections in that window, or it
				// would route them through the wrong outbounds. New
				// connections just queue in the kernel until the new plane
				// serves the same listener, and the old plane's dialers stop
				// writing connectivity state into the shared maps.
				log.Debug("Retiring previous control plane")
				writeReloadProgress("Switching to the new control plane...")
				localAPI.SetHandler(nil)
				managementAPI.SetHandler(nil)
				if managementAPI != nextAPI {
					managementAPI.Close()
				}
				managementAPI = nextAPI
				resolver.Configure(resolverServer, nil)
				if closeErr := retireControlPlaneForReload(c, abortConnections); closeErr != nil {
					// The old filters may still interpret shared maps with the old
					// rule layout. Do not install new rules or adopt bitmaps into
					// that state; assign cleanup ownership to the candidate only so
					// its teardown closes the otherwise unowned BPF objects.
					newC.InjectBpf()
					return errors.Join(fmt.Errorf("reload: could not retire previous control plane safely: %w", closeErr), newC.Close())
				}
				log.Debug("Retired previous control plane")

				// Phase 2b: commit. Assign BPF cleanup ownership to the new plane,
				// then push its state into the kernel. Failures past this point are
				// terminal, so we tear everything down.
				log.Debug("Activating replacement control plane")
				writeReloadProgress("Activating new control plane...")
				newC.InjectBpf()
				// Hand over the retired plane's domain registry (recomputing
				// match bitmaps against the new rules) so domain routing and
				// sniff verification survive the reload; Activate then skips
				// wiping the kernel domain maps.
				newC.InheritDomainRegistry(c)
				newC.InheritConnections(c)
				if err = newC.Activate(); err != nil {
					sdnotify.Stopping()
					return errors.Join(fmt.Errorf("reload: could not activate replacement control plane: %w", err), newC.Close())
				}
				logStartupNodeStatus(newC.GroupsStatus())

				// Swap in the new plane.
				c = newC
				conf = newConf
				logger.SetLogger(conf.Global.LogLevel, disableTimestamp, nil)
				pendingReload = true
			case syscall.SIGHUP:
				// Ignore.
				continue
			default:
				log.Infof("Received signal: %v", sig.String())
				break loop
			}
		case err := <-errCh:
			return err
		}
	}
	return nil
}

const shutdownTimeout = 15 * time.Second

// Bound terminal shutdown even when a plugin or an I/O operation cannot be
// canceled. Shared state must stay alive until its users finish; on timeout the
// daemon exits instead of continuing teardown underneath those users.
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
	return func() {
		close(done)
		stop()
	}
}

func exit(c *control.ControlPlane, servers ...*apiserver.Server) {
	startPprofServer(0)
	startMetricsServer(0)
	// Interrupt API requests and traffic before joining handlers or workers.
	for _, server := range servers {
		server.Stop()
	}
	if err := c.StopAndAbortConnections(); err != nil {
		log.WithError(err).Error("Could not stop control plane ingress")
	}
	for _, server := range servers {
		server.Close()
	}
	if err := os.Remove(PidFilePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.WithError(err).Warn("Could not remove PID file")
	}
	if e := c.Close(); e != nil {
		log.WithError(e).Error("Could not close control plane")
	}
	if err := control.GetDaeNetns().Close(); err != nil {
		log.WithError(err).Error("Could not close dae network namespace")
	}
	control.CloseSysctlManager()
}
