/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/samber/oops"
	"gopkg.in/natefinch/lumberjack.v2"

	_ "net/http/pprof"

	"github.com/daeuniverse/dae/cmd/internal"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/filewatch"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/api"
	"github.com/daeuniverse/dae/component/mitm/plugin"
	"github.com/daeuniverse/dae/component/settings"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/daeuniverse/dae/pkg/logger"
	"github.com/mohae/deepcopy"
	"github.com/okzk/sdnotify"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const (
	PidFilePath            = "/var/run/dae.pid"
	SignalProgressFilePath = "/var/run/dae.progress"
	StatusSocketPath       = "/var/run/dae.sock"

	observabilityShutdownTimeout = 3 * time.Second
)

var (
	// Keep lifecycle diagnostics on stderr when daemon logs go to --logfile.
	std             = log.New()
	pprofServer     *http.Server
	metricsServer   *http.Server
	pprofListener   net.Listener
	metricsListener net.Listener
	pprofPort       uint16
	// metricsPort is the port metricsServer listens on; 0 means disabled.
	metricsPort     uint16
	metricsRegistry = prometheus.NewRegistry()
	observabilityMu sync.Mutex
	statusServer    *api.StatusServer
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

func init() {
	std.SetFormatter(logger.NewTextFormatter(false))
	log.SetFormatter(logger.NewTextFormatter(false))
	metricsRegistry.MustRegister(stats.DefaultStore)

}

var (
	cfgFile           string
	logFile           string
	logFileMaxSize    int
	logFileMaxBackups int
	disableTimestamp  bool
	disablePidFile    bool
	disableAuthSudo   bool
)

func newRunCommand(setups map[string]plugin.Setup) *cobra.Command {
	runCmd := &cobra.Command{
		Use:   "run",
		Short: "To run dae in the foreground.",
		Run: func(cmd *cobra.Command, args []string) {
			std.SetFormatter(logger.NewTextFormatter(disableTimestamp))
			log.SetFormatter(logger.NewTextFormatter(disableTimestamp))
			if cfgFile == "" {
				std.Fatalln("Argument \"--config\" or \"-c\" is required but not provided.")
			}
			if disableAuthSudo && os.Geteuid() != 0 {
				std.Fatalln("Auto-sudo is disabled and current user is not root.")
			}
			// Require "sudo" if necessary.
			if !disableAuthSudo {
				internal.AutoSu()
			}

			// Read config from --config cfgFile.
			conf, includes, err := readConfig(cfgFile)
			if err != nil {
				std.WithFields(log.Fields{
					"err": err,
				}).Fatalln("Failed to read config")
			}
			// AutoSu has returned in the final privileged process. Install the
			// process-global resolver before constructors can resolve hostnames.
			if err = configureDaemonResolver(&conf.Global); err != nil {
				std.WithError(err).Fatalln("Failed to configure marked resolver")
			}
			var logOpts *lumberjack.Logger
			if logFile != "" {
				logOpts = &lumberjack.Logger{
					Filename:   logFile,
					MaxSize:    logFileMaxSize,
					MaxAge:     0,
					MaxBackups: logFileMaxBackups,
					LocalTime:  true,
					Compress:   true,
				}
			}
			logger.SetLogger(conf.Global.LogLevel, disableTimestamp, logOpts)

			std.Infof("Include config files: [%v]", strings.Join(includes, ", "))
			Run(conf, []string{filepath.Dir(cfgFile)}, setups)
		},
	}
	runCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "Config file of dae.(required)")
	runCmd.PersistentFlags().StringVar(&logFile, "logfile", "", "Log file to write. Empty means writing to std and stderr.")
	runCmd.PersistentFlags().IntVar(&logFileMaxSize, "logfile-maxsize", 30, "Unit: MB. The maximum size in megabytes of the log file before it gets rotated.")
	runCmd.PersistentFlags().IntVar(&logFileMaxBackups, "logfile-maxbackups", 3, "The maximum number of old log files to retain.")
	runCmd.PersistentFlags().BoolVar(&disableTimestamp, "disable-timestamp", false, "Disable timestamp.")
	runCmd.PersistentFlags().BoolVar(&disablePidFile, "disable-pidfile", false, "Not generate /var/run/dae.pid.")
	runCmd.PersistentFlags().BoolVar(&disableAuthSudo, "disable-sudo", false, "Disable sudo prompt ,may cause startup failure due to insufficient permissions")
	return runCmd
}

func configureDaemonResolver(global *config.Global) error {
	mark := common.EffectiveSoMarkFromDae(global.SoMarkFromDae)
	if err := common.ValidateSoMarkFromDae(mark); err != nil {
		return err
	}
	return netutils.InstallDefaultResolver(mark)
}

// writeReloadProgress reports the current reload step through the signal
// progress file, so `dae reload` can display it to the user.
func writeReloadProgress(format string, args ...any) {
	writeReloadState(consts.ReloadProcessing, fmt.Sprintf(format, args...))
}

func writeReloadState(code byte, content string) {
	data := []byte{code}
	if content != "" {
		data = append(data, []byte("\n"+content)...)
	}
	if err := writeFileAtomic(SignalProgressFilePath, data, 0600); err != nil {
		std.Warnf("Failed to update reload progress: %v", err)
	}
}

// writeFileAtomic prevents readers from observing a partially-written
// progress record while the daemon and CLI communicate through a file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		if err != nil {
			_ = os.Remove(tmpPath)
		}
	}()
	if err = tmp.Chmod(perm); err != nil {
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

// Run starts dae after command startup has configured process-wide name
// resolution. Embedders calling Run directly must install a marked default
// resolver before starting concurrent work.
// Run starts the daemon with the binary's complete set of MITM plugin types.
func Run(conf *config.Config, externGeoDataDirs []string, setups map[string]plugin.Setup) {
	// Remove AbortFile at beginning.
	_ = os.Remove(AbortFile)
	startPprofServer(conf.Global.PprofPort)

	runtimeSettingsPath := filepath.Join(cacheDirectory(), "runtime-state.json")
	runtimeSettings, err := settings.Open(runtimeSettingsPath)
	if err != nil {
		std.Fatalf("runtime settings: %v", err)
	}
	settingsWatcher, err := filewatch.New(runtimeSettingsPath, 100*time.Millisecond)
	if err != nil {
		std.Fatalf("watch runtime settings: %v", err)
	}
	defer settingsWatcher.Close()

	// New ControlPlane.
	startupStarted := time.Now()
	startupCtx, stopStartupSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	c, err := newControlPlane(startupCtx, nil, conf, externGeoDataDirs, runtimeSettings, setups)
	startupErr := startupCtx.Err()
	stopStartupSignals()
	if err == nil && startupErr != nil {
		err = errors.Join(startupErr, cleanupStartup(c))
		c = nil
	}
	if err != nil {
		if errors.Is(err, context.Canceled) {
			log.Info("Startup canceled")
			return
		}
		std.Fatalln(err)
	}
	managementAPI, err := prepareAPIServer(nil, conf.Global.APIPort)
	if err != nil {
		_ = c.Close()
		std.Fatalln(err)
	}
	if err = c.Activate(); err != nil {
		managementAPI.Close()
		_ = c.Close()
		std.Fatalln(err)
	}
	logStartupNodeStatus(c.GroupsStatus())

	startMetricsServer(conf.Global.MetricsPort)

	if statusServer == nil {
		if statusServer, err = api.StartStatusServer(StatusSocketPath, Version); err != nil {
			std.Warnf("Failed to start status server: %v", err)
		}
	}
	// Serve tproxy TCP/UDP server util signals.
	var listener *control.Listener
	sigs := make(chan os.Signal, 1)
	errCh := make(chan error, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGKILL, syscall.SIGILL, syscall.SIGUSR1, syscall.SIGUSR2)
	startupPlane := c
	startupPort := conf.Global.TproxyPort
	readyChan := make(chan bool, 1)
	go func() {
		startedListener, err := control.GetDaeNetns().With(func() (*control.Listener, error) {
			startedListener, err := startupPlane.ListenAndServe(readyChan, startupPort)
			if err != nil {
				return nil, oops.Wrapf(err, "ListenAndServe")
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
		managementAPI.Close()
		exit(c)
	}()
	select {
	case ready := <-readyChan:
		if !ready {
			std.Errorf("%+v", <-errCh)
			return
		}
	case startupErr := <-errCh:
		std.Errorf("%+v", startupErr)
		return
	}
	if statusServer != nil {
		statusServer.Publish(startupPlane.StatusSnapshot)
	}
	managementAPI.setHandler(startupPlane.APIHandler())
	if managementAPI != nil {
		std.Infof("Configuration page and API listening on port %d", managementAPI.port)
	}
	sdnotify.Ready()
	log.WithField("duration", time.Since(startupStarted)).Info("Startup completed")
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
		case err := <-settingsWatcher.Errors:
			std.WithError(err).Warn("Runtime settings watcher error")
		case <-settingsWatcher.Changes:
			changed, err := c.ReloadRuntimeSettings()
			if err != nil {
				std.WithError(err).Warn("Could not reload runtime-state.json; keeping previous settings")
			} else if changed {
				std.Info("Reloaded runtime-state.json")
			}
		case sig := <-sigs:
			switch sig {
			case nil:
				if listener == nil {
					// Failed to listen. Exit.
					break loop
				}
				// Serve.
				std.Infoln("[Reload] Serve")
				readyChan := make(chan bool, 1)
				go func() {
					if err := c.Serve(readyChan, listener); err != nil {
						errCh <- oops.Wrapf(err, "Serve")
					} else {
						sigs <- nil
					}
				}()
				if ready := <-readyChan; !ready {
					serveErr := <-errCh
					std.Errorf("%+v", serveErr)
					writeReloadState(consts.ReloadError, serveErr.Error())
					break loop
				}
				if pendingReload {
					reconfigureObservabilityServers(conf.Global.PprofPort, conf.Global.MetricsPort)
					stats.DefaultStore.RecordReload()
					if statusServer != nil {
						statusServer.Publish(c.StatusSnapshot)
					}
					managementAPI.setHandler(c.APIHandler())
					if managementAPI != nil {
						std.Infof("Configuration page and API listening on port %d", managementAPI.port)
					}
					pendingReload = false
				}
				sdnotify.Ready()
				writeReloadState(consts.ReloadDone, "OK")
				std.Warnln("[Reload] Finished")
			case syscall.SIGUSR2:
				if pendingReload {
					std.Warnln("[Reload] Ignoring suspend signal until the new control plane starts serving")
					continue
				}
				isSuspend = true
				fallthrough
			case syscall.SIGUSR1:
				if pendingReload {
					std.Warnln("[Reload] Ignoring reload signal until the new control plane starts serving")
					continue
				}
				// Reload signal.
				if isSuspend {
					std.Warnln("[Reload] Received suspend signal; prepare to suspend")
				} else {
					std.Warnln("[Reload] Received reload signal; prepare to reload")
				}
				sdnotify.Reloading()
				writeReloadState(consts.ReloadProcessing, "")

				// On failure keep the current control plane running and
				// report the error through the log and the progress file.
				reloadFailed := func(step string, err error) {
					std.Errorf("%+v", oops.Wrapf(err, "[Reload] %v; keeping current control plane", step))
					sdnotify.Ready()
					writeReloadState(consts.ReloadError, err.Error())
				}

				// Load new config.
				abortConnections = os.Remove(AbortFile) == nil
				std.Warnln("[Reload] Load new config")
				var newConf *config.Config
				if isSuspend {
					isSuspend = false
					newConf = deepcopy.Copy(conf).(*config.Config)
					newConf.Global.WanInterface = nil
					newConf.Global.LanInterface = nil
					newConf.Global.LogLevel = "warning"
				} else {
					var includes []string
					if newConf, includes, err = readConfig(cfgFile); err == nil {
						std.Infof("Include config files: [%v]", strings.Join(includes, ", "))
					}
				}
				if err != nil {
					reloadFailed("Failed to load config", err)
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
				// New logger.
				logger.SetLogger(newConf.Global.LogLevel, disableTimestamp, nil)

				// Phase 1: build the new control plane in memory. This step
				// loads external resources (e.g. geoip) and validates the
				// configuration without touching shared BPF maps or interface
				// bindings, so the existing plane keeps serving traffic if it
				// fails.
				std.Warnln("[Reload] Build new control plane")
				writeReloadProgress("Building new control plane...")
				obj := c.EjectBpf()
				newC, err := newControlPlane(context.Background(), obj, newConf, externGeoDataDirs, runtimeSettings, setups)
				if err != nil {
					// Restore BPF ownership on the old plane and keep it running.
					c.InjectBpf()
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
				std.Warnln("[Reload] Stop old control plane")
				writeReloadProgress("Switching to the new control plane...")
				if statusServer != nil {
					statusServer.Publish(nil)
				}
				managementAPI.setHandler(nil)
				if managementAPI != nextAPI {
					managementAPI.Close()
				}
				managementAPI = nextAPI
				if closeErr := retireControlPlaneForReload(c, abortConnections); closeErr != nil {
					// The old filters may still interpret shared maps with the old
					// rule layout. Do not install new rules or adopt bitmaps into
					// that state; assign cleanup ownership to the candidate only so
					// its teardown closes the otherwise unowned BPF objects.
					newC.InjectBpf()
					_ = newC.Close()
					std.Panicf("%+v", oops.Wrapf(closeErr, "[Reload] Failed to retire old control plane safely"))
				}
				std.Warnln("[Reload] Stopped old control plane")

				// Phase 2b: commit. Assign BPF cleanup ownership to the new plane,
				// then push its state into the kernel. Failures past this point are
				// terminal, so we tear everything down.
				std.Warnln("[Reload] Activate new control plane")
				writeReloadProgress("Activating new control plane...")
				newC.InjectBpf()
				// Hand over the retired plane's domain registry (recomputing
				// match bitmaps against the new rules) so domain routing and
				// sniff verification survive the reload; Activate then skips
				// wiping the kernel domain maps.
				newC.InheritDomainRegistry(c)
				if err = newC.Activate(); err != nil {
					sdnotify.Stopping()
					_ = newC.Close()
					std.Panicf("%+v", oops.Wrapf(err, "[Reload] Failed to activate new control plane"))
				}
				logStartupNodeStatus(newC.GroupsStatus())

				// Swap in the new plane.
				c = newC
				conf = newConf
				pendingReload = true
			case syscall.SIGHUP:
				// Ignore.
				continue
			default:
				std.Infof("Received signal: %v", sig.String())
				break loop
			}
		case err := <-errCh:
			std.Errorf("%+v", err)
			break loop
		}
	}
}

func exit(c *control.ControlPlane) {
	startPprofServer(0)
	startMetricsServer(0)
	if statusServer != nil {
		statusServer.Close()
	}
	if err := os.Remove(PidFilePath); err != nil {
		std.Errorf("%+v", oops.Wrapf(err, "failed to remove pid file"))
	}
	if e := c.Close(); e != nil {
		std.Errorf("%+v", oops.Wrapf(e, "failed to close control plane"))
	}
	if err := control.GetDaeNetns().Close(); err != nil {
		std.Errorf("%+v", oops.Wrapf(err, "failed to close netns"))
	}
	control.CloseSysctlManager()
}

func stopHTTPServer(name string, server *http.Server, listener net.Listener) {
	stopHTTPServerWithin(name, server, listener, observabilityShutdownTimeout)
}

func stopHTTPServerWithin(name string, server *http.Server, listener net.Listener, timeout time.Duration) {
	if server == nil {
		return
	}
	if listener != nil {
		_ = listener.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		std.Warnf("Failed to stop %s server gracefully: %v", name, err)
		if closeErr := server.Close(); closeErr != nil && !errors.Is(closeErr, http.ErrServerClosed) {
			std.Warnf("Failed to close %s server: %v", name, closeErr)
		}
	}
}

func serveHTTP(name string, server *http.Server, listener net.Listener, clearCurrent func(*http.Server)) {
	err := server.Serve(listener)
	clearCurrent(server)
	if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
		std.Warnf("%s server stopped unexpectedly: %v", name, err)
		stopHTTPServer(name, server, listener)
	}
}

func clearPprofServer(server *http.Server) {
	observabilityMu.Lock()
	defer observabilityMu.Unlock()
	if pprofServer == server {
		pprofServer = nil
		pprofListener = nil
		pprofPort = 0
		runtime.SetBlockProfileRate(0)
		runtime.SetMutexProfileFraction(0)
	}
}

func clearMetricsServer(server *http.Server) {
	observabilityMu.Lock()
	defer observabilityMu.Unlock()
	if metricsServer == server {
		metricsServer = nil
		metricsListener = nil
		metricsPort = 0
	}
}

func reconfigureObservabilityServers(pprofTarget, metricsTarget uint16) {
	observabilityMu.Lock()
	currentPprof := pprofPort
	currentMetrics := metricsPort
	observabilityMu.Unlock()

	// Release a port first when the other service needs to take it over.
	if pprofTarget != 0 && pprofTarget == currentMetrics && metricsTarget != currentMetrics {
		startMetricsServer(0)
	}
	if metricsTarget != 0 && metricsTarget == currentPprof && pprofTarget != currentPprof {
		startPprofServer(0)
	}
	startPprofServer(pprofTarget)
	startMetricsServer(metricsTarget)
}

func startPprofServer(port uint16) {
	observabilityMu.Lock()
	if pprofServer != nil && pprofPort == port && port != 0 {
		observabilityMu.Unlock()
		return
	}
	if port == 0 {
		old := pprofServer
		oldListener := pprofListener
		pprofServer = nil
		pprofListener = nil
		pprofPort = 0
		runtime.SetBlockProfileRate(0)
		runtime.SetMutexProfileFraction(0)
		observabilityMu.Unlock()
		stopHTTPServer("pprof", old, oldListener)
		return
	}
	server := &http.Server{
		Addr:              fmt.Sprintf("localhost:%d", port),
		Handler:           http.DefaultServeMux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		observabilityMu.Unlock()
		std.Warnf("Failed to start pprof server: %v", err)
		return
	}
	old := pprofServer
	oldListener := pprofListener
	pprofServer = server
	pprofListener = listener
	pprofPort = port
	runtime.SetBlockProfileRate(1)
	runtime.SetMutexProfileFraction(1)
	go serveHTTP("pprof", server, listener, clearPprofServer)
	observabilityMu.Unlock()
	stopHTTPServer("pprof", old, oldListener)
}

// startMetricsServer restarts the metrics server only when its process-level
// listener changes. The registry is stable across control-plane reloads.
func startMetricsServer(port uint16) {
	observabilityMu.Lock()
	if metricsServer != nil && metricsPort == port && port != 0 {
		observabilityMu.Unlock()
		return
	}

	if port == 0 {
		old := metricsServer
		oldListener := metricsListener
		metricsServer = nil
		metricsListener = nil
		metricsPort = 0
		observabilityMu.Unlock()
		stopHTTPServer("metrics", old, oldListener)
		return
	}

	server := &http.Server{
		Addr: fmt.Sprintf("localhost:%d", port),
		Handler: promhttp.HandlerFor(metricsRegistry, promhttp.HandlerOpts{
			ErrorHandling: promhttp.ContinueOnError,
		}),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		observabilityMu.Unlock()
		std.Warnf("Failed to start metrics server: %v", err)
		return
	}
	old := metricsServer
	oldListener := metricsListener
	metricsServer = server
	metricsListener = listener
	metricsPort = port
	go serveHTTP("metrics", server, listener, clearMetricsServer)
	observabilityMu.Unlock()
	stopHTTPServer("metrics", old, oldListener)
}

func readConfig(cfgFile string) (conf *config.Config, includes []string, err error) {
	merger := config.NewMerger(cfgFile)
	sections, includes, err := merger.Merge()
	if err != nil {
		return nil, nil, err
	}
	if conf, err = config.New(sections); err != nil {
		return nil, nil, err
	}
	return conf, includes, nil
}
