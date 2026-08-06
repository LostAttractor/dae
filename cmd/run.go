/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/daeuniverse/outbound/protocol/direct"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/samber/oops"
	"gopkg.in/natefinch/lumberjack.v2"

	_ "net/http/pprof"

	"github.com/daeuniverse/dae/cmd/internal"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/common/subscription"
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

	// Time bounds applied to the reload path only. A reload must not hang for
	// a long time when the network is down, because the old control plane
	// keeps serving traffic while the new one is being built. Startup, in
	// contrast, may wait for the network without a bound, since the network
	// may not be online yet when dae first starts.
	reloadNetworkWaitTimeout       = 15 * time.Second
	reloadSubscriptionTimeout      = 10 * time.Second
	reloadSubscriptionPhaseTimeout = 30 * time.Second
)

var (
	CheckNetworkLinks = []string{
		"http://edge.microsoft.com/captiveportal/generate_204",
		"http://www.gstatic.com/generate_204",
		"http://www.qualcomm.cn/generate_204",
	}
	std              = log.New()
	pprofServer      *http.Server
	prometheusServer *http.Server
	// prometheusPort is the port prometheusServer listens on; 0 means disabled.
	prometheusPort uint16
	// prometheusHandler holds the handler bound to the current control plane's
	// registry, so it can be swapped on reload without restarting the server.
	prometheusHandler atomic.Value // http.Handler
	statusServer      *control.StatusServer
	controlPlane      *control.ControlPlane
)

func init() {
	runCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "Config file of dae.(required)")
	runCmd.PersistentFlags().StringVar(&logFile, "logfile", "", "Log file to write. Empty means writing to std and stderr.")
	runCmd.PersistentFlags().IntVar(&logFileMaxSize, "logfile-maxsize", 30, "Unit: MB. The maximum size in megabytes of the log file before it gets rotated.")
	runCmd.PersistentFlags().IntVar(&logFileMaxBackups, "logfile-maxbackups", 3, "The maximum number of old log files to retain.")
	runCmd.PersistentFlags().BoolVar(&disableTimestamp, "disable-timestamp", false, "Disable timestamp.")
	runCmd.PersistentFlags().BoolVar(&disablePidFile, "disable-pidfile", false, "Not generate /var/run/dae.pid.")
	runCmd.PersistentFlags().BoolVar(&disableAuthSudo, "disable-sudo", false, "Disable sudo prompt ,may cause startup failure due to insufficient permissions")
	rand.Shuffle(len(CheckNetworkLinks), func(i, j int) {
		CheckNetworkLinks[i], CheckNetworkLinks[j] = CheckNetworkLinks[j], CheckNetworkLinks[i]
	})
}

var (
	cfgFile           string
	logFile           string
	logFileMaxSize    int
	logFileMaxBackups int
	disableTimestamp  bool
	disablePidFile    bool
	disableAuthSudo   bool

	runCmd = &cobra.Command{
		Use:   "run",
		Short: "To run dae in the foreground.",
		Run: func(cmd *cobra.Command, args []string) {
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
			Run(conf, []string{filepath.Dir(cfgFile)})
		},
	}
)

// writeReloadProgress reports the current reload step through the signal
// progress file, so `dae reload` can display it to the user.
func writeReloadProgress(format string, args ...any) {
	_ = os.WriteFile(SignalProgressFilePath, append([]byte{consts.ReloadProcessing}, []byte("\n"+fmt.Sprintf(format, args...))...), 0644)
}

func Run(conf *config.Config, externGeoDataDirs []string) {
	// Remove AbortFile at beginning.
	_ = os.Remove(AbortFile)
	startPprofServer(conf.Global.PprofPort)

	// New ControlPlane.
	c, err := newControlPlane(nil, conf, externGeoDataDirs)
	if err != nil {
		std.Fatalln(err)
	}
	if err = c.Activate(); err != nil {
		_ = c.Close()
		std.Fatalln(err)
	}

	startPrometheusServer(conf.Global.MetricsPort, c.PrometheusRegistry)

	if statusServer == nil {
		if statusServer, err = control.StartStatusServer(StatusSocketPath, Version); err != nil {
			std.Warnf("Failed to start status server: %v", err)
		}
	}
	if statusServer != nil {
		statusServer.SetControlPlane(c)
	}

	// Serve tproxy TCP/UDP server util signals.
	var listener *control.Listener
	sigs := make(chan os.Signal, 1)
	errCh := make(chan error, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGKILL, syscall.SIGILL, syscall.SIGUSR1, syscall.SIGUSR2)
	go func() {
		readyChan := make(chan bool, 1)
		go func() {
			<-readyChan
			sdnotify.Ready()
			if !disablePidFile {
				_ = os.WriteFile(PidFilePath, []byte(strconv.Itoa(os.Getpid())), 0644)
			}
			_ = os.WriteFile(SignalProgressFilePath, []byte{consts.ReloadDone}, 0644)
		}()
		err := control.GetDaeNetns().With(func() error {
			if listener, err = c.ListenAndServe(readyChan, conf.Global.TproxyPort); err != nil {
				return oops.Wrapf(err, "ListenAndServe")
			}
			return nil
		})
		if err != nil {
			errCh <- err
		} else {
			sigs <- nil
		}
	}()

	// Close the CURRENT plane on exit: c is re-assigned on every reload, and
	// a deferred exit(c) would capture the startup plane, closing the retired
	// plane a second time while the final, bpf-owning plane is never closed.
	defer func() { exit(c) }()

	reloadingErr := error(nil)
	isSuspend := false
	abortConnections := false
loop:
	for {
		select {
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
				<-readyChan
				sdnotify.Ready()
				if reloadingErr == nil {
					_ = os.WriteFile(SignalProgressFilePath, append([]byte{consts.ReloadDone}, []byte("\nOK")...), 0644)
				} else {
					_ = os.WriteFile(SignalProgressFilePath, append([]byte{consts.ReloadError}, []byte("\n"+reloadingErr.Error())...), 0644)
				}
				std.Warnln("[Reload] Finished")
			case syscall.SIGUSR2:
				isSuspend = true
				fallthrough
			case syscall.SIGUSR1:
				// Reload signal.
				if isSuspend {
					std.Warnln("[Reload] Received suspend signal; prepare to suspend")
				} else {
					std.Warnln("[Reload] Received reload signal; prepare to reload")
				}
				sdnotify.Reloading()
				_ = os.WriteFile(SignalProgressFilePath, []byte{consts.ReloadProcessing}, 0644)
				reloadingErr = nil

				// On failure keep the current control plane running and
				// report the error through the log and the progress file.
				reloadFailed := func(step string, err error) {
					reloadingErr = err
					std.Errorf("%+v", oops.Wrapf(err, "[Reload] %v; keeping current control plane", step))
					sdnotify.Ready()
					_ = os.WriteFile(SignalProgressFilePath, append([]byte{consts.ReloadError}, []byte("\n"+err.Error())...), 0644)
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
				// The tproxy listener and the tproxy port baked into the
				// shared eBPF programs are reused across reloads, so a
				// tproxy_port change cannot take effect without a restart.
				if newConf.Global.TproxyPort != conf.Global.TproxyPort {
					reloadFailed("Failed to reload",
						fmt.Errorf("tproxy_port (%v -> %v) cannot be changed by reload; restart dae to apply it", conf.Global.TproxyPort, newConf.Global.TproxyPort))
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
				newC, err := newControlPlane(obj, newConf, externGeoDataDirs)
				if err != nil {
					// Restore BPF ownership on the old plane and keep it running.
					c.InjectBpf()
					reloadFailed("Failed to build new control plane", err)
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
				if abortConnections {
					c.AbortConnections()
				}
				std.Warnln("[Reload] Stop old control plane")
				writeReloadProgress("Switching to the new control plane...")
				c.Close()
				std.Warnln("[Reload] Stopped old control plane")

				// Phase 2b: commit. The new plane now owns BPF and pushes
				// rules into the kernel. Failures past this point leave the
				// system in an inconsistent state, so we tear everything down.
				std.Warnln("[Reload] Activate new control plane")
				writeReloadProgress("Activating new control plane...")
				newC.InjectBpf()
				if err = newC.Activate(); err != nil {
					sdnotify.Stopping()
					_ = newC.Close()
					std.Panicf("%+v", oops.Wrapf(err, "[Reload] Failed to activate new control plane"))
				}

				// Swap in the new plane.
				c = newC
				conf = newConf

				startPprofServer(conf.Global.PprofPort)
				startPrometheusServer(conf.Global.MetricsPort, c.PrometheusRegistry)
				if statusServer != nil {
					statusServer.SetControlPlane(c)
				}
				stats.RecordReload()
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
	if statusServer != nil {
		statusServer.Close()
	}
	if err := os.Remove(PidFilePath); err != nil {
		std.Errorf("%+v", oops.Wrapf(err, "failed to remove pid file"))
	}
	if err := control.GetDaeNetns().Close(); err != nil {
		std.Errorf("%+v", oops.Wrapf(err, "failed to close netns"))
	}
	control.CloseSysctlManager()
	if e := c.Close(); e != nil {
		std.Errorf("%+v", oops.Wrapf(e, "failed to close control plane"))
	}
}

func startPprofServer(port uint16) {
	if pprofServer != nil {
		pprofServer.Shutdown(context.Background())
		pprofServer = nil
	}

	if port == 0 {
		return
	}
	pprofServer = &http.Server{Addr: fmt.Sprintf("localhost:%d", port)}
	go pprofServer.ListenAndServe()
	runtime.SetBlockProfileRate(1)
	runtime.SetMutexProfileFraction(1)
}

// startPrometheusServer rebinds the metrics handler to the given registry,
// restarting the HTTP server only when the listen port changed.
func startPrometheusServer(port uint16, prometheusRegistry *prometheus.Registry) {
	if prometheusServer != nil && prometheusPort == port && port != 0 {
		// Port unchanged: keep the listener, just swap the registry.
		prometheusHandler.Store(promhttp.HandlerFor(prometheusRegistry, promhttp.HandlerOpts{}))
		return
	}

	if prometheusServer != nil {
		prometheusServer.Shutdown(context.Background())
		prometheusServer = nil
		prometheusPort = 0
	}

	if port == 0 {
		return
	}

	prometheusHandler.Store(promhttp.HandlerFor(prometheusRegistry, promhttp.HandlerOpts{}))
	prometheusServer = &http.Server{
		Addr: fmt.Sprintf("localhost:%d", port),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			prometheusHandler.Load().(http.Handler).ServeHTTP(w, r)
		}),
	}
	prometheusPort = port
	go prometheusServer.ListenAndServe()
}

// reloadDeadline returns the deadline after which a reload step must give up
// waiting. At startup (isReload == false) it returns the zero time, i.e. no
// bound.
func reloadDeadline(isReload bool, timeout time.Duration) time.Time {
	if !isReload {
		return time.Time{}
	}
	return time.Now().Add(timeout)
}

// waitForNetworkOnline blocks until the network is reachable. Startup waits
// indefinitely because the network may not be online yet when dae first
// starts. During a reload the wait is bounded by reloadNetworkWaitTimeout:
// the old control plane keeps serving traffic, so a reload must not hang on
// a dead network.
func waitForNetworkOnline(isReload bool) {
	epo := 5 * time.Second
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return direct.Direct.DialContext(ctx, "tcp", addr)
			},
		},
		Timeout: epo,
	}
	deadline := reloadDeadline(isReload, reloadNetworkWaitTimeout)
	if isReload {
		writeReloadProgress("Checking network...")
	}
	log.Infoln("Waiting for network...")
	for i := 0; ; i++ {
		if isReload && time.Now().After(deadline) {
			log.Warnf("Network is still not online after %v; continuing without network check", reloadNetworkWaitTimeout)
			return
		}
		resp, err := client.Get(CheckNetworkLinks[i%len(CheckNetworkLinks)])
		if err != nil {
			log.Debugf("%+v", oops.Wrapf(err, "CheckNetwork"))
			var neterr net.Error
			if errors.As(err, &neterr) && neterr.Timeout() {
				// Do not sleep.
				continue
			}
			time.Sleep(epo)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 500 {
			log.Infoln("Network online.")
			return
		}
		log.Infof("Bad status: %v (%v)", resp.Status, resp.StatusCode)
		time.Sleep(epo)
	}
}

func newControlPlane(bpf interface{}, conf *config.Config, externGeoDataDirs []string) (c *control.ControlPlane, err error) {
	// Deep copy to prevent modification.
	conf = deepcopy.Copy(conf).(*config.Config)

	// A non-nil bpf means this is a reload (or suspend/resume): the ejected
	// bpf object of the previous control plane is reused. During a reload the
	// old control plane keeps serving traffic, so the network check and the
	// subscription fetches below must be bounded and must not block for too
	// long.
	isReload := bpf != nil

	/// Get tag -> nodeList mapping.
	tagToNodeList := map[string][]string{}
	if len(conf.Node) > 0 {
		for _, node := range conf.Node {
			tagToNodeList[""] = append(tagToNodeList[""], string(node))
		}
	}

	/// Init Direct Dialers.
	direct.InitDirectDialers(conf.Global.FallbackResolver, conf.Global.Mptcp, int(conf.Global.SoMarkFromDae))

	// Resolve subscriptions to nodes.
	resolvingfailed := false
	if !conf.Global.DisableWaitingNetwork {
		waitForNetworkOnline(isReload)
	}
	if len(conf.Subscription) > 0 {
		if isReload {
			writeReloadProgress("Fetching subscriptions...")
		}
		log.Infoln("Fetching subscriptions...")
	}
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return direct.Direct.DialContext(ctx, "tcp", addr)
			},
		},
		Timeout: 30 * time.Second,
	}
	// Bound the time a reload may spend on unreachable subscription servers:
	// the old control plane keeps serving traffic, and subscriptions can be
	// fetched again on the next reload. Startup keeps the full timeout since
	// the network may not be online yet.
	if isReload {
		client.Timeout = reloadSubscriptionTimeout
	}
	subscriptionDir := os.Getenv("DAE_LOCATION_SUBSCRIPTION")
	if subscriptionDir == "" {
		subscriptionDir = filepath.Dir(cfgFile)
	}
	subDeadline := reloadDeadline(isReload, reloadSubscriptionPhaseTimeout)
	for _, sub := range conf.Subscription {
		if isReload && time.Now().After(subDeadline) {
			log.Warnf("Subscription resolution exceeded %v; skipping the remaining subscriptions", reloadSubscriptionPhaseTimeout)
			break
		}
		tag, nodes, err := subscription.ResolveSubscription(&client, subscriptionDir, string(sub))
		if err != nil {
			log.Warnf(`failed to resolve subscription "%v": %v`, sub, err)
			resolvingfailed = true
			continue
		}
		if len(nodes) > 0 {
			tagToNodeList[tag] = append(tagToNodeList[tag], nodes...)
		}
	}

	// Delete all files in persist.d that are not in tagToNodeList
	files, err := os.ReadDir(filepath.Join(subscriptionDir, "persist.d"))
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	for _, file := range files {
		tag := strings.TrimSuffix(file.Name(), ".sub")
		if _, ok := tagToNodeList[tag]; !ok {
			err := os.Remove(filepath.Join(subscriptionDir, "persist.d", file.Name()))
			if err != nil {
				return nil, err
			}
		}
	}

	if len(tagToNodeList) == 0 {
		if resolvingfailed {
			log.Warnln("No node found because all subscription resolving failed.")
		} else {
			log.Warnln("No node found.")
		}
	}

	if len(conf.Global.LanInterface) == 0 && len(conf.Global.WanInterface) == 0 {
		log.Warnln("No interface to bind.")
	}

	if err = preprocessWanInterfaceAuto(conf); err != nil {
		return nil, err
	}

	c, err = control.NewControlPlane(
		bpf,
		tagToNodeList,
		conf.Group,
		&conf.Routing,
		&conf.Global,
		&conf.Dns,
		externGeoDataDirs,
	)
	if err != nil {
		return nil, err
	}
	// Call GC to release memory.
	runtime.GC()

	return c, nil
}

func preprocessWanInterfaceAuto(params *config.Config) error {
	// preprocess "auto".
	ifs := make([]string, 0, len(params.Global.WanInterface)+2)
	for _, ifname := range params.Global.WanInterface {
		if ifname == "auto" {
			defaultIfs, err := common.GetDefaultIfnames()
			if err != nil {
				return oops.Errorf("failed to convert 'auto': %w", err)
			}
			ifs = append(ifs, defaultIfs...)
		} else {
			ifs = append(ifs, ifname)
		}
	}
	params.Global.WanInterface = common.Deduplicate(ifs)
	return nil
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

func init() {
	rootCmd.AddCommand(runCmd)
}
