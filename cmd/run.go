// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/daeuniverse/dae/cmd/internal"
	"github.com/daeuniverse/dae/common/netutils"
	"github.com/daeuniverse/dae/common/resource"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/internal/daemon"
	"github.com/daeuniverse/dae/pkg/logger"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/natefinch/lumberjack.v2"
)

func init() {
	log.SetFormatter(logger.NewTextFormatter(false))
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

func newRunCommand(definitions map[string]plugin.Definition) *cobra.Command {
	runCmd := &cobra.Command{
		Use:   "run",
		Short: "To run dae in the foreground.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			log.SetFormatter(logger.NewTextFormatter(disableTimestamp))
			if cfgFile == "" {
				return errors.New("argument --config or -c is required")
			}
			if disableAuthSudo && os.Geteuid() != 0 {
				return errors.New("auto-sudo is disabled and current user is not root")
			}
			// Require "sudo" if necessary.
			if !disableAuthSudo {
				if err := internal.AutoSu(); err != nil {
					return err
				}
			}

			// Read config from --config cfgFile.
			conf, includes, err := config.Load(cfgFile)
			if err != nil {
				return fmt.Errorf("read config: %w", err)
			}
			// AutoSu has returned in the final privileged process. Install the
			// process-global resolver before constructors can resolve hostnames.
			resolver, err := netutils.InstallDefaultResolver(conf.Global.SoMarkFromDae, conf.Global.DNSResolver)
			if err != nil {
				return fmt.Errorf("configure marked resolver: %w", err)
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

			log.WithField("files", includes).Debug("Loaded configuration files")
			err = daemon.Run(conf, []string{filepath.Dir(cfgFile)}, definitions, resolver, daemon.Options{
				ConfigFile: cfgFile, Version: Version, DisableTimestamp: disableTimestamp, DisablePidFile: disablePidFile,
			})
			if err != nil {
				// Own the terminal error here so Cobra does not print it again.
				cmd.SilenceErrors = true
				err = resource.RedactError(err)
				log.WithError(err).Error("Daemon stopped with an error")
			}
			return err
		},
	}
	runCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "Config file of dae.(required)")
	runCmd.PersistentFlags().StringVar(&logFile, "logfile", "", "Log file to write. Empty means stderr.")
	runCmd.PersistentFlags().IntVar(&logFileMaxSize, "logfile-maxsize", 30, "Unit: MB. The maximum size in megabytes of the log file before it gets rotated.")
	runCmd.PersistentFlags().IntVar(&logFileMaxBackups, "logfile-maxbackups", 3, "The maximum number of old log files to retain.")
	runCmd.PersistentFlags().BoolVar(&disableTimestamp, "disable-timestamp", false, "Disable timestamp.")
	runCmd.PersistentFlags().BoolVar(&disablePidFile, "disable-pidfile", false, "Not generate /var/run/dae.pid.")
	runCmd.PersistentFlags().BoolVar(&disableAuthSudo, "disable-sudo", false, "Disable sudo prompt ,may cause startup failure due to insufficient permissions")
	return runCmd
}
