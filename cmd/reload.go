/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/daeuniverse/dae/cmd/internal"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/internal/daemon"
	"github.com/spf13/cobra"
)

const (
	reloadCommandTimeout = 3 * time.Minute
	reloadPollInterval   = 200 * time.Millisecond
)

func readSignalProgressFile(path string) (code byte, content string, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, "", err
	}
	var firstLine string
	firstLine, content, _ = strings.Cut(string(b), "\n")
	if len(firstLine) != 1 {
		return 0, "", fmt.Errorf("unexpected format: %v", string(b))
	}
	code = firstLine[0]
	return code, content, nil
}

type reloadWaitOptions struct {
	progressPath string
	timeout      time.Duration
	pollInterval time.Duration
	processAlive func() error
	onProgress   func(string)
}

func waitForReload(opts reloadWaitOptions) (string, error) {
	deadline := time.NewTimer(opts.timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(opts.pollInterval)
	defer ticker.Stop()
	lastContent := ""

	for {
		code, content, err := readSignalProgressFile(opts.progressPath)
		if err != nil {
			return "", fmt.Errorf("failed to read reload progress: %w", err)
		}

		if opts.processAlive != nil {
			if err := opts.processAlive(); err != nil && !errors.Is(err, syscall.EPERM) {
				return "", fmt.Errorf("dae stopped while reloading: %w", err)
			}
		}

		switch code {
		case consts.ReloadSend:
			// Wait for the daemon to acknowledge the signal.
		case consts.ReloadProcessing:
			if content != "" && content != lastContent {
				lastContent = content
				if opts.onProgress != nil {
					opts.onProgress(content)
				}
			}
		case consts.ReloadDone:
			if content == "" {
				content = "OK"
			}
			return content, nil
		case consts.ReloadError:
			if content == "" {
				content = "daemon reported that reload failed"
			}
			return "", errors.New(content)
		default:
			return "", fmt.Errorf("unexpected reload progress code %q", code)
		}

		select {
		case <-deadline.C:
			if lastContent != "" {
				return "", fmt.Errorf("reload timed out after %v (last step: %s)", opts.timeout, lastContent)
			}
			return "", fmt.Errorf("reload timed out after %v", opts.timeout)
		case <-ticker.C:
		}
	}
}

var (
	abort     bool
	reloadCmd = &cobra.Command{
		Use:   "reload [pid]",
		Short: "To reload config file without interrupt connections.",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			if len(args) == 0 {
				_pid, err := os.ReadFile(daemon.PidFilePath)
				if err != nil {
					return fmt.Errorf("failed to read pid file: %w", err)
				}
				args = []string{strings.TrimSpace(string(_pid))}
			}
			pid, err := parsePositivePID(args[0])
			if err != nil {
				return err
			}
			if err := internal.AutoSu(); err != nil {
				return err
			}
			// Read the first line of SignalProgressFilePath.
			code, _, err := readSignalProgressFile(daemon.SignalProgressFilePath)
			if err == nil && code != consts.ReloadDone && code != consts.ReloadError {
				return fmt.Errorf("%v shows another reload operation is in progress", daemon.SignalProgressFilePath)
			}
			if err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("failed to inspect reload progress: %w", err)
			}
			abortMarkerCreated := false
			cleanupAbortMarker := func() {
				if abortMarkerCreated {
					_ = os.Remove(daemon.AbortFile)
				}
			}
			if abort {
				f, err := os.OpenFile(daemon.AbortFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
				if err != nil {
					return fmt.Errorf("failed to create abort marker: %w", err)
				}
				abortMarkerCreated = true
				if err = f.Close(); err != nil {
					cleanupAbortMarker()
					return fmt.Errorf("failed to close abort marker: %w", err)
				}
			}
			// Set the progress as ReloadSend.
			if err = daemon.WriteFileAtomic(daemon.SignalProgressFilePath, []byte{consts.ReloadSend}, 0600); err != nil {
				cleanupAbortMarker()
				return fmt.Errorf("failed to initialize reload progress: %w", err)
			}
			// Send signal.
			if err = syscall.Kill(pid, syscall.SIGUSR1); err != nil {
				cleanupAbortMarker()
				daemon.WriteReloadState(consts.ReloadError, err.Error())
				return fmt.Errorf("failed to signal dae: %w", err)
			}

			result, err := waitForReload(reloadWaitOptions{
				progressPath: daemon.SignalProgressFilePath,
				timeout:      reloadCommandTimeout,
				pollInterval: reloadPollInterval,
				processAlive: func() error { return syscall.Kill(pid, 0) },
				onProgress: func(content string) {
					fmt.Fprintln(cmd.OutOrStdout(), content)
				},
			})
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), result)
			return nil
		},
	}
)

func init() {
	rootCmd.AddCommand(reloadCmd)
	reloadCmd.PersistentFlags().BoolVarP(&abort, "abort", "a", false, "Abort established connections.")
}
