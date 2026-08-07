/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/daeuniverse/dae/cmd/internal"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/spf13/cobra"
)

const (
	reloadCommandTimeout = 3 * time.Minute
	reloadLegacyGrace    = 3 * time.Second
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
	legacyGrace  time.Duration
	pollInterval time.Duration
	processAlive func() error
	onProgress   func(string)
}

func waitForReload(opts reloadWaitOptions) (string, bool, error) {
	if opts.timeout <= 0 || opts.pollInterval <= 0 || opts.legacyGrace <= 0 {
		return "", false, fmt.Errorf("invalid reload wait timing")
	}
	deadline := time.NewTimer(opts.timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(opts.pollInterval)
	defer ticker.Stop()
	legacyAt := time.Now().Add(opts.legacyGrace)
	protocolObserved := false
	lastContent := ""

	for {
		code, content, err := readSignalProgressFile(opts.progressPath)
		if err != nil {
			return "", false, fmt.Errorf("failed to read reload progress: %w", err)
		}

		if opts.processAlive != nil {
			if err := opts.processAlive(); err != nil && !errors.Is(err, syscall.EPERM) {
				return "", false, fmt.Errorf("dae stopped while reloading: %w", err)
			}
		}

		switch code {
		case consts.ReloadSend:
			if protocolObserved {
				return "", false, fmt.Errorf("reload progress unexpectedly returned to the sent state")
			}
			if !time.Now().Before(legacyAt) {
				// Older daemons do not implement the progress protocol.
				return "OK", true, nil
			}
		case consts.ReloadProcessing:
			protocolObserved = true
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
			return content, false, nil
		case consts.ReloadError:
			if content == "" {
				content = "daemon reported that reload failed"
			}
			return "", false, errors.New(content)
		default:
			return "", false, fmt.Errorf("unexpected reload progress code %q", code)
		}

		select {
		case <-deadline.C:
			if lastContent != "" {
				return "", false, fmt.Errorf("reload timed out after %v (last step: %s)", opts.timeout, lastContent)
			}
			return "", false, fmt.Errorf("reload timed out after %v", opts.timeout)
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
			internal.AutoSu()
			if len(args) == 0 {
				_pid, err := os.ReadFile(PidFilePath)
				if err != nil {
					return fmt.Errorf("failed to read pid file: %w", err)
				}
				args = []string{strings.TrimSpace(string(_pid))}
			}
			pid, err := strconv.Atoi(args[0])
			if err != nil || pid <= 0 {
				return fmt.Errorf("invalid pid %q", args[0])
			}
			// Read the first line of SignalProgressFilePath.
			code, _, err := readSignalProgressFile(SignalProgressFilePath)
			if err == nil && code != consts.ReloadDone && code != consts.ReloadError {
				return fmt.Errorf("%v shows another reload operation is in progress", SignalProgressFilePath)
			}
			if err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("failed to inspect reload progress: %w", err)
			}
			abortMarkerCreated := false
			cleanupAbortMarker := func() {
				if abortMarkerCreated {
					_ = os.Remove(AbortFile)
				}
			}
			if abort {
				f, err := os.OpenFile(AbortFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
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
			if err = writeFileAtomic(SignalProgressFilePath, []byte{consts.ReloadSend}, 0644); err != nil {
				cleanupAbortMarker()
				return fmt.Errorf("failed to initialize reload progress: %w", err)
			}
			// Send signal.
			if err = syscall.Kill(pid, syscall.SIGUSR1); err != nil {
				cleanupAbortMarker()
				writeReloadState(consts.ReloadError, err.Error())
				return fmt.Errorf("failed to signal dae: %w", err)
			}

			result, legacy, err := waitForReload(reloadWaitOptions{
				progressPath: SignalProgressFilePath,
				timeout:      reloadCommandTimeout,
				legacyGrace:  reloadLegacyGrace,
				pollInterval: reloadPollInterval,
				processAlive: func() error { return syscall.Kill(pid, 0) },
				onProgress: func(content string) {
					fmt.Fprintln(cmd.OutOrStdout(), content)
				},
			})
			if err != nil {
				return err
			}
			if legacy {
				// Leave a terminal state behind; otherwise the next invocation
				// would mistake the old daemon's unchanged ReloadSend marker for
				// an operation still in progress.
				data := append([]byte{consts.ReloadDone}, []byte("\n"+result)...)
				if err = writeFileAtomic(SignalProgressFilePath, data, 0644); err != nil {
					return fmt.Errorf("failed to finalize legacy reload progress: %w", err)
				}
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
