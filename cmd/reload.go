// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/api/client"
	"github.com/daeuniverse/dae/client/cli"
	"github.com/daeuniverse/dae/client/progress"
	"github.com/daeuniverse/dae/cmd/internal"
	"github.com/daeuniverse/dae/internal/handoff"
	"github.com/spf13/cobra"
)

const (
	reloadCommandTimeout = 4 * time.Minute
	reloadPollInterval   = 200 * time.Millisecond
)

type operationWaitOptions struct {
	id, kind              string
	timeout, pollInterval time.Duration
	poll                  func(context.Context, string) (*api.Operation, error)
	onProgress            func(string)
	replacing             bool
}

// A client timeout stops waiting only. It cannot cancel or overwrite another
// transaction, and an expired or previous-daemon ID is an explicit failure.
func waitForOperation(ctx context.Context, opts operationWaitOptions) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, opts.timeout)
	defer cancel()
	ticker := time.NewTicker(opts.pollInterval)
	defer ticker.Stop()
	lastProgress := ""
	for {
		status, err := opts.poll(ctx, opts.id)
		if ctx.Err() != nil {
			break
		}
		if err != nil {
			if !retryOperationPoll(err, opts.replacing) {
				return "", fmt.Errorf("read %s operation %s: %w", opts.kind, opts.id, err)
			}
		} else {
			if status == nil || status.ID != opts.id || status.Kind != opts.kind {
				return "", fmt.Errorf("daemon returned a different %s operation", opts.kind)
			}
			if status.Progress != "" && status.Progress != lastProgress {
				lastProgress = status.Progress
				if opts.onProgress != nil {
					opts.onProgress(lastProgress)
				}
			}
			switch status.State {
			case "completed":
				if status.Result == "" {
					return "OK", nil
				}
				return status.Result, nil
			case "failed", "canceled":
				if status.Error == "" {
					return "", fmt.Errorf("%s %s", opts.kind, status.State)
				}
				return "", errors.New(status.Error)
			case "queued", "running":
			default:
				return "", fmt.Errorf("unexpected operation state %q", status.State)
			}
		}
		select {
		case <-ctx.Done():
		case <-ticker.C:
			continue
		}
		break
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		if lastProgress != "" {
			return "", fmt.Errorf("%s timed out after %v (operation %s; last step: %s)", opts.kind, opts.timeout, opts.id, lastProgress)
		}
		return "", fmt.Errorf("%s timed out after %v (operation %s)", opts.kind, opts.timeout, opts.id)
	}
	return "", ctx.Err()
}

func retryOperationPoll(err error, replacing bool) bool {
	if response, ok := errors.AsType[*client.Error](err); ok {
		return response.StatusCode == http.StatusServiceUnavailable
	}
	if !replacing {
		return false
	}
	_, transport := errors.AsType[net.Error](err)
	return transport || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

func newReloadCommand(suspend bool) *cobra.Command {
	kind, description := "reload", "To reload config file without interrupt connections."
	if suspend {
		kind, description = "suspend", "To suspend dae. This command puts dae into no-load state. Recover it by 'dae reload'."
	}
	var connection cli.Connection
	var abort bool
	var replace bool
	var binary string
	command := &cobra.Command{
		Use:   kind,
		Short: description,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Flags().Changed("binary") && binary == "" {
				return errors.New("--binary requires a non-empty path")
			}
			return runReloadCommand(cmd, &connection, kind, abort, replace, binary)
		},
	}
	connection.Bind(command.PersistentFlags())
	command.PersistentFlags().BoolVarP(&abort, "abort", "a", false, "Abort established connections.")
	if !suspend {
		command.PersistentFlags().BoolVar(&replace, "replace", false, "Replace the local daemon even when its executable is unchanged.")
		command.PersistentFlags().StringVar(&binary, "binary", "", "Replace the local daemon with the executable at this path.")
		command.Short = "Reload configuration, or replace the local daemon when the executable has changed."
	}
	return command
}

func runReloadCommand(cmd *cobra.Command, connection *cli.Connection, kind string, abort, force bool, binary string) error {
	cmd.SilenceUsage = true
	request := api.OperationRequest{Kind: kind, Abort: abort}
	remote, err := connection.Open()
	if err != nil {
		return err
	}
	defer remote.Close()
	if kind == "reload" {
		request.Replace = force
		if remote.Local() {
			request.ExecutablePID = os.Getpid()
			if binary != "" {
				if err := authorizeBinaryReload(cmd, remote, binary); err != nil {
					return err
				}
				executable, err := handoff.OpenExecutable(binary)
				if err != nil {
					return err
				}
				defer executable.Close()
				request.ExecutableFD = int(executable.Fd())
			}
		} else if binary != "" {
			return errors.New("--binary requires a local Unix API socket")
		} else if request.Replace {
			return errors.New("--replace requires a local Unix API socket")
		}
	}
	status, err := remote.SubmitOperation(cmd.Context(), request)
	if err != nil {
		// Only a local permission failure needs elevation. Remote APIs use
		// their configured credentials and must keep the caller's environment.
		if remote.Local() && binary == "" && errors.Is(err, os.ErrPermission) {
			if elevateErr := internal.AutoSu(); elevateErr != nil {
				return elevateErr
			}
		}
		return err
	}
	spinner := progress.Start(cmd.ErrOrStderr(), "Waiting for "+kind+"...")
	defer spinner.Stop()
	result, err := waitForOperation(cmd.Context(), operationWaitOptions{
		id: status.ID, kind: kind, timeout: reloadCommandTimeout, pollInterval: reloadPollInterval,
		poll:      remote.Operation,
		replacing: request.ExecutablePID != 0,
		onProgress: func(content string) {
			if spinner.Enabled() {
				spinner.Update(content)
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), content)
			}
		},
	})
	spinner.Stop()
	if err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), result)
	return nil
}

// Establish socket access before opening the candidate, so elevation never
// reopens a file the original process has already selected.
func authorizeBinaryReload(cmd *cobra.Command, remote *client.Client, binary string) error {
	if os.Geteuid() == 0 {
		return nil
	}
	_, denied := remote.ResourceRefreshStatus(cmd.Context())
	if !errors.Is(denied, os.ErrPermission) {
		return denied
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	if !filepath.IsAbs(binary) {
		dir, err := os.Getwd()
		if err != nil {
			return err
		}
		// Keep ".." after symlinks for the kernel to resolve at selection time.
		binary = dir + "/" + binary
	}
	flags := cmd.Flags()
	if err := flags.Set("binary", binary); err != nil {
		return err
	}
	// Privilege helpers need not retain DAE_API_ENDPOINT or the working directory.
	if err := flags.Set("api", flags.Lookup("api").Value.String()); err != nil {
		return err
	}
	return errors.Join(denied, internal.AutoSu(append([]string{executable}, commandArguments(cmd)...)...))
}
