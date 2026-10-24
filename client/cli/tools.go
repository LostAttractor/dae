// SPDX-License-Identifier: AGPL-3.0-only
package cli

import (
	"encoding/json/v2"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/spf13/cobra"
)

func NewCertificateCommand() *cobra.Command {
	var connection Connection
	root := &cobra.Command{Use: "certificate", Short: "Download the CA or verify trust and MITM from this client."}
	connection.Bind(root.PersistentFlags())
	for _, action := range []string{"info", "download", "verify", "verify-mitm"} {
		var format, output string
		command := &cobra.Command{Use: action, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			remote, err := connection.Open()
			if err != nil {
				return err
			}
			defer remote.Close()
			if action == "download" {
				return downloadOutput(output, cmd.OutOrStdout(), func(out io.Writer) error {
					return remote.DownloadCertificate(cmd.Context(), format, out)
				})
			}
			var value any
			switch action {
			case "info":
				value, err = remote.Certificate(cmd.Context())
			case "verify":
				value, err = remote.VerifyCertificate(cmd.Context())
			case "verify-mitm":
				value, err = remote.VerifyMITM(cmd.Context())
			}
			if err != nil {
				return err
			}
			return json.MarshalWrite(cmd.OutOrStdout(), value)
		}}
		if action == "download" {
			command.Flags().StringVar(&format, "format", "pem", "pem, cer or mobileconfig")
			command.Flags().StringVarP(&output, "output", "o", "", "Output file (default stdout)")
		}
		root.AddCommand(command)
	}
	return root
}
func NewPprofCommand() *cobra.Command {
	connection := Connection{timeout: time.Minute}
	var output string
	var seconds int
	command := &cobra.Command{Use: "pprof PROFILE", Short: "Download a standard profile for go tool pprof or go tool trace.", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		remote, err := connection.Open()
		if err != nil {
			return err
		}
		defer remote.Close()
		return downloadOutput(output, cmd.OutOrStdout(), func(out io.Writer) error {
			return remote.Profile(cmd.Context(), args[0], seconds, out)
		})
	}}
	connection.Bind(command.Flags())
	command.Flags().IntVar(&seconds, "seconds", 0, "Sampling duration; set --timeout longer than the capture")
	command.Flags().StringVarP(&output, "output", "o", "", "Output file (default stdout)")
	return command
}

// Replace the destination only after the complete download has been written.
func downloadOutput(path string, stdout io.Writer, download func(io.Writer) error) error {
	if path == "" {
		return download(stdout)
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".dae-download-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err := download(file); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

func NewOperationCommand() *cobra.Command {
	var connection Connection
	var abort bool
	root := &cobra.Command{Use: "operation", Short: "Submit daemon operations or query their results."}
	connection.Bind(root.PersistentFlags())
	for _, kind := range []string{"reload", "suspend", "refresh", "get"} {
		command := &cobra.Command{Use: kind, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
			remote, err := connection.Open()
			if err != nil {
				return err
			}
			defer remote.Close()
			var result *api.Operation
			if kind == "get" {
				result, err = remote.Operation(cmd.Context(), args[0])
			} else {
				result, err = remote.SubmitOperation(cmd.Context(), api.OperationRequest{Kind: kind, Abort: abort})
			}
			if err != nil {
				return err
			}
			if err = json.MarshalWrite(cmd.OutOrStdout(), result); err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout())
			return err
		}}
		if kind == "get" {
			command.Use = "get ID"
			command.Args = cobra.ExactArgs(1)
		}
		if kind == "reload" || kind == "suspend" {
			command.Flags().BoolVar(&abort, "abort", false, "Interrupt existing connections")
		}
		root.AddCommand(command)
	}
	root.AddCommand(&cobra.Command{Use: "resources", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		remote, err := connection.Open()
		if err != nil {
			return err
		}
		defer remote.Close()
		result, err := remote.ResourceRefreshStatus(cmd.Context())
		if err != nil {
			return err
		}
		return json.MarshalWrite(cmd.OutOrStdout(), result)
	}})
	return root
}
