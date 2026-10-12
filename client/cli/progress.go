// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"github.com/daeuniverse/dae/client/progress"
	"github.com/spf13/cobra"
)

func startProgress(cmd *cobra.Command, message string) *progress.Spinner {
	if raw, _ := cmd.Flags().GetBool("json"); raw {
		return new(progress.Spinner)
	}
	return progress.Start(cmd.ErrOrStderr(), message)
}

// WithProgress displays terminal feedback while work waits for the API. Work
// must return before printing results or prompting for input. JSON mode is quiet.
func WithProgress[T any](cmd *cobra.Command, message string, work func() (T, error)) (T, error) {
	spinner := startProgress(cmd, message)
	defer spinner.Stop()
	return work()
}
