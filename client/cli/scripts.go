// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"strings"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/client/status"
	"github.com/spf13/cobra"
)

type ScriptTrigger func(context.Context, string, api.ScriptRunRequest) (*api.ScriptRunResponse, error)

// NewSurgeListCommand requires a non-nil daemon status source.
func NewSurgeListCommand(fetch MITMSource) *cobra.Command {
	var module string
	var raw bool
	command := &cobra.Command{
		Use: "list", Short: "List configured cron and generic scripts.",
		Long: `List manually runnable scripts from the daemon, including their instance, module, type and current state.
Use --instance and --module to narrow the list, then run a script by its SCRIPT name.`,
		Args: cobra.NoArgs, SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			tasks, err := surgeScriptTasks(cmd.Context(), fetch, module)
			if err != nil {
				return err
			}
			if raw {
				return json.MarshalWrite(cmd.OutOrStdout(), tasks)
			}
			if _, err := fmt.Fprintln(cmd.OutOrStdout(), status.RenderSurgeScriptTasks(tasks)); err != nil {
				return err
			}
			if len(tasks) != 0 {
				_, err = fmt.Fprintf(cmd.OutOrStdout(), "\nRun a script with:\n  %srun <SCRIPT> --instance <INSTANCE> --module <MODULE>\n",
					strings.TrimSuffix(cmd.CommandPath(), "list"))
			}
			return err
		},
	}
	command.Flags().StringVar(&module, "module", "", "List only scripts in this module")
	command.Flags().BoolVar(&raw, "json", false, "Print the task list as JSON")
	return command
}

// NewSurgeRunCommand requires non-nil daemon status and trigger callbacks.
func NewSurgeRunCommand(fetch MITMSource, trigger ScriptTrigger) *cobra.Command {
	var module string
	var raw bool
	command := &cobra.Command{
		Use: "run <script>", Short: "Trigger one configured cron or generic script in the daemon.",
		Long: `Trigger an existing cron or generic script in the running daemon and return its acceptance.
Use list to discover script names and status to inspect completion.
--module and --instance select ambiguous names.`,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("script name is required; use %q to list configured script tasks", strings.TrimSuffix(cmd.CommandPath(), "run")+"list")
			}
			return cobra.ExactArgs(1)(cmd, args)
		},
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			response, err := triggerSurgeScript(cmd.Context(), fetch, trigger, api.ScriptRunRequest{Module: module, Script: args[0]})
			if err != nil {
				return err
			}
			if raw {
				return json.MarshalWrite(cmd.OutOrStdout(), response)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Accepted %s %s/%s/%s (run %d).\n", response.Status.Type, response.Instance, response.Module, response.Status.Name, response.Run)
			return err
		},
	}
	command.Flags().StringVar(&module, "module", "", "Select a module when the script name is not unique")
	command.Flags().BoolVar(&raw, "json", false, "Print the acceptance snapshot as JSON")
	return command
}

// triggerSurgeScript resolves a unique task from reports before issuing one API mutation.
func triggerSurgeScript(ctx context.Context, fetch MITMSource, trigger ScriptTrigger, request api.ScriptRunRequest) (*api.ScriptRunResponse, error) {
	tasks, err := surgeScriptTasks(ctx, fetch, request.Module)
	if err != nil {
		return nil, err
	}
	var selected *status.SurgeScriptTask
	for i := range tasks {
		task := &tasks[i]
		if task.Name != request.Script {
			continue
		}
		if selected != nil {
			return nil, fmt.Errorf("script task %q is ambiguous; specify --instance and --module", request.Script)
		}
		selected = task
	}
	if selected == nil {
		return nil, fmt.Errorf("script task %q not found; use surge list to see configured tasks", request.Script)
	}
	request.Module = selected.Module
	return trigger(ctx, selected.Instance, request)
}

// Both list and run discover tasks from the same scoped daemon snapshot.
func surgeScriptTasks(ctx context.Context, fetch MITMSource, module string) ([]status.SurgeScriptTask, error) {
	instances, err := fetch(ctx)
	if err != nil {
		return nil, err
	}
	report, err := status.Surge(instances)
	if err != nil {
		return nil, err
	}
	tasks := make([]status.SurgeScriptTask, 0)
	for _, m := range report.Modules {
		if module != "" && module != m.Name {
			continue
		}
		for _, job := range m.Tasks {
			tasks = append(tasks, status.SurgeScriptTask{Instance: m.Instance, Module: m.Name, ScriptTaskStatus: job})
		}
	}
	return tasks, nil
}
