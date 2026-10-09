// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"encoding/json/v2"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/daeuniverse/dae/api"
	"github.com/spf13/cobra"
)

// NewSelectorCommand manages daemon-owned choices over the same API as the UI.
func NewSelectorCommand() *cobra.Command {
	var connection Connection
	var raw bool
	command := &cobra.Command{
		Use: "selector [GROUP]", Short: "List selector choices and candidates.",
		Args: cobra.MaximumNArgs(1), SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			remote, err := connection.open()
			if err != nil {
				return err
			}
			defer remote.Close()
			response, err := remote.Selectors(cmd.Context())
			if err != nil {
				return err
			}
			if len(args) != 0 {
				index := slices.IndexFunc(response.Selectors, func(group api.SelectorState) bool { return group.Name == args[0] })
				if index == -1 {
					return fmt.Errorf("selector %q not found", args[0])
				}
				return printSelector(cmd.OutOrStdout(), response.Selectors[index], raw)
			}
			if raw {
				return json.MarshalWrite(cmd.OutOrStdout(), response)
			}
			for _, group := range response.Selectors {
				if err := printSelector(cmd.OutOrStdout(), group, false); err != nil {
					return err
				}
			}
			if len(response.Selectors) == 0 {
				_, err = fmt.Fprintln(cmd.OutOrStdout(), "No active selector groups.")
			}
			return err
		},
	}
	connection.Bind(command.PersistentFlags())
	command.PersistentFlags().BoolVar(&raw, "json", false, "Print the API response as JSON")
	set := &cobra.Command{
		Use: "set GROUP NODE", Short: "Save a choice by exact node name or node ID.", Args: cobra.ExactArgs(2), SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			remote, err := connection.open()
			if err != nil {
				return err
			}
			defer remote.Close()
			response, err := remote.Selectors(cmd.Context())
			if err != nil {
				return err
			}
			index := slices.IndexFunc(response.Selectors, func(group api.SelectorState) bool { return group.Name == args[0] })
			if index == -1 {
				return fmt.Errorf("selector %q not found", args[0])
			}
			nodes := response.Selectors[index].Nodes
			id := ""
			if i := slices.IndexFunc(nodes, func(node api.SelectorNode) bool { return node.ID == args[1] }); i != -1 {
				id = nodes[i].ID
			} else {
				for _, node := range nodes {
					if node.Name != args[1] {
						continue
					}
					if id != "" {
						return fmt.Errorf("node name %q is ambiguous in selector %q; use a node ID from `selector %q`", args[1], args[0], args[0])
					}
					id = node.ID
				}
			}
			if id == "" {
				return fmt.Errorf("node %q not found in selector %q", args[1], args[0])
			}
			state, err := remote.SelectNode(cmd.Context(), args[0], id)
			if err != nil {
				return err
			}
			return printSelector(cmd.OutOrStdout(), *state, raw)
		},
	}
	reset := &cobra.Command{
		Use: "reset GROUP", Short: "Clear a saved choice and restore the configured default.", Args: cobra.ExactArgs(1), SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			remote, err := connection.open()
			if err != nil {
				return err
			}
			defer remote.Close()
			state, err := remote.ResetSelector(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return printSelector(cmd.OutOrStdout(), *state, raw)
		},
	}
	command.AddCommand(set, reset)
	return command
}

func printSelector(w io.Writer, group api.SelectorState, raw bool) error {
	if raw {
		return json.MarshalWrite(w, group)
	}
	var output strings.Builder
	fmt.Fprintf(&output, "%s\n", group.Name)
	if saved := group.SavedSelection; saved != nil {
		fmt.Fprintf(&output, "  Saved: %s (%s)\n", saved.Name, saved.Status)
		if saved.Status != "matched" {
			fmt.Fprintln(&output, "  Using the startup choice temporarily; the saved choice is retained.")
		}
	}
	table := tabwriter.NewWriter(&output, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "  \tID\tNAME\tSTATE")
	for _, node := range group.Nodes {
		selected := ""
		if node.ID == group.NodeID {
			selected = "*"
		}
		state := "not tested"
		switch {
		case node.Checking:
			state = "checking"
		case node.Tested && node.Healthy:
			state = "available"
		case node.Tested:
			state = "unavailable"
		}
		if node.ID == group.DefaultNodeID {
			state += ", default"
		}
		fmt.Fprintf(table, "  %s\t%s\t%s\t%s\n", selected, node.ID, node.Name, state)
	}
	if err := table.Flush(); err != nil {
		return err
	}
	_, err := io.WriteString(w, output.String())
	return err
}
