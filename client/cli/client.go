// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"encoding/json/v2"
	"fmt"
	"io"
	"strings"

	"github.com/daeuniverse/dae/api"
	"github.com/spf13/cobra"
)

func NewClientCommand() *cobra.Command {
	var connection Connection
	var flags diagnosticFlags
	var raw, joined bool
	root := &cobra.Command{Use: "client", Short: "Manage client MAC memberships and inspect their routing effects.", SilenceUsage: true}
	connection.Bind(root.PersistentFlags())
	flags.bind(root.PersistentFlags())
	root.PersistentFlags().BoolVar(&raw, "json", false, "Print the API response as JSON")
	root.PersistentFlags().BoolVar(&joined, "joined", true, "Desired membership for impact preview")
	for _, operation := range []string{"list", "show", "join", "leave", "impact", "device"} {
		args := cobra.ExactArgs(1)
		use := operation + " GROUP"
		if operation == "list" || operation == "device" {
			args, use = cobra.NoArgs, operation
		}
		command := &cobra.Command{Use: use, Args: args, Short: "Client " + operation + ".", RunE: func(cmd *cobra.Command, args []string) error {
			remote, err := connection.open()
			if err != nil {
				return err
			}
			defer remote.Close()
			if flags.self && flags.mac != "" {
				return fmt.Errorf("choose --self or --mac")
			}
			name := ""
			if len(args) != 0 {
				name = args[0]
			}
			var response any
			switch operation {
			case "list":
				if flags.self {
					response, err = remote.Device(cmd.Context())
				} else {
					response, err = remote.ClientGroups(cmd.Context())
				}
			case "show":
				if flags.self {
					device, readErr := remote.Device(cmd.Context())
					err = readErr
					if err == nil {
						found := false
						for _, set := range device.Sets {
							if set.Name == name {
								device.Sets = []api.ClientSetState{set}
								found = true
								break
							}
						}
						if !found {
							return fmt.Errorf("client set %q not found", name)
						}
						response = device
					}
				} else {
					response, err = remote.ClientGroup(cmd.Context(), name)
				}
			case "device":
				if flags.self {
					response, err = remote.Device(cmd.Context())
				} else if flags.mac != "" {
					response, err = remote.ManagedDevice(cmd.Context(), flags.mac)
				} else {
					return fmt.Errorf("specify --self or --mac")
				}
			case "join", "leave":
				if flags.self {
					response, err = remote.SetMembership(cmd.Context(), name, operation == "join")
				} else if flags.mac != "" {
					response, err = remote.SetClientMember(cmd.Context(), name, flags.mac, operation == "join")
				} else {
					return fmt.Errorf("specify --self or --mac")
				}
			case "impact":
				if !flags.self && flags.mac == "" {
					return fmt.Errorf("specify --self or --mac")
				}
				request, buildErr := flags.request(cmd, "flow", flags.target)
				if buildErr != nil {
					return buildErr
				}
				impact := api.ClientImpactRequest{Joined: new(joined), Context: request.Context}
				if flags.target != "" || flags.input != "" {
					impact.Flow = &request.Flow
				}
				response, err = remote.ClientImpact(cmd.Context(), name, impact, flags.self)
			}
			if err != nil {
				return err
			}
			return printClient(cmd.OutOrStdout(), response, raw)
		}}
		root.AddCommand(command)
	}
	mitm := &cobra.Command{Use: "mitm", Short: "Manage a device's HTTPS module override."}
	for _, action := range []string{"enable", "disable", "reset"} {
		mitm.AddCommand(&cobra.Command{Use: action, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			if flags.self == (flags.mac != "") {
				return fmt.Errorf("specify exactly one of --self or --mac")
			}
			remote, err := connection.open()
			if err != nil {
				return err
			}
			defer remote.Close()
			certificate, err := remote.Certificate(cmd.Context())
			if err != nil {
				return err
			}
			var enabled *bool
			if action != "reset" {
				enabled = new(action == "enable")
			}
			var response any
			if flags.self {
				if enabled == nil {
					response, err = remote.ResetMITM(cmd.Context(), certificate.Fingerprint)
				} else {
					response, err = remote.SetMITM(cmd.Context(), *enabled, certificate.Fingerprint)
				}
			} else {
				response, err = remote.SetManagedMITM(cmd.Context(), flags.mac, enabled, certificate.Fingerprint)
			}
			if err != nil {
				return err
			}
			return printClient(cmd.OutOrStdout(), response, raw)
		}})
	}
	root.AddCommand(mitm)
	return root
}

func printClient(w io.Writer, value any, raw bool) error {
	if raw {
		return json.MarshalWrite(w, value)
	}
	var output strings.Builder
	group := func(g api.ClientGroup) {
		fmt.Fprintf(&output, "%s · %s\n", diagnosticText(g.Name), diagnosticText(g.Description))
		for _, mac := range g.Members {
			fmt.Fprintf(&output, "  %s\n", mac)
		}
		if g.IPSet != "" {
			fmt.Fprintf(&output, "  ipset: %s\n", diagnosticText(g.IPSet))
		}
		if g.NFTSet != "" {
			fmt.Fprintf(&output, "  nftset: %s\n", diagnosticText(g.NFTSet))
		}
	}
	sets := func(mac string, values []api.ClientSetState) {
		fmt.Fprintln(&output, mac)
		for _, set := range values {
			fmt.Fprintf(&output, "  %s joined=%t · %s\n", diagnosticText(set.Name), set.Joined, diagnosticText(set.Description))
		}
	}
	switch result := value.(type) {
	case *api.ClientGroups:
		for _, entry := range result.Groups {
			group(entry)
		}
	case *api.ClientGroup:
		group(*result)
	case *api.DeviceState:
		sets(result.MAC, result.Sets)
		if result.MITM != nil {
			fmt.Fprintf(&output, "  MITM enabled=%t\n", result.MITM.Enabled)
		}
	case *api.ManagedDevice:
		sets(result.MAC, result.Sets)
		if result.MITMOverride == nil {
			fmt.Fprintln(&output, "  MITM: configuration default (depends on source IP)")
		} else {
			fmt.Fprintf(&output, "  MITM override=%t\n", *result.MITMOverride)
		}
	case *api.ClientImpact:
		fmt.Fprintf(&output, "%s: joined %t → %t; existing connections: %s\n", diagnosticText(result.Name), result.JoinedBefore, result.JoinedAfter, result.ConnectionBehavior)
		for _, rule := range result.Rules {
			fmt.Fprintf(&output, "  [%s] %s\n", diagnosticText(rule.Parent), diagnosticText(rule.Expression))
			for _, condition := range rule.Conditions {
				fmt.Fprintf(&output, "    %s: %s → %s\n", diagnosticText(condition.Expression), condition.Actual, condition.Expected)
			}
		}
		for _, export := range result.Exports {
			fmt.Fprintf(&output, "  Export: %s (external firewall rules are not evaluated)\n", diagnosticText(export))
		}
		if _, err := io.WriteString(w, output.String()); err != nil {
			return err
		}
		if result.Trace != nil {
			return printExplanation(w, result.Trace)
		}
		return nil
	default:
		return fmt.Errorf("unexpected client response %T", value)
	}
	_, err := io.WriteString(w, output.String())
	return err
}
