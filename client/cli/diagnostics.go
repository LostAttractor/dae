// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"encoding/json/v2"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/api"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type diagnosticFlags struct {
	self                                                                                       bool
	mac, source, iface, policy, origin, protocol, sni, targetIP, target, input, network, qtype string
	sport, dscp                                                                                int
	join, leave                                                                                []string
}

func (f *diagnosticFlags) bind(flags *pflag.FlagSet) {
	flags.BoolVar(&f.self, "self", false, "Inherit the verified LAN device visiting the API")
	flags.StringVar(&f.mac, "mac", "", "Source MAC and its current memberships")
	flags.StringVar(&f.source, "source-ip", "", "Source IP")
	flags.IntVar(&f.sport, "source-port", 0, "Source port (omitted means unknown)")
	flags.StringVar(&f.iface, "interface", "", "Ingress interface")
	flags.StringVar(&f.policy, "policy", "", "Override the selected active routing policy")
	flags.StringVar(&f.origin, "origin", "lan", "Flow origin: lan, local or daemon")
	flags.IntVar(&f.dscp, "dscp", 0, "DSCP (omitted means unknown)")
	flags.StringVar(&f.protocol, "protocol", "tcp", "Transport protocol: tcp or udp")
	flags.StringVar(&f.sni, "sni", "", "TLS hostname (an explicit empty value means absent)")
	flags.StringVar(&f.targetIP, "dst-ip", "", "Destination IP, without resolving a hostname")
	flags.StringVar(&f.target, "target", "", "Optional IP:port, domain:port or HTTP(S) URL")
	flags.StringVar(&f.input, "input", "", "Read the complete request JSON from a file, or - for stdin")
	flags.StringVar(&f.network, "network", "", "Outbound network: tcp4, tcp6, udp4 or udp6")
	flags.StringVar(&f.qtype, "qtype", "A", "DNS question type")
	flags.StringSliceVar(&f.join, "join", nil, "Compare with membership in these client sets")
	flags.StringSliceVar(&f.leave, "leave", nil, "Compare without membership in these client sets")
}

func (f *diagnosticFlags) request(cmd *cobra.Command, kind, target string) (api.ExplainRequest, error) {
	request := api.ExplainRequest{Kind: kind, Context: api.DiagnosticContext{MAC: f.mac, SourceIP: f.source, Interface: f.iface, Policy: f.policy, Origin: f.origin}, Flow: api.DiagnosticFlow{Protocol: f.protocol}, Network: f.network, Detail: "predicates"}
	if f.input != "" {
		var reader io.Reader = cmd.InOrStdin()
		if f.input != "-" {
			file, err := os.Open(f.input)
			if err != nil {
				return request, err
			}
			defer file.Close()
			reader = file
		}
		data, err := io.ReadAll(io.LimitReader(reader, (64<<10)+1))
		if err != nil {
			return request, err
		}
		if len(data) > 64<<10 {
			return request, fmt.Errorf("input exceeds 64 KiB")
		}
		if err := json.Unmarshal(data, &request, json.RejectUnknownMembers(true)); err != nil {
			return request, err
		}
		return request, nil
	}
	if f.self {
		if f.mac != "" || f.source != "" || f.iface != "" || f.policy != "" || cmd.Flags().Changed("origin") {
			return request, fmt.Errorf("--self inherits identity and cannot be combined with source identity overrides")
		}
		request.Context.Origin = ""
	}
	if cmd.Flags().Changed("source-port") {
		request.Context.SourcePort = new(f.sport)
	}
	if cmd.Flags().Changed("dscp") {
		request.Context.DSCP = new(f.dscp)
	}
	if cmd.Flags().Changed("sni") {
		request.Flow.SNI = new(f.sni)
	}
	if kind == "outbound" {
		request.Outbound = target
		target = f.target
	}
	if kind == "dns" {
		request.DNS = &api.DiagnosticDNS{Name: target, Type: f.qtype}
		target = f.target
		if !cmd.Flags().Changed("protocol") {
			request.Flow.Protocol = "udp"
		}
	}
	if target == "" {
		target = f.target
	}
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		request.Flow.HTTP = &api.DiagnosticHTTP{URL: target, Method: "GET"}
	} else if target != "" {
		host, port, err := net.SplitHostPort(target)
		if err != nil {
			if kind != "domain" && kind != "plugins" {
				return request, fmt.Errorf("target requires IP:port, domain:port or an HTTP(S) URL")
			}
			host = target
		} else {
			request.Flow.Destination.Port, err = strconv.Atoi(port)
			if err != nil {
				return request, err
			}
		}
		if ip, err := netip.ParseAddr(host); err == nil {
			request.Flow.Destination.IP = ip.String()
		} else {
			request.Flow.Destination.Domain = host
		}
	}
	if f.targetIP != "" {
		request.Flow.Destination.IP = f.targetIP
	}
	if len(f.join)+len(f.leave) > 0 {
		request.Compare = &api.DiagnosticAssumptions{ClientSets: make(map[string]bool)}
		for _, name := range f.join {
			request.Compare.ClientSets[name] = true
		}
		for _, name := range f.leave {
			if request.Compare.ClientSets[name] {
				return request, fmt.Errorf("client set %q appears in both --join and --leave", name)
			}
			request.Compare.ClientSets[name] = false
		}
	}
	return request, nil
}

func NewExplainCommand() *cobra.Command {
	var connection Connection
	var flags diagnosticFlags
	var raw bool
	root := &cobra.Command{Use: "explain", Short: "Explain routing and subsystem decisions without sending traffic.", SilenceUsage: true}
	connection.Bind(root.PersistentFlags())
	flags.bind(root.PersistentFlags())
	root.PersistentFlags().BoolVar(&raw, "json", false, "Print the complete structured explanation")
	for _, command := range []struct{ name, kind string }{{"route", "flow"}, {"dns", "dns"}, {"domain", "domain"}, {"outbound", "outbound"}, {"plugins", "plugins"}} {
		child := &cobra.Command{Use: command.name + " [TARGET]", Short: "Explain " + command.name + " decisions.", Args: cobra.MaximumNArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
			target := ""
			if len(args) != 0 {
				target = args[0]
			}
			request, err := flags.request(cmd, command.kind, target)
			if err != nil {
				return err
			}
			remote, err := connection.open()
			if err != nil {
				return err
			}
			defer remote.Close()
			response, err := remote.Explain(cmd.Context(), request, flags.self)
			if err != nil {
				return err
			}
			if raw {
				return json.MarshalWrite(cmd.OutOrStdout(), response)
			}
			return printExplanation(cmd.OutOrStdout(), response)
		}}
		root.AddCommand(child)
	}
	return root
}

func diagnosticText(value string) string {
	return strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return ' '
		}
		return r
	}, value)), " ")
}

func printExplanation(w io.Writer, response *api.ExplainResponse) error {
	var output strings.Builder
	fmt.Fprintf(&output, "Generation %d · %s\n", response.Generation, response.ObservedAt.Format("2006-01-02T15:04:05Z07:00"))
	for _, field := range response.Context {
		fmt.Fprintf(&output, "  %s: %s [%s]\n", diagnosticText(field.Name), diagnosticText(field.Value), field.Source)
	}
	printResult := func(label string, result api.ExplainResult) {
		d := result.Decision
		fmt.Fprintf(&output, "\n%s: %s · outbound=%s · target=%s · mark=%d · must=%t · complete=%t\n", label, d.Verdict, diagnosticText(d.Outbound), diagnosticText(strings.Join(d.Targets, ", ")), d.Mark, d.Must, d.Complete)
		if len(d.Missing) != 0 {
			fmt.Fprintf(&output, "  Required context: %s\n", strings.Join(d.Missing, ", "))
		}
		for _, step := range result.Steps {
			fmt.Fprintf(&output, "  [%s] %s: %s (%s; %s)\n", step.Status, step.Stage, diagnosticText(step.Expression), step.Match, diagnosticText(step.Reason))
			for _, source := range step.Sources {
				fmt.Fprintf(&output, "    %s:%d:%d %s\n", diagnosticText(source.File), source.Line, source.Column, diagnosticText(source.Expression))
			}
			for _, condition := range step.Conditions {
				fmt.Fprintf(&output, "    [%s/%s] %s: %s; actual=%s\n", condition.Match, condition.Status, diagnosticText(condition.Expression), diagnosticText(condition.Reason), diagnosticText(condition.Actual))
			}
		}
		for _, evidence := range result.Domains {
			fmt.Fprintf(&output, "  DNS %s → %s resident=%t [%s]\n", diagnosticText(evidence.Domain), evidence.IP, evidence.Resident, evidence.Source)
		}
		for _, outbound := range result.Outbounds {
			fmt.Fprintf(&output, "  Outbound %s (%s, %s) available=%t random=%t\n", diagnosticText(outbound.Name), outbound.Policy, outbound.Network, outbound.Available, outbound.Random)
			for _, node := range outbound.Nodes {
				fmt.Fprintf(&output, "    %s: %s\n", diagnosticText(node.Name), node.Reason)
			}
		}
		for _, note := range result.Notes {
			fmt.Fprintf(&output, "  %s\n", diagnosticText(note))
		}
	}
	printResult("Current", response.Current)
	if response.Compared != nil {
		printResult("Comparison", *response.Compared)
	}
	_, err := io.WriteString(w, output.String())
	return err
}
