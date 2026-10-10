// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"cmp"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common/consts"
	dns "github.com/miekg/dns"
)

func prepareDiagnosticRequest(request *api.ExplainRequest) error {
	if request.DNS != nil {
		value := *request.DNS
		request.DNS = &value
	}
	request.Kind = cmp.Or(request.Kind, "flow")
	switch request.Kind {
	case "flow", "dns", "domain", "outbound", "plugins":
	default:
		return fmt.Errorf("kind must be flow, dns, domain, outbound or plugins")
	}
	if request.Detail != "" && request.Detail != "rules" && request.Detail != "predicates" {
		return fmt.Errorf("detail must be rules or predicates")
	}
	flow := &request.Flow
	flow.Protocol = cmp.Or(flow.Protocol, "tcp")
	if flow.Protocol != "tcp" && flow.Protocol != "udp" {
		return fmt.Errorf("protocol must be tcp or udp")
	}
	if request.Context.Origin == "" {
		request.Context.Origin = "lan"
	}
	if request.Context.Origin != "lan" && request.Context.Origin != "local" && request.Context.Origin != "daemon" {
		return fmt.Errorf("origin must be lan, local or daemon")
	}
	if request.Context.Origin == "lan" && request.Context.ProcessName != nil && *request.Context.ProcessName != "" {
		return fmt.Errorf("LAN ingress does not supply process identity")
	}
	if request.Context.Mark != nil && *request.Context.Mark != 0 {
		return fmt.Errorf("nonzero input marks require a specific local hook; only rule-generated marks are supported")
	}
	if request.Context.SourcePort != nil && (*request.Context.SourcePort < 0 || *request.Context.SourcePort > 65535) {
		return fmt.Errorf("invalid source_port")
	}
	if request.Context.DSCP != nil && (*request.Context.DSCP < 0 || *request.Context.DSCP > 63) {
		return fmt.Errorf("dscp must be in 0..63")
	}
	if request.Context.ProcessName != nil && (len(*request.Context.ProcessName) > 15 || strings.ContainsRune(*request.Context.ProcessName, 0)) {
		return fmt.Errorf("process_name must fit Linux comm (15 bytes)")
	}
	if request.Context.MAC != "" {
		mac, err := diagnosticMAC(request.Context.MAC)
		if err != nil {
			return err
		}
		request.Context.MAC = net.HardwareAddr(mac[:]).String()
	}
	if request.Context.SourceIP != "" {
		if _, err := diagnosticAddress(request.Context.SourceIP); err != nil {
			return err
		}
	}
	if request.Context.Interface != "" {
		iface, err := net.InterfaceByName(request.Context.Interface)
		if err != nil {
			return fmt.Errorf("interface: %w", err)
		}
		if request.Context.IfIndex != nil && *request.Context.IfIndex != uint32(iface.Index) {
			return fmt.Errorf("interface and ifindex disagree")
		}
		request.Context.IfIndex = new(uint32(iface.Index))
	}
	if flow.HTTP != nil {
		u, err := url.Parse(flow.HTTP.URL)
		if err != nil || u.Hostname() == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("http.url must be an absolute HTTP(S) URL without credentials")
		}
		if flow.Destination.Domain == "" {
			flow.Destination.Domain = u.Hostname()
		}
		if flow.Destination.Port == 0 {
			flow.Destination.Port = 80
			if u.Scheme == "https" {
				flow.Destination.Port = 443
			}
			if u.Port() != "" {
				flow.Destination.Port, err = strconv.Atoi(u.Port())
				if err != nil {
					return fmt.Errorf("invalid URL port")
				}
			}
		}
	}
	if flow.Destination.IP != "" {
		if _, err := diagnosticAddress(flow.Destination.IP); err != nil {
			return err
		}
	}
	if flow.Destination.Port < 0 || flow.Destination.Port > 65535 {
		return fmt.Errorf("invalid destination port")
	}
	for _, name := range []string{flow.Destination.Domain, diagnosticHostname(*request)} {
		if len(name) > 253 || strings.ContainsAny(name, "\x00\r\n /\\") {
			return fmt.Errorf("invalid hostname")
		}
	}
	if request.Compare != nil {
		for _, binding := range request.Compare.Bindings {
			if _, err := diagnosticAddress(binding.IP); err != nil {
				return err
			}
			for _, name := range binding.Domains {
				if name == "" || len(name) > 253 || strings.ContainsAny(name, "\x00\r\n /\\") {
					return fmt.Errorf("invalid assumed domain")
				}
			}
		}
	}
	if request.Kind == "dns" && (request.DNS == nil || request.DNS.Name == "") {
		return fmt.Errorf("dns.name is required")
	}
	if q := request.DNS; q != nil {
		if _, ok := dns.IsDomainName(q.Name); !ok || strings.ContainsAny(q.Name, "\x00\r\n ") {
			return fmt.Errorf("invalid dns.name")
		}
		q.Name = dns.CanonicalName(q.Name)
		q.Type = strings.ToUpper(cmp.Or(q.Type, "A"))
		if _, ok := dns.StringToType[q.Type]; !ok {
			return fmt.Errorf("unknown DNS type %q", q.Type)
		}
		q.Class = strings.ToUpper(cmp.Or(q.Class, "IN"))
		if _, ok := dns.StringToClass[q.Class]; !ok {
			return fmt.Errorf("unknown DNS class %q", q.Class)
		}
		if q.UDPSize < 0 || q.UDPSize > 65535 {
			return fmt.Errorf("invalid DNS UDP size")
		}
		if q.RCode != nil && (*q.RCode < 0 || *q.RCode > 4095) {
			return fmt.Errorf("invalid DNS response code")
		}
		for _, ip := range q.AnswerIPs {
			if _, err := diagnosticAddress(ip); err != nil {
				return err
			}
		}
	}
	return nil
}

func diagnosticHostname(request api.ExplainRequest) string {
	if request.Flow.SNI != nil {
		return strings.TrimSuffix(strings.ToLower(*request.Flow.SNI), ".")
	}
	if request.Flow.HTTP != nil {
		if u, err := url.Parse(request.Flow.HTTP.URL); err == nil {
			return strings.ToLower(u.Hostname())
		}
	}
	if request.Context.Origin == "daemon" {
		return strings.TrimSuffix(strings.ToLower(request.Flow.Destination.Domain), ".")
	}
	return ""
}

func diagnosticInput(request api.ExplainRequest, matcher *RoutingMatcher) (routingInput, map[string]bool, []api.DiagnosticField, error) {
	input := routingInput{kernel: request.Context.Origin != "daemon", l4proto: consts.L4ProtoType_TCP}
	if request.Flow.Protocol == "udp" {
		input.l4proto = consts.L4ProtoType_UDP
	}
	missing := make(map[string]bool)
	fields := make([]api.DiagnosticField, 0)
	add := func(name, value, source string, known bool) {
		if !known {
			missing[name], source, value = true, "unknown", ""
		}
		fields = append(fields, api.DiagnosticField{Name: name, Value: value, Source: source})
	}
	dst := netip.IPv4Unspecified()
	if request.Flow.Destination.IP != "" {
		dst, _ = diagnosticAddress(request.Flow.Destination.IP)
	}
	src := netip.IPv4Unspecified()
	if dst.Is6() {
		src = netip.IPv6Unspecified()
	}
	if request.Context.SourceIP != "" {
		src, _ = diagnosticAddress(request.Context.SourceIP)
	}
	if request.Context.Origin != "daemon" && request.Context.SourceIP != "" && request.Flow.Destination.IP != "" && src.Is4() != dst.Is4() {
		return input, nil, nil, fmt.Errorf("source and destination address families differ")
	}
	input.src, input.dst = netip.AddrPortFrom(src, 0), netip.AddrPortFrom(dst, uint16(request.Flow.Destination.Port))
	if request.Context.SourcePort != nil {
		input.src = netip.AddrPortFrom(src, uint16(*request.Context.SourcePort))
	}
	if request.Context.MAC != "" {
		input.mac, _ = diagnosticMAC(request.Context.MAC)
	}
	if request.Context.IfIndex != nil {
		input.ifindex = *request.Context.IfIndex
	}
	if request.Context.PhysicalIfIndex != nil {
		input.physinif = *request.Context.PhysicalIfIndex
	}
	if request.Context.DSCP != nil {
		input.dscp = uint8(*request.Context.DSCP)
	}
	if request.Context.ProcessName != nil {
		copy(input.processName[:], *request.Context.ProcessName)
	}
	input.profileID = matcher.profileForInterface(input.ifindex)
	if request.Context.Policy != "" {
		found := false
		for _, profile := range matcher.profileInfo {
			if profileName(profile) == request.Context.Policy {
				input.profileID, found = profile.ID, true
			}
		}
		if !found {
			return input, nil, nil, fmt.Errorf("unknown active policy %q", request.Context.Policy)
		}
	}
	add("origin", request.Context.Origin, "input", true)
	add("source_ip", src.String(), "input", request.Context.SourceIP != "" || request.Context.Origin == "daemon")
	add("source_port", strconv.Itoa(int(input.src.Port())), "input", request.Context.SourcePort != nil || request.Context.Origin == "daemon")
	add("mac", request.Context.MAC, "input", request.Context.MAC != "" || request.Context.Origin == "daemon")
	add("ifindex", strconv.Itoa(int(input.ifindex)), "input", request.Context.IfIndex != nil || request.Context.Origin == "daemon")
	add("physical_ifindex", strconv.Itoa(int(input.physinif)), "input", request.Context.PhysicalIfIndex != nil || request.Context.Origin == "daemon")
	add("process_name", strings.TrimRight(string(input.processName[:]), "\x00"), "input", request.Context.ProcessName != nil || request.Context.Origin != "local")
	add("dscp", strconv.Itoa(int(input.dscp)), "input", request.Context.DSCP != nil || request.Context.Origin == "daemon")
	add("destination.ip", request.Flow.Destination.IP, "input", request.Flow.Destination.IP != "")
	add("destination.port", strconv.Itoa(request.Flow.Destination.Port), "input", request.Flow.Destination.Port != 0)
	add("protocol", request.Flow.Protocol, "input", true)
	add("hostname", diagnosticHostname(request), "input", request.Flow.SNI != nil || request.Flow.HTTP != nil || request.Context.Origin == "daemon")
	add("destination.domain", request.Flow.Destination.Domain, "input", request.Flow.Destination.Domain != "")
	if request.Flow.SNI != nil {
		add("tls.sni", *request.Flow.SNI, "input", true)
	}
	if request.Flow.HTTP != nil {
		add("http.host", request.Flow.HTTP.Host, "input", request.Flow.HTTP.Host != "")
		add("http.url", request.Flow.HTTP.URL, "input", true)
	}
	add("policy", matcher.diagnosticPolicy(input), "runtime", true)
	return input, missing, fields, nil
}
