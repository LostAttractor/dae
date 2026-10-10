// SPDX-License-Identifier: AGPL-3.0-only

package api

import "time"

const DiagnosticsSchemaVersion = 1

// DiagnosticContext describes a hypothetical new flow. Omitted packet fields
// are unknown, not zero. Device endpoints fill identity from verified ingress.
type DiagnosticContext struct {
	Origin          string  `json:"origin,omitempty"`
	SourceIP        string  `json:"source_ip,omitempty"`
	SourcePort      *int    `json:"source_port,omitempty"`
	MAC             string  `json:"mac,omitempty"`
	Interface       string  `json:"interface,omitempty"`
	IfIndex         *uint32 `json:"ifindex,omitempty"`
	PhysicalIfIndex *uint32 `json:"physical_ifindex,omitempty"`
	ProcessName     *string `json:"process_name,omitempty"`
	DSCP            *int    `json:"dscp,omitempty"`
	Mark            *uint32 `json:"mark,omitempty"`
	Policy          string  `json:"policy,omitempty"`
}

type DiagnosticTarget struct {
	IP     string `json:"ip,omitempty"`
	Domain string `json:"domain,omitempty"`
	Port   int    `json:"port,omitzero"`
}

type DiagnosticHTTP struct {
	URL             string              `json:"url"`
	Method          string              `json:"method,omitempty"`
	Host            string              `json:"host,omitempty"`
	Headers         map[string][]string `json:"headers,omitempty"`
	ResponseStatus  int                 `json:"response_status,omitzero"`
	ResponseHeaders map[string][]string `json:"response_headers,omitempty"`
}

type DiagnosticFlow struct {
	Protocol    string           `json:"protocol,omitempty"`
	Destination DiagnosticTarget `json:"destination"`
	SNI         *string          `json:"sni,omitempty"`
	HTTP        *DiagnosticHTTP  `json:"http,omitempty"`
}

type DiagnosticDNS struct {
	Name      string   `json:"name"`
	Type      string   `json:"type,omitempty"`
	Class     string   `json:"class,omitempty"`
	Upstream  string   `json:"upstream,omitempty"`
	AnswerIPs []string `json:"answer_ips,omitempty"`
	RCode     *int     `json:"rcode,omitempty"`
	RD        *bool    `json:"rd,omitempty"`
	CD        bool     `json:"cd,omitzero"`
	DO        bool     `json:"do,omitzero"`
	UDPSize   int      `json:"udp_size,omitzero"`
}

type DiagnosticBinding struct {
	IP      string   `json:"ip"`
	Domains []string `json:"domains"`
}

// Assumptions apply to a private snapshot, never to live routing or settings.
type DiagnosticAssumptions struct {
	ClientSets map[string]bool     `json:"client_sets,omitempty"`
	MITM       *bool               `json:"mitm,omitempty"`
	Bindings   []DiagnosticBinding `json:"bindings,omitempty"`
	Outbounds  map[string]bool     `json:"outbounds,omitempty"`
}

type ExplainRequest struct {
	Kind     string                 `json:"kind,omitempty"` // flow, dns, domain, outbound, plugins
	Context  DiagnosticContext      `json:"context"`
	Flow     DiagnosticFlow         `json:"flow"`
	DNS      *DiagnosticDNS         `json:"dns,omitempty"`
	Outbound string                 `json:"outbound,omitempty"`
	Network  string                 `json:"network,omitempty"`
	Compare  *DiagnosticAssumptions `json:"compare,omitempty"`
	Detail   string                 `json:"detail,omitempty"` // rules or predicates
}

type DiagnosticField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Source string `json:"source"` // input, request, runtime, default, assumption, unknown
}

type DiagnosticSource struct {
	File       string `json:"file,omitempty"`
	Line       int    `json:"line,omitzero"`
	Column     int    `json:"column,omitzero"`
	Expression string `json:"expression"`
}

type ExplainCondition struct {
	Expression string `json:"expression"`
	Match      string `json:"match"`  // match, miss, ambiguous, unknown
	Status     string `json:"status"` // evaluated, short_circuit, supplementary
	Reason     string `json:"reason"`
	Actual     string `json:"actual"`
	Expected   string `json:"expected"`
}

// Steps are ordered. Parent identifies a policy, plugin or an earlier step;
// clients can render a tree without parsing human-readable expressions.
type ExplainStep struct {
	ID         string             `json:"id"`
	Parent     string             `json:"parent,omitempty"`
	Stage      string             `json:"stage"`
	Expression string             `json:"expression"`
	Sources    []DiagnosticSource `json:"sources,omitempty"`
	Status     string             `json:"status"`
	Match      string             `json:"match"`
	Reason     string             `json:"reason"`
	Conditions []ExplainCondition `json:"conditions,omitempty"`
	Action     string             `json:"action,omitempty"`
	Outbound   string             `json:"outbound,omitempty"`
	Mark       uint32             `json:"mark,omitzero"`
	Must       bool               `json:"must,omitzero"`
	Targets    []string           `json:"targets,omitempty"`
}

type ExplainDecision struct {
	Complete         bool     `json:"complete"`
	Verdict          string   `json:"verdict"` // kernel_direct, drop, userspace, unknown, analysis
	Policy           string   `json:"policy,omitempty"`
	RuleID           string   `json:"rule_id,omitempty"`
	OriginalTarget   string   `json:"original_target,omitempty"`
	Targets          []string `json:"targets,omitempty"`
	Outbound         string   `json:"outbound,omitempty"`
	OriginalOutbound string   `json:"original_outbound,omitempty"`
	Mark             uint32   `json:"mark"`
	Must             bool     `json:"must"`
	Capture          []string `json:"capture,omitempty"`
	Missing          []string `json:"missing,omitempty"`
}

type DomainEvidence struct {
	Domain      string    `json:"domain"`
	IP          string    `json:"ip"`
	Resident    bool      `json:"resident"`
	RetainUntil time.Time `json:"retain_until,omitzero"`
	Source      string    `json:"source"`
}

type ExplainNode struct {
	ID        string           `json:"id"`
	Name      string           `json:"name"`
	Selected  bool             `json:"selected"`
	Usable    bool             `json:"usable"`
	Reason    string           `json:"reason"`
	Selection *SelectionStatus `json:"selection,omitempty"`
}

type ExplainOutbound struct {
	Name       string        `json:"name"`
	Policy     string        `json:"policy"`
	Network    string        `json:"network"`
	Available  bool          `json:"available"`
	Random     bool          `json:"random"`
	ObservedAt time.Time     `json:"observed_at"`
	Nodes      []ExplainNode `json:"nodes"`
}

type ExplainResult struct {
	Assumptions *DiagnosticAssumptions `json:"assumptions,omitempty"`
	Decision    ExplainDecision        `json:"decision"`
	Steps       []ExplainStep          `json:"steps"`
	Domains     []DomainEvidence       `json:"domains"`
	Outbounds   []ExplainOutbound      `json:"outbounds"`
	Notes       []string               `json:"notes"`
}

type ExplainResponse struct {
	Schema     int               `json:"schema"`
	Generation uint32            `json:"generation"`
	ObservedAt time.Time         `json:"observed_at"`
	Context    []DiagnosticField `json:"context"`
	Current    ExplainResult     `json:"current"`
	Compared   *ExplainResult    `json:"compared,omitempty"`
}

type DeviceContext struct {
	Generation uint32            `json:"generation"`
	Context    DiagnosticContext `json:"context"`
	Device     DeviceState       `json:"device"`
	Fields     []DiagnosticField `json:"fields"`
}

type ClientGroup struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	IPSet       string   `json:"ipset,omitempty"`
	NFTSet      string   `json:"nftset,omitempty"`
	Members     []string `json:"members"`
}

type ClientGroups struct {
	Groups []ClientGroup `json:"groups"`
}

// ManagedDevice reports stored MAC settings. Effective MITM defaults require
// an IP and are evaluated by the diagnostics endpoint instead.
type ManagedDevice struct {
	MAC          string           `json:"mac"`
	Sets         []ClientSetState `json:"sets"`
	MITMOverride *bool            `json:"mitm_override"`
}

type ClientImpactRequest struct {
	Joined  *bool             `json:"joined"`
	Context DiagnosticContext `json:"context"`
	Flow    *DiagnosticFlow   `json:"flow,omitempty"`
}

type ClientImpact struct {
	Generation         uint32           `json:"generation"`
	Name               string           `json:"name"`
	JoinedBefore       bool             `json:"joined_before"`
	JoinedAfter        bool             `json:"joined_after"`
	ConnectionBehavior string           `json:"connection_behavior"`
	Exports            []string         `json:"exports"`
	Rules              []ExplainStep    `json:"rules"`
	Trace              *ExplainResponse `json:"trace,omitempty"`
}
