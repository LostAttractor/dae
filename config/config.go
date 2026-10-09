/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package config

import (
	"fmt"
	"reflect"
	"time"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/config_parser"
)

var (
	Version string
)

type Global struct {
	ResourceCache          bool                   `mapstructure:"resource_cache" default:"true"`
	ResourceUpdateInterval time.Duration          `mapstructure:"resource_update_interval" default:"24h"`
	APIPort                uint16                 `mapstructure:"api_port" default:"0"`
	APIKey                 string                 `mapstructure:"api_key"`
	TproxyPort             uint16                 `mapstructure:"tproxy_port" default:"12345"`
	TproxyPortProtect      bool                   `mapstructure:"tproxy_port_protect" default:"true"`
	SoMarkFromDae          uint32                 `mapstructure:"so_mark_from_dae"`
	SoMarkFromDaeSet       bool                   `mapstructure:"_" outline:"-"`
	LogLevel               string                 `mapstructure:"log_level" default:"info"`
	UdpCheckDns            []string               `mapstructure:"udp_check_dns" default:"dns.google:53,8.8.8.8,2001:4860:4860::8888"`
	CheckInterval          time.Duration          `mapstructure:"check_interval" default:"3m"`
	CheckIntervalMax       time.Duration          `mapstructure:"check_interval_max" default:"1h"`
	CheckTolerance         time.Duration          `mapstructure:"check_tolerance" default:"0"`
	LanInterface           []string               `mapstructure:"lan_interface"`
	WanInterface           []string               `mapstructure:"wan_interface"`
	AllowInsecure          bool                   `mapstructure:"allow_insecure" default:"false"`
	DialTargetOverride     bool                   `mapstructure:"dial_target_override" default:"true"`
	RerouteMode            consts.RerouteMode     `mapstructure:"reroute_mode" default:"while_needed"`
	SniffVerifyMode        consts.SniffVerifyMode `mapstructure:"sniff_verify_mode" default:"loose"`
	SniffingTimeout        time.Duration          `mapstructure:"sniffing_timeout" default:"100ms"`
	DNSRetentionWindow     time.Duration          `mapstructure:"dns_retention_window" default:"168h"`
	DNSResolver            string                 `mapstructure:"dns_resolver"`
	DisableWaitingNetwork  bool                   `mapstructure:"disable_waiting_network" default:"false"`
	// DEPRECATED: not used as of https://github.com/daeuniverse/dae/pull/912
	EnableLocalTcpFastRedirect bool `mapstructure:"enable_local_tcp_fast_redirect" default:"false"`
	AutoConfigKernelParameter  bool `mapstructure:"auto_config_kernel_parameter" default:"false"`
	// DEPRECATED: not used as of https://github.com/daeuniverse/dae/pull/458
	AutoConfigFirewallRule bool   `mapstructure:"auto_config_firewall_rule" default:"false"`
	TlsImplementation      string `mapstructure:"tls_implementation" default:"tls"`
	UtlsImitate            string `mapstructure:"utls_imitate" default:"chrome_auto"`
	TlsFragment            bool   `mapstructure:"tls_fragment" default:"false"`
	TlsFragmentLength      string `mapstructure:"tls_fragment_length" default:"50-100"`
	TlsFragmentInterval    string `mapstructure:"tls_fragment_interval" default:"10-20"`
	PprofPort              uint16 `mapstructure:"pprof_port" default:"0"`
	MetricsPort            uint16 `mapstructure:"metrics_port" default:"0"`
	Mptcp                  bool   `mapstructure:"mptcp" default:"false"`
	BandwidthMaxTx         string `mapstructure:"bandwidth_max_tx" default:"0"`
	BandwidthMaxRx         string `mapstructure:"bandwidth_max_rx" default:"0"`
	NoConnectivityTrySniff bool   `mapstructure:"no_connectivity_try_sniff" default:"true"`
	// TODO: skip?
	NoConnectivityBehavior string        `mapstructure:"no_connectivity_behavior" default:"block"`
	RouteChangeBehavior    string        `mapstructure:"route_change_behavior" default:"keep"`
	UDPHopInterval         time.Duration `mapstructure:"udphop_interval" default:"30s"`
}

type Utls struct {
	Imitate string `mapstructure:"imitate"`
}

type FunctionOrString any

// QuotedString preserves a routing target's explicit quoting so names using
// reserved must spellings can be resolved literally.
type QuotedString string

func ParseFunctionOrString(fs FunctionOrString) (*config_parser.Function, error) {
	switch fs := fs.(type) {
	case string:
		return &config_parser.Function{Name: fs}, nil
	case QuotedString:
		return &config_parser.Function{Name: string(fs), Quoted: true}, nil
	case *config_parser.Function:
		if fs == nil {
			return nil, fmt.Errorf("function must not be nil")
		}
		return fs, nil
	case []*config_parser.Function:
		if len(fs) != 1 {
			return nil, fmt.Errorf("expected exactly 1 function, got %d", len(fs))
		}
		if fs[0] == nil {
			return nil, fmt.Errorf("function must not be nil")
		}
		return fs[0], nil
	default:
		return nil, fmt.Errorf("unsupported function-or-string value type: %T", fs)
	}
}

type FunctionListOrString any

func ParseFunctionListOrString(fs FunctionListOrString) ([]*config_parser.Function, error) {
	switch fs := fs.(type) {
	case string:
		return []*config_parser.Function{{Name: fs}}, nil
	case QuotedString:
		return []*config_parser.Function{{Name: string(fs), Quoted: true}}, nil
	case *config_parser.Function:
		if fs == nil {
			return nil, fmt.Errorf("function must not be nil")
		}
		return []*config_parser.Function{fs}, nil
	case []*config_parser.Function:
		if fs == nil {
			return nil, fmt.Errorf("function list must not be nil")
		}
		for i, f := range fs {
			if f == nil {
				return nil, fmt.Errorf("function at index %d must not be nil", i)
			}
		}
		return fs, nil
	default:
		return nil, fmt.Errorf("unsupported function-list-or-string value type: %T", fs)
	}
}

type Group struct {
	Name string `mapstructure:"_"`
	// Present records explicitly configured fields whose zero values would
	// otherwise be indistinguishable from omission.
	Present map[string]bool `mapstructure:"_" json:"-" outline:"-"`

	Paths  []*config_parser.ProxyPath `mapstructure:"path"`
	Policy FunctionListOrString       `mapstructure:"policy"`

	UdpCheckDns        []string      `mapstructure:"udp_check_dns"`
	CheckInterval      time.Duration `mapstructure:"check_interval"`
	CheckIntervalMax   time.Duration `mapstructure:"check_interval_max"`
	CheckTolerance     time.Duration `mapstructure:"check_tolerance"`
	CheckAsync         bool          `mapstructure:"check_async"`
	TrackAll           bool          `mapstructure:"track_all"`
	ReselectBehavior   string        `mapstructure:"reselect_behavior"`
	FailureRecovery    time.Duration `mapstructure:"failure_recovery"`
	ProbeTimeout       time.Duration `mapstructure:"probe_timeout"`
	SelectionTimeout   time.Duration `mapstructure:"selection_timeout"`
	UpgradeInterval    time.Duration `mapstructure:"upgrade_interval"`
	UpgradeIntervalMax time.Duration `mapstructure:"upgrade_interval_max"`
}

func ValidateConnectionBehavior(name, value string) error {
	switch value {
	case "", "keep", "close":
		return nil
	default:
		return fmt.Errorf("%s must be keep or close, got %q", name, value)
	}
}

type KeyableString string

// Routing separates reusable rule sets, complete policies, and their bindings.
// An empty Default selects the anonymous policy written directly in routing.
// Routing is an opaque outline leaf because its statements are ordered.
type Routing struct {
	Default    string             `mapstructure:"default" outline:"-"`
	RuleSets   []RoutingRuleSet   `mapstructure:"rule_set" outline:"-"`
	Policies   []RoutingPolicy    `mapstructure:"policy" outline:"-"`
	Interfaces []RoutingInterface `mapstructure:"interface" outline:"-"`
}

type RoutingStatementKind uint8

const (
	RoutingStatementRule RoutingStatementKind = iota
	RoutingStatementUse
)

type RoutingStatement struct {
	Kind RoutingStatementKind
	Rule *config_parser.RoutingRule
	Use  string
	// Condition is ANDed with every rule reached by this use, including nested uses.
	Condition []*config_parser.Function
}

type RoutingRuleSet struct {
	Name       string
	Statements []RoutingStatement
}

type RoutingPolicy struct {
	Name       string
	Statements []RoutingStatement
	Fallback   *config_parser.Function
}

type RoutingInterface struct {
	Name   string
	Policy string
}

type Config struct {
	Global       Global         `mapstructure:"global" required:"" desc:"GlobalDesc"`
	MITM         MITM           `mapstructure:"mitm" desc:"MITMDesc"`
	Plugins      Plugins        `mapstructure:"plugins"`
	Subscription []Subscription `mapstructure:"subscription"`
	Node         []Node         `mapstructure:"node"`
	Group        []Group        `mapstructure:"group" desc:"GroupDesc"`
	Client       []Client       `mapstructure:"client" desc:"ClientDesc"`
	Routing      Routing        `mapstructure:"routing" required:""`
	Rules        Rules          `mapstructure:"rules"`
}

func sectionHasParam(section *config_parser.Section, key string) bool {
	for _, item := range section.Items {
		param, ok := item.Value.(*config_parser.Param)
		if ok && param.Key == key {
			return true
		}
	}
	return false
}

// New params from sections. This func assumes merging (section "include") and deduplication for section names has been executed.
func New(sections []*config_parser.Section) (conf *Config, err error) {
	// Set up name to section for further use.
	type Section struct {
		Val    *config_parser.Section
		Parsed bool
	}
	nameToSection := make(map[string]*Section)
	for _, section := range sections {
		nameToSection[section.Name] = &Section{Val: section}
	}

	conf = &Config{}

	// Use specified parser to parse corresponding section.
	_val := reflect.ValueOf(conf)
	val := _val.Elem()
	typ := val.Type()
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		structField := typ.Field(i)

		// Find corresponding section from sections.
		sectionName, ok := structField.Tag.Lookup("mapstructure")
		if !ok {
			return nil, fmt.Errorf("no mapstructure is specified in field %v", structField.Name)
		}
		section, ok := nameToSection[sectionName]
		if !ok {
			if _, required := structField.Tag.Lookup("required"); required {
				return nil, fmt.Errorf("section %v is required but not provided", sectionName)
			} else {
				continue
			}
		}

		// Parse section and unmarshal to field.
		if err := SectionParser(field.Addr(), section.Val); err != nil {
			return nil, fmt.Errorf("failed to parse \"%v\": %w", sectionName, err)
		}
		if sectionName == "global" {
			conf.Global.SoMarkFromDaeSet = sectionHasParam(section.Val, "so_mark_from_dae")
		}
		section.Parsed = true
	}

	// Report unknown. Not "unused" because we assume section name deduplication has been executed before this func.
	for name, section := range nameToSection {
		if section.Val.Name == "include" {
			continue
		}
		if !section.Parsed {
			return nil, fmt.Errorf("unknown section: %v", name)
		}
	}

	if err = validateClients(conf.Client); err != nil {
		return nil, err
	}

	// Apply config patches.
	if _, err = conf.Rules.Plan(); err != nil {
		return nil, err
	}

	for _, patch := range patches {
		if err = patch(conf); err != nil {
			return nil, err
		}
	}
	return conf, nil
}
