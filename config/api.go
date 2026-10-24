// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode"

	"github.com/daeuniverse/dae/api"
)

type API struct {
	Listen            string   `mapstructure:"listen"`
	UserKey           string   `mapstructure:"user_key"`
	AdminKey          string   `mapstructure:"admin_key"`
	AllowLANAnonymous bool     `mapstructure:"allow_lan_anonymous"`
	WebOrigins        []string `mapstructure:"web_origins"`
	Web               bool     `mapstructure:"web" default:"true"`
	Pprof             bool     `mapstructure:"pprof"`
	MITMTestIPv4      string   `mapstructure:"mitm_test_ipv4"`
	MITMTestIPv6      string   `mapstructure:"mitm_test_ipv6"`
}

// Endpoint distinguishes a LAN interface binding from an explicit local IP.
// Empty listen disables TCP; Unix administration is independent of this setting.
func (a API) Endpoint() (address string, port uint16, lan bool, err error) {
	return ParseAPIEndpoint(a.Listen)
}

func ParseAPIEndpoint(listen string) (address string, port uint16, lan bool, err error) {
	if listen == "" {
		return "", 0, false, nil
	}
	host, portText := "", listen
	lan = !strings.Contains(listen, ":")
	if !lan {
		host, portText, err = net.SplitHostPort(listen)
		if err != nil {
			return "", 0, false, fmt.Errorf("api.listen: expected a port or IP:port: %w", err)
		}
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return "", 0, false, fmt.Errorf("api.listen: an explicit address must be an IP literal")
		}
		host = ip.String()
	}
	n, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || n == 0 {
		return "", 0, false, fmt.Errorf("api.listen: port must be between 1 and 65535; omit listen to disable TCP")
	}
	return net.JoinHostPort(host, strconv.Itoa(int(n))), uint16(n), lan, nil
}

// Port is used only after configuration validation.
func (a API) Port() uint16 {
	_, port, _, _ := a.Endpoint()
	return port
}

func (a API) Validate() error {
	if _, _, _, err := a.Endpoint(); err != nil {
		return err
	}
	if a.UserKey != "" && a.UserKey == a.AdminKey {
		return fmt.Errorf("api.user_key and api.admin_key must be different")
	}
	for _, key := range []string{a.UserKey, a.AdminKey} {
		if strings.ContainsFunc(key, func(r rune) bool { return r > 126 || unicode.IsSpace(r) || unicode.IsControl(r) }) {
			return fmt.Errorf("API keys must contain printable ASCII without whitespace")
		}
	}
	for _, origin := range a.WebOrigins {
		if _, err := api.NormalizeOrigin(origin); err != nil {
			return fmt.Errorf("api.web_origins: %w", err)
		}
	}
	return nil
}
