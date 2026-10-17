// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"fmt"
	"strings"
	"unicode"
)

type Client struct {
	Name        string `mapstructure:"_"`
	Description string `mapstructure:"description"`
	IPSet       string `mapstructure:"ipset"`
	NFTSet      string `mapstructure:"nftset"`
}

func ValidateClientName(name string) error {
	if strings.TrimSpace(name) == "" || len(name) > 128 || strings.ContainsRune(name, '/') || strings.ContainsFunc(name, unicode.IsControl) {
		return fmt.Errorf("client set names must be non-empty, at most 128 bytes, and cannot contain '/' or control characters")
	}
	return nil
}

func validateClients(clients []Client) error {
	for i, client := range clients {
		if err := ValidateClientName(client.Name); err != nil {
			return err
		}
		if err := ValidateClientExports(client.IPSet, client.NFTSet); err != nil {
			return fmt.Errorf("client %q: %w", client.Name, err)
		}
		for _, other := range clients[:i] {
			if client.Name == other.Name {
				return fmt.Errorf("duplicate client name %q", client.Name)
			}
			if client.IPSet != "" && client.IPSet == other.IPSet || client.NFTSet != "" && client.NFTSet == other.NFTSet {
				return fmt.Errorf("clients %q and %q cannot export to the same kernel set", client.Name, other.Name)
			}
		}
	}
	return nil
}

func validKernelSetName(name string, limit int) bool {
	if len(name) == 0 || len(name) > limit {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// ValidateClientExports checks the syntax of optional kernel set targets.
func ValidateClientExports(ipset, nftset string) error {
	if ipset != "" && !validKernelSetName(ipset, 31) {
		return fmt.Errorf("ipset names must contain 1–31 ASCII letters, digits, '_', '-' or '.'")
	}
	if nftset != "" {
		_, _, _, err := ParseNFTSet(nftset)
		return err
	}
	return nil
}

// ParseNFTSet validates the configured family/table/set reference independently
// of the kernel exporter.
func ParseNFTSet(target string) (family, table, set string, err error) {
	parts := strings.Split(target, "/")
	if len(parts) != 3 || !validKernelSetName(parts[1], 255) || !validKernelSetName(parts[2], 255) {
		return "", "", "", fmt.Errorf("nftset requires family/table/set with ASCII letters, digits, '_', '-' or '.' in table/set names")
	}
	switch parts[0] {
	case "inet", "ip", "ip6", "bridge", "netdev", "arp":
	default:
		return "", "", "", fmt.Errorf("unsupported nftset family %q", parts[0])
	}
	return parts[0], parts[1], parts[2], nil
}
