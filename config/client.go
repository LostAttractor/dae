// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/daeuniverse/dae/component/clientset"
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
		if err := clientset.Validate(client.IPSet, client.NFTSet); err != nil {
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
