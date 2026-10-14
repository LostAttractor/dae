// SPDX-License-Identifier: AGPL-3.0-only

// Package clientset exports device membership to netfilter MAC sets.
package clientset

import (
	"errors"
	"fmt"
	"strings"

	"github.com/google/nftables"
	log "github.com/sirupsen/logrus"
)

func validName(name string, limit int) bool {
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

func Validate(ipset, nftset string) error {
	if ipset != "" && !validName(ipset, 31) {
		return fmt.Errorf("ipset names must contain 1–31 ASCII letters, digits, '_', '-' or '.'")
	}
	if nftset != "" {
		_, _, err := nftTarget(nftset)
		return err
	}
	return nil
}

func nftTarget(target string) (*nftables.Table, string, error) {
	parts := strings.Split(target, "/")
	if len(parts) != 3 || !validName(parts[1], 255) || !validName(parts[2], 255) {
		return nil, "", fmt.Errorf("nftset requires family/table/set with ASCII letters, digits, '_', '-' or '.' in table/set names")
	}
	family, ok := map[string]nftables.TableFamily{
		"inet": nftables.TableFamilyINet, "ip": nftables.TableFamilyIPv4,
		"ip6": nftables.TableFamilyIPv6, "bridge": nftables.TableFamilyBridge,
		"netdev": nftables.TableFamilyNetdev, "arp": nftables.TableFamilyARP,
	}[parts[0]]
	if !ok {
		return nil, "", fmt.Errorf("unsupported nftset family %q", parts[0])
	}
	return &nftables.Table{Family: family, Name: parts[1]}, parts[2], nil
}

// Replace publishes one membership snapshot using the same rollback journal as
// multi-target activation. Callers must serialize changes to the same targets.
func Replace(ipset, nftset string, members [][6]byte) error {
	tx, err := Prepare([]Target{{IPSet: ipset, NFTSet: nftset, Members: members}})
	if err != nil {
		return err
	}
	if err := tx.Apply(); err != nil {
		return errors.Join(err, tx.Rollback())
	}
	if err := tx.Commit(); err != nil {
		log.WithError(err).Warn("Remove temporary client sets")
	}
	return nil
}
