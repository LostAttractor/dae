// SPDX-License-Identifier: AGPL-3.0-only

// Package clientset exports device membership to netfilter MAC sets.
package clientset

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strings"

	"github.com/google/nftables"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
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

// Replace publishes a complete membership snapshot. Each backend updates
// atomically. If nftables fails, swap the original ipset back. Callers must
// serialize changes to the same targets.
func Replace(ipset, nftset string, members [][6]byte) error {
	var temporary string
	if ipset != "" {
		// Build an unreferenced set. After swapping, keep the original kernel
		// members here until nftables commits, so rollback needs only a swap.
		temporary = "dae_" + rand.Text()[:20]
		if err := netlink.IpsetCreate(temporary, "hash:mac", netlink.IpsetCreateOptions{}); err != nil {
			return fmt.Errorf("stage ipset %q: %w", ipset, err)
		}
		defer func() {
			if err := netlink.IpsetDestroy(temporary); err != nil {
				log.WithError(err).WithField("set", temporary).Warn("Remove temporary client ipset")
			}
		}()
		for _, mac := range members {
			if err := netlink.IpsetAdd(temporary, &netlink.IPSetEntry{MAC: mac[:]}); err != nil {
				return fmt.Errorf("populate ipset %q: %w", ipset, err)
			}
		}
		if err := netlink.IpsetCreate(ipset, "hash:mac", netlink.IpsetCreateOptions{Replace: true}); err != nil {
			return fmt.Errorf("ipset %q: %w", ipset, err)
		}
		if err := netlink.IpsetSwap(ipset, temporary); err != nil {
			return fmt.Errorf("swap ipset %q: %w", ipset, err)
		}
	}
	if nftset != "" {
		if err := replaceNFTSet(nftset, members); err != nil {
			if temporary != "" {
				if rollbackErr := netlink.IpsetSwap(ipset, temporary); rollbackErr != nil {
					err = errors.Join(err, fmt.Errorf("restore ipset %q: %w", ipset, rollbackErr))
				}
			}
			return fmt.Errorf("nftset %q: %w", nftset, err)
		}
	}
	return nil
}
