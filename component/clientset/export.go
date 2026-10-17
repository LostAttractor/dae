// SPDX-License-Identifier: AGPL-3.0-only

// Package clientset exports device membership to netfilter MAC sets.
package clientset

import (
	"errors"

	"github.com/daeuniverse/dae/config"

	"github.com/google/nftables"
	log "github.com/sirupsen/logrus"
)

func nftTarget(target string) (*nftables.Table, string, error) {
	family, table, set, err := config.ParseNFTSet(target)
	if err != nil {
		return nil, "", err
	}
	families := map[string]nftables.TableFamily{
		"inet": nftables.TableFamilyINet, "ip": nftables.TableFamilyIPv4,
		"ip6": nftables.TableFamilyIPv6, "bridge": nftables.TableFamilyBridge,
		"netdev": nftables.TableFamilyNetdev, "arp": nftables.TableFamilyARP,
	}
	return &nftables.Table{Family: families[family], Name: table}, set, nil
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
