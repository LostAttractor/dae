// SPDX-License-Identifier: AGPL-3.0-only

package clientset

import (
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"syscall"

	"github.com/daeuniverse/dae/config"
	"github.com/google/nftables"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

type Target struct {
	IPSet, NFTSet string
	Members       [][6]byte
}

type stagedIPSet struct {
	name, temporary           string
	options                   netlink.IpsetCreateOptions
	existed, created, swapped bool
}

type stagedNFTSet struct {
	set            *nftables.Set
	previous, next []nftables.SetElement
	existed        bool
}

// Transaction retains actual kernel snapshots until activation has completed.
// BPF, ipset and nft are separate commit domains; Rollback compensates in reverse
// order and reports any incomplete restoration. The owner serializes targets.
type Transaction struct {
	ips        []stagedIPSet
	nfts       []stagedNFTSet
	tables     []*nftables.Table // tables absent before preparation
	nftApplied bool
	done       bool
}

func Prepare(targets []Target) (tx *Transaction, err error) {
	tx = new(Transaction)
	defer func() {
		if err != nil {
			err = errors.Join(err, tx.Rollback())
			tx = nil
		}
	}()
	seen := make(map[string]bool)
	tables := make(map[string]bool)
	conn := &nftables.Conn{}
	for _, target := range targets {
		if err := config.ValidateClientExports(target.IPSet, target.NFTSet); err != nil {
			return tx, err
		}
		for _, mac := range target.Members {
			if mac == [6]byte{} {
				return tx, errors.New("client set cannot contain the zero MAC")
			}
		}
		if target.NFTSet != "" {
			key := "nft:" + target.NFTSet
			if seen[key] {
				return tx, fmt.Errorf("duplicate export target %s", key)
			}
			seen[key] = true
			table, name, _ := nftTarget(target.NFTSet)
			set, err := conn.GetSetByName(table, name)
			if err != nil && !errors.Is(err, syscall.ENOENT) {
				return tx, err
			}
			entry := stagedNFTSet{set: set, existed: err == nil}
			if entry.existed {
				if set.KeyType != nftables.TypeEtherAddr || set.IsMap || set.Constant || set.Interval || set.HasTimeout || set.Dynamic {
					return tx, fmt.Errorf("nftset %q: expected an ether_addr set without constant, interval, timeout or dynamic flags", target.NFTSet)
				}
				entry.previous, err = conn.GetSetElements(set)
				if err != nil {
					return tx, err
				}
			} else {
				entry.set = &nftables.Set{Table: table, Name: name, KeyType: nftables.TypeEtherAddr}
				tableKey := fmt.Sprintf("%d/%s", table.Family, table.Name)
				if !tables[tableKey] {
					all, err := conn.ListTablesOfFamily(table.Family)
					if err != nil {
						return tx, err
					}
					if !slices.ContainsFunc(all, func(t *nftables.Table) bool { return t.Name == table.Name }) {
						tx.tables = append(tx.tables, table)
					}
					tables[tableKey] = true
				}
			}
			for _, mac := range target.Members {
				entry.next = append(entry.next, nftables.SetElement{Key: slices.Clone(mac[:])})
			}
			tx.nfts = append(tx.nfts, entry)
		}
		if target.IPSet != "" {
			key := "ipset:" + target.IPSet
			if seen[key] {
				return tx, fmt.Errorf("duplicate export target %s", key)
			}
			seen[key] = true
			entry := stagedIPSet{name: target.IPSet, temporary: "dae_" + rand.Text()[:20]}
			old, err := netlink.IpsetList(entry.name)
			if err != nil && !errors.Is(err, syscall.ENOENT) {
				return tx, fmt.Errorf("read ipset %q: %w", entry.name, err)
			}
			entry.existed = err == nil
			if entry.existed {
				if old.TypeName != "hash:mac" {
					return tx, fmt.Errorf("ipset %q: expected hash:mac", entry.name)
				}
				entry.options = netlink.IpsetCreateOptions{Family: old.Family, Revision: old.Revision, MaxElements: old.MaxElements, Timeout: old.Timeout,
					Counters: old.CadtFlags&nl.IPSET_FLAG_WITH_COUNTERS != 0, Comments: old.CadtFlags&nl.IPSET_FLAG_WITH_COMMENT != 0, Skbinfo: old.CadtFlags&nl.IPSET_FLAG_WITH_SKBINFO != 0}
			}
			if err := netlink.IpsetCreate(entry.temporary, "hash:mac", entry.options); err != nil {
				return tx, err
			}
			tx.ips = append(tx.ips, entry)
			for _, mac := range target.Members {
				if err := netlink.IpsetAdd(entry.temporary, &netlink.IPSetEntry{MAC: mac[:]}); err != nil {
					return tx, fmt.Errorf("populate ipset %q: %w", entry.name, err)
				}
			}
		}
	}
	return tx, nil
}

func (t *Transaction) Apply() error {
	if t.done {
		return errors.New("client set transaction is closed")
	}
	for i := range t.ips {
		entry := &t.ips[i]
		if entry.swapped {
			continue
		}
		if !entry.existed && !entry.created {
			if err := netlink.IpsetCreate(entry.name, "hash:mac", entry.options); err != nil {
				return err
			}
			entry.created = true
		}
		if err := netlink.IpsetSwap(entry.name, entry.temporary); err != nil {
			return err
		}
		entry.swapped = true
	}
	if t.nftApplied || len(t.nfts) == 0 {
		return nil
	}
	conn := &nftables.Conn{}
	for _, table := range t.tables {
		conn.AddTable(table)
	}
	for _, entry := range t.nfts {
		if entry.existed {
			conn.FlushSet(entry.set)
		} else if err := conn.AddSet(entry.set, nil); err != nil {
			return err
		}
		if err := addElements(conn, entry.set, entry.next); err != nil {
			return err
		}
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("publish nft client sets: %w", err)
	}
	t.nftApplied = true
	return nil
}

func addElements(conn *nftables.Conn, set *nftables.Set, elements []nftables.SetElement) error {
	for chunk := range slices.Chunk(elements, 256) {
		if err := conn.SetAddElements(set, chunk); err != nil {
			return err
		}
	}
	return nil
}

func (t *Transaction) Rollback() error {
	if t.done {
		return nil
	}
	var rollback error
	if t.nftApplied {
		conn := &nftables.Conn{}
		for _, entry := range t.nfts {
			if !entry.existed {
				conn.DelSet(entry.set)
				continue
			}
			conn.FlushSet(entry.set)
			rollback = errors.Join(rollback, addElements(conn, entry.set, entry.previous))
		}
		for _, table := range t.tables {
			conn.DelTable(table)
		}
		if rollback == nil {
			rollback = conn.Flush()
		}
		if rollback == nil {
			t.nftApplied = false
		}
	}
	for i := len(t.ips) - 1; i >= 0; i-- {
		entry := &t.ips[i]
		var err error
		if entry.created {
			err = netlink.IpsetDestroy(entry.name)
			if err == nil {
				entry.created, entry.swapped = false, false
			}
		} else if entry.swapped {
			err = netlink.IpsetSwap(entry.name, entry.temporary)
			if err == nil {
				entry.swapped = false
			}
		}
		if err != nil {
			rollback = errors.Join(rollback, fmt.Errorf("restore ipset %q (backup %q): %w", entry.name, entry.temporary, err))
		}
	}
	if rollback != nil {
		return fmt.Errorf("client set rollback incomplete; backups retained: %w", rollback)
	}
	return t.Commit()
}

// Commit releases backups only after the owner has accepted the whole operation.
// Cleanup errors do not revert successful publication.
func (t *Transaction) Commit() error {
	if t.done {
		return nil
	}
	var err error
	for _, entry := range t.ips {
		if e := netlink.IpsetDestroy(entry.temporary); e != nil {
			err = errors.Join(err, fmt.Errorf("remove backup %q: %w", entry.temporary, e))
		}
	}
	t.done = true
	return err
}
