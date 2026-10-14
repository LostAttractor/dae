// SPDX-License-Identifier: AGPL-3.0-only

package clientset

import (
	"os"
	"slices"
	"testing"

	"github.com/google/nftables"
	"github.com/vishvananda/netlink"
)

func TestKernelTransactionRestoresActualSnapshots(t *testing.T) {
	if os.Getenv("DAE_TEST_NETFILTER") != "1" {
		t.Skip("requires an isolated network namespace with CAP_NET_ADMIN")
	}
	const ipset = "dae_transaction"
	const first, second = "inet/dae_transaction/first", "inet/dae_transaction/second"
	table, _, _ := nftTarget(first)
	conn := &nftables.Conn{}
	t.Cleanup(func() { _ = netlink.IpsetDestroy(ipset); conn.DelTable(table); _ = conn.Flush() })
	old, next := [6]byte{2, 0, 0, 0, 0, 1}, [6]byte{2, 0, 0, 0, 0, 2}
	if err := Replace(ipset, first, [][6]byte{old}); err != nil {
		t.Fatal(err)
	}
	assertFirst := func(want [6]byte) {
		t.Helper()
		set, err := conn.GetSetByName(table, "first")
		if err != nil {
			t.Fatal(err)
		}
		members, err := conn.GetSetElements(set)
		if err != nil || len(members) != 1 || !slices.Equal(members[0].Key, want[:]) {
			t.Fatalf("nft members = %v, %v", members, err)
		}
		ips, err := netlink.IpsetList(ipset)
		if err != nil || len(ips.Entries) != 1 || !slices.Equal(ips.Entries[0].MAC, want[:]) {
			t.Fatalf("ipset = %v, %v", ips, err)
		}
	}
	tx, err := Prepare([]Target{{IPSet: ipset, NFTSet: first, Members: [][6]byte{next}}, {NFTSet: second, Members: [][6]byte{next}}})
	if err != nil {
		t.Fatal(err)
	}
	assertFirst(old)
	if err := tx.Apply(); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	assertFirst(next)
	// A later activation step failed. Restore actual external state, including
	// removing a newly created set, before releasing the old ipset backup.
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	assertFirst(old)
	if _, err := conn.GetSetByName(table, "second"); err == nil {
		t.Fatal("rollback left a new set")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal("rollback is not idempotent", err)
	}

	limited := &nftables.Set{Table: table, Name: "limited", KeyType: nftables.TypeEtherAddr, Size: 1}
	if err := conn.AddSet(limited, []nftables.SetElement{{Key: old[:]}}); err != nil {
		t.Fatal(err)
	}
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	tx, err = Prepare([]Target{{IPSet: ipset, NFTSet: first, Members: [][6]byte{next}}, {NFTSet: "inet/dae_transaction/limited", Members: [][6]byte{old, next}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(); err == nil {
		t.Fatal("expected capacity failure after ipset swap")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	assertFirst(old)
}
