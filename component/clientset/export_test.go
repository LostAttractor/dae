// SPDX-License-Identifier: AGPL-3.0-only

package clientset

import (
	"os"
	"slices"
	"testing"

	"github.com/google/nftables"
	"github.com/vishvananda/netlink"
)

// Run with DAE_TEST_NETFILTER=1 in an isolated network namespace.
func TestKernelExports(t *testing.T) {
	if os.Getenv("DAE_TEST_NETFILTER") != "1" {
		t.Skip("requires an isolated network namespace with CAP_NET_ADMIN")
	}
	const ipset, nftset = "dae_clients", "inet/dae_test/clients"
	table, name, _ := nftTarget(nftset)
	t.Cleanup(func() {
		_ = netlink.IpsetDestroy(ipset)
		conn := &nftables.Conn{}
		conn.DelTable(table)
		_ = conn.Flush()
	})
	check := func(want [][6]byte) {
		t.Helper()
		set, err := netlink.IpsetList(ipset)
		if err != nil {
			t.Fatal(err)
		}
		var ips [][6]byte
		for _, entry := range set.Entries {
			ips = append(ips, [6]byte(entry.MAC))
		}
		conn := &nftables.Conn{}
		nft, err := conn.GetSetByName(table, name)
		if err != nil {
			t.Fatal(err)
		}
		elements, err := conn.GetSetElements(nft)
		if err != nil {
			t.Fatal(err)
		}
		var nfts [][6]byte
		for _, element := range elements {
			nfts = append(nfts, [6]byte(element.Key))
		}
		for _, got := range [][][6]byte{ips, nfts} {
			if len(got) != len(want) {
				t.Fatalf("kernel set contains %d members, want %d", len(got), len(want))
			}
			for _, mac := range want {
				if !slices.Contains(got, mac) {
					t.Fatalf("kernel set is missing %x", mac)
				}
			}
		}
	}
	bulk := make([][6]byte, 4096)
	for i := range bulk {
		bulk[i] = [6]byte{2, 0, 0, 0, byte(i >> 8), byte(i)}
	}
	for _, members := range [][][6]byte{nil, bulk, {bulk[100]}, nil} {
		if err := Replace(ipset, nftset, members); err != nil {
			t.Fatal(err)
		}
		check(members)
	}
	// An invalid MAC must not replace the live ipset with a partial snapshot.
	if err := Replace(ipset, nftset, [][6]byte{bulk[0], {}}); err == nil {
		t.Fatal("zero MAC was accepted by hash:mac")
	}
	check(nil)
	if err := Replace("dae_invalid", "", [][6]byte{{}}); err == nil {
		t.Fatal("accepted an invalid MAC in a new ipset")
	}
	if _, err := netlink.IpsetList("dae_invalid"); err == nil {
		t.Fatal("failed staging created a live ipset")
	}

	// A foreign nft set must survive unchanged; failure after updating ipset
	// must restore the original kernel members without a caller-supplied copy.
	conn := &nftables.Conn{}
	wrong := &nftables.Set{Table: table, Name: "foreign", KeyType: nftables.TypeIPAddr}
	if err := conn.AddSet(wrong, []nftables.SetElement{{Key: []byte{192, 0, 2, 1}}}); err != nil {
		t.Fatal(err)
	}
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := Replace(ipset, nftset, bulk[:1]); err != nil {
		t.Fatal(err)
	}
	if err := Replace(ipset, "inet/dae_test/foreign", bulk[1:2]); err == nil {
		t.Fatal("overwrote a foreign set type")
	}
	check(bulk[:1])
	elements, err := conn.GetSetElements(wrong)
	if err != nil || len(elements) != 1 || !slices.Equal(elements[0].Key, []byte{192, 0, 2, 1}) {
		t.Fatalf("foreign set changed: %+v, %v", elements, err)
	}
	// Existing sets with counters support updates. Exceeding capacity fails at
	// commit, and must retain the previous member despite the queued FlushSet.
	limited := &nftables.Set{Table: table, Name: "limited", KeyType: nftables.TypeEtherAddr, Size: 1, Counter: true}
	if err := conn.AddSet(limited, nil); err != nil {
		t.Fatal(err)
	}
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := Replace("", "inet/dae_test/limited", bulk[:1]); err != nil {
		t.Fatal(err)
	}
	if err := Replace(ipset, "inet/dae_test/limited", bulk); err == nil {
		t.Fatal("accepted more members than the set capacity")
	}
	check(bulk[:1])
	elements, err = conn.GetSetElements(limited)
	if err != nil || len(elements) != 1 || !slices.Equal(elements[0].Key, bulk[0][:]) {
		t.Fatalf("failed transaction changed nft membership: %+v, %v", elements, err)
	}
	ipsets, err := netlink.IpsetListAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(ipsets) != 1 || ipsets[0].SetName != ipset {
		t.Fatalf("temporary ipsets survived replacement or rollback: %+v", ipsets)
	}
}
