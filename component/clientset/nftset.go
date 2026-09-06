// SPDX-License-Identifier: AGPL-3.0-only

package clientset

import (
	"errors"
	"fmt"
	"slices"
	"syscall"

	"github.com/google/nftables"
)

func replaceNFTSet(target string, members [][6]byte) error {
	table, name, err := nftTarget(target)
	if err != nil {
		return err
	}
	conn := &nftables.Conn{}
	set, err := conn.GetSetByName(table, name)
	if err != nil && !errors.Is(err, syscall.ENOENT) {
		return err
	}
	if err == nil {
		if set.KeyType != nftables.TypeEtherAddr || set.IsMap || set.Constant || set.Interval || set.HasTimeout || set.Dynamic {
			return fmt.Errorf("expected an ether_addr set without constant, interval, timeout or dynamic flags")
		}
		conn.FlushSet(set)
	} else {
		tables, err := conn.ListTablesOfFamily(table.Family)
		if err != nil {
			return err
		}
		if !slices.ContainsFunc(tables, func(t *nftables.Table) bool { return t.Name == table.Name }) {
			conn.AddTable(table)
		}
		set = &nftables.Set{Table: table, Name: name, KeyType: nftables.TypeEtherAddr}
		if err := conn.AddSet(set, nil); err != nil {
			return err
		}
	}
	// Bound each netlink message; all chunks and the flush/create share one
	// transaction, including when membership is empty.
	const batchSize = 256
	for chunk := range slices.Chunk(members, batchSize) {
		var elements []nftables.SetElement
		for _, mac := range chunk {
			elements = append(elements, nftables.SetElement{Key: mac[:]})
		}
		if err := conn.SetAddElements(set, elements); err != nil {
			return err
		}
	}
	return conn.Flush()
}
