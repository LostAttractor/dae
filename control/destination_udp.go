// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
)

var destinationOwners atomic.Uint64
var destinationOwnershipLocks common.KeyLocker[bpfDestinationUdpKey]

// This wrapper retains only a cloned map descriptor, not a retired plane.
// Ownership tokens stop delayed socket closes from removing a successor entry.
type ownedDestinationConn struct {
	net.PacketConn
	once    sync.Once
	release func() error
	err     error
}

func (c *ownedDestinationConn) Close() error {
	c.once.Do(func() { c.err = errors.Join(c.release(), c.PacketConn.Close()) })
	return c.err
}

func (c *ControlPlane) ownDestinationUDP(conn net.PacketConn, key udpEndpointKey, result *bpfRoutingResult) (net.PacketConn, error) {
	m, err := c.core.bpf.DestinationUdpMap.Clone()
	if err != nil {
		return nil, err
	}
	k := bpfDestinationUdpKey{Tuples: bpfTuplesKey{Sport: common.Htons(key.Source.Port()), Dport: common.Htons(key.Destination.Port()), L4proto: 17}, Ifindex: key.Interface}
	k.Tuples.Sip.U6Addr8 = key.Source.Addr().As16()
	k.Tuples.Dip.U6Addr8 = key.Destination.Addr().As16()
	owner := destinationOwners.Add(1)
	value := bpfDestinationUdpValue{Result: *result, Owner: owner}
	l, _ := destinationOwnershipLocks.Lock(k)
	err = m.Update(k, value, ebpf.UpdateAny)
	destinationOwnershipLocks.Unlock(k, l)
	if err != nil {
		_ = m.Close()
		return nil, err
	}
	return &ownedDestinationConn{PacketConn: conn, release: func() error {
		l, _ := destinationOwnershipLocks.Lock(k)
		defer destinationOwnershipLocks.Unlock(k, l)
		defer m.Close()
		var current bpfDestinationUdpValue
		if err := m.Lookup(k, &current); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return nil
			}
			return err
		}
		if current.Owner != owner {
			return nil
		}
		if err := m.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
		return nil
	}}, nil
}

func clearDestinationUDP(m *ebpf.Map) error {
	var key bpfDestinationUdpKey
	for {
		if err := m.NextKey(nil, &key); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return nil
			}
			return err
		}
		if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
}

// Each rewritten UDP association owns a socket and a fixed destination. This
// keeps replies unambiguous even if multiple original IPs map to the same peer.
type destinationPacketConn struct {
	net.PacketConn
	original, target netip.AddrPort
}

func (c *destinationPacketConn) WriteTo(data []byte, _ net.Addr) (int, error) {
	return c.PacketConn.WriteTo(data, net.UDPAddrFromAddrPort(c.target))
}

func (c *destinationPacketConn) ReadFrom(data []byte) (int, net.Addr, error) {
	for {
		n, from, err := c.PacketConn.ReadFrom(data)
		if err != nil {
			return n, from, err
		}
		if common.ConvergeAddrPort(addrPortOf(from)) == c.target {
			return n, net.UDPAddrFromAddrPort(c.original), nil
		}
	}
}
