// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// The attachment order is also the role numbering in the replacement manifest.
const (
	netnsSocketLookup = iota
	netnsPeerEgress
	netnsPeerIngress
	netnsHostIngress
	netnsRoleCount
)

func (p *bpfPrograms) namespacePrograms() [netnsRoleCount]*ebpf.Program {
	return [netnsRoleCount]*ebpf.Program{
		netnsSocketLookup: p.TproxySkLookup, netnsPeerEgress: p.TproxyDae0peerEgress,
		netnsPeerIngress: p.TproxyDae0peerIngress, netnsHostIngress: p.TproxyDae0Ingress,
	}
}

func namespaceAttachType(role uint8, netkit bool) ebpf.AttachType {
	switch role {
	case netnsSocketLookup:
		return ebpf.AttachSkLookup
	case netnsPeerEgress:
		return ebpf.AttachTCXEgress
	case netnsPeerIngress:
		if netkit {
			return ebpf.AttachNetkitPrimary
		}
	case netnsHostIngress:
		if netkit {
			return ebpf.AttachNetkitPeer
		}
	}
	return ebpf.AttachTCXIngress
}

// attachPrograms attaches only the internal handoff and return paths. Host
// capture predicates and kernel-direct decisions remain in the host TCX programs.
func (ns *DaeNetns) attachPrograms(programs bpfPrograms) ([]link.Link, error) {
	var links []link.Link
	for role, program := range programs.namespacePrograms() {
		attach := namespaceAttachType(uint8(role), ns.dae0.Type() == "netkit")
		var l link.Link
		var err error
		switch {
		case attach == ebpf.AttachSkLookup:
			l, err = link.AttachNetNs(int(ns.daeNs), program)
		case attach == ebpf.AttachNetkitPrimary || attach == ebpf.AttachNetkitPeer:
			l, err = link.AttachNetkit(link.NetkitOptions{Interface: ns.dae0.Attrs().Index, Program: program, Attach: attach})
		case role == netnsHostIngress:
			l, err = link.AttachTCX(link.TCXOptions{Interface: ns.dae0.Attrs().Index, Program: program, Attach: attach})
		default:
			l, err = ns.With(func() (link.Link, error) {
				return link.AttachTCX(link.TCXOptions{Interface: ns.dae0peer.Attrs().Index, Program: program, Attach: attach})
			})
		}
		if err != nil {
			return nil, errors.Join(fmt.Errorf("attach namespace role %d (%s): %w", role, attach, err), closeBpfLinks(links))
		}
		links = append(links, l)
	}
	return links, nil
}
