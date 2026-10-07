// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// attachPrograms attaches only the internal handoff and return paths. Host
// capture predicates and kernel-direct decisions remain in the host TCX programs.
// Netkit and TCX share SCHED_CLS programs; link creation selects the hook.
func (ns *DaeNetns) attachPrograms(programs bpfPrograms) (links []link.Link, err error) {
	defer func() {
		if err != nil {
			err = errors.Join(err, closeBpfLinks(links))
			links = nil
		}
	}()
	skLookup, err := link.AttachNetNs(int(ns.daeNs), programs.TproxySkLookup)
	if err != nil {
		return nil, fmt.Errorf("attach SK_LOOKUP program to dae netns: %w", err)
	}
	links = append(links, skLookup)
	if ns.dae0.Type() == "netkit" {
		for _, target := range []struct {
			program *ebpf.Program
			attach  ebpf.AttachType
		}{
			{programs.TproxyDae0peerIngress, ebpf.AttachNetkitPrimary},
			{programs.TproxyDae0Ingress, ebpf.AttachNetkitPeer},
		} {
			attached, err := link.AttachNetkit(link.NetkitOptions{
				Interface: ns.dae0.Attrs().Index, Program: target.program, Attach: target.attach,
			})
			if err != nil {
				return links, fmt.Errorf("attach %s program: %w", target.attach, err)
			}
			links = append(links, attached)
		}
		return links, nil
	}
	peer, err := ns.With(func() (link.Link, error) {
		return link.AttachTCX(link.TCXOptions{
			Interface: ns.dae0peer.Attrs().Index, Program: programs.TproxyDae0peerIngress,
			Attach: ebpf.AttachTCXIngress,
		})
	})
	if err != nil {
		return links, fmt.Errorf("attach veth dae0peer ingress: %w", err)
	}
	links = append(links, peer)
	host, err := link.AttachTCX(link.TCXOptions{
		Interface: ns.dae0.Attrs().Index, Program: programs.TproxyDae0Ingress,
		Attach: ebpf.AttachTCXIngress,
	})
	if err != nil {
		return links, fmt.Errorf("attach veth dae0 ingress: %w", err)
	}
	return append(links, host), nil
}
