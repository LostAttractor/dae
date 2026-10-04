// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"slices"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Attachments share Runtime's lifetime. Reload stops the old plane's
// writers, but keeps TCP interception, return paths and socket identity alive.
type kernelLinks struct {
	mu           sync.Mutex
	hostTCXLinks []hostTCXLink
	netnsLinks   []link.Link
	pidLinks     []link.Link
	exitLink     link.Link
	generation   uint64
}

func (k *kernelLinks) ownHostTCXLink(owned hostTCXLink) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, existing := range k.hostTCXLinks {
		if existing.linkIndex == owned.linkIndex && existing.role == owned.role {
			return false
		}
	}
	owned.generation = k.generation
	k.hostTCXLinks = append(k.hostTCXLinks, owned)
	return true
}

func (k *kernelLinks) hostTCXLink(index int, role hostTCXRole) (link.Link, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, owned := range k.hostTCXLinks {
		if owned.linkIndex == index && owned.role == role {
			return owned.link, true
		}
	}
	return nil, false
}

func (k *kernelLinks) closeHostTCXLinks(index int, roles ...hostTCXRole) error {
	k.mu.Lock()
	var removed []hostTCXLink
	kept := k.hostTCXLinks[:0]
	for _, owned := range k.hostTCXLinks {
		if owned.linkIndex != index || len(roles) > 0 && !slices.Contains(roles, owned.role) {
			kept = append(kept, owned)
		} else {
			removed = append(removed, owned)
		}
	}
	k.hostTCXLinks = kept
	k.mu.Unlock()
	var err error
	for i := len(removed) - 1; i >= 0; i-- {
		err = errors.Join(err, removed[i].close())
	}
	return err
}

func (k *kernelLinks) beginRebind() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.generation++
}

func (k *kernelLinks) useHostTCXLink(index int, role hostTCXRole) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	for i := range k.hostTCXLinks {
		owned := &k.hostTCXLinks[i]
		if owned.linkIndex == index && owned.role == role {
			owned.generation = k.generation
			return true
		}
	}
	return false
}

func (k *kernelLinks) updateHostTCXLink(index int, spec hostTCXProgram) (bool, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	for i := range k.hostTCXLinks {
		owned := &k.hostTCXLinks[i]
		if owned.linkIndex != index || owned.role != spec.role {
			continue
		}
		if owned.program != spec.program {
			if err := owned.link.Update(spec.program); err != nil {
				return true, err
			}
			owned.program = spec.program
		}
		owned.generation = k.generation
		return true, nil
	}
	return false, nil
}

// Replace inherited classifiers even when WAN discovery temporarily cannot
// rediscover an interface. Never leave an attachment referencing a retired plane.
func (k *kernelLinks) updatePrograms(old, next *bpfObjects) error {
	pairs := map[*ebpf.Program]*ebpf.Program{
		old.LanIngressL2: next.LanIngressL2, old.LanIngressL3: next.LanIngressL3,
		old.LanEgressL2: next.LanEgressL2, old.LanEgressL3: next.LanEgressL3,
		old.TproxyWanIngressL2: next.TproxyWanIngressL2, old.TproxyWanIngressL3: next.TproxyWanIngressL3,
		old.TproxyWanEgressL2: next.TproxyWanEgressL2, old.TproxyWanEgressL3: next.TproxyWanEgressL3,
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	for i := range k.hostTCXLinks {
		owned := &k.hostTCXLinks[i]
		if program := pairs[owned.program]; program != nil {
			if err := owned.link.Update(program); err != nil {
				return err
			}
			owned.program = program
		}
	}
	return nil
}

// Seed discovery from the still-attached WAN links on reload. An authoritative
// snapshot replaces these provisional owners; an unavailable snapshot retains
// them until discovery recovers instead of creating an interception gap.
func (c *controlPlaneCore) seedAutoWanBindings() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.kernelLinks.mu.Lock()
	defer c.kernelLinks.mu.Unlock()
	for _, owned := range c.hostTCXLinks {
		if owned.role != hostTCXWanEgress {
			continue
		}
		binding := c.wanBindings[owned.linkIndex]
		if binding == nil {
			binding = &wanBinding{manualPatterns: make(map[string]struct{})}
			c.wanBindings[owned.linkIndex] = binding
		}
		binding.automatic = true
	}
}

// Only interfaces removed from the configuration lose their attachments.
// Unchanged interfaces never pass through a detach/attach window.
func (k *kernelLinks) finishRebind() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	var err error
	kept := k.hostTCXLinks[:0]
	for _, owned := range k.hostTCXLinks {
		if owned.generation == k.generation {
			kept = append(kept, owned)
		} else {
			err = errors.Join(err, owned.close())
		}
	}
	k.hostTCXLinks = kept
	return err
}

func (k *kernelLinks) Close() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	var err error
	for i := len(k.hostTCXLinks) - 1; i >= 0; i-- {
		err = errors.Join(err, k.hostTCXLinks[i].close())
	}
	k.hostTCXLinks = nil
	err = errors.Join(err, closeBpfLinks(k.netnsLinks), closeBpfLinks(k.pidLinks))
	k.netnsLinks, k.pidLinks = nil, nil
	if k.exitLink != nil {
		err = errors.Join(err, k.exitLink.Close())
		k.exitLink = nil
	}
	return err
}
