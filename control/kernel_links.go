// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"net"
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
	pinPath      string
	inherited    bool // preparePins adopted host links a crashed process left
	frozen       bool // ExportReplacement snapshot is active outside mu
	recheckHost  bool // a released snapshot may have missed interface removals
	transferred  bool // Block surrendered the old runtime's attachment ownership
	privatePins  bool // private generation; canonical pins stay borrowed until ConfirmReady
	preparing    bool // host topology stays frozen until final readiness
	prepareErr   error
}

func (k *kernelLinks) ownHostTCXLink(owned hostTCXLink) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.transferred || k.frozen {
		return false
	}
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

func (k *kernelLinks) unpinHostTCXLink(owned hostTCXLink) error {
	if k.pinPath != "" && !k.privatePins && !k.transferred && owned.link != nil {
		return unpinLinkIfPresent(owned.link)
	}
	return nil
}

func (k *kernelLinks) detachHostTCXLink(owned hostTCXLink) error {
	return errors.Join(k.unpinHostTCXLink(owned), owned.close())
}

func (k *kernelLinks) closeHostTCXLinks(index int, roles ...hostTCXRole) error {
	k.mu.Lock()
	if k.preparing || k.transferred || k.frozen {
		k.mu.Unlock()
		return nil
	}
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
		err = errors.Join(err, k.detachHostTCXLink(removed[i]))
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
	if k.transferred || k.frozen {
		return true, net.ErrClosed
	}
	for i := range k.hostTCXLinks {
		owned := &k.hostTCXLinks[i]
		if owned.linkIndex != index || owned.role != spec.role {
			continue
		}
		if owned.program != spec.program {
			if k.preparing {
				k.prepareErr = errors.New("host attachment changed during preparation")
				return true, k.prepareErr
			}
			if err := owned.link.Update(spec.program); err != nil {
				return true, err
			}
			owned.program = spec.program
		}
		owned.generation = k.generation
		return true, nil
	}
	if k.preparing {
		k.prepareErr = errors.New("interception interfaces changed; reload configuration before replacing the executable")
		return true, k.prepareErr
	}
	return false, nil
}

// Replace inherited classifiers even when WAN discovery temporarily cannot
// rediscover an interface. Never leave an attachment referencing a retired plane.
func (k *kernelLinks) updatePrograms(old, next *bpfObjects) error {
	pairs := make(map[*ebpf.Program]*ebpf.Program)
	for _, role := range []hostTCXRole{hostTCXLanIngress, hostTCXLanEgress, hostTCXWanIngress, hostTCXWanEgress} {
		for _, ethernet := range []bool{false, true} {
			pairs[role.program(&old.bpfPrograms, ethernet)] = role.program(&next.bpfPrograms, ethernet)
		}
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.transferred || k.frozen {
		return net.ErrClosed
	}
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

// Only interfaces removed from the configuration lose their attachments.
// Unchanged interfaces never pass through a detach/attach window.
func (k *kernelLinks) finishRebind() error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.transferred || k.frozen {
		return net.ErrClosed
	}
	if k.preparing {
		if k.prepareErr != nil {
			return k.prepareErr
		}
		for _, owned := range k.hostTCXLinks {
			if owned.generation != k.generation {
				return errors.New("interception interfaces changed; reload configuration before replacing the executable")
			}
		}
		return nil
	}
	var err error
	kept := k.hostTCXLinks[:0]
	for _, owned := range k.hostTCXLinks {
		if owned.generation == k.generation {
			kept = append(kept, owned)
		} else {
			err = errors.Join(err, k.detachHostTCXLink(owned))
		}
	}
	k.hostTCXLinks = kept
	return err
}

// Close releases this process's link references. Unless retainPins, it also
// removes the pinned links, detaching every dae attachment.
func (k *kernelLinks) Close(retainPins bool) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.frozen = false
	var err error
	for i := len(k.hostTCXLinks) - 1; i >= 0; i-- {
		err = errors.Join(err, k.hostTCXLinks[i].close())
	}
	k.hostTCXLinks = nil
	err = errors.Join(err, closeBpfLinks(k.netnsLinks))
	err = errors.Join(err, closeBpfLinks(k.pidLinks))
	k.netnsLinks, k.pidLinks = nil, nil
	if k.exitLink != nil {
		err = errors.Join(err, k.exitLink.Close())
		k.exitLink = nil
	}
	if retainPins {
		return err
	}
	return k.removePinnedLinks(err)
}
