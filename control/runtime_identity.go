// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	ciliumLink "github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/internal/kernel"
)

// Socket identity is host-owned and precedes any persistent outbound socket.
// Loading this subset creates no routing, traffic, timer or listener maps.
type socketIdentity struct {
	SockCreate  *ebpf.Program `ebpf:"tproxy_wan_cg_sock_create"`
	Connect4    *ebpf.Program `ebpf:"tproxy_wan_cg_connect4"`
	Connect6    *ebpf.Program `ebpf:"tproxy_wan_cg_connect6"`
	Sendmsg4    *ebpf.Program `ebpf:"tproxy_wan_cg_sendmsg4"`
	Sendmsg6    *ebpf.Program `ebpf:"tproxy_wan_cg_sendmsg6"`
	SocketOwner *ebpf.Map     `ebpf:"socket_owner_map"`
}

func (s *socketIdentity) programs() []*ebpf.Program {
	return []*ebpf.Program{s.SockCreate, s.Connect4, s.Connect6, s.Sendmsg4, s.Sendmsg6}
}

func (s *socketIdentity) Close() (err error) {
	if s == nil {
		return nil
	}
	for _, program := range s.programs() {
		err = errors.Join(err, program.Close())
	}
	return errors.Join(err, s.SocketOwner.Close())
}

// PrepareUserspace supplies borrowed process resources and installs only the
// socket-owner hooks needed by WAN. Full business BPF is installed afterwards.
func (r *Runtime) PrepareUserspace(ctx context.Context, soMarkFromDae uint32, wan bool) (UserspaceResources, error) {
	if err := r.waitForRetirement(ctx); err != nil {
		return UserspaceResources{}, err
	}
	r.lifecycle.Lock()
	defer r.lifecycle.Unlock()
	if r.offline {
		return UserspaceResources{}, net.ErrClosed
	}
	if err := r.prepareHost(ctx, soMarkFromDae); err != nil {
		return UserspaceResources{}, err
	}
	interfaces, err := r.Interfaces()
	if err != nil {
		return UserspaceResources{}, err
	}
	if wan && len(r.kernelLinks.pidLinks) < len(socketIdentityAttachTypes) {
		if r.socketIdentity == nil {
			if err := r.prepareKernelPins(); err != nil {
				return UserspaceResources{}, err
			}
			spec, err := loadBPFSpec()
			if err != nil {
				return UserspaceResources{}, err
			}
			hasCurrentTask, err := probeBPFCurrentTask()
			if err != nil {
				return UserspaceResources{}, err
			}
			if err := spec.Variables["PARAM"].Set(bpfDaeParam{HasBpfGetCurrentTask: hasCurrentTask}); err != nil {
				return UserspaceResources{}, err
			}
			opts := &ebpf.CollectionOptions{Cache: kernelBTFCache}
			if owner := r.shared["socket_owner_map"]; owner != nil {
				opts.MapReplacements = map[string]*ebpf.Map{"socket_owner_map": owner}
			}
			if r.kernelLinks.privatePins {
				for _, m := range spec.Maps {
					m.Pinning = ebpf.PinNone
				}
			} else {
				opts.Maps.PinPath = kernelPinPath()
				// Never inspect or replace business pins while preparing identity.
				identitySpec := &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{"socket_owner_map": spec.Maps["socket_owner_map"]}}
				if err := removeIncompatiblePinnedMaps(identitySpec, opts.Maps.PinPath); err != nil {
					return UserspaceResources{}, err
				}
			}
			identity := new(socketIdentity)
			if err := spec.LoadAndAssign(identity, opts); err != nil {
				return UserspaceResources{}, explainBPFLoadError(err)
			}
			r.socketIdentity = identity
		}
		if err := r.kernelLinks.attachSocketIdentity(r.socketIdentity.programs()); err != nil {
			return UserspaceResources{}, err
		}
	}
	return UserspaceResources{Interfaces: interfaces, Outbounds: &r.outboundResources, SkipConnectivityWait: r.staged}, ctx.Err()
}

var socketIdentityAttachTypes = [...]ebpf.AttachType{
	ebpf.AttachCGroupInetSockCreate,
	ebpf.AttachCGroupInet4Connect,
	ebpf.AttachCGroupInet6Connect,
	ebpf.AttachCGroupUDP4Sendmsg,
	ebpf.AttachCGroupUDP6Sendmsg,
}

func (k *kernelLinks) attachSocketIdentity(programs []*ebpf.Program) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.pidLinks) == len(socketIdentityAttachTypes) {
		return nil
	}
	/// Set-up SrcPidMapper to support pname routing.
	cgroupPath, err := detectCgroupPath()
	if err != nil {
		return err
	}
	for i := len(k.pidLinks); i < len(programs); i++ {
		prog := programs[i]
		var attached ciliumLink.Link
		path := filepath.Join(k.pinPath, fmt.Sprintf("pid_%d", socketIdentityAttachTypes[i]))
		if k.pinPath != "" && !k.privatePins {
			attached, err = ciliumLink.LoadPinnedLink(path, nil)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("load socket identity hook: %w", err)
			}
		}
		if attached != nil {
			if err := attached.Update(prog); err != nil {
				return errors.Join(fmt.Errorf("update socket identity hook: %w", err), attached.Close())
			}
		} else {
			attached, err = ciliumLink.AttachCgroup(ciliumLink.CgroupOptions{
				Path: cgroupPath, Attach: socketIdentityAttachTypes[i], Program: prog,
			})
			if err != nil {
				return fmt.Errorf("AttachCgroup: %v: %w", prog.String(), err)
			}
			if k.pinPath != "" && !k.privatePins {
				if err := attached.Pin(path); err != nil {
					return errors.Join(fmt.Errorf("pin socket identity hook: %w", err), attached.Close())
				}
			}
		}
		k.pidLinks = append(k.pidLinks, attached)
	}
	return nil
}

func (r *Runtime) prepareKernelPins() error {
	return r.prepareKernelPinsAt(kernelPinPath())
}

func (r *Runtime) prepareKernelPinsAt(pinPath string) error {
	if !r.IsReload() && !r.staged {
		for _, name := range []string{replacementMarker, "guards"} {
			if _, err := os.Stat(filepath.Join(pinPath, name)); err == nil {
				r.recoveringGuards = true
				break
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	r.kernelLinks.privatePins = r.kernelLinks.privatePins || r.staged || r.recoveringGuards
	if err := os.MkdirAll(pinPath, 0755); err != nil {
		return fmt.Errorf("failed to prepare BPF pin directory %s: %w; verify bpffs is mounted read-write at %s and is writable by this process", pinPath, err, consts.BpfPinRoot)
	}
	if err := r.kernelLinks.preparePins(pinPath); err != nil {
		return err
	}
	return nil
}

// prepareHost establishes the interface view before userspace routing is compiled.
func (r *Runtime) prepareHost(ctx context.Context, soMarkFromDae uint32) error {
	if err := r.checkSocketMark(soMarkFromDae); err != nil {
		return err
	}
	if err := kernel.CheckVersion(); err != nil {
		return err
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("rlimit.RemoveMemlock:%v", err)
	}

	r.kernelOwned = true
	InitDaeNetns()
	if err := InitSysctlManager(); err != nil {
		return err
	}
	if r.staged {
		if err := GetDaeNetns().inheritSysctls(); err != nil {
			return fmt.Errorf("validate inherited namespace sysctls: %w", err)
		}
	}
	if err := GetDaeNetns().Setup(); err != nil {
		return fmt.Errorf("failed to setup dae netns: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	return nil
}
