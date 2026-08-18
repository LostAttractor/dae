/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/features"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/control/internal/splice"
	log "github.com/sirupsen/logrus"
)

type _bpfTuples struct {
	Sip     [4]uint32
	Dip     [4]uint32
	Sport   uint16
	Dport   uint16
	L4proto uint8
	_       [3]byte
}

type _bpfLpmKey struct {
	PrefixLen uint32
	Data      [4]uint32
}

type _bpfPortRange struct {
	PortStart uint16
	PortEnd   uint16
}

// bpfState keeps reload-persistent process metadata with the shared BPF
// objects. During reload, cleanup ownership is released by the old core and
// acquired later by the successor while this state remains alive.
type bpfState struct {
	*bpfObjects
	splice        *splice.Runtime
	soMarkFromDae uint32

	// activeLpmTrieCount is the LPM trie count from the last BuildKernspace
	// that committed successfully. BuildKernspace advances it only after its
	// writes complete; any activation failure is terminal because kernel state
	// may be partially written.
	activeLpmTrieCount uint32
}

func validateReusableBpfState(value interface{}, soMarkFromDae uint32) (*bpfState, error) {
	if value == nil {
		return nil, nil
	}
	state, ok := value.(*bpfState)
	if !ok || state == nil {
		return nil, fmt.Errorf("unexpected bpf type: %T", value)
	}
	if state.soMarkFromDae != soMarkFromDae {
		return nil, fmt.Errorf("reused BPF objects were loaded with so_mark_from_dae %#x, requested %#x; restart dae to apply it", state.soMarkFromDae, soMarkFromDae)
	}
	return state, nil
}

func (b *bpfState) Close() error {
	var spliceErr error
	if b.splice != nil {
		spliceErr = b.splice.Close()
	}
	return errors.Join(spliceErr, b.bpfObjects.Close())
}

func (r _bpfPortRange) Encode() (b [16]byte) {
	binary.LittleEndian.PutUint16(b[:2], r.PortStart)
	binary.LittleEndian.PutUint16(b[2:], r.PortEnd)
	return b
}

func ParsePortRange(b []byte) (portStart, portEnd uint16) {
	portStart = binary.LittleEndian.Uint16(b[:2])
	portEnd = binary.LittleEndian.Uint16(b[2:])
	return portStart, portEnd
}

func (o *bpfObjects) newLpmMap(keys []_bpfLpmKey, values []uint32) (m *ebpf.Map, err error) {
	m, err = ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.LPMTrie,
		Flags:      o.UnusedLpmType.Flags(),
		MaxEntries: o.UnusedLpmType.MaxEntries(),
		KeySize:    o.UnusedLpmType.KeySize(),
		ValueSize:  o.UnusedLpmType.ValueSize(),
	})
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return m, nil
	}
	if _, err = m.BatchUpdate(keys, values, &ebpf.BatchOptions{
		ElemFlags: uint64(ebpf.UpdateAny),
	}); err != nil {
		_ = m.Close()
		return nil, err
	}
	return m, nil
}

func cidrToBpfLpmKey(prefix netip.Prefix) _bpfLpmKey {
	bits := prefix.Bits()
	if prefix.Addr().Is4() {
		bits += 96
	}
	ip := prefix.Addr().As16()
	return _bpfLpmKey{
		PrefixLen: uint32(bits),
		Data:      common.Ipv6ByteSliceToUint32Array(ip[:]),
	}
}

// BpfMapBatchDelete deletes keys and ignores ErrKeyNotExist.
func BpfMapBatchDelete(m *ebpf.Map, keys interface{}) (n int, err error) {
	// Simulate
	vKeys := reflect.ValueOf(keys)
	if vKeys.Kind() != reflect.Slice {
		return 0, fmt.Errorf("keys must be slice")
	}
	length := vKeys.Len()

	for i := 0; i < length; i++ {
		vKey := vKeys.Index(i)
		if err = m.Delete(vKey.Interface()); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return i, err
		}
	}
	return vKeys.Len(), nil
}

// detectCgroupPath returns the first-found cgroup2 mount point.
func detectCgroupPath() (string, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return fields[1], nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", errors.New("cgroup2 not mounted")
}

func loadBpfObjectsWithConstants(obj interface{}, opts *ebpf.CollectionOptions, constants map[string]interface{}) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}
	if err := spec.RewriteConstants(constants); err != nil {
		return err
	}
	return spec.LoadAndAssign(obj, opts)
}

func fullLoadBpfObjects(
	bpf *bpfObjects,
	pinPath string,
	soMarkFromDae uint32,
	opts *ebpf.CollectionOptions,
) (err error) {
	// The daemon reuses loaded BPF objects across reloads, so kernel and module
	// BTF are no longer needed after this initial CO-RE relocation pass.
	defer btf.FlushKernelSpec()
retryLoadBpf:
	hasBpfGetCurrentTask := uint8(0)
	if err := features.HaveProgramHelper(ebpf.CGroupSockAddr, asm.FnGetCurrentTask); err == nil {
		hasBpfGetCurrentTask = 1
		log.Debugf("bpf_get_current_task is supported")
	} else {
		log.Warnf("Kernel does not support bpf_get_current_task helper: %v; process names may be truncated or less accurate (degraded to bpf_get_current_comm)", err)
	}
	constants := map[string]interface{}{
		"PARAM": struct {
			controlPlanePid      uint32
			dae0Ifindex          uint32
			dae0peerIfindex      uint32
			dae0peerMac          [6]byte
			hasBpfGetCurrentTask uint8
			padding              uint8
			soMarkFromDae        uint32
		}{
			controlPlanePid:      uint32(os.Getpid()),
			dae0Ifindex:          uint32(GetDaeNetns().Dae0().Attrs().Index),
			dae0peerIfindex:      uint32(GetDaeNetns().Dae0Peer().Attrs().Index),
			dae0peerMac:          [6]byte(GetDaeNetns().Dae0Peer().Attrs().HardwareAddr),
			hasBpfGetCurrentTask: hasBpfGetCurrentTask,
			soMarkFromDae:        soMarkFromDae,
		},
	}
	if err = loadBpfObjectsWithConstants(bpf, opts, constants); err != nil {
		if errors.Is(err, ebpf.ErrMapIncompatible) {
			// Map property is incompatible. Remove the old map and try again.
			prefix := "use pinned map "
			_, after, ok := strings.Cut(err.Error(), prefix)
			if !ok {
				return fmt.Errorf("loading objects: bad format: %w", err)
			}
			mapName, _, _ := strings.Cut(after, ":")
			_ = os.Remove(filepath.Join(pinPath, mapName))
			log.Infof("Incompatible new map format with existing map %v detected; removed the old one.", mapName)
			goto retryLoadBpf
		}
		// Get detailed log from ebpf.internal.(*VerifierError)
		if log.IsLevelEnabled(log.FatalLevel) {
			if v := reflect.Indirect(reflect.ValueOf(errors.Unwrap(errors.Unwrap(err)))); v.Kind() == reflect.Struct {
				if _log := v.FieldByName("Log"); _log.IsValid() {
					if strSlice, ok := _log.Interface().([]string); ok {
						log.Fatalln(strings.Join(strSlice, "\n"))
					}
				}
			}
		}
		if strings.Contains(err.Error(), "no BTF found for kernel version") {
			err = fmt.Errorf("%w: you should re-compile linux kernel with BTF configurations; see docs for more information", err)
		} else if strings.Contains(err.Error(), "unknown func bpf_trace_printk") {
			err = fmt.Errorf(`%w: please try to compile dae without bpf_printk"`, err)
		} else if strings.Contains(err.Error(), "unknown func bpf_probe_read") {
			err = fmt.Errorf(`%w: please re-compile linux kernel with CONFIG_BPF_EVENTS=y and CONFIG_KPROBE_EVENTS=y"`, err)
		}
		return err
	}
	return nil
}
