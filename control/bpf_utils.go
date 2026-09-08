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
	"github.com/cilium/ebpf/features"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/control/internal/splice"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
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

func deleteUDPRoutingTuples(m *ebpf.Map) error {
	var (
		key   bpfTuplesKey
		value bpfRoutingResult
		keys  []bpfTuplesKey
	)
	iter := m.Iterate()
	for iter.Next(&key, &value) {
		if key.L4proto == unix.IPPROTO_UDP {
			keys = append(keys, key)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate routing tuples: %w", err)
	}
	for i := range keys {
		if err := m.Delete(&keys[i]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete UDP routing tuple: %w", err)
		}
	}
	return nil
}

func deleteUDPRoutingCache(m *ebpf.Map, preserveDirect bool) error {
	var (
		key   bpfUdpRoutingCacheKey
		value bpfUdpRoutingCacheValue
		keys  []bpfUdpRoutingCacheKey
	)
	iter := m.Iterate()
	for iter.Next(&key, &value) {
		if !preserveDirect || value.Result.Outbound != 0 {
			keys = append(keys, key)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate UDP routing cache: %w", err)
	}
	for i := range keys {
		if err := m.Delete(&keys[i]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete UDP routing cache entry: %w", err)
		}
	}
	return nil
}

// BPFState keeps reload-persistent process metadata with the shared BPF
// objects. During reload, cleanup ownership is released by the old core and
// acquired later by the successor while this state remains alive.
type BPFState struct {
	*bpfObjects
	deviceRoutes               *deviceRoutes
	splice                     *splice.Runtime
	soMarkFromDae              uint32
	routingProfileIDs          routingProfileIDAllocator
	routingRegistrationCancels []func()

	// activeLpmTrieCount is the LPM trie count from the last BuildKernspace
	// that committed successfully. BuildKernspace advances it only after its
	// writes complete; any activation failure is terminal because kernel state
	// may be partially written.
	activeLpmTrieCount uint32
}

func (b *BPFState) Close() error {
	b.clearRoutingRegistrations()
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

func (o *bpfObjects) newLpmMap(prefixes []netip.Prefix) (m *ebpf.Map, err error) {
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
	if len(prefixes) == 0 {
		return m, nil
	}
	keys := make([]_bpfLpmKey, len(prefixes))
	values := make([]uint32, len(prefixes))
	for i, prefix := range prefixes {
		keys[i], values[i] = cidrToBpfLpmKey(prefix), 1
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
	for name, value := range constants {
		variable, ok := spec.Variables[name]
		if !ok {
			return fmt.Errorf("missing constant %s", name)
		}
		if !variable.Constant() {
			return fmt.Errorf("variable %s is not a constant", name)
		}
		if err := variable.Set(value); err != nil {
			return fmt.Errorf("set constant %s: %w", name, err)
		}
	}
	if opts != nil && opts.Maps.PinPath != "" {
		if err := removeIncompatiblePinnedMaps(spec, opts.Maps.PinPath); err != nil {
			return err
		}
	}
	return spec.LoadAndAssign(obj, opts)
}

func fullLoadBpfObjects(
	bpf *bpfObjects,
	soMarkFromDae uint32,
	opts *ebpf.CollectionOptions,
) (err error) {
	hasBpfGetCurrentTask := uint8(0)
	if err := features.HaveProgramHelper(ebpf.CGroupSockAddr, asm.FnGetCurrentTask); err == nil {
		hasBpfGetCurrentTask = 1
		log.Debugf("bpf_get_current_task is supported")
	} else {
		log.WithError(err).Warn("Kernel lacks bpf_get_current_task; process name routing uses truncated task names")
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
		var verifierErr *ebpf.VerifierError
		if log.IsLevelEnabled(log.TraceLevel) && errors.As(err, &verifierErr) {
			log.WithField("verifier", fmt.Sprintf("%+v", verifierErr)).Trace("eBPF verifier rejected program")
		}
		if strings.Contains(err.Error(), "no BTF found for kernel version") {
			err = fmt.Errorf("%w: you should re-compile linux kernel with BTF configurations; see docs for more information", err)
		} else if strings.Contains(err.Error(), "unknown func bpf_trace_printk") {
			err = fmt.Errorf("%w: compile dae without bpf_printk", err)
		} else if strings.Contains(err.Error(), "unknown func bpf_probe_read") {
			err = fmt.Errorf("%w: compile the kernel with CONFIG_BPF_EVENTS=y and CONFIG_KPROBE_EVENTS=y", err)
		}
		return err
	}
	return nil
}

func (b *BPFState) clearRoutingRegistrations() {
	for _, cancel := range b.routingRegistrationCancels {
		cancel()
	}
	b.routingRegistrationCancels = nil
}

func removeIncompatiblePinnedMaps(spec *ebpf.CollectionSpec, pinPath string) error {
	for _, mapSpec := range spec.Maps {
		if mapSpec.Pinning != ebpf.PinByName {
			continue
		}
		path := filepath.Join(pinPath, mapSpec.Name)
		pinned, err := ebpf.LoadPinnedMap(path, nil)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("load pinned map %q for compatibility check: %w", mapSpec.Name, err)
		}
		compatibleErr := mapSpec.Compatible(pinned)
		if err := pinned.Close(); err != nil {
			return fmt.Errorf("close pinned map %q: %w", mapSpec.Name, err)
		}
		if compatibleErr == nil {
			continue
		}
		if !errors.Is(compatibleErr, ebpf.ErrMapIncompatible) {
			return fmt.Errorf("check pinned map %q compatibility: %w", mapSpec.Name, compatibleErr)
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove incompatible pinned map %q: %w", mapSpec.Name, err)
		}
		log.WithField("map", mapSpec.Name).Info("Removed incompatible pinned eBPF map")
	}
	return nil
}
