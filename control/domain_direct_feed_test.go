// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"encoding/binary"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestDomainDirectFeedBatchSlotsKernel(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required for isolated BPF map tests")
	}
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 16, ValueSize: 16, MaxEntries: 2, Flags: unix.BPF_F_NO_PREALLOC})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	f := &domainDirectFeed{slots: m}
	a := netip.MustParseAddr("192.0.2.1")
	b, c := a.Next(), a.Next().Next()
	if err := f.setSlot(a, 1); err != nil {
		t.Fatal(err)
	}
	keys := [][16]byte{a.As16(), b.As16(), c.As16()}
	values := []domainDirectSlot{{Token: 2}, {Token: 3}, {Token: 4}}
	if err := f.setSlots(keys, values); err == nil {
		t.Fatal("over-capacity batch reported success")
	}
	verify := func(i int) {
		t.Helper()
		var got domainDirectSlot
		if err := m.Lookup(keys[i], &got); err != nil || got != values[i] {
			t.Fatalf("slot %d: got %+v, error=%v, want %+v", i, got, err, values[i])
		}
	}
	verify(0)
	verify(1)
	if err := f.setSlot(a, values[0].Token); err != nil {
		t.Fatal(err)
	}
	if err := f.setSlots(keys[:2], values[:2]); err != nil {
		t.Fatal(err)
	}
	verify(0)
	verify(1)
}

func TestDomainDirectFeedStamp(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.7")
	clock := domainDirectClock{at: time.Now(), ns: int64(time.Hour)}
	stamp := uint64(time.Hour - time.Minute)
	var raw [domainDirectRecordSize]byte
	key := ip.As16()
	copy(raw[:16], key[:])
	binary.NativeEndian.PutUint64(raw[16:24], 7)
	binary.NativeEndian.PutUint64(raw[24:], stamp)
	got := clock.decode(raw[:])
	want := domainDirectObservation{ip: ip, token: 7, stamp: stamp, at: clock.at.Add(-time.Minute)}
	if got != want || clock.observation(key, domainDirectSlot{7, stamp}) != got {
		t.Fatalf("decode %+v, want %+v", got, want)
	}
	reanchored := clock.anchored(clock.at.Add(time.Hour)).decode(raw[:])
	if reanchored.stamp != got.stamp || !reanchored.at.Equal(got.at) {
		t.Fatalf("moving the wall clock anchor changed the monotonic observation: %+v", reanchored)
	}
	if bad := clock.decode(raw[:31]); bad.token != 0 {
		t.Fatalf("accepted a short record %+v", bad)
	}
	binary.NativeEndian.PutUint64(raw[24:], 0)
	if bad := clock.decode(raw[:]); bad.token != 0 {
		t.Fatalf("accepted an empty stamp %+v", bad)
	}
}

type directScanFixture struct {
	calls, length int
	overflow      bool
	scalar        bool
}

func (s *directScanFixture) BatchLookup(_ *ebpf.MapBatchCursor, keys, values any, _ *ebpf.BatchOptions) (int, error) {
	s.calls++
	if s.overflow {
		return 0, unix.ENOSPC
	}
	keys.([][16]byte)[0] = netip.MustParseAddr("2001:db8::1").As16()
	values.([]domainDirectSlot)[0] = domainDirectSlot{Token: 1, LastSeen: 3}
	if s.calls%s.length == 0 {
		return 1, ebpf.ErrKeyNotExist // A final syscall can still contain data.
	}
	return 1, nil
}

func (s *directScanFixture) NextKey(previous, next any) error {
	s.scalar = true
	if previous != nil {
		return ebpf.ErrKeyNotExist
	}
	*next.(*[16]byte) = netip.MustParseAddr("2001:db8::2").As16()
	return nil
}

func (*directScanFixture) Lookup(_ any, value any) error {
	*value.(*domainDirectSlot) = domainDirectSlot{Token: 2, LastSeen: 4}
	return nil
}

func (*directScanFixture) MaxEntries() uint32 { return 4 }

func TestDomainDirectFeedLossEpoch(t *testing.T) {
	clock := domainDirectClock{at: time.Now(), ns: 5}
	fixture := &directScanFixture{length: domainDirectScanSteps + 1}
	var r domainDirectRecovery
	var losses uint64
	var observations int
	poll := func() {
		if err := r.poll(func() (uint64, error) { return losses, nil }, fixture, clock, func(batch []domainDirectObservation) {
			observations += len(batch)
			for _, o := range batch {
				if o.token != 1 || o.stamp != 3 || !o.at.Equal(clock.at.Add(-2)) {
					t.Fatalf("bad observation %+v", o)
				}
			}
		}); err != nil {
			t.Fatal(err)
		}
	}
	poll()
	if fixture.calls != 0 {
		t.Fatal("scanned without a loss")
	}
	losses++
	poll()
	if fixture.calls != domainDirectScanSteps || !r.scanning {
		t.Fatalf("poll exceeded its budget or lost its cursor: calls=%d scanning=%t", fixture.calls, r.scanning)
	}
	losses++ // A new loss after a prior step must request a second scan.
	poll()
	if r.completed != 0 || !r.force {
		t.Fatal("a loss during recovery was treated as complete")
	}
	poll()
	poll()
	if r.completed != losses || r.scanning || r.force || observations != 2*fixture.length {
		t.Fatalf("unexpected recovery: completed=%d, scanning=%t, force=%t, observations=%d", r.completed, r.scanning, r.force, observations)
	}
	poll()
	if fixture.calls != 2*fixture.length {
		t.Fatal("stable epoch triggered another scan")
	}
}

func TestDomainDirectFeedRecoveryFragmented(t *testing.T) {
	clock := domainDirectClock{at: time.Now(), ns: 5}
	fixture := &directScanFixture{overflow: true}
	var r domainDirectRecovery
	var collected []domainDirectObservation
	for range 5 {
		if err := r.poll(func() (uint64, error) { return 1, nil }, fixture, clock, func(batch []domainDirectObservation) {
			collected = append(collected, batch...)
		}); err != nil {
			t.Fatal(err)
		}
	}
	if len(r.keys) != domainDirectScanMax || !fixture.scalar || len(collected) != 1 ||
		collected[0].token != 2 || r.completed != 1 {
		t.Fatalf("fragmented recovery: keys=%d scalar=%t observations=%v completed=%d", len(r.keys), fixture.scalar, collected, r.completed)
	}
}
