package fq

import (
	"bytes"
	"testing"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

func TestPartialForcedFrameKeepsOwnershipAndOrder(t *testing.T) {
	used := netproxy.DatagramMemory.Status().Used
	var released int
	s := &Scheduler{Release: func([]byte) { released++ }}
	defer s.Clear()
	bulk, sparse := new(Flow), new(Flow)
	forced := make([]byte, 3000)
	for i := range forced {
		forced[i] = byte(i)
	}
	admit(s, bulk, epoch, forced, true)
	var wire []byte
	for _, part := range s.Take(epoch, 1000, nil) {
		wire = append(wire, part...)
	}
	s.ReleaseBatch()
	if released != 0 || netproxy.DatagramMemory.Status().Used-used != 4096 {
		t.Fatal("partial forced frame lost its capacity reservation")
	}
	last := bytes.Repeat([]byte{0x5a}, 16)
	s.Push(sparse, last)
	for s.Queued() {
		for _, part := range s.Take(epoch.Add(100*Interval), 1000, nil) {
			wire = append(wire, part...)
		}
		s.ReleaseBatch()
	}
	if !bytes.Equal(wire, append(forced, last...)) {
		t.Fatal("another frame interrupted the forced frame")
	}
	if released != 2 || netproxy.DatagramMemory.Status().Used != used {
		t.Fatalf("released=%d held=%d", released, netproxy.DatagramMemory.Status().Used-used)
	}
}

func TestClearKeepsBorrowedPartialCapacity(t *testing.T) {
	for _, borrowing := range []bool{true, false} {
		t.Run(map[bool]string{true: "during-write", false: "between-writes"}[borrowing], func(t *testing.T) {
			used := netproxy.DatagramMemory.Status().Used
			released := 0
			s := &Scheduler{Release: func([]byte) { released++ }}
			admit(s, new(Flow), epoch, make([]byte, 3000), true)
			s.Take(epoch, 1000, nil)
			if !borrowing {
				s.ReleaseBatch()
			}
			s.Clear()
			if borrowing && (released != 0 || netproxy.DatagramMemory.Status().Used-used != 4096) {
				t.Fatal("Clear freed a writer's borrowed buffer")
			}
			s.ReleaseBatch()
			if released != 1 || netproxy.DatagramMemory.Status().Used != used {
				t.Fatalf("released=%d held=%d", released, netproxy.DatagramMemory.Status().Used-used)
			}
		})
	}
}

// A stream frame stays the writer's until the batch that completes it is
// released, also after only part of it was taken.
func TestBorrowedStreamFrameIsReleasedWithItsBatch(t *testing.T) {
	released := 0
	s := &Scheduler{Release: func([]byte) { released++ }}
	f := new(Flow)
	s.Push(f, make([]byte, 3000, 4096))
	s.Take(epoch, 1000, nil)
	s.ReleaseBatch()
	if released != 0 {
		t.Fatal("partly sent frame was released")
	}
	s.Take(epoch, 2000, nil)
	if released != 0 {
		t.Fatal("completed but still borrowed frame was released")
	}
	s.ReleaseBatch()
	if released != 1 {
		t.Fatal("completed frame was not released")
	}
}

func TestDatagramAdmissionReclaimsEnoughCapacity(t *testing.T) {
	limit := netproxy.DatagramMemory.UseLimit(4096)
	defer limit.Close()
	s := &Scheduler{Drops: testDrops}
	defer s.Clear()
	flow := new(Flow)
	for range 4 {
		if !admit(s, flow, epoch, make([]byte, 1024), false) {
			t.Fatal("small datagram rejected")
		}
	}
	before := testDrops.Memory.Load()
	if s.AllocateDatagram(new(Flow), epoch, 2048, false) == nil {
		t.Fatal("larger datagram rejected despite reclaimable capacity")
	}
	if dropped := testDrops.Memory.Load() - before; dropped != 2 || flow.queue.Len() != 2 {
		t.Fatalf("dropped=%d queued=%d, want two evictions", dropped, flow.queue.Len())
	}
	if used := netproxy.DatagramMemory.Status().Used; used != 4096 {
		t.Fatalf("used=%d, want 4096", used)
	}
}

// An admission that evicting every droppable datagram could not make room
// for evicts none: the datagram exceeds the budget, or other owners hold
// the rest of it.
func TestImpossibleAdmissionKeepsQueuedDatagrams(t *testing.T) {
	for _, tc := range []struct {
		name               string
		limit, size, other int64
	}{
		{"over budget", 16 << 10, 32 << 10, 0},
		{"held by others", 64 << 10, 32 << 10, 48 << 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			limit := netproxy.DatagramMemory.UseLimit(tc.limit)
			defer limit.Close()
			held, err := netproxy.DatagramMemory.Reserve(tc.other)
			if err != nil {
				t.Fatal(err)
			}
			defer held.Close()
			s := &Scheduler{Drops: testDrops}
			defer s.Clear()
			flow := new(Flow)
			for range 16 {
				if !admit(s, flow, epoch, make([]byte, 1024), false) {
					t.Fatal("small datagram rejected")
				}
			}
			dropped := drops(testDrops.Memory)
			if s.AllocateDatagram(new(Flow), epoch, int(tc.size), false) != nil {
				t.Fatal("admitted a datagram beyond the reclaimable budget")
			}
			if n := dropped(); n != 1 || flow.queue.Len() != 16 {
				t.Fatalf("impossible admission evicted queued data: drops=%d queued=%d", n, flow.queue.Len())
			}
		})
	}
}

func TestForcedAdmissionDoesNotExceedSharedBudget(t *testing.T) {
	limit := netproxy.DatagramMemory.UseLimit(64)
	defer limit.Close()
	held, err := netproxy.DatagramMemory.Reserve(64)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	released := 0
	s := &Scheduler{Release: func([]byte) { released++ }}
	defer s.Clear()
	flow := new(Flow)
	if admit(s, flow, epoch, make([]byte, 8), true) || s.Queued() || released != 0 {
		t.Fatal("request bypassed admission or retained rejected memory")
	}
	if used := netproxy.DatagramMemory.Status().Used; used != 64 {
		t.Fatalf("used=%d, want 64", used)
	}
	held.Close()
	if !admit(s, flow, epoch, make([]byte, 8), true) {
		t.Fatal("request failed after capacity returned")
	}
	s.Clear()
	if used := netproxy.DatagramMemory.Status().Used; used != 0 || released != 1 {
		t.Fatalf("used=%d released=%d", used, released)
	}
}
