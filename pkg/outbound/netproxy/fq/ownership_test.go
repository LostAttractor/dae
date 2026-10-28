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
	forced := make([]byte, 3000, 4096)
	for i := range forced {
		forced[i] = byte(i)
	}
	s.Force(bulk, epoch, forced)
	var wire []byte
	for _, part := range s.Take(epoch, 1000, nil) {
		wire = append(wire, part...)
	}
	s.ReleaseBatch()
	if released != 0 || netproxy.DatagramMemory.Status().Used-used != int64(cap(forced)) {
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
			s.Force(new(Flow), epoch, make([]byte, 3000, 4096))
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

func TestStreamCapacityIncludesInFlight(t *testing.T) {
	s := new(Scheduler)
	f := new(Flow)
	s.Push(f, make([]byte, 3000, 4096))
	s.Take(epoch, 1000, nil)
	s.ReleaseBatch()
	if f.Buffered() != 4096 {
		t.Fatalf("partial capacity=%d", f.Buffered())
	}
	s.Take(epoch, 2000, nil)
	if f.Buffered() != 4096 {
		t.Fatal("completed but still borrowed frame became free")
	}
	s.ReleaseBatch()
	if f.Buffered() != 0 {
		t.Fatal("completed frame kept its capacity")
	}
	s.Clear()
}

func TestDatagramAdmissionReclaimsEnoughCapacity(t *testing.T) {
	limit := netproxy.DatagramMemory.UseLimit(4096)
	defer limit.Close()
	s := new(Scheduler)
	defer s.Clear()
	flow := new(Flow)
	for range 4 {
		if !s.Offer(flow, epoch, make([]byte, 1024)) {
			t.Fatal("small datagram rejected")
		}
	}
	before := netproxy.DropUploadMemory.Load()
	if s.AllocateDatagram(new(Flow), epoch, 2048, false) == nil {
		t.Fatal("larger datagram rejected despite reclaimable capacity")
	}
	if dropped := netproxy.DropUploadMemory.Load() - before; dropped != 2 || flow.queue.Len() != 2 {
		t.Fatalf("dropped=%d queued=%d, want two evictions", dropped, flow.queue.Len())
	}
	if used := netproxy.DatagramMemory.Status().Used; used != 4096 {
		t.Fatalf("used=%d, want 4096", used)
	}
}

func TestImpossibleAdmissionKeepsQueuedDatagrams(t *testing.T) {
	limit := netproxy.DatagramMemory.UseLimit(1024)
	defer limit.Close()
	s := new(Scheduler)
	defer s.Clear()
	flow := new(Flow)
	if !s.Offer(flow, epoch, make([]byte, 1024)) {
		t.Fatal("small datagram rejected")
	}
	before := netproxy.DropUploadMemory.Load()
	if s.AllocateDatagram(new(Flow), epoch, 2048, false) != nil {
		t.Fatal("admitted a datagram larger than the budget")
	}
	if dropped := netproxy.DropUploadMemory.Load() - before; dropped != 1 || flow.queue.Len() != 1 {
		t.Fatalf("impossible admission evicted queued data: drops=%d queued=%d", dropped, flow.queue.Len())
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
	if s.Force(flow, epoch, make([]byte, 8)) || s.Queued() || released != 1 {
		t.Fatal("request bypassed admission or retained rejected memory")
	}
	if used := netproxy.DatagramMemory.Status().Used; used != 64 {
		t.Fatalf("used=%d, want 64", used)
	}
	held.Close()
	if !s.Force(flow, epoch, make([]byte, 8)) {
		t.Fatal("request failed after capacity returned")
	}
	s.Clear()
	if used := netproxy.DatagramMemory.Status().Used; used != 0 || released != 2 {
		t.Fatalf("used=%d released=%d", used, released)
	}
}
