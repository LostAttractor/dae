package sniffing

import (
	"errors"
	"testing"
	"time"
)

func TestPacketSnifferStopsAtPacketLimit(t *testing.T) {
	s := NewPacketSniffer(nil, time.Second)
	t.Cleanup(func() { _ = s.Close() })
	for range packetSniffingMaxPackets {
		s.AppendData([]byte{0})
	}
	if s.packetLimit {
		t.Fatal("packet limit reached before the configured maximum")
	}
	s.AppendData([]byte{0})
	if _, err := s.SniffUdp(); !errors.Is(err, ErrNotApplicable) {
		t.Fatalf("SniffUdp error = %v, want ErrNotApplicable", err)
	}
	if s.NeedMore() {
		t.Fatal("limited packet sniffer requested more data")
	}
	if got := len(s.Data()); got != packetSniffingMaxPackets+2 {
		t.Fatalf("retained slices = %d, want sentinel plus %d datagrams", got, packetSniffingMaxPackets+1)
	}
}

func TestPacketSnifferStopsAtByteLimit(t *testing.T) {
	s := NewPacketSniffer(nil, time.Second)
	t.Cleanup(func() { _ = s.Close() })
	s.AppendData(make([]byte, packetSniffingMaxBufferedBytes))
	if s.packetLimit {
		t.Fatal("byte limit reached at the configured maximum")
	}
	s.AppendData([]byte{0})
	if !s.packetLimit {
		t.Fatal("byte limit was not enforced")
	}
	if got := s.packetBytes; got != packetSniffingMaxBufferedBytes+1 {
		t.Fatalf("buffered bytes = %d, want %d", got, packetSniffingMaxBufferedBytes+1)
	}
}
