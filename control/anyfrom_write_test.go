// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"
)

func TestAnyfromWriteFamiliesDeadlinesAndClose(t *testing.T) {
	for _, network := range []string{"udp4", "udp6", "udp"} {
		t.Run(network, func(t *testing.T) {
			sender, err := net.ListenUDP(network, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer sender.Close()
			family, address := "udp4", "127.0.0.1:0"
			if network == "udp6" {
				family, address = "udp6", "[::1]:0"
			}
			receiver, err := net.ListenPacket(family, address)
			if err != nil {
				t.Fatal(err)
			}
			defer receiver.Close()
			dst := receiver.LocalAddr().(*net.UDPAddr).AddrPort()
			a := &Anyfrom{conn: sender, idleTTL: time.Hour}
			data := []byte("deadline isolation")
			if _, err := a.WriteToUDPAddrPortWithDeadline(data, dst, time.Now().Add(-time.Second)); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("expired write: %v", err)
			}
			// A live slow writer may change the poller deadline. Immediate raw sends
			// must honor their own deadline independently of this shared state.
			if err := sender.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
				t.Fatal(err)
			}
			a.writeMu.Lock()
			for _, payload := range [][]byte{data, nil} {
				if n, err := a.WriteToUDPAddrPortWithDeadline(payload, dst, time.Now().Add(time.Second)); err != nil || n != len(payload) {
					t.Fatalf("write = %d, %v", n, err)
				}
				if err := receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				buffer := make([]byte, 128)
				n, _, err := receiver.ReadFrom(buffer)
				if err != nil || !bytes.Equal(buffer[:n], payload) {
					t.Fatalf("read = %q, %v", buffer[:n], err)
				}
			}
			a.writeMu.Unlock()
			if err := a.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := a.WriteToUDPAddrPortWithDeadline(data, dst, time.Now().Add(time.Second)); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("closed write = %v", err)
			}
		})
	}
}

func TestAnyfromConcurrentPacketDeadlines(t *testing.T) {
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	if err := receiver.SetReadBuffer(1 << 20); err != nil {
		t.Fatal(err)
	}
	sender, err := net.ListenUDP("udp4", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	a := &Anyfrom{conn: sender, idleTTL: time.Hour}
	dst := receiver.LocalAddr().(*net.UDPAddr).AddrPort()
	var workers sync.WaitGroup
	for i := range 64 {
		workers.Go(func() {
			data := []byte{byte(i)}
			if i%2 == 0 {
				if _, err := a.WriteToUDPAddrPortWithDeadline(data, dst, time.Now().Add(-time.Second)); !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Errorf("expired write: %v", err)
				}
			} else if _, err := a.WriteToUDPAddrPortWithDeadline(data, dst, time.Now().Add(time.Second)); err != nil {
				t.Error(err)
			}
		})
	}
	workers.Wait()
	seen := make(map[byte]bool)
	if err := receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	for range 32 {
		var data [2]byte
		n, _, err := receiver.ReadFromUDPAddrPort(data[:])
		if err != nil || n != 1 || data[0]%2 == 0 || seen[data[0]] {
			t.Fatalf("invalid packet: %v, %d, %v", data, n, err)
		}
		seen[data[0]] = true
	}
}

func TestAnyfromInvalidDestinationUsesNetValidation(t *testing.T) {
	sender, err := net.ListenUDP("udp4", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	a := &Anyfrom{conn: sender, idleTTL: time.Hour}
	for _, dst := range []netip.AddrPort{{}, netip.MustParseAddrPort("[::1]:1234")} {
		if _, err := a.WriteToUDPAddrPortWithDeadline(nil, dst, time.Now().Add(time.Second)); err == nil {
			t.Fatal("invalid destination accepted")
		}
	}
}
