// SPDX-License-Identifier: AGPL-3.0-only

package handoff

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestSocketExportPreservesNonblocking(t *testing.T) {
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	file, err := DupSocket(udp, "udp")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.O_NONBLOCK == 0 {
		t.Fatal("ExtraFiles would turn the live socket into blocking mode")
	}
	_ = udp.SetReadDeadline(time.Now().Add(time.Millisecond))
	var buf [1]byte
	if _, _, err := udp.ReadFromUDP(buf[:]); err == nil {
		t.Fatal("deadline was lost")
	}
}

func TestChannelFrames(t *testing.T) {
	parent, file, err := SocketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	defer file.Close()
	child, err := FromFile(file)
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	_ = parent.SetDeadline(time.Now().Add(time.Second))
	_ = child.SetDeadline(time.Now().Add(time.Second))
	want := struct {
		Stage string
		IDs   []uint32
	}{"ready", []uint32{3, 7}}
	for range 2 {
		if err := parent.Send(want); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		var got struct {
			Stage string
			IDs   []uint32
		}
		if err := child.Receive(&got); err != nil {
			t.Fatal(err)
		}
		if got.Stage != want.Stage || len(got.IDs) != 2 || got.IDs[1] != 7 {
			t.Fatal(got)
		}
	}
}

func TestHeldListener(t *testing.T) {
	for _, activate := range []bool{false, true} {
		raw, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		held := Hold(raw)
		defer held.Close()
		done := make(chan error, 1)
		go func() {
			conn, err := held.Accept()
			if conn != nil {
				_ = conn.Close()
			}
			done <- err
		}()
		conn, err := net.Dial("tcp", raw.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		select {
		case err := <-done:
			t.Fatalf("accepted before activation: %v", err)
		case <-time.After(10 * time.Millisecond):
		}
		if activate {
			held.Activate()
			held.Activate()
		} else {
			_ = held.Close()
		}
		select {
		case err := <-done:
			if activate && err != nil || !activate && !errors.Is(err, net.ErrClosed) {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("Accept was not released")
		}
	}
}

func TestChannelPeerExit(t *testing.T) {
	parent, file, err := SocketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	_ = file.Close()
	_ = parent.SetDeadline(time.Now().Add(time.Second))
	var value any
	if err := parent.Receive(&value); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
}
