package control

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestUDPOriginalDestinationRejectsShortControlMessage(t *testing.T) {
	for _, option := range []struct{ level, kind int32 }{
		{unix.SOL_IP, unix.IP_RECVORIGDSTADDR},
		{unix.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR},
	} {
		// Valid ancillary framing with an incomplete IPv4 or IPv6 sockaddr.
		buffer := make([]byte, unix.CmsgSpace(4))
		header := (*unix.Cmsghdr)(unsafe.Pointer(&buffer[0]))
		header.Level, header.Type = option.level, option.kind
		header.SetLen(unix.CmsgLen(4))
		if RetrieveOriginalDest(buffer).IsValid() {
			t.Fatal("accepted truncated destination")
		}
	}
}

// appendControlMessage appends one control message as the kernel lays it out.
func appendControlMessage(oob []byte, level, kind int32, data []byte) []byte {
	message := make([]byte, unix.CmsgSpace(len(data)))
	header := (*unix.Cmsghdr)(unsafe.Pointer(&message[0]))
	header.Level, header.Type = level, kind
	header.SetLen(unix.CmsgLen(len(data)))
	copy(message[unix.CmsgLen(0):], data)
	return append(oob, message...)
}

func originalDestControlMessage(destination netip.AddrPort) []byte {
	if destination.Addr().Is4() {
		var sockaddr [unix.SizeofSockaddrInet4]byte
		binary.NativeEndian.PutUint16(sockaddr[:], unix.AF_INET)
		binary.BigEndian.PutUint16(sockaddr[2:], destination.Port())
		address := destination.Addr().As4()
		copy(sockaddr[4:], address[:])
		return appendControlMessage(nil, unix.SOL_IP, unix.IP_RECVORIGDSTADDR, sockaddr[:])
	}
	var sockaddr [unix.SizeofSockaddrInet6]byte
	binary.NativeEndian.PutUint16(sockaddr[:], unix.AF_INET6)
	binary.BigEndian.PutUint16(sockaddr[2:], destination.Port())
	address := destination.Addr().As16()
	copy(sockaddr[8:], address[:])
	return appendControlMessage(nil, unix.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, sockaddr[:])
}

func TestUDPOriginalDestinationParsesControlMessages(t *testing.T) {
	for _, destination := range []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.1:443"),
		netip.MustParseAddrPort("[2001:db8::1]:53"),
	} {
		// Unrelated messages before the destination are skipped.
		oob := appendControlMessage(nil, unix.SOL_SOCKET, unix.SCM_TIMESTAMP, make([]byte, 5))
		oob = append(oob, originalDestControlMessage(destination)...)
		if got := RetrieveOriginalDest(oob); got != destination {
			t.Fatalf("destination = %v, want %v", got, destination)
		}
		if allocs := testing.AllocsPerRun(100, func() { RetrieveOriginalDest(oob) }); allocs != 0 {
			t.Fatalf("parsing allocated %v times", allocs)
		}
		// A header claiming more bytes than were received is truncated.
		header := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
		header.SetLen(len(oob) + 1)
		if RetrieveOriginalDest(oob).IsValid() {
			t.Fatal("accepted a control message beyond the received bytes")
		}
	}
	if RetrieveOriginalDest(nil).IsValid() {
		t.Fatal("accepted missing control messages")
	}
}

func BenchmarkRetrieveOriginalDest(b *testing.B) {
	oob := originalDestControlMessage(netip.MustParseAddrPort("192.0.2.1:443"))
	b.ReportAllocs()
	for b.Loop() {
		if !RetrieveOriginalDest(oob).IsValid() {
			b.Fatal("missing destination")
		}
	}
}

func TestServeReportsIngressFailure(t *testing.T) {
	for _, test := range []struct {
		name    string
		failure string
	}{
		{name: "TCP", failure: "accept TCP connection"},
		{name: "UDP", failure: "read UDP datagram"},
		{name: "retirement"},
	} {
		t.Run(test.name, func(t *testing.T) {
			m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.SockMap, KeySize: 4, ValueSize: 8, MaxEntries: 2})
			if errors.Is(err, unix.EPERM) {
				t.Skip("creating a BPF map requires privileges")
			}
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()
			lc := net.ListenConfig{}
			lc.SetMultipathTCP(false)
			tcp, err := lc.Listen(t.Context(), "tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer tcp.Close()
			udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer udp.Close()
			c := NewRuntime()
			c.shared["listen_socket_map"], err = m.Clone()
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			ready, done := make(chan bool, 1), make(chan error, 1)
			go func() { done <- c.Serve(ready, &Listener{tcpListener: tcp, packetConn: udp}) }()
			select {
			case started := <-ready:
				if !started {
					t.Fatal(<-done)
				}
			case <-time.After(time.Second):
				t.Fatal("ingress did not start")
			}
			if test.failure != "" {
				// Simulate a failed serving descriptor while the plane is active.
				closeSocket := tcp.Close
				if test.name == "UDP" {
					closeSocket = udp.Close
				}
				if err := closeSocket(); err != nil {
					t.Fatal(err)
				}
			} else if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if test.failure == "" {
					if err != nil {
						t.Fatalf("normal retirement reported failure: %v", err)
					}
				} else if err == nil || !strings.Contains(err.Error(), test.failure) {
					t.Fatalf("ingress failure = %v, want %q", err, test.failure)
				}
			case <-time.After(time.Second):
				t.Fatal("Serve did not return after ingress stopped")
			}
		})
	}
}

func TestTransparentListenerNeverTriesMPTCP(t *testing.T) {
	t.Setenv("GODEBUG", "multipathtcp=1")
	config := tproxyListenConfig()
	control := config.Control
	var protocols []int
	config.Control = func(network, address string, c syscall.RawConn) error {
		if err := c.Control(func(fd uintptr) {
			protocol, _ := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PROTOCOL)
			protocols = append(protocols, protocol)
		}); err != nil {
			return err
		}
		return control(network, address, c)
	}
	// Without privileges tproxyControl fails, after the protocol was chosen.
	if listener, err := config.Listen(t.Context(), "tcp", "127.0.0.1:0"); err == nil {
		_ = listener.Close()
	}
	if len(protocols) != 1 || protocols[0] != unix.IPPROTO_TCP {
		t.Fatalf("tproxyControl saw socket protocols %v", protocols)
	}
}

func TestRuntimeListenerUsesSockmapCompatibleTCP(t *testing.T) {
	t.Setenv("GODEBUG", "multipathtcp=1")
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.SockMap, KeySize: 4, ValueSize: 8, MaxEntries: 2})
	if errors.Is(err, unix.EPERM) {
		t.Skip("BPF privileges required")
	}
	if err != nil {
		t.Fatal(err)
	}
	r := NewRuntime()
	r.shared["listen_socket_map"] = m
	t.Cleanup(func() { _ = r.Close() })
	ready, done := make(chan bool, 1), make(chan error, 1)
	go func() { _, err := r.ListenAndServe(ready, 0); done <- err }()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal(<-done)
		}
	case err := <-done:
		t.Fatalf("listen failed: %v", err)
	case <-time.After(time.Second):
		t.Fatal("listener did not start")
	}
	raw, err := r.listener.tcpListener.(syscall.Conn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.Control(func(fd uintptr) {
		protocol, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_PROTOCOL)
		if err != nil || protocol != unix.IPPROTO_TCP {
			t.Errorf("transparent listener protocol=%d, %v", protocol, err)
		}
	}); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
