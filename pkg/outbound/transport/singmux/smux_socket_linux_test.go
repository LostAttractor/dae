package singmux

import (
	"net"
	"testing"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"golang.org/x/sys/unix"
)

func TestSmuxPreservesTCPSendPolicy(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	raw, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	lowat := func() int {
		t.Helper()
		var value int
		var optionErr error
		if err := raw.Control(func(fd uintptr) {
			value, optionErr = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT)
		}); err != nil || optionErr != nil {
			t.Fatal(err, optionErr)
		}
		return value
	}
	before := lowat()
	s := newTestSmuxSession(netproxy.TrackConn(conn, func() {}))
	defer s.abort()
	stream, err := s.OpenStream(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	frames := readFrames(peer)
	for _, cmd := range []byte{smuxCmdSYN, smuxCmdPSH, smuxCmdFIN} {
		if got := nextFrame(t, frames); got.cmd != cmd {
			t.Fatalf("command = %d, want %d", got.cmd, cmd)
		}
	}
	waitIdle(t, s)
	if after := lowat(); after != before {
		t.Fatalf("TCP_NOTSENT_LOWAT changed from %d to %d", before, after)
	}
}
