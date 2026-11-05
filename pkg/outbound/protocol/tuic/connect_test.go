package tuic

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/quic-go"
)

// fakeStream records each carrier write; reads come from reply.
type fakeStream struct {
	net.Conn // nil: only the methods below are used
	reply    io.Reader
	writes   [][]byte
	finAfter int // writes sent before CloseWrite, -1 without CloseWrite
	fail     error
}

func (s *fakeStream) Write(b []byte) (int, error) {
	if s.fail != nil {
		return 0, s.fail
	}
	s.writes = append(s.writes, bytes.Clone(b))
	return len(b), nil
}
func (s *fakeStream) Read(p []byte) (int, error)       { return s.reply.Read(p) }
func (s *fakeStream) CloseWrite() error                { s.finAfter = len(s.writes); return nil }
func (s *fakeStream) DependencyLease() *netproxy.Lease { return nil }

// The CONNECT command rides the first payload in one stream write; a Read or
// CloseWrite before any Write sends it alone, and a failed send sticks.
func TestConnectCommandRidesFirstWrite(t *testing.T) {
	m, err := protocol.ParseMetadata("example.test:443")
	if err != nil {
		t.Fatal(err)
	}
	open := func(reply string) (*connectConn, *fakeStream) {
		command := bytes.NewBuffer([]byte{Ver5, ConnectType})
		if err := addressFromMetadata(&m).appendTo(command); err != nil {
			t.Fatal(err)
		}
		s := &fakeStream{reply: strings.NewReader(reply), finAfter: -1}
		return newConnectConn(s, command.Bytes()), s
	}
	// payload returns what follows a valid CONNECT command in wire.
	payload := func(wire []byte) string {
		r := bytes.NewReader(wire)
		if addr, err := readConnectFixture(r); err != nil || addr.String() != "example.test:443" {
			t.Fatalf("CONNECT=%v err=%v", addr, err)
		}
		rest, _ := io.ReadAll(r)
		return string(rest)
	}

	c, s := open("")
	if n, err := c.Write([]byte("hello")); n != 5 || err != nil {
		t.Fatalf("first write = %d, %v", n, err)
	}
	if _, err := c.Write([]byte("again")); err != nil {
		t.Fatal(err)
	}
	if len(s.writes) != 2 || payload(s.writes[0]) != "hello" || string(s.writes[1]) != "again" {
		t.Fatalf("stream writes = %q", s.writes)
	}

	c, s = open("pong")
	reply := make([]byte, 4)
	if _, err := io.ReadFull(c, reply); err != nil || string(reply) != "pong" {
		t.Fatalf("read = %q, %v", reply, err)
	}
	if len(s.writes) != 1 || payload(s.writes[0]) != "" {
		t.Fatalf("read did not send CONNECT alone: %q", s.writes)
	}

	c, s = open("")
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if len(s.writes) != 1 || payload(s.writes[0]) != "" || s.finAfter != 1 {
		t.Fatalf("CloseWrite: writes=%q FIN after %d", s.writes, s.finAfter)
	}

	c, s = open("pong")
	fail := errors.New("stream reset")
	s.fail = fail
	if n, err := c.Write([]byte("hello")); n != 0 || err != fail {
		t.Fatalf("failed write = %d, %v", n, err)
	}
	s.fail = nil
	_, writeErr := c.Write([]byte("hello"))
	_, readErr := c.Read(reply)
	if writeErr != fail || readErr != fail || c.CloseWrite() != fail || len(s.writes) != 0 || s.finAfter != -1 {
		t.Fatalf("failure not sticky: write=%v read=%v writes=%q", writeErr, readErr, s.writes)
	}
}

// DialContext sends nothing: the peer sees the stream only with the first
// payload, behind the CONNECT command.
func TestDialSendsNothingBeforeFirstWrite(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	f := newCloseFixture(t, ctx, quic.Config{})
	client, err := f.runtime.Dialer().DialContext(ctx, "tcp", "example.test:443")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	idle, stop := context.WithTimeout(ctx, 100*time.Millisecond)
	defer stop()
	if _, err := f.server.AcceptStream(idle); err == nil {
		t.Fatal("DialContext sent the stream")
	}
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	remote, err := f.server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	request := bufio.NewReader(remote)
	if addr, err := readConnectFixture(request); err != nil || addr.String() != "example.test:443" {
		t.Fatalf("CONNECT=%v err=%v", addr, err)
	}
	got := make([]byte, 5)
	if _, err := io.ReadFull(request, got); err != nil || string(got) != "hello" {
		t.Fatalf("payload=%q err=%v", got, err)
	}
}
