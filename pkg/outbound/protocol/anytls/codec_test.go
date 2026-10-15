package anytls

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
)

// Decode the peer wire independently of the production encoder.
func peerFrames(t *testing.T, wire []byte) (commands []byte, ids []uint32, bodies [][]byte) {
	t.Helper()
	for len(wire) != 0 {
		if len(wire) < 7 {
			t.Fatal("truncated frame header")
		}
		size := int(binary.BigEndian.Uint16(wire[5:7]))
		if len(wire) < 7+size {
			t.Fatal("truncated frame payload")
		}
		commands = append(commands, wire[0])
		ids = append(ids, binary.BigEndian.Uint32(wire[1:5]))
		bodies = append(bodies, append([]byte(nil), wire[7:7+size]...))
		wire = wire[7+size:]
	}
	return
}
func TestClientPreambleOnceAndUint16StreamFraming(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	carrier := &capturedFrameConn{Conn: client, frames: make(chan []byte, 8)}
	session := newSession(carrier, nil, nil)
	session.sendPadding = false
	defer session.Close()
	first, err := session.newStreamContext(context.Background(), "target.test:443")
	if err != nil {
		t.Fatal(err)
	}
	commands, ids, bodies := peerFrames(t, <-carrier.frames)
	if !bytes.Equal(commands, []byte{cmdSettings, cmdSYN, cmdPSH}) || ids[0] != 0 || ids[1] != ids[2] || !bytes.HasPrefix(bodies[0], []byte("v=2\nclient=dae\n")) {
		t.Fatalf("first carrier write commands=%v ids=%v", commands, ids)
	}
	if _, err := session.newStreamContext(context.Background(), "second.test:80"); err != nil {
		t.Fatal(err)
	}
	commands, _, _ = peerFrames(t, <-carrier.frames)
	if !bytes.Equal(commands, []byte{cmdSYN, cmdPSH}) {
		t.Fatalf("repeated settings or fragmented opening: %v", commands)
	}
	payload := bytes.Repeat([]byte("x"), 70000)
	if n, err := first.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("large stream write=%d,%v", n, err)
	}
	commands, _, bodies = peerFrames(t, <-carrier.frames)
	if !bytes.Equal(commands, []byte{cmdPSH, cmdPSH}) || len(bodies[0]) != 65535 || !bytes.Equal(bytes.Join(bodies, nil), payload) {
		t.Fatal("uint16 frame length truncated payload")
	}
}
func TestPeerAlertAndMalformedControlAreResourceFailures(t *testing.T) {
	for _, test := range []struct {
		name    string
		command byte
		reason  netproxy.FailureReason
	}{{"alert", cmdAlert, netproxy.ReasonRejected}, {"control_body", cmdFIN, netproxy.ReasonProtocol}} {
		t.Run(test.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer server.Close()
			s := newSession(client, nil, nil)
			defer s.Close()
			go func() { _, _ = server.Write([]byte{test.command, 0, 0, 0, 1, 0, 3, 'b', 'a', 'd'}) }()
			err := s.run()
			failure := netproxy.ClassifyFailure(err)
			if failure.Scope != netproxy.ScopeSharedResource || failure.Reason != test.reason || failure.Origin != netproxy.OriginPeer || s.lease.Valid() {
				t.Fatalf("peer failure: %+v", failure)
			}
			if !errors.Is(s.lease.AbortCause(), err) {
				t.Fatalf("peer failure did not issue abort: %v", s.lease.AbortCause())
			}
		})
	}
}
func TestPaddingUpdateBelongsToOneClient(t *testing.T) {
	first, _ := NewDialer(testParentDialer{}, protocol.Header{})
	defer first.Close()
	second, _ := NewDialer(testParentDialer{}, protocol.Header{})
	defer second.Close()
	client, server := net.Pipe()
	defer server.Close()
	s := newSession(client, nil, nil)
	s.padding = &first.padding
	done := make(chan error, 1)
	go func() { done <- s.run() }()
	defer func() { s.Close(); <-done }()
	update := []byte("stop=3\n0=8-8\n1=20-20")
	wire := []byte{cmdUpdatePaddingScheme, 0, 0, 0, 0, 0, byte(len(update))}
	wire = append(wire, update...)
	if _, err := server.Write(wire); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for first.padding.Load() == defaultPadding && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if first.padding.Load() == defaultPadding || second.padding.Load() != defaultPadding {
		t.Fatal("padding update leaked across clients or was lost")
	}
}
func TestDatagramFramingSurvivesReadDeadlineAndShortBuffer(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	s := newSession(client, nil, nil)
	defer s.Close()
	stream := newStream(s, 1)
	s.streams[1] = stream
	packet := &packetStream{stream: stream, addr: "dns.example:53"}
	defer packet.Close()
	firstByte := make(chan struct{})
	continueWrite := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		stream.receive([]byte{0})
		close(firstByte)
		<-continueWrite
		stream.receive([]byte{3, 'a', 'b', 'c', 0, 4, 'd', 'r', 'o', 'p', 0, 2, 'o', 'k'})
	}()
	_ = packet.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if _, _, err := packet.ReadFrom(make([]byte, 8)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal(err)
	}
	<-firstByte
	close(continueWrite)
	_ = packet.SetReadDeadline(time.Time{})
	data := make([]byte, 8)
	n, addr, err := packet.ReadFrom(data)
	if err != nil || string(data[:n]) != "abc" || addr.String() != "dns.example:53" {
		t.Fatalf("partial header lost: %q %v %v", data[:n], addr, err)
	}
	if _, _, err := packet.ReadFrom(data[:1]); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatal(err)
	}
	n, _, err = packet.ReadFrom(data)
	if err != nil || string(data[:n]) != "ok" {
		t.Fatalf("short buffer lost next packet: %q %v", data[:n], err)
	}
	<-done
}

func TestClientAuthenticatesAndExchangesWithTLSPeer(t *testing.T) {
	certificate := httptest.NewTLSServer(nil)
	config := certificate.TLS.Clone()
	certificate.Close()
	client, peer := net.Pipe()
	defer client.Close()
	result := make(chan error, 1)
	go func() {
		carrier := tls.Server(peer, config)
		defer carrier.Close()
		if err := carrier.Handshake(); err != nil {
			result <- err
			return
		}
		var auth [34]byte
		if _, err := io.ReadFull(carrier, auth[:]); err != nil {
			result <- err
			return
		}
		key := sha256.Sum256([]byte("password"))
		if !bytes.Equal(auth[:32], key[:]) || binary.BigEndian.Uint16(auth[32:]) != 30 {
			result <- errors.New("invalid authentication or padding0")
			return
		}
		if _, err := io.CopyN(io.Discard, carrier, 30); err != nil {
			result <- err
			return
		}
		settings := 0
		for {
			var header [7]byte
			if _, err := io.ReadFull(carrier, header[:]); err != nil {
				result <- err
				return
			}
			size := int(binary.BigEndian.Uint16(header[5:]))
			body := make([]byte, size)
			if _, err := io.ReadFull(carrier, body); err != nil {
				result <- err
				return
			}
			if header[0] == cmdSettings {
				settings++
			}
			if header[0] == cmdPSH {
				if settings != 1 || !bytes.Contains(body, []byte("target.test")) {
					result <- errors.New("invalid stream preamble")
					return
				}
				frame := append([]byte{cmdPSH}, header[1:5]...)
				frame = append(frame, 0, 5)
				frame = append(frame, []byte("reply")...)
				_, err := carrier.Write(frame)
				result <- err
				if err == nil {
					// Keep the shared session alive until the client closes it.
					_, _ = io.Copy(io.Discard, carrier)
				}
				return
			}
		}
	}()
	d, err := NewDialer(oneConnectionParent{client}, protocol.Header{Password: "password", ProxyAddress: "peer.test:443", TlsConfig: &tls.Config{InsecureSkipVerify: true}})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := d.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	c, err := d.DialContext(ctx, "tcp", "target.test:443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	data := make([]byte, 5)
	if _, err := io.ReadFull(c, data); err != nil || string(data) != "reply" {
		t.Fatalf("peer response %q %v", data, err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

type oneConnectionParent struct{ net.Conn }

func (p oneConnectionParent) DialContext(context.Context, string, string) (net.Conn, error) {
	return p.Conn, nil
}
func (p oneConnectionParent) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("unexpected packet")
}
