package tls_test

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/dialer"
	transporttls "github.com/daeuniverse/dae/pkg/outbound/transport/tls"
	"github.com/daeuniverse/dae/pkg/outbound/transport/ws"
)

func TestFragmentConfigValidation(t *testing.T) {
	for _, test := range []struct {
		length, interval string
		valid            bool
	}{
		{"50-100", "10-20", true},
		{"1024-2048", "0-0", true},
		{"9223372036854775807-9223372036854775807", "0-0", true},
		{"1-1", "0-9223372036854", true},
		{"0-0", "0-0", false},
		{"0-1", "0-0", false},
		{"100-50", "0-0", false},
		{"", "0-0", false},
		{"10", "0-0", false},
		{"1-2-3", "0-0", false},
		{"1-9223372036854775808", "0-0", false},
		{"1-1", "-1-1", false},
		{"1-1", "2-1", false},
		{"1-1", "0-9223372036855", false},
	} {
		t.Run(test.length+"/"+test.interval, func(t *testing.T) {
			for _, builder := range []dialer.Builder{
				&transporttls.TLSConfig{Host: "example.test:443"},
				&ws.WsConfig{Scheme: "wss", Host: "example.test:443"},
			} {
				_, err := builder.Build(&dialer.ExtraOption{TlsFragment: true, TlsFragmentLength: test.length, TlsFragmentInterval: test.interval}, dialer.NewUpstream(nil))
				if (err == nil) != test.valid {
					t.Fatalf("%T: valid=%t, error=%v", builder, test.valid, err)
				}
			}
		})
	}
}

type fragmentSink struct {
	net.Conn
	wire bytes.Buffer
}

func (c *fragmentSink) Write(b []byte) (int, error) { return c.wire.Write(b) }

type fragmentWriteLimitConn struct {
	fragmentSink
	limit, calls int
	err          error
}

func (c *fragmentWriteLimitConn) Write(b []byte) (int, error) {
	c.calls++
	n, _ := c.wire.Write(b[:min(len(b), c.limit-c.wire.Len())])
	if c.wire.Len() == c.limit {
		return n, c.err
	}
	return n, nil
}

func TestFragmentWriteProgress(t *testing.T) {
	input := []byte{22, 3, 3, 0, 5, 1, 2, 3, 4, 5}
	wire := []byte{22, 3, 3, 0, 2, 1, 2, 22, 3, 3, 0, 2, 3, 4, 22, 3, 3, 0, 1, 5}
	consumed := []int{0, 1, 2, 3, 4, 5, 6, 7, 7, 7, 7, 7, 7, 8, 9, 9, 9, 9, 9, 9, 10}
	trailing := []byte{23, 3, 3, 0, 2, 6, 7}
	input = append(input, trailing...)
	wire = append(wire, trailing...)
	for i := range len(trailing) {
		consumed = append(consumed, 11+i)
	}
	for _, interval := range []string{"0-0", "1-1"} {
		for _, underlyingErr := range []error{os.ErrDeadlineExceeded, nil} {
			for limit, wantN := range consumed {
				if underlyingErr == nil && limit == len(wire) {
					continue
				}
				t.Run(fmt.Sprintf("interval=%s/error=%v/limit=%d", interval, underlyingErr, limit), func(t *testing.T) {
					synctest.Test(t, func(t *testing.T) {
						config, err := transporttls.ParseFragmentConfig("2-2", interval)
						if err != nil {
							t.Fatal(err)
						}
						sink := &fragmentWriteLimitConn{limit: limit, err: underlyingErr}
						conn := config.Wrap(sink)
						wantErr := underlyingErr
						if wantErr == nil {
							wantErr = io.ErrShortWrite
						}
						if n, err := conn.Write(input); n != wantN || !errors.Is(err, wantErr) {
							t.Fatalf("Write() = %d, %v; want %d, %v", n, err, wantN, wantErr)
						}
						if !bytes.Equal(sink.wire.Bytes(), wire[:limit]) {
							t.Fatalf("wire = %x; want %x", sink.wire.Bytes(), wire[:limit])
						}
						calls := sink.calls
						for _, retry := range [][]byte{input, input[wantN:], []byte("passthrough"), nil} {
							if n, err := conn.Write(retry); n != 0 || !errors.Is(err, wantErr) || sink.calls != calls {
								t.Fatalf("retry = %d, %v, %d writes; want 0, %v, %d writes", n, err, sink.calls, wantErr, calls)
							}
						}
					})
				})
			}
		}
	}
}

func TestFragmentPassthroughWriteProgress(t *testing.T) {
	for _, input := range [][]byte{[]byte("passthrough"), {22, 3, 3, 0, 3}, {22, 3, 3, 0, 3, 1}} {
		for _, underlyingErr := range []error{os.ErrDeadlineExceeded, nil} {
			t.Run(fmt.Sprintf("input=%x/error=%v", input, underlyingErr), func(t *testing.T) {
				config, err := transporttls.ParseFragmentConfig("2-2", "0-0")
				if err != nil {
					t.Fatal(err)
				}
				sink := &fragmentWriteLimitConn{limit: 3, err: underlyingErr}
				conn := config.Wrap(sink)
				wantErr := underlyingErr
				if wantErr == nil {
					wantErr = io.ErrShortWrite
				}
				if n, err := conn.Write(input); n != 3 || !errors.Is(err, wantErr) {
					t.Fatalf("Write() = %d, %v; want 3, %v", n, err, wantErr)
				}
				if n, err := conn.Write(input); n != 0 || !errors.Is(err, wantErr) || sink.calls != 1 {
					t.Fatalf("retry = %d, %v, %d writes; want 0, %v, 1 write", n, err, sink.calls, wantErr)
				}
			})
		}
	}
}

func TestFragmentConcurrentWrites(t *testing.T) {
	config, err := transporttls.ParseFragmentConfig("1-1", "1-1")
	if err != nil {
		t.Fatal(err)
	}
	local, peer := net.Pipe()
	defer peer.Close()
	conn := config.Wrap(local)
	defer conn.Close()
	deadline := time.Now().Add(5 * time.Second)
	if err := conn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := peer.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 2)
	write := func(input []byte) {
		n, err := conn.Write(input)
		if err == nil && n != len(input) {
			err = fmt.Errorf("Write() = %d; want %d", n, len(input))
		}
		done <- err
	}
	go write([]byte{22, 3, 3, 0, 2, 1, 2})
	var wire [24]byte
	if _, err := io.ReadFull(peer, wire[:6]); err != nil {
		t.Fatal(err)
	}
	go write([]byte{22, 3, 3, 0, 2, 3, 4})
	if _, err := io.ReadFull(peer, wire[6:]); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	want := []byte{22, 3, 3, 0, 1, 1, 22, 3, 3, 0, 1, 2, 22, 3, 3, 0, 1, 3, 22, 3, 3, 0, 1, 4}
	if !bytes.Equal(wire[:], want) {
		t.Fatalf("wire = %x; want %x", wire, want)
	}
}

func TestFragmentPreservesRecords(t *testing.T) {
	for _, test := range []struct{ length, interval string }{
		{"50-100", "0-0"},
		{"1024-2048", "0-0"},
		{"1024-2048", "1-1"},
		{"9223372036854775807-9223372036854775807", "0-0"},
	} {
		t.Run(test.length+"/"+test.interval, func(t *testing.T) {
			config, err := transporttls.ParseFragmentConfig(test.length, test.interval)
			if err != nil {
				t.Fatal(err)
			}
			payload := bytes.Repeat([]byte("handshake"), 1024)
			record := append([]byte{22, 3, 3, byte(len(payload) >> 8), byte(len(payload))}, payload...)
			trailing := []byte{23, 3, 3, 0, 3, 1, 2, 3}
			record = append(record, trailing...)
			sink := new(fragmentSink)
			if n, err := config.Wrap(sink).Write(record); err != nil || n != len(record) {
				t.Fatalf("write: %d, %v", n, err)
			}
			var got []byte
			for len(got) < len(payload) {
				var header [5]byte
				if _, err := io.ReadFull(&sink.wire, header[:]); err != nil {
					t.Fatal(err)
				}
				size := int(binary.BigEndian.Uint16(header[3:]))
				if !bytes.Equal(header[:3], record[:3]) || size == 0 {
					t.Fatalf("invalid fragment header: %x", header)
				}
				fragment := make([]byte, size)
				if _, err := io.ReadFull(&sink.wire, fragment); err != nil {
					t.Fatal(err)
				}
				got = append(got, fragment...)
			}
			if !bytes.Equal(got, payload) || !bytes.Equal(sink.wire.Bytes(), trailing) {
				t.Fatal("fragmentation changed the handshake payload or subsequent records")
			}
		})
	}
}

func TestFragmentClientHello(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, length := range []string{"1-1", "50-100", "1024-2048"} {
			t.Run(fmt.Sprintf("version=%x/length=%s", version, length), func(t *testing.T) {
				config, err := transporttls.ParseFragmentConfig(length, "0-0")
				if err != nil {
					t.Fatal(err)
				}
				conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", server.Listener.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				client := tls.Client(config.Wrap(conn), &tls.Config{InsecureSkipVerify: true, MinVersion: version, MaxVersion: version})
				defer client.Close()
				if err := client.HandshakeContext(t.Context()); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
