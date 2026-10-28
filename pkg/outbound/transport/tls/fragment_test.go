package tls_test

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

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
	for _, length := range []string{"50-100", "1024-2048"} {
		t.Run(fmt.Sprintf("length=%s", length), func(t *testing.T) {
			config, err := transporttls.ParseFragmentConfig(length, "0-0")
			if err != nil {
				t.Fatal(err)
			}
			conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", server.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			client := tls.Client(config.Wrap(conn), &tls.Config{InsecureSkipVerify: true})
			defer client.Close()
			if err := client.HandshakeContext(t.Context()); err != nil {
				t.Fatal(err)
			}
		})
	}
}
