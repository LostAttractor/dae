package v2ray

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	_ "github.com/daeuniverse/dae/pkg/outbound/protocol/vless"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/vmess"
	"github.com/google/uuid"
)

const cipherTestID = "01234567-89ab-cdef-0123-456789abcdef"

func vmessCipherLink(format, cipher string) string {
	payload := fmt.Sprintf(`{"v":"2","add":"127.0.0.1","port":"9","id":%q,"aid":"0","net":"tcp","scy":%q}`, cipherTestID, cipher)
	if format == "compact" {
		payload = cipher + ":" + cipherTestID + "@127.0.0.1:9"
	}
	return "vmess://" + base64.RawURLEncoding.EncodeToString([]byte(payload))
}

type requestSink struct{ bytes.Buffer }

func (c *requestSink) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *requestSink) Close() error                     { return nil }
func (c *requestSink) LocalAddr() net.Addr              { return netproxy.NewAddr("tcp", "127.0.0.1:1") }
func (c *requestSink) RemoteAddr() net.Addr             { return netproxy.NewAddr("tcp", "127.0.0.1:9") }
func (c *requestSink) SetDeadline(time.Time) error      { return nil }
func (c *requestSink) SetReadDeadline(time.Time) error  { return nil }
func (c *requestSink) SetWriteDeadline(time.Time) error { return nil }

type cipherTestParent struct{ conn *requestSink }

func (p cipherTestParent) DialContext(context.Context, string, string) (net.Conn, error) {
	return p.conn, nil
}
func (p cipherTestParent) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, fmt.Errorf("unexpected UDP carrier")
}

// Decode the AEAD request received by a peer; inspect the on-wire security
// nibble rather than the builder's internal field or an intercepted Header.
func buildRequestSecurity(t *testing.T, builder dialer.Builder) byte {
	t.Helper()
	sink := new(requestSink)
	layer, err := builder.Build(&dialer.ExtraOption{}, dialer.NewUpstream(cipherTestParent{sink}))
	if err != nil {
		t.Fatal(err)
	}
	defer layer.Close()
	conn, err := layer.Data.DialContext(context.Background(), "tcp", "target.example:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	wire := sink.Bytes()
	if len(wire) < 58 {
		t.Fatalf("short request: %x", wire)
	}
	id := uuid.MustParse(cipherTestID)
	key := md5.Sum(append(id[:], []byte("c48619fe-8f02-49e0-b9e9-edf763e17e21")...))
	auth, nonce := wire[:16], wire[34:42]
	aead, err := vmess.NewAesGcm(vmess.KDF(key[:], []byte(vmess.KDFSaltConstVMessHeaderPayloadLengthAEADKey), auth, nonce)[:16])
	if err != nil {
		t.Fatal(err)
	}
	length, err := aead.Open(nil, vmess.KDF(key[:], []byte(vmess.KDFSaltConstVMessHeaderPayloadLengthAEADIV), auth, nonce)[:12], wire[16:34], auth)
	if err != nil {
		t.Fatal(err)
	}
	if int(binary.BigEndian.Uint16(length))+58 != len(wire) {
		t.Fatal("wrong encrypted request length")
	}
	aead, err = vmess.NewAesGcm(vmess.KDF(key[:], []byte(vmess.KDFSaltConstVMessHeaderPayloadAEADKey), auth, nonce)[:16])
	if err != nil {
		t.Fatal(err)
	}
	request, err := aead.Open(nil, vmess.KDF(key[:], []byte(vmess.KDFSaltConstVMessHeaderPayloadAEADIV), auth, nonce)[:12], wire[42:], auth)
	if err != nil {
		t.Fatal(err)
	}
	return request[35] & 15
}
func TestVMessShareCipherReachesWireAndExport(t *testing.T) {
	previous := hasAESGCMHardwareSupport
	defer func() { hasAESGCMHardwareSupport = previous }()
	for _, tc := range []struct {
		format, selected string
		hardware         bool
		want             byte
	}{
		{"json", "chacha20-poly1305", true, 4},
		{"compact", "aes-128-gcm", false, 3},
		{"json", "", false, 4},
		{"compact", "auto", true, 3},
	} {
		t.Run(tc.format+"/"+tc.selected, func(t *testing.T) {
			hasAESGCMHardwareSupport = tc.hardware
			link := vmessCipherLink(tc.format, tc.selected)
			for round := 0; round < 2; round++ {
				builder, property, err := NewV2Ray(link)
				if err != nil {
					t.Fatal(err)
				}
				if got := buildRequestSecurity(t, builder); got != tc.want {
					t.Fatalf("request security=%d,want=%d (export round %d)", got, tc.want, round)
				}
				link = property.Link
			}
		})
	}
}

func TestShareLinksRejectUnsupportedDataEncryption(t *testing.T) {
	for _, tc := range []struct{ format, cipher string }{{"json", "none"}, {"compact", "zero"}, {"json", "unsupported"}} {
		if _, _, err := NewV2Ray(vmessCipherLink(tc.format, tc.cipher)); err == nil || !strings.Contains(err.Error(), "cipher") {
			t.Fatalf("VMess cipher %q: %v", tc.cipher, err)
		}
	}
	link := "vless://" + cipherTestID + "@127.0.0.1:9?encryption=unsupported&type=tcp&security=none"
	if _, _, err := NewV2Ray(link); err == nil || !strings.Contains(err.Error(), "encryption") {
		t.Fatalf("VLESS unsupported encryption: %v", err)
	}
}

func TestVLESSWebSocketRejectsH2ALPN(t *testing.T) {
	link := "vless://" + cipherTestID + "@127.0.0.1:9?encryption=none&type=ws&security=tls&alpn=h2,http/1.1"
	builder, _, err := NewV2Ray(link)
	if err != nil {
		t.Fatal(err)
	}
	layer, err := builder.Build(&dialer.ExtraOption{}, dialer.NewUpstream(new(testParentDialer)))
	defer layer.Close()
	if err == nil || !strings.Contains(err.Error(), "unsupported WebSocket ALPN") {
		t.Fatalf("HTTP/2 ALPN accepted by HTTP/1.1 Upgrade client: %v", err)
	}
}
