package juicity

import (
	"bytes"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/ciphers"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/shadowsocks"
)

func TestClientMetadataWireFormat(t *testing.T) {
	for _, tc := range []struct{ addr, wire string }{
		{"1.2.3.4:443", "010102030401bb"},
		{"[2001:db8::1]:53", "0420010db80000000000000000000000010035"},
		{"example.com:80", "030b6578616d706c652e636f6d0050"},
	} {
		t.Run(tc.addr, func(t *testing.T) {
			metadata, err := protocol.ParseMetadata(tc.addr)
			if err != nil {
				t.Fatal(err)
			}
			m := Metadata{Metadata: metadata, Network: "tcp"}
			buf := new(bytes.Buffer)
			if err = m.appendTo(buf); err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(buf.Bytes()); got != tc.wire {
				t.Fatalf("wire=%s", got)
			}
			got, err := readMetadata(buf)
			if err != nil || got.Hostname != m.Hostname || got.Port != m.Port || got.Type != m.Type {
				t.Fatalf("decoded=%+v err=%v", got, err)
			}
		})
	}
}

func TestUnderlayUDPShortReadAndInitialSaltRetry(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	key := &shadowsocks.Key{CipherConf: CipherConf, MasterKey: bytes.Repeat([]byte{7}, CipherConf.KeyLen)}
	salt := bytes.Repeat([]byte{9}, CipherConf.SaltLen)
	salt[0], salt[1] = 0, 0
	client := &TransportPacketConn{PacketConn: raw, proxyAddr: server.LocalAddr().(*net.UDPAddr), target: netproxy.NewAddr("udp", "127.0.0.1:0"), key: key, firstIv: append([]byte(nil), salt...)}
	defer client.Close()
	client.SetWriteDeadline(time.Now().Add(-time.Second))
	if _, err = client.Write([]byte("request")); err == nil {
		t.Fatal("past deadline accepted write")
	}
	if !bytes.Equal(client.firstIv, salt) {
		t.Fatal("failed first write consumed authentication salt")
	}
	client.SetWriteDeadline(time.Time{})
	if n, err := client.Write([]byte("request")); err != nil || n != 7 {
		t.Fatalf("Write=%d %v", n, err)
	}
	server.SetReadDeadline(time.Now().Add(time.Second))
	wire := make([]byte, 256)
	n, addr, err := server.ReadFrom(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire[:CipherConf.SaltLen], salt) {
		t.Fatal("first salt changed")
	}
	plaintext := make([]byte, 256)
	if n, err := DecryptUDP(plaintext, key, wire[:n], ciphers.JuicityReusedInfo); err != nil || string(plaintext[:n]) != "request" {
		t.Fatalf("request decrypt=%q %v", plaintext[:n], err)
	}
	response, err := EncryptUDPFromPool(key, []byte("long response"), salt, ciphers.JuicityReusedInfo)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.PutBuffer(response)
	if _, err = server.WriteTo(response, addr); err != nil {
		t.Fatal(err)
	}
	client.SetReadDeadline(time.Now().Add(time.Second))
	tiny := make([]byte, 4)
	if n, _, err := client.ReadFrom(tiny); err != nil || n != 4 || string(tiny) != "long" {
		t.Fatalf("short ReadFrom=%q n=%d err=%v", tiny, n, err)
	}
}
