package shadowsocksr

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

func share(payload string) string {
	return "ssr://" + base64.RawURLEncoding.EncodeToString([]byte(payload))
}
func TestSSRIPv6ShareRoundTrip(t *testing.T) {
	for _, server := range []string{"2001:db8::1", "[2001:db8::1]"} {
		link := share(server + ":8388:origin:aes-128-cfb:plain:cGFzc3dvcmQ/?remarks=5rWL6K-V&protoparam=dGVzdA&obfsparam=aG9zdC50ZXN0")
		builder, property, err := dialer.NewFromLink(link)
		if err != nil {
			t.Fatal(err)
		}
		result := builder.(*ShadowsocksR)
		if property.Address != "[2001:db8::1]:8388" || result.Name != "测试" || result.Password != "password" {
			t.Fatalf("IPv6 share=%+v", result)
		}
		exported, err := ParseSSRURL(result.ExportToURL())
		if err != nil || *exported != *result {
			t.Fatalf("share roundtrip=%+v,%v", exported, err)
		}
	}
}

func TestSSRMalformedLinksReturnErrors(t *testing.T) {
	cases := []string{
		"shadowsocksr://abc", "ssr://%%%", share("missing"),
		share("host:8388:origin:aes-128-cfb:plain:c\nA"),
		share(":8388:origin:aes-128-cfb:plain:cA"),
		share("host:65536:origin:aes-128-cfb:plain:cA"),
		share("host:8388::aes-128-cfb:plain:cA"),
		share("host:8388:origin:aes-128-cfb:plain:!"),
		share("host:8388:origin:aes-128-cfb:plain:cA/?obfsparam=%xx"),
		share("not:ipv6:8388:origin:aes-128-cfb:plain:cA"),
	}
	for _, link := range cases {
		if _, err := ParseSSRURL(link); !errors.Is(err, dialer.InvalidParameterErr) {
			t.Fatalf("malformed %q: %v", link, err)
		}
	}
}

type directParent struct{}

func (directParent) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return new(net.Dialer).DialContext(ctx, network, address)
}
func (directParent) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("unexpected UDP")
}

func TestRegisteredSSRBuildExchangesWithAESCFBPeer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverResult := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		defer raw.Close()
		_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
		// EVP_BytesToKey's first digest is the AES-128 key; the peer uses only the
		// standard library cipher, independent of the production SSR/SS codec.
		key := md5.Sum([]byte("password"))
		block, err := aes.NewCipher(key[:])
		if err != nil {
			serverResult <- err
			return
		}
		var iv [16]byte
		if _, err := io.ReadFull(raw, iv[:]); err != nil {
			serverResult <- err
			return
		}
		reader := cipher.StreamReader{S: cipher.NewCFBDecrypter(block, iv[:]), R: raw}
		var prefix [2]byte
		if _, err := io.ReadFull(reader, prefix[:]); err != nil {
			serverResult <- err
			return
		}
		if prefix[0] != 3 {
			serverResult <- errors.New("missing SOCKS domain target")
			return
		}
		target := make([]byte, int(prefix[1])+2)
		if _, err := io.ReadFull(reader, target); err != nil {
			serverResult <- err
			return
		}
		if string(target[:len(target)-2]) != "target.example" || binary.BigEndian.Uint16(target[len(target)-2:]) != 443 {
			serverResult <- errors.New("incorrect target")
			return
		}
		payload, err := io.ReadAll(reader)
		if err != nil || string(payload) != "request" {
			serverResult <- errors.New("application payload changed")
			return
		}
		replyIV := bytes.Repeat([]byte{0x7f}, 16)
		reply := []byte("response")
		cipher.NewCFBEncrypter(block, replyIV).XORKeyStream(reply, reply)
		_, err = raw.Write(append(replyIV, reply...))
		serverResult <- err
	}()
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	link := share(host + ":" + port + ":origin:aes-128-cfb:plain:cGFzc3dvcmQ/?remarks=cGVlcg")
	builder, property, err := dialer.NewFromLink(link)
	if err != nil {
		t.Fatal(err)
	}
	if property.Address != listener.Addr().String() {
		t.Fatal("server hostname was decoded again")
	}
	layer, err := builder.Build(&dialer.ExtraOption{}, dialer.NewUpstream(directParent{}))
	if err != nil {
		t.Fatal(err)
	}
	defer layer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := layer.Data.DialContext(ctx, "tcp", "target.example:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.WriteString(conn, "request"); err != nil {
		t.Fatal(err)
	}
	writer, ok := conn.(netproxy.CloseWriter)
	if !ok {
		t.Fatal("client tunnel lost CloseWrite")
	}
	if err := writer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(conn)
	if err != nil || string(reply) != "response" {
		t.Fatalf("reverse response %q %v", reply, err)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
	config := builder.(*ShadowsocksR)
	config.Port = 65536
	if _, err := config.Build(&dialer.ExtraOption{}, dialer.NewUpstream(directParent{})); !errors.Is(err, dialer.InvalidParameterErr) {
		t.Fatalf("port overflow %s: %v", strconv.Itoa(config.Port), err)
	}
}
