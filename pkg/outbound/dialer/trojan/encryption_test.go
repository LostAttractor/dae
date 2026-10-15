package trojan

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"golang.org/x/crypto/hkdf"
)

type socketParent struct{ net.Dialer }

func (socketParent) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, fmt.Errorf("unexpected UDP carrier")
}

// The peer implements AEAD framing with cryptographic primitives, without the
// production Shadowsocks codec. Its first decoded bytes must be the Trojan hash.
func TestShadowsocksTransportStartsWithTrojanHeader(t *testing.T) {
	certServer := httptest.NewTLSServer(nil)
	serverTLS := &tls.Config{Certificates: certServer.TLS.Certificates}
	certServer.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	const trojanPassword = "trojan-secret"
	const ssPassword = "ss-secret;with-semicolon"
	const targetHost = "target.example"
	hash := sha256.Sum224([]byte(trojanPassword))
	wantHeader := []byte(hex.EncodeToString(hash[:]) + "\r\n")
	wantHeader = append(wantHeader, 1, 3, byte(len(targetHost)))
	wantHeader = append(wantHeader, targetHost...)
	wantHeader = binary.BigEndian.AppendUint16(wantHeader, 8443)
	wantHeader = append(wantHeader, '\r', '\n')
	headerReceived := make(chan struct{})
	peerResult := make(chan error, 1)
	go func() {
		peerResult <- func() error {
			raw, err := listener.Accept()
			if err != nil {
				return err
			}
			defer raw.Close()
			_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
			conn := tls.Server(raw, serverTLS)
			defer conn.Close()
			salt := make([]byte, 16)
			if _, err := io.ReadFull(conn, salt); err != nil {
				return err
			}
			decrypt, err := peerAEAD(ssPassword, salt)
			if err != nil {
				return err
			}
			nonce := make([]byte, 12)
			first, err := readAEADFrame(conn, decrypt, nonce)
			if err != nil {
				return err
			}
			if !bytes.Equal(first, wantHeader) {
				return fmt.Errorf("first plaintext = %x, want Trojan hash and target = %x", first, wantHeader)
			}
			close(headerReceived)
			var payload []byte
			for {
				frame, err := readAEADFrame(conn, decrypt, nonce)
				if err == io.EOF {
					break
				}
				if err != nil {
					return err
				}
				payload = append(payload, frame...)
			}
			if string(payload) != "request" {
				return fmt.Errorf("payload = %q", payload)
			}
			// The reply is sent only after receiving the client's TLS half-close.
			if _, err := rand.Read(salt); err != nil {
				return err
			}
			encrypt, err := peerAEAD(ssPassword, salt)
			if err != nil {
				return err
			}
			clear(nonce)
			wire := append([]byte(nil), salt...)
			wire = encrypt.Seal(wire, nonce, []byte{0, 8}, nil)
			incrementNonce(nonce)
			wire = encrypt.Seal(wire, nonce, []byte("response"), nil)
			_, err = conn.Write(wire)
			return err
		}()
	}()
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	portNumber, _ := strconv.Atoi(port)
	config := &Trojan{Server: host, Port: portNumber, Password: trojanPassword, Encryption: "ss;aes-128-gcm;" + ssPassword}
	built, err := config.Build(&dialer.ExtraOption{TlsImplementation: "tls", AllowInsecure: true}, dialer.NewUpstream(&socketParent{}))
	if err != nil {
		t.Fatal(err)
	}
	defer built.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := built.Data.DialContext(ctx, "tcp", net.JoinHostPort(targetHost, "8443"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	select {
	case <-headerReceived:
	case err := <-peerResult:
		t.Fatalf("handshake: %v", err)
	case <-ctx.Done():
		t.Fatal("DialContext did not send the Trojan handshake")
	}
	if _, err := conn.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := conn.(netproxy.CloseWriter).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(conn)
	if err != nil || string(response) != "response" {
		t.Fatalf("half-close response = %q, %v", response, err)
	}
	if err := <-peerResult; err != nil {
		t.Fatal(err)
	}
}

func peerAEAD(password string, salt []byte) (cipher.AEAD, error) {
	master := md5.Sum([]byte(password)) // EVP_BytesToKey for AES-128.
	key := make([]byte, 16)
	if _, err := io.ReadFull(hkdf.New(sha1.New, master[:], salt, []byte("ss-subkey")), key); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func readAEADFrame(r io.Reader, aead cipher.AEAD, nonce []byte) ([]byte, error) {
	length := make([]byte, 2+aead.Overhead())
	if _, err := io.ReadFull(r, length); err != nil {
		return nil, err
	}
	length, err := aead.Open(length[:0], nonce, length, nil)
	if err != nil {
		return nil, err
	}
	incrementNonce(nonce)
	payload := make([]byte, int(binary.BigEndian.Uint16(length))+aead.Overhead())
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	plain, err := aead.Open(payload[:0], nonce, payload, nil)
	incrementNonce(nonce)
	return plain, err
}

func incrementNonce(nonce []byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}

func TestInvalidEncryptionReturnsError(t *testing.T) {
	for _, encryption := range []string{"ss;aes-128-gcm", "ss;;password", "ss;unknown;password", "other;aes-128-gcm;password"} {
		t.Run(encryption, func(t *testing.T) {
			config := &Trojan{Server: "proxy.example", Port: 443, Encryption: encryption}
			built, err := config.Build(&dialer.ExtraOption{TlsImplementation: "tls"}, dialer.NewUpstream(testParentDialer{}))
			if err == nil {
				built.Close()
				t.Fatal("malformed or unsupported encryption accepted")
			}
		})
	}
}
