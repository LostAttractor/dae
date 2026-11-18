package tls

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/cryptobyte"
)

func testRealityURL(spider string) string {
	return "reality://example.test:443?" + url.Values{
		"fp": {"chrome"}, "pbk": {"YAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		"sid": {"0123456789abcdef"}, "spx": {spider},
	}.Encode()
}
func TestRealityRejectsInvalidSpiderParameters(t *testing.T) {
	for _, field := range []string{"p", "c", "t", "i", "r"} {
		for _, value := range []string{"10-5", "100000000000", "-1", "no", "", "1-2-3", "9223372036854775808"} {
			t.Run(field+"="+value, func(t *testing.T) {
				if _, err := NewReality(testRealityURL("/?"+field+"="+value), nil); err == nil {
					t.Fatal("accepted invalid spider parameter")
				}
			})
		}
	}
}
func TestRealityRandomRangeDoesNotPanic(t *testing.T) {
	for _, pair := range [][2]int64{{10, 5}, {0, -1}, {0, 0}, {8, 8}} {
		if got := randBetween(pair[0], pair[1]); got != pair[0] {
			t.Fatalf("unexpected fallback: %d", got)
		}
	}
}

func TestRealityVerifyConnection(t *testing.T) {
	conn := RealityUConn{ServerName: "example.test", AuthKey: []byte("test key")}
	if err := conn.verifyConnection(utls.ConnectionState{}); err == nil || conn.Verified {
		t.Fatalf("empty certificate chain: verified = %v, error = %v", conn.Verified, err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{PublicKey: pub}
	state := utls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	if err := conn.verifyConnection(state); err == nil || conn.Verified {
		t.Fatalf("unauthenticated certificate: verified = %v, error = %v", conn.Verified, err)
	}
	h := hmac.New(sha512.New, conn.AuthKey)
	h.Write(pub)
	cert.Signature = h.Sum(nil)
	if err := conn.verifyConnection(state); err != nil || !conn.Verified {
		t.Fatalf("authenticated certificate: verified = %v, error = %v", conn.Verified, err)
	}
}

// realityTestServer authenticates ClientHellos the way XTLS REALITY servers
// do: X25519 with the standalone share, else with the X25519 half of
// X25519MLKEM768, and AES-GCM over the hello with the session ID zeroed.
type realityTestServer struct {
	key     *ecdh.PrivateKey
	shortID [8]byte
	result  chan error
}

func (s *realityTestServer) DialContext(context.Context, string, string) (net.Conn, error) {
	client, server := net.Pipe()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	_ = server.SetDeadline(time.Now().Add(2 * time.Second))
	go func() {
		defer server.Close()
		s.result <- s.authenticate(server)
	}()
	return client, nil
}

func (*realityTestServer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, netproxy.UnsupportedTunnelTypeError
}

func (s *realityTestServer) authenticate(conn net.Conn) error {
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	hello := make([]byte, binary.BigEndian.Uint16(header[3:]))
	if _, err := io.ReadFull(conn, hello); err != nil {
		return err
	}
	in := cryptobyte.String(hello)
	var msgType uint8
	var body, sessionID, suites, compression, extensions cryptobyte.String
	var random []byte
	if !in.ReadUint8(&msgType) || msgType != 1 || !in.ReadUint24LengthPrefixed(&body) ||
		!body.Skip(2) || !body.ReadBytes(&random, 32) ||
		!body.ReadUint8LengthPrefixed(&sessionID) || len(sessionID) != 32 ||
		!body.ReadUint16LengthPrefixed(&suites) || !body.ReadUint8LengthPrefixed(&compression) ||
		!body.ReadUint16LengthPrefixed(&extensions) {
		return errors.New("malformed ClientHello")
	}
	var peer []byte
	for !extensions.Empty() {
		var extension uint16
		var data, shares cryptobyte.String
		if !extensions.ReadUint16(&extension) || !extensions.ReadUint16LengthPrefixed(&data) {
			return errors.New("malformed extension")
		}
		if extension != 51 || !data.ReadUint16LengthPrefixed(&shares) { // key_share
			continue
		}
		for !shares.Empty() {
			var group uint16
			var share cryptobyte.String
			if !shares.ReadUint16(&group) || !shares.ReadUint16LengthPrefixed(&share) {
				return errors.New("malformed key share")
			}
			switch {
			case group == uint16(tls.X25519) && len(share) == 32:
				peer = share
			case group == uint16(tls.X25519MLKEM768) && len(share) == mlkem.EncapsulationKeySize768+32 && peer == nil:
				peer = share[mlkem.EncapsulationKeySize768:]
			}
		}
	}
	peerKey, err := ecdh.X25519().NewPublicKey(peer)
	if err != nil {
		return err
	}
	shared, err := s.key.ECDH(peerKey)
	if err != nil {
		return err
	}
	authKey, err := hkdf.Key(sha256.New, shared, random[:20], "REALITY", 32)
	if err != nil {
		return err
	}
	block, _ := aes.NewCipher(authKey)
	aead, _ := cipher.NewGCM(block)
	aad := bytes.Clone(hello)
	clear(aad[39:71])
	plain, err := aead.Open(nil, random[20:], sessionID, aad)
	if err != nil {
		return err
	}
	if !bytes.Equal(plain[8:], s.shortID[:]) {
		return errors.New("short ID mismatch")
	}
	return nil
}

func TestRealityHelloAuthenticatesToServer(t *testing.T) {
	for _, fingerprint := range []string{"chrome", "firefox", "safari", " Chrome_120 ", "", "random", "randomized", "randomizedalpn", "randomizednoalpn"} {
		t.Run(fingerprint, func(t *testing.T) {
			key, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			server := &realityTestServer{key: key, shortID: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, result: make(chan error, 1)}
			x, err := NewReality("reality://reality.test:443?"+url.Values{
				"fp":  {fingerprint},
				"pbk": {base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())},
				"sid": {hex.EncodeToString(server.shortID[:])},
			}.Encode(), server)
			if err != nil {
				t.Fatal(err)
			}
			defer x.Close()
			builds := 1
			if strings.HasPrefix(fingerprint, "random") {
				builds = 200
				// A seed that previously selected TLS 1.2 makes the regression deterministic.
				id := *x.fingerprint
				id.Weights = nil
				for i := range 256 {
					id.Seed = &utls.PRNGSeed{byte(i)}
					spec, err := utls.UTLSIdToSpec(id)
					if err != nil {
						t.Fatal(err)
					}
					if spec.TLSVersMax == utls.VersionTLS12 {
						// Do not mutate the shared ID on old code either.
						x.fingerprint = new(*x.fingerprint)
						x.fingerprint.Seed = id.Seed
						break
					}
				}
				if x.fingerprint.Seed == nil {
					t.Fatal("no TLS 1.2 seed found")
				}
			}
			for i := range builds {
				// The server stops after the ClientHello, so the dial itself fails.
				_, dialErr := x.DialContext(t.Context(), "tcp", "reality.test:443")
				if err := <-server.result; err != nil {
					t.Fatalf("build %d: server rejected the ClientHello: %v (dial: %v)", i, err, dialErr)
				}
				x.fingerprint.Seed = nil
			}
		})
	}
}

func TestRealityKeepsDecodedSpiderPath(t *testing.T) {
	x, err := NewReality(testRealityURL("/a+b?q=1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := "/a+b?q=1"; x.spiderX != want {
		t.Fatalf("spider path %q; want %q", x.spiderX, want)
	}
}
