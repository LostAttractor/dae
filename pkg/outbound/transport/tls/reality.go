// Modified from https://github.com/Reality/Xray-core/blob/fbc56b88da2808e3181add4935c143e319772c93/transport/internet/reality/reality.go

package tls

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/hkdf"
)

var (
	Reality_Version_x byte = 1
	Reality_Version_y byte = 8
	Reality_Version_z byte = 10
)

// realityECDHEKey returns the X25519 key REALITY servers authenticate: the
// standalone X25519 share, or the X25519 half of X25519MLKEM768 without one.
func realityECDHEKey(state *utls.PubClientHandshakeState) *ecdh.PrivateKey {
	if keys := state.State13.KeyShareKeys; keys != nil {
		if keys.Ecdhe != nil && keys.Ecdhe.Curve() == ecdh.X25519() {
			return keys.Ecdhe
		}
		return keys.MlkemEcdhe
	}
	return nil
}

type RealityUConn struct {
	*utls.UConn
	lease      *netproxy.Lease
	ServerName string
	AuthKey    []byte
	Verified   bool
}

func (c *RealityUConn) verifyConnection(state utls.ConnectionState) error {
	certs := state.PeerCertificates
	if len(certs) == 0 {
		return errors.New("REALITY: server sent no certificates")
	}
	if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, c.AuthKey)
		h.Write(pub)
		if hmac.Equal(h.Sum(nil), certs[0].Signature) {
			c.Verified = true
			return nil
		}
	}
	opts := x509.VerifyOptions{
		DNSName:       c.ServerName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}
	return nil
}

type Reality struct {
	infoWriter io.Writer

	nextDialer    netproxy.Dialer
	serverName    string
	fingerprint   *utls.ClientHelloID
	shortId       [8]byte
	publicKey     *ecdh.PublicKey
	spiderX       string
	spider        realitySpiderConfig
	spiderMu      sync.Mutex
	spiderCancel  context.CancelFunc
	spiderClosed  bool
	spiderWorkers sync.WaitGroup
}

func NewReality(s string, d netproxy.Dialer) (*Reality, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("NewReality: %w", err)
	}

	x := &Reality{
		nextDialer: d,
	}

	query := u.Query()
	x.serverName = query.Get("sni")
	_, err = hex.Decode(x.shortId[:], []byte(query.Get("sid")))
	if err != nil {
		return nil, fmt.Errorf("invalid reality sid")
	}
	_publicKey := query.Get("pbk")
	const x25519ScalarSize = 32
	var publicKey [x25519ScalarSize]byte
	_, err = base64.RawURLEncoding.Decode(publicKey[:], []byte(_publicKey))
	if err != nil {
		return nil, fmt.Errorf("invalid reality pbk")
	}
	x.publicKey, err = ecdh.X25519().NewPublicKey(publicKey[:])
	if err != nil {
		return nil, fmt.Errorf("REALITY: publicKey == nil: %w", err)
	}
	x.spiderX = query.Get("spx")
	_fingerprint := query.Get("fp")

	if x.serverName == "" {
		x.serverName = u.Hostname()
	} else if strings.ToLower(x.serverName) == "nosni" { // If ServerName is set to "nosni", we set it empty.
		x.serverName = ""
	}

	id, err := nameToUtlsClientHelloID(_fingerprint)
	if err != nil {
		return nil, fmt.Errorf("failed to get fingerprint: %w", err)
	}
	x.fingerprint = new(*id)
	switch id.Client {
	case utls.HelloRandomized.Client, utls.HelloRandomizedALPN.Client, utls.HelloRandomizedNoALPN.Client:
		// REALITY authenticates with an X25519 share, which random TLS 1.2 hellos omit.
		weights := utls.DefaultWeights
		weights.TLSVersMax_Set_VersionTLS13 = 1
		weights.FirstKeyShare_Set_CurveP256 = 0
		x.fingerprint.Weights = &weights
	}

	x.spiderX, x.spider, err = parseRealitySpider(x.spiderX)
	if err != nil {
		return nil, err
	}

	return x, nil
}

func (x *Reality) DialContext(ctx context.Context, network, addr string) (c net.Conn, err error) {
	x.spiderMu.Lock()
	closed := x.spiderClosed
	x.spiderMu.Unlock()
	if closed {
		return nil, net.ErrClosed
	}
	switch network {
	case "tcp":
		c, err := x.nextDialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, fmt.Errorf("[REALITY]: dial to %s: %w", addr, err)
		}
		closeConn := true
		defer func() {
			if closeConn {
				_ = c.Close()
			}
		}()
		uConn := &RealityUConn{lease: netproxy.DependencyOf(c)}
		utlsConfig := &utls.Config{
			VerifyConnection:       uConn.verifyConnection,
			ServerName:             x.serverName,
			InsecureSkipVerify:     true,
			SessionTicketsDisabled: true,
			KeyLogWriter:           x.infoWriter,
		}
		uConn.ServerName = utlsConfig.ServerName
		uConn.UConn = utls.UClient(c, utlsConfig, *x.fingerprint)
		{
			err = uConn.BuildHandshakeState()
			if err != nil {
				return nil, err
			}
			hello := uConn.HandshakeState.Hello
			hello.SessionId = make([]byte, 32)
			copy(hello.Raw[39:], hello.SessionId) // the fixed location of `Session ID`
			hello.SessionId[0] = Reality_Version_x
			hello.SessionId[1] = Reality_Version_y
			hello.SessionId[2] = Reality_Version_z
			hello.SessionId[3] = 0 // reserved
			binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
			copy(hello.SessionId[8:], x.shortId[:])
			ecdheKey := realityECDHEKey(&uConn.HandshakeState)
			if ecdheKey == nil {
				return nil, fmt.Errorf("REALITY: fingerprint %s %s offers no TLS 1.3 X25519 key share", x.fingerprint.Client, x.fingerprint.Version)
			}
			uConn.AuthKey, _ = ecdheKey.ECDH(x.publicKey)
			if uConn.AuthKey == nil {
				return nil, errors.New("REALITY: SharedKey == nil")
			}
			if _, err := hkdf.New(sha256.New, uConn.AuthKey, hello.Random[:20], []byte("REALITY")).Read(uConn.AuthKey); err != nil {
				return nil, err
			}
			// REALITY servers open the payload with AES-GCM regardless of the
			// offered cipher suites.
			block, _ := aes.NewCipher(uConn.AuthKey)
			aead, _ := cipher.NewGCM(block)
			aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
			copy(hello.Raw[39:], hello.SessionId)
		}
		if err := uConn.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		if !uConn.Verified {
			// Successful admission transfers this invalid connection to the spider.
			// Dial cancellation does not cancel camouflage; the owner and deadline do.
			closeConn = !x.startSpider(uConn)
			waitRealitySpider(ctx, time.Duration(randBetween(x.spider.returnDelay.min, x.spider.returnDelay.max))*time.Millisecond)
			return nil, errors.New("REALITY: processed invalid connection")
		}
		closeConn = false
		return uConn, nil

	case "udp":
		return nil, fmt.Errorf("%w: Reality+udp", netproxy.UnsupportedTunnelTypeError)
	default:
		return nil, fmt.Errorf("%w: %v", netproxy.UnsupportedTunnelTypeError, network)
	}

}

func (x *Reality) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, fmt.Errorf("%w: Reality+udp", netproxy.UnsupportedTunnelTypeError)
}

// randBetween samples [left, right); equal or inverted bounds return left.
func randBetween(left int64, right int64) int64 {
	if right <= left {
		return left
	}
	// Subtract as big integers so even the full int64 range cannot overflow.
	lower := big.NewInt(left)
	span := new(big.Int).Sub(big.NewInt(right), lower)
	value, err := rand.Int(rand.Reader, span)
	if err != nil {
		return left
	}
	return value.Add(value, lower).Int64()
}
