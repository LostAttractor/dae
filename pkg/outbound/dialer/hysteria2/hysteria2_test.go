package hysteria2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/dialer"
)

func TestUnsupportedObfuscationIsNotSilentlyDisabled(t *testing.T) {
	for _, query := range []string{"obfs=salamander&obfs-password=secret", "obfs-password=secret"} {
		if _, err := ParseHysteria2URL("hysteria2://password@proxy.example:443?" + query); !errors.Is(err, dialer.InvalidParameterErr) {
			t.Fatalf("unsupported encryption configuration accepted: %v", err)
		}
	}
}

func TestPinnedCertVerifierBindsTheLeaf(t *testing.T) {
	newCert := func() *x509.Certificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(1), NotAfter: time.Now().Add(time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	pinned, other := newCert(), newCert()
	sum := sha256.Sum256(pinned.Raw)
	verify := pinnedCertVerifier(normalizeCertHash(hex.EncodeToString(sum[:])))
	if err := verify([][]byte{pinned.Raw}, nil); err != nil {
		t.Fatalf("pinned leaf rejected: %v", err)
	}
	if err := verify([][]byte{other.Raw, pinned.Raw}, nil); err == nil {
		t.Fatal("accepted the pinned certificate after an unverified leaf")
	}
	if err := verify([][]byte{other.Raw}, [][]*x509.Certificate{{other, pinned}}); err != nil {
		t.Fatalf("pinned certificate of a verified chain rejected: %v", err)
	}
}
