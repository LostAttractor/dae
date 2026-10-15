package ciphers

import (
	"bytes"
	"testing"

	"github.com/daeuniverse/dae/pkg/outbound/common"
)

func TestCloneUsesFreshIV(t *testing.T) {
	cipher, err := NewStreamCipher("aes-128-cfb", "password")
	if err != nil {
		t.Fatal(err)
	}
	first, err := cipher.InitEncrypt()
	if err != nil {
		t.Fatal(err)
	}
	second, err := cipher.Clone().InitEncrypt()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("clone reused a connection IV")
	}
	if _, err := NewStreamCipher("seed-cfb", "password"); err == nil {
		t.Fatal("unimplemented SEED must not silently select RC2")
	}
}

func TestEvpBytesToKey(t *testing.T) {
	key := common.EVPBytesToKey("foobar", 32)
	keyTarget := []byte{0x38, 0x58, 0xf6, 0x22, 0x30, 0xac, 0x3c, 0x91, 0x5f, 0x30, 0x0c, 0x66, 0x43, 0x12, 0xc6, 0x3f, 0x56, 0x83, 0x78, 0x52, 0x96, 0x14, 0xd2, 0x2d, 0xdb, 0x49, 0x23, 0x7d, 0x2f, 0x60, 0xbf, 0xdf}
	if !bytes.Equal(key, keyTarget) {
		t.Errorf("key not correct\n\texpect: %v\n\tgot:   %v\n", keyTarget, key)
	}
}

// Fragmented encryption and decryption must agree even across stream block
// boundaries. The table covers every registered cipher, including Salsa's
// custom offset bookkeeping; wire authentication is tested by client peers.
func TestStreamCiphersFragmented(t *testing.T) {
	for method := range streamCipherMethod {
		t.Run(method, func(t *testing.T) {
			enc, err := NewStreamCipher(method, "foobar")
			if err != nil {
				t.Fatal(err)
			}
			dec := enc.Clone()
			iv, err := enc.InitEncrypt()
			if err != nil {
				t.Fatal(err)
			}
			if err := dec.InitDecrypt(iv); err != nil {
				t.Fatal(err)
			}
			plain := bytes.Repeat([]byte("fragment"), 37)
			wire, got := make([]byte, len(plain)), make([]byte, len(plain))
			for pos := 0; pos < len(plain); pos += 17 {
				end := min(pos+17, len(plain))
				enc.Encrypt(wire[pos:end:end], plain[pos:end])
			}
			for pos := 0; pos < len(wire); pos += 31 {
				end := min(pos+31, len(wire))
				dec.Decrypt(got[pos:end:end], wire[pos:end])
			}
			if !bytes.Equal(got, plain) {
				t.Fatal("fragmented stream corrupted plaintext")
			}
		})
	}
}
