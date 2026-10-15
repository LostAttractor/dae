package proto

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"testing"

	"github.com/daeuniverse/dae/pkg/outbound/ciphers"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/shadowsocks_stream"
)

func TestProtocolRejectsInvalidUserIDs(t *testing.T) {
	for _, name := range []string{"auth_chain_a", "auth_chain_b", "auth_aes128_md5", "auth_aes128_sha1"} {
		t.Run(name, func(t *testing.T) {
			for _, param := range []string{"-1:secret", "4294967296:secret", "18446744073709551615:secret", "not-a-number:secret", "1234"} {
				if _, err := NewDialer(new(shadowsocks_stream.Dialer), name, param, 0); err == nil {
					t.Errorf("accepted invalid dialer user parameter %q", param)
				}
				cipher, err := ciphers.NewStreamCipher("aes-128-cfb", "test-key")
				if err != nil {
					t.Fatal(err)
				}
				d := &Dialer{name: name, param: param}
				if _, err := d.newProtocol(cipher, 7); err == nil {
					t.Errorf("accepted invalid user parameter %q", param)
				}
			}
		})
	}
}

func TestProtocolPreservesUserIDAndPassword(t *testing.T) {
	for _, name := range []string{"auth_chain_a", "auth_chain_b", "auth_aes128_md5", "auth_aes128_sha1"} {
		for _, id := range []uint32{0, 1234, 1<<32 - 1} {
			codec := NewProtocol(name)
			const password = "secret:with:colons"
			if err := codec.InitWithServerInfo(&ServerInfo{Param: strconv.FormatUint(uint64(id), 10) + ":" + password}); err != nil {
				t.Fatal(err)
			}
			var uid [4]byte
			var gotKey, wantKey []byte
			switch codec := codec.(type) {
			case *authChainA:
				uid, gotKey, wantKey = codec.uid, codec.userKey, []byte(password)
			case *authAES128:
				uid, gotKey, wantKey = codec.uid, codec.userKey, codec.hashDigest([]byte(password))
			}
			if binary.LittleEndian.Uint32(uid[:]) != id || !bytes.Equal(gotKey, wantKey) {
				t.Fatalf("%s changed the supplied identity %d", name, id)
			}
		}
		codec := NewProtocol(name)
		if err := codec.InitWithServerInfo(&ServerInfo{Key: []byte("base-key")}); err != nil {
			t.Fatalf("%s rejected absent user parameter: %v", name, err)
		}
	}
}
