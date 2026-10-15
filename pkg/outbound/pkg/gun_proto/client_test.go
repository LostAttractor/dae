package gun_proto

import (
	"bytes"
	"testing"
)

func TestGunWireAndMalformedPeerMessages(t *testing.T) {
	wire, err := (codec{}).Marshal(&Hunk{Data: []byte("hello")})
	if err != nil || !bytes.Equal(wire, []byte{0x0a, 5, 'h', 'e', 'l', 'l', 'o'}) {
		t.Fatalf("wire %v %v", wire, err)
	}
	// Unknown fields are skipped; a repeated singular bytes field uses its last value.
	wire = append(wire, 0x10, 3, 0x0a, 1, 'x')
	var h Hunk
	if err := (codec{}).Unmarshal(wire, &h); err != nil || string(h.Data) != "x" {
		t.Fatalf("peer extension %q %v", h.Data, err)
	}
	wire[len(wire)-1] = 'z'
	if string(h.Data) != "x" {
		t.Fatal("decoder retained gRPC-owned receive memory")
	}
	for _, wire := range [][]byte{{0x0a, 2, 1}, {0x08, 1}, {0}, {0x12, 0xff}} {
		if err := (codec{}).Unmarshal(wire, &h); err == nil {
			t.Fatalf("accepted malformed protobuf %v", wire)
		}
	}
}
