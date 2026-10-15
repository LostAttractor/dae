package socks5

import (
	"bytes"
	"io"
	"testing"
	"testing/iotest"
)

func TestAddressFragmentsAndTruncation(t *testing.T) {
	for _, tc := range []struct {
		wire    []byte
		address string
	}{
		{[]byte{1, 192, 0, 2, 1, 1, 187}, "192.0.2.1:443"},
		{[]byte{4, 0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 53}, "[2001:db8::1]:53"},
		{append([]byte{3, 11}, append([]byte("example.org"), 0, 53)...), "example.org:53"},
	} {
		addr, err := ReadAddr(iotest.OneByteReader(bytes.NewReader(tc.wire)))
		if err != nil || addr.String() != tc.address {
			t.Fatalf("fragmented %q: %v %v", tc.address, addr, err)
		}
		for n := 0; n < len(tc.wire); n++ {
			if _, err := ReadAddrInfo(bytes.NewReader(tc.wire[:n])); err == nil {
				t.Fatalf("accepted %q truncated at %d", tc.address, n)
			}
		}
		data := bytes.NewReader(append(bytes.Clone(tc.wire), []byte("payload")...))
		if _, err := ReadAddrInfo(data); err != nil {
			t.Fatal(err)
		}
		remaining, _ := io.ReadAll(data)
		if string(remaining) != "payload" {
			t.Fatal("address decoder consumed payload")
		}
	}
}
