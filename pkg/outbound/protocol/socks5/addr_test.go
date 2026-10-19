package socks5

import (
	"bytes"
	"errors"
	"io"
	"net/netip"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/daeuniverse/dae/pkg/outbound/protocol/infra/socks"
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

func TestDecodedAddressOwnsItsData(t *testing.T) {
	host := strings.Repeat("x", 255)
	domainWire := append([]byte{3, 255}, append([]byte(host), 0, 53)...)
	ipWire := []byte{1, 192, 0, 2, 1, 1, 187}
	domain, err := ReadAddrInfo(bytes.NewReader(domainWire))
	if err != nil {
		t.Fatal(err)
	}
	ip, err := ReadAddr(bytes.NewReader(ipWire))
	if err != nil {
		t.Fatal(err)
	}
	// Decoding later packets reuses scratch storage but must not modify any
	// address already returned to the caller, including maximum-length domains.
	for range 100 {
		if _, err := ReadAddrInfo(bytes.NewReader([]byte{1, 198, 51, 100, 2, 0, 80})); err != nil {
			t.Fatal(err)
		}
	}
	clear(domainWire)
	clear(ipWire)
	if domain.Hostname != host || domain.Port != 53 || domain.IP != (netip.Addr{}) {
		t.Fatalf("domain changed after reuse: %+v", domain)
	}
	if ip.String() != "192.0.2.1:443" {
		t.Fatalf("IP changed after reuse: %v", ip)
	}
}

func TestReadAddrInfoInvalidAndTruncated(t *testing.T) {
	for _, tc := range []struct {
		wire []byte
		err  error
	}{
		{nil, io.EOF},
		{[]byte{1}, io.EOF},
		{[]byte{1, 192}, io.ErrUnexpectedEOF},
		{[]byte{3}, io.EOF},
		{[]byte{3, 0}, socks.Errors[8]},
		{[]byte{3, 1, 'x', 0}, io.ErrUnexpectedEOF},
		{[]byte{0}, socks.Errors[8]},
		{[]byte{255}, socks.Errors[8]},
	} {
		addr, err := ReadAddrInfo(bytes.NewReader(tc.wire))
		if addr != nil || !errors.Is(err, tc.err) {
			t.Fatalf("wire %x: address=%v error=%v; want %v", tc.wire, addr, err, tc.err)
		}
	}
}
