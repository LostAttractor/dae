package vmess

import (
	"encoding/binary"

	"github.com/daeuniverse/dae/pkg/outbound/protocol/socks5"
)

type request struct {
	address *socks5.AddressInfo
	network string
	cipher  Cipher
}

func (r request) addrLen() int {
	if r.address.Type == socks5.AddressTypeDomain {
		return 1 + len(r.address.Hostname)
	}
	return len(r.address.IP.AsSlice())
}
func (r request) putAddress(dst []byte) {
	binary.BigEndian.PutUint16(dst, r.address.Port)
	switch r.address.Type {
	case socks5.AddressTypeIPv4:
		dst[2] = 1
		copy(dst[3:], r.address.IP.AsSlice())
	case socks5.AddressTypeIPv6:
		dst[2] = 3
		copy(dst[3:], r.address.IP.AsSlice())
	case socks5.AddressTypeDomain:
		dst[2] = 2
		dst[3] = byte(len(r.address.Hostname))
		copy(dst[4:], r.address.Hostname)
	}
}
