package socks5

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"

	"github.com/daeuniverse/dae/pkg/outbound/pool"
)

// WriteNetAddr avoids formatting and reparsing the IP on every UDP packet.
// Domain addresses and unusual address implementations use the string codec.
func WriteNetAddr(addr net.Addr, buf *bytes.Buffer) error {
	if addr == nil {
		return ErrInvalidAddress
	}
	udp, ok := addr.(*net.UDPAddr)
	if !ok {
		return WriteAddr(addr.String(), buf)
	}
	if udp == nil || udp.Port < 0 || udp.Port > 65535 {
		return ErrInvalidAddress
	}
	if udp.Zone != "" {
		return WriteAddr(udp.String(), buf)
	}
	ip, ok := netip.AddrFromSlice(udp.IP)
	if !ok {
		return ErrInvalidAddress
	}
	info := AddressInfo{IP: ip.Unmap(), Port: uint16(udp.Port), Type: AddressTypeIPv6}
	if info.IP.Is4() {
		info.Type = AddressTypeIPv4
	}
	return WriteAddrInfo(&info, buf)
}

// AppendNetAddr appends addr as WriteNetAddr writes it. IP addresses do not
// allocate.
func AppendNetAddr(dst []byte, addr net.Addr) ([]byte, error) {
	if udp, ok := addr.(*net.UDPAddr); ok && udp != nil && udp.Zone == "" && udp.Port >= 0 && udp.Port <= 65535 {
		if ip, ok := netip.AddrFromSlice(udp.IP); ok {
			if ip = ip.Unmap(); ip.Is4() {
				a := ip.As4()
				dst = append(append(dst, byte(AddressTypeIPv4)), a[:]...)
			} else {
				a := ip.As16()
				dst = append(append(dst, byte(AddressTypeIPv6)), a[:]...)
			}
			return binary.BigEndian.AppendUint16(dst, uint16(udp.Port)), nil
		}
	}
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	if err := WriteNetAddr(addr, buf); err != nil {
		return dst, err
	}
	return append(dst, buf.Bytes()...), nil
}
