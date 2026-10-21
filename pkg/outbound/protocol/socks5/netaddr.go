package socks5

import (
	"bytes"
	"net"
	"net/netip"
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
