package vmess

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
)

const SeqPacketMagicAddress = "sp.packet-addr.v2fly.arpa"

func appendPacketAddress(dst []byte, addr net.Addr) ([]byte, error) {
	if addr == nil {
		return nil, fmt.Errorf("missing VMess UDP destination")
	}
	address, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return nil, fmt.Errorf("VMess packet-address requires an IP destination: %w", err)
	}
	ip := address.Addr().Unmap()
	typ := byte(2)
	if ip.Is4() {
		typ = 1
	}
	dst = append(dst, typ)
	dst = append(dst, ip.AsSlice()...)
	dst = binary.BigEndian.AppendUint16(dst, address.Port())
	return dst, nil
}
func extractPacketAddress(data []byte) (net.Addr, []byte, error) {
	if len(data) == 0 {
		return nil, nil, protocolError("missing packet address")
	}
	size := 0
	switch data[0] {
	case 1:
		size = 4
	case 2:
		size = 16
	default:
		return nil, nil, protocolError("invalid packet address type")
	}
	if len(data) < size+3 {
		return nil, nil, protocolError("truncated packet address")
	}
	ip, _ := netip.AddrFromSlice(data[1 : 1+size])
	port := binary.BigEndian.Uint16(data[1+size:])
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, port)), data[3+size:], nil
}
