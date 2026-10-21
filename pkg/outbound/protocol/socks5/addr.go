package socks5

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/infra/socks"
)

type AddressType uint8

// Address type constants for Shadowsocks protocol
const (
	AddressTypeIPv4   AddressType = 1
	AddressTypeDomain AddressType = 3
	AddressTypeIPv6   AddressType = 4
)

var (
	ErrInvalidAddress = fmt.Errorf("invalid address")
)

// AddressInfo represents decoded address information
type AddressInfo struct {
	Type     AddressType
	Hostname string
	IP       netip.Addr
	Port     uint16
}

func WriteAddr(addr string, buf *bytes.Buffer) error {
	addressInfo, err := parseAddress(addr)
	if err != nil {
		return err
	}
	return WriteAddrInfo(&addressInfo, buf)
}

// WriteAddr writes address information to buffer
func WriteAddrInfo(addr *AddressInfo, buf *bytes.Buffer) error {
	buf.WriteByte(byte(addr.Type))
	switch addr.Type {
	case AddressTypeIPv4, AddressTypeIPv6:
		if (addr.Type == AddressTypeIPv4 && !addr.IP.Is4()) || (addr.Type == AddressTypeIPv6 && !addr.IP.Is6()) {
			return ErrInvalidAddress
		}
		buf.Write(addr.IP.AsSlice())
	case AddressTypeDomain:
		lenDN := len(addr.Hostname)
		if lenDN == 0 || lenDN > 255 {
			return fmt.Errorf("invalid domain length: %d bytes", lenDN)
		}
		buf.WriteByte(uint8(lenDN))
		buf.WriteString(addr.Hostname)
	default:
		return fmt.Errorf("unsupported address type: %v", addr.Type)
	}
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], addr.Port)
	buf.Write(port[:])
	return nil
}

func ReadAddr(data io.Reader) (net.Addr, error) {
	addressInfo, err := ReadAddrInfo(data)
	if err != nil {
		return nil, err
	}

	// Preserve domain addresses without performing hidden DNS lookups.
	switch addressInfo.Type {
	case AddressTypeIPv4, AddressTypeIPv6:
		return net.UDPAddrFromAddrPort(netip.AddrPortFrom(addressInfo.IP, addressInfo.Port)), nil
	case AddressTypeDomain:
		return netproxy.NewAddr("udp", net.JoinHostPort(addressInfo.Hostname, strconv.Itoa(int(addressInfo.Port)))), nil
	default:
		return nil, ErrInvalidAddress
	}
}

// ReadAddrInfo shares the exact-length SOCKS address decoder used by the
// other client protocols, including readers that fragment every field.
func ReadAddrInfo(data io.Reader) (*AddressInfo, error) {
	buf := pool.GetBuffer(socks.MaxAddrLen)
	defer pool.PutBuffer(buf)
	addr, err := socks.ReadAddrInto(data, buf)
	if err != nil {
		return nil, fmt.Errorf("read SOCKS address: %w", err)
	}
	info := &AddressInfo{Type: AddressType(addr[0]), Port: binary.BigEndian.Uint16(addr[len(addr)-2:])}
	switch info.Type {
	case AddressTypeIPv4:
		info.IP = netip.AddrFrom4([4]byte(addr[1:5]))
	case AddressTypeIPv6:
		info.IP = netip.AddrFrom16([16]byte(addr[1:17]))
	case AddressTypeDomain:
		info.Hostname = string(addr[2 : len(addr)-2])
	}
	return info, nil
}

func AddressFromString(addr string) (*AddressInfo, error) {
	info, err := parseAddress(addr)
	if err != nil {
		return nil, err
	}
	return &info, nil
}

func parseAddress(addr string) (AddressInfo, error) {
	hostname, port_, err := net.SplitHostPort(addr)
	if err != nil {
		return AddressInfo{}, err
	}
	port, err := strconv.ParseUint(port_, 10, 16)
	if err != nil {
		return AddressInfo{}, fmt.Errorf("invalid port: %v", port_)
	}

	info := AddressInfo{Port: uint16(port)}

	ip, err := netip.ParseAddr(hostname)
	if err != nil {
		if len(hostname) == 0 || len(hostname) > 255 {
			return AddressInfo{}, ErrInvalidAddress
		}
		info.Type = AddressTypeDomain
		info.Hostname = hostname
	} else {
		info.IP = ip
		if ip.Is4() {
			info.Type = AddressTypeIPv4
		} else {
			info.Type = AddressTypeIPv6
		}
	}
	return info, nil
}
