// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/internal/routingabi"
	"golang.org/x/sys/unix"
)

// Read destination and packet identity from the same recvmsg, never from the latest tuple entry.
type udpMetadata struct {
	destination netip.AddrPort
	mark        uint32
	cookie      uint64
}

var udpOOBSize = unix.CmsgSpace(unix.SizeofSockaddrInet4) + unix.CmsgSpace(unix.SizeofSockaddrInet6) + unix.CmsgSpace(16) + 2*unix.CmsgSpace(4)

func parseUDPMetadata(oob []byte) (metadata udpMetadata, valid bool) {
	var haveMark, haveStamp bool
	for len(oob) >= unix.CmsgLen(0) {
		header := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
		if uint64(header.Len) < uint64(unix.CmsgLen(0)) || uint64(header.Len) > uint64(len(oob)) {
			return udpMetadata{}, false
		}
		data := oob[unix.CmsgLen(0):header.Len]
		var destination netip.AddrPort
		switch {
		case header.Level == unix.SOL_IP && header.Type == unix.IP_RECVORIGDSTADDR:
			if len(data) != unix.SizeofSockaddrInet4 || binary.NativeEndian.Uint16(data) != unix.AF_INET {
				return udpMetadata{}, false
			}
			destination = netip.AddrPortFrom(netip.AddrFrom4([4]byte(data[4:8])), binary.BigEndian.Uint16(data[2:4]))
		case header.Level == unix.SOL_IPV6 && header.Type == unix.IPV6_RECVORIGDSTADDR:
			if len(data) != unix.SizeofSockaddrInet6 || binary.NativeEndian.Uint16(data) != unix.AF_INET6 {
				return udpMetadata{}, false
			}
			destination = netip.AddrPortFrom(netip.AddrFrom16([16]byte(data[8:24])), binary.BigEndian.Uint16(data[2:4]))
		case header.Level == unix.SOL_SOCKET && header.Type == unix.SO_MARK:
			if haveMark || len(data) != 4 {
				return udpMetadata{}, false
			}
			haveMark = true
			metadata.mark = binary.NativeEndian.Uint32(data)
		case header.Level == unix.SOL_SOCKET && header.Type == unix.SO_TIMESTAMPNS_NEW:
			if haveStamp || len(data) != 16 {
				return udpMetadata{}, false
			}
			haveStamp = true
			seconds, nanos := int64(binary.NativeEndian.Uint64(data)), int64(binary.NativeEndian.Uint64(data[8:]))
			if seconds < 0 || nanos < 0 || nanos >= 1e9 || seconds > (math.MaxInt64-nanos)/1e9 {
				return udpMetadata{}, false
			}
			metadata.cookie = uint64(seconds*1e9 + nanos)
		}
		if destination.IsValid() {
			destination = common.ConvergeAddrPort(destination)
			if metadata.destination.IsValid() && metadata.destination != destination {
				return udpMetadata{}, false
			}
			metadata.destination = destination
		}
		oob = oob[min(unix.CmsgSpace(len(data)), len(oob)):]
	}
	if len(oob) != 0 || !metadata.destination.IsValid() {
		return udpMetadata{}, false
	}
	return metadata, true
}

func (m udpMetadata) validDNS() bool {
	return m.mark == routingabi.DNS_METADATA_MARK && m.cookie != 0
}

// Cookies are never reused; the consumed snapshot stays immutable throughout queueing and DNS processing.
type dnsPacket struct {
	cookie uint64
	reply  bpfDnsReply
}

func retrieveDNSRoutingResult(m *ebpf.Map, src, dst netip.AddrPort, cookie uint64) (*routingResult, error) {
	if cookie == 0 || cookie > math.MaxInt64 {
		return nil, errors.New("invalid DNS packet cookie")
	}
	var handoff bpfDnsHandoff
	if err := m.LookupAndDelete(cookie, &handoff); err != nil {
		return nil, fmt.Errorf("consume DNS handoff: %w", err)
	}
	if handoff.Reply.Tuple != tuplesKey(src, dst, unix.IPPROTO_UDP) {
		return nil, errors.New("DNS handoff tuple mismatch")
	}
	return &routingResult{
		bpfRoutingResult: handoff.Result, Pname: handoff.Pname,
		dns: &dnsPacket{cookie: cookie, reply: handoff.Reply},
	}, nil
}

func receiveDNSMetadataControl(c syscall.RawConn) error {
	var socketErr error
	err := c.Control(func(fd uintptr) {
		for _, option := range []int{unix.SO_TIMESTAMPNS_NEW, unix.SO_RCVMARK} {
			if socketErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, option, 1); socketErr != nil {
				return
			}
		}
	})
	return errors.Join(err, socketErr)
}

func enableDNSReplyMetadata(fd int) error {
	var option [8]byte // struct sock_txtime
	binary.NativeEndian.PutUint32(option[:], unix.CLOCK_MONOTONIC)
	return unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_TXTIME, string(option[:]))
}

func dnsReplyOOB(cookie uint64) []byte {
	oob := make([]byte, unix.CmsgSpace(4)+unix.CmsgSpace(8))
	mark := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	mark.Level, mark.Type = unix.SOL_SOCKET, unix.SO_MARK
	mark.SetLen(unix.CmsgLen(4))
	binary.NativeEndian.PutUint32(oob[unix.CmsgLen(0):], routingabi.DNS_REPLY_MARK)
	stamp := oob[unix.CmsgSpace(4):]
	header := (*unix.Cmsghdr)(unsafe.Pointer(&stamp[0]))
	header.Level, header.Type = unix.SOL_SOCKET, unix.SCM_TXTIME
	header.SetLen(unix.CmsgLen(8))
	binary.NativeEndian.PutUint64(stamp[unix.CmsgLen(0):], cookie)
	return oob
}
