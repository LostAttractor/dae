package protocol

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

type Metadata struct {
	Type     MetadataType
	Hostname string
	Port     uint16
}

type MetadataType int

const (
	MetadataTypeIPv4 MetadataType = iota
	MetadataTypeIPv6
	MetadataTypeDomain
)

func ParseMetadata(tgt string) (mdata Metadata, err error) {
	host, strPort, err := net.SplitHostPort(tgt)
	if err != nil {
		return mdata, fmt.Errorf("SplitHostPort: %w", err)
	}
	port, err := strconv.ParseUint(strPort, 10, 16)
	if err != nil {
		return mdata, fmt.Errorf("failed to parse port: %w", err)
	}
	if host == "" || len(host) > 255 {
		return mdata, fmt.Errorf("invalid destination host %q", host)
	}
	tgtIP, err := netip.ParseAddr(host)
	var typ MetadataType
	if err != nil {
		typ = MetadataTypeDomain
	} else if tgtIP.Is4() {
		typ = MetadataTypeIPv4
	} else {
		typ = MetadataTypeIPv6
	}
	return Metadata{
		Type:     typ,
		Hostname: host,
		Port:     uint16(port),
	}, nil
}
