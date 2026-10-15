package juicity

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/daeuniverse/dae/pkg/outbound/protocol"
)

type Metadata struct {
	protocol.Metadata
	Network string
}

func (m *Metadata) appendTo(buf *bytes.Buffer) error {
	switch m.Type {
	case protocol.MetadataTypeIPv4:
		buf.WriteByte(1)
		buf.Write(net.ParseIP(m.Hostname).To4())
	case protocol.MetadataTypeIPv6:
		buf.WriteByte(4)
		buf.Write(net.ParseIP(m.Hostname).To16())
	case protocol.MetadataTypeDomain:
		if len(m.Hostname) == 0 || len(m.Hostname) > 255 {
			return fmt.Errorf("invalid Juicity domain length")
		}
		buf.Write([]byte{3, byte(len(m.Hostname))})
		buf.WriteString(m.Hostname)
	default:
		return fmt.Errorf("invalid Juicity address type")
	}
	buf.Write(binary.BigEndian.AppendUint16(nil, m.Port))
	return nil
}

// readMetadata reads the source address preceding a server UDP payload.
func readMetadata(r io.Reader) (Metadata, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:1]); err != nil {
		return Metadata{}, err
	}
	size := 0
	m := Metadata{}
	switch header[0] {
	case 1:
		m.Type, size = protocol.MetadataTypeIPv4, 4
	case 4:
		m.Type, size = protocol.MetadataTypeIPv6, 16
	case 3:
		m.Type = protocol.MetadataTypeDomain
		if _, err := io.ReadFull(r, header[1:]); err != nil {
			return m, err
		}
		size = int(header[1])
	default:
		return m, fmt.Errorf("invalid Juicity address type: %d", header[0])
	}
	var storage [257]byte
	if _, err := io.ReadFull(r, storage[:size+2]); err != nil {
		return m, err
	}
	if m.Type == protocol.MetadataTypeDomain {
		m.Hostname = string(storage[:size])
	} else {
		m.Hostname = net.IP(storage[:size]).String()
	}
	m.Port = binary.BigEndian.Uint16(storage[size:])
	return m, nil
}
