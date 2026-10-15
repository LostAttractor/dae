package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/daeuniverse/dae/pkg/outbound/pool"
	"github.com/daeuniverse/quic-go/quicvarint"
)

const (
	FrameTypeTCPRequest = 0x401

	// Max length values are for preventing DoS attacks

	MaxAddressLength = 2048
	MaxMessageLength = 2048
	MaxPaddingLength = 4096
)

// TCPRequest format:
// 0x401 (QUIC varint)
// Address length (QUIC varint)
// Address (bytes)
// Padding length (QUIC varint)
// Padding (bytes)

func WriteTCPRequest(w io.Writer, addr string) error {
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	padding := tcpRequestPadding.String()
	buf.Write(quicvarint.Append(nil, FrameTypeTCPRequest))
	buf.Write(quicvarint.Append(nil, uint64(len(addr))))
	buf.WriteString(addr)
	buf.Write(quicvarint.Append(nil, uint64(len(padding))))
	buf.WriteString(padding)
	_, err := buf.WriteTo(w)
	return err
}

// TCPResponse format:
// Status (byte, 0=ok, 1=error)
// Message length (QUIC varint)
// Message (bytes)
// Padding length (QUIC varint)
// Padding (bytes)

func ReadTCPResponse(r io.Reader) (bool, string, error) {
	var status [1]byte
	if _, err := io.ReadFull(r, status[:]); err != nil {
		return false, "", err
	}
	bReader := quicvarint.NewReader(r)
	msgLen, err := quicvarint.Read(bReader)
	if err != nil {
		return false, "", err
	}
	if msgLen > MaxMessageLength {
		return false, "", errors.New("invalid message length")
	}
	var msgBuf []byte
	// No message is fine
	if msgLen > 0 {
		msgBuf = make([]byte, msgLen)
		_, err = io.ReadFull(r, msgBuf)
		if err != nil {
			return false, "", err
		}
	}
	paddingLen, err := quicvarint.Read(bReader)
	if err != nil {
		return false, "", err
	}
	if paddingLen > MaxPaddingLength {
		return false, "", errors.New("invalid padding length")
	}
	if paddingLen > 0 {
		_, err = io.CopyN(io.Discard, r, int64(paddingLen))
		if err != nil {
			return false, "", err
		}
	}
	return status[0] == 0, string(msgBuf), nil
}

// UDPMessage format:
// Session ID (uint32 BE)
// Packet ID (uint16 BE)
// Fragment ID (uint8)
// Fragment count (uint8)
// Address length (QUIC varint)
// Address (bytes)
// Data...

type UDPMessage struct {
	SessionID uint32 // 4
	PacketID  uint16 // 2
	FragID    uint8  // 1
	FragCount uint8  // 1
	Addr      string // varint + bytes
	Data      []byte
}

func (m *UDPMessage) HeaderSize() int {
	lAddr := len(m.Addr)
	return 4 + 2 + 1 + 1 + int(quicvarint.Len(uint64(lAddr))) + lAddr
}

func (m *UDPMessage) Size() int {
	return m.HeaderSize() + len(m.Data)
}

func (m *UDPMessage) AppendTo(buf *bytes.Buffer) {
	buf.Write(binary.BigEndian.AppendUint32(nil, m.SessionID))
	buf.Write(binary.BigEndian.AppendUint16(nil, m.PacketID))
	buf.Write([]byte{m.FragID, m.FragCount})
	buf.Write(quicvarint.Append(nil, uint64(len(m.Addr))))
	buf.WriteString(m.Addr)
	buf.Write(m.Data)
}

func ParseUDPMessage(msg []byte) (*UDPMessage, error) {
	if len(msg) < 9 {
		return nil, io.ErrUnexpectedEOF
	}
	reader := bytes.NewReader(msg[8:])
	addrLen, err := quicvarint.Read(reader)
	if err != nil {
		return nil, err
	}
	if addrLen == 0 || addrLen > MaxAddressLength || addrLen >= uint64(reader.Len()) {
		return nil, errors.New("invalid UDP address or payload length")
	}
	offset := len(msg) - reader.Len()
	return &UDPMessage{
		SessionID: binary.BigEndian.Uint32(msg), PacketID: binary.BigEndian.Uint16(msg[4:]),
		FragID: msg[6], FragCount: msg[7],
		Addr: string(msg[offset : offset+int(addrLen)]), Data: msg[offset+int(addrLen):],
	}, nil
}
