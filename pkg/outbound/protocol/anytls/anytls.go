package anytls

import (
	"bytes"
	"encoding/binary"

	"github.com/daeuniverse/dae/pkg/outbound/pool"
)

const ( // cmds
	cmdWaste               = iota // Paddings
	cmdSYN                        // stream open
	cmdPSH                        // data push
	cmdFIN                        // stream close, a.k.a EOF mark
	cmdSettings                   // Settings (Client send to Server)
	cmdAlert                      // Alert
	cmdUpdatePaddingScheme        // update padding scheme
	// Since version 2
	cmdSYNACK         // Server reports to the client that the stream has been opened
	cmdHeartRequest   // Keep alive command
	cmdHeartResponse  // Keep alive command
	cmdServerSettings // Settings (Server send to client)
)

const (
	headerOverHeadSize = 1 + 4 + 2
)

// appendFrame writes one complete frame. The caller owns buf throughout the
// carrier write; data is copied so padding never aliases a caller's payload.
func appendFrame(buf *bytes.Buffer, command byte, id uint32, data []byte) {
	var header [headerOverHeadSize]byte
	header[0] = command
	binary.BigEndian.PutUint32(header[1:], id)
	binary.BigEndian.PutUint16(header[5:], uint16(len(data)))
	_, _ = buf.Write(header[:])
	_, _ = buf.Write(data)
}

func (s *session) writeFrame(command byte, id uint32, data []byte, streamStop, operationStop <-chan struct{}) (int, error) {
	if err := s.lockWrite(streamStop, operationStop); err != nil {
		return 0, err
	}
	defer func() { s.writeGate <- struct{}{} }()
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	if command == cmdSYN {
		// Settings, SYN and target share packet 1. Later streams only send SYN/PSH.
		if !s.settingsSent {
			appendFrame(buf, cmdSettings, 0, settingsBytes(s.padding.Load()))
		}
		appendFrame(buf, cmdSYN, id, nil)
		appendFrame(buf, cmdPSH, id, data)
	} else if command == cmdPSH {
		// Application writes may exceed the uint16 frame length.
		for remaining := data; len(remaining) != 0; {
			count := min(len(remaining), 65535)
			appendFrame(buf, command, id, remaining[:count])
			remaining = remaining[count:]
		}
	} else {
		appendFrame(buf, command, id, data)
	}
	if _, err := s.writeLocked(buf.Bytes()); err != nil {
		return 0, err
	}
	if command == cmdSYN {
		s.settingsSent = true
	}
	return len(data), nil
}
