// SPDX-License-Identifier: AGPL-3.0-only

package netutils

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
)

// ReadDNSFrame reads a two-byte length followed by the exact message bytes.
// The caller owns the returned bytes. Empty and opaque messages are preserved;
// DNS parsing and response validation belong to the consumer.
func ReadDNSFrame(reader io.Reader) ([]byte, error) {
	return readDNSFrame(reader, func(size int) []byte { return make([]byte, size) })
}

// The resolver supplies pooled storage and must release it even on read error.
func readDNSFrame(reader io.Reader, allocate func(int) []byte) ([]byte, error) {
	var prefix [2]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return nil, fmt.Errorf("read DNS frame length: %w", err)
	}
	wire := allocate(int(binary.BigEndian.Uint16(prefix[:])))
	if _, err := io.ReadFull(reader, wire); err != nil {
		return wire, fmt.Errorf("read DNS frame: %w", err)
	}
	return wire, nil
}

// WriteDNSFrame writes an exact DNS message with its two-byte length prefix.
func WriteDNSFrame(writer io.Writer, wire []byte) error {
	if len(wire) > consts.MaxDnsMessageSize {
		return fmt.Errorf("DNS frame exceeds %d bytes", consts.MaxDnsMessageSize)
	}
	frame := pool.GetBuffer(2 + len(wire))
	defer pool.PutBuffer(frame)
	binary.BigEndian.PutUint16(frame, uint16(len(wire)))
	copy(frame[2:], wire)
	for len(frame) > 0 {
		n, err := writer.Write(frame)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		frame = frame[n:]
	}
	return nil
}
