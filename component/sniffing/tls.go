/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package sniffing

import (
	"bytes"
	"encoding/binary"
	"strings"

	"github.com/daeuniverse/dae/component/sniffing/internal/quicutils"
	"github.com/daeuniverse/outbound/pool"
	"golang.org/x/crypto/cryptobyte"
)

const (
	ContentType_HandShake                byte   = 22
	HandShakeType_Hello                  byte   = 1
	TlsExtension_ServerName              uint16 = 0
	TlsExtension_ServerNameType_HostName byte   = 0

	AssumedTlsClientHelloMaxLength = quicutils.MaxCryptoReassemblySize
)

var (
	Version_Tls1_0 = []byte{0x03, 0x01}
	Version_Tls1_2 = []byte{0x03, 0x03}
)

// SniffTls only supports tls1.2, tls1.3
func (s *Sniffer) SniffTls() (d string, err error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()
	return s.sniffTlsLocked()
}

func (s *Sniffer) sniffTlsLocked() (d string, err error) {
	// TCP reads and TLS records may both split a ClientHello. Keep the raw
	// bytes for relay; allocate a joined handshake only when records split it.
	records := s.buf.Bytes()
	var hello []byte
	var joined *bytes.Buffer
	defer func() {
		if joined != nil {
			pool.PutBytesBuffer(joined)
		}
	}()
	for {
		if len(records) > 0 && records[0] != ContentType_HandShake ||
			len(records) > 1 && records[1] != 3 ||
			len(records) > 2 && (records[2] < 1 || records[2] > 3) {
			return "", ErrNotApplicable
		}
		if len(records) < 5 {
			return "", ErrNeedMore
		}
		length := int(binary.BigEndian.Uint16(records[3:5]))
		if len(records) < 5+length {
			return "", ErrNeedMore
		}
		payload := records[5 : 5+length]
		records = records[5+length:]
		if hello == nil {
			hello = payload
		} else {
			if joined == nil {
				joined = pool.GetBytesBuffer()
				joined.Write(hello)
			}
			joined.Write(payload)
			hello = joined.Bytes()
		}
		if len(hello) < 4 {
			continue
		}
		size := 4 + int(hello[1])<<16 + int(hello[2])<<8 + int(hello[3])
		if hello[0] != HandShakeType_Hello || size > streamSniffingMaxBytes {
			return "", ErrNotApplicable
		}
		if len(hello) >= size {
			extensions, err := clientHelloExtensions(hello[:size])
			if err != nil {
				return "", err
			}
			d, err = findSniExtension(extensions)
			s.tcpTLS = err == nil || err == ErrNotFound
			return d, err
		}
	}
}

// clientHelloExtensions accepts one complete, contiguous ClientHello.
func clientHelloExtensions(hello []byte) ([]byte, error) {
	input := cryptobyte.String(hello)
	var kind uint8
	var version uint16
	var body, ignored, extensions cryptobyte.String
	if !input.ReadUint8(&kind) || kind != HandShakeType_Hello ||
		!input.ReadUint24LengthPrefixed(&body) || !input.Empty() ||
		!body.ReadUint16(&version) || version != 0x0303 ||
		!body.Skip(32) || // random
		!body.ReadUint8LengthPrefixed(&ignored) || // session ID
		!body.ReadUint16LengthPrefixed(&ignored) || // cipher suites
		!body.ReadUint8LengthPrefixed(&ignored) || // compression methods
		!body.ReadUint16LengthPrefixed(&extensions) || !body.Empty() {
		return nil, ErrNotApplicable
	}
	return extensions, nil
}

func findTLSExtension(extensions []byte, want uint16) (cryptobyte.String, error) {
	input := cryptobyte.String(extensions)
	for !input.Empty() {
		var kind uint16
		var data cryptobyte.String
		if !input.ReadUint16(&kind) || !input.ReadUint16LengthPrefixed(&data) {
			return nil, ErrNotApplicable
		}
		if kind == want {
			return data, nil
		}
	}
	return nil, ErrNotFound
}

func findSniExtension(extensions []byte) (string, error) {
	data, err := findTLSExtension(extensions, TlsExtension_ServerName)
	if err != nil {
		return "", err
	}
	var names cryptobyte.String
	if !data.ReadUint16LengthPrefixed(&names) || !data.Empty() || names.Empty() {
		return "", ErrNotApplicable
	}
	for !names.Empty() {
		var kind uint8
		var name cryptobyte.String
		if !names.ReadUint8(&kind) || !names.ReadUint16LengthPrefixed(&name) || name.Empty() {
			return "", ErrNotApplicable
		}
		if kind == TlsExtension_ServerNameType_HostName {
			return strings.TrimSuffix(string(name), "."), nil
		}
	}
	return "", ErrNotFound
}
