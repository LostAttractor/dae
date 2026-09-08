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
	// The Transport Layer Security (TLS) Protocol Version 1.3
	// https://www.rfc-editor.org/rfc/rfc8446#page-27
	boundary := 5
	if s.buf.Len() < boundary {
		return "", ErrNotApplicable
	}

	if s.buf.Bytes()[0] != ContentType_HandShake || (!bytes.Equal(s.buf.Bytes()[1:3], Version_Tls1_0) && !bytes.Equal(s.buf.Bytes()[1:3], Version_Tls1_2)) {
		return "", ErrNotApplicable
	}

	length := int(binary.BigEndian.Uint16(s.buf.Bytes()[3:5]))
	search := s.buf.Bytes()[5:]
	if len(search) < length {
		return "", ErrNeedMore
	}
	extensions, err := clientHelloExtensions(search[:length])
	if err != nil {
		return "", err
	}
	return findSniExtension(extensions)
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
