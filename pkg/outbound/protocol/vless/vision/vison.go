// Package vision implements the client side of xtls-rprx-vision.
package vision

import (
	"bytes"
	gotls "crypto/tls"
	"errors"
	"fmt"
	"net"
	"reflect"
	"unsafe"

	utls "github.com/refraction-networking/utls"
)

var ErrNotTLS13 = errors.New("XTLS Vision requires a TLS 1.3 carrier")

func NewConn(overlay net.Conn, userUUID []byte) (*Conn, error) {
	if len(userUUID) != 16 {
		return nil, fmt.Errorf("Vision requires a 16-byte UUID")
	}
	provider, ok := overlay.(interface{ TLSConn() net.Conn })
	if !ok {
		return nil, fmt.Errorf("Vision requires an explicit TLS carrier: %T", overlay)
	}
	carrier := provider.TLSConn()
	var raw net.Conn
	var t reflect.Type
	var pointer unsafe.Pointer
	switch conn := carrier.(type) {
	case *gotls.Conn:
		if conn.ConnectionState().Version != gotls.VersionTLS13 {
			return nil, ErrNotTLS13
		}
		raw = conn.NetConn()
		t = reflect.TypeOf(conn).Elem()
		pointer = unsafe.Pointer(conn)
	case *utls.UConn:
		if conn.ConnectionState().Version != utls.VersionTLS13 {
			return nil, ErrNotTLS13
		}
		raw = conn.NetConn()
		t = reflect.TypeOf(conn.Conn).Elem()
		pointer = unsafe.Pointer(conn.Conn)
	default:
		return nil, fmt.Errorf("unsupported Vision TLS carrier: %T", carrier)
	}
	// Vision must drain TLS's already decrypted and encrypted input before the
	// authenticated peer requests direct forwarding. Check the concrete layout;
	// never search through arbitrary connection wrappers.
	input, okInput := t.FieldByName("input")
	rawInput, okRaw := t.FieldByName("rawInput")
	if !okInput || !okRaw || input.Type != reflect.TypeOf(bytes.Reader{}) || rawInput.Type != reflect.TypeOf(bytes.Buffer{}) {
		return nil, fmt.Errorf("unsupported Vision TLS input layout: %s", t)
	}
	c := &Conn{Conn: raw, overlay: overlay, writePadding: true, readPadding: true, packetsToFilter: 6}
	copy(c.uuid[:], userUUID)
	c.input = (*bytes.Reader)(unsafe.Add(pointer, input.Offset))
	c.rawInput = (*bytes.Buffer)(unsafe.Add(pointer, rawInput.Offset))
	return c, nil
}
