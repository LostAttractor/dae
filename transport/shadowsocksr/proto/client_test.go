package proto

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"hash"
	"hash/adler32"
	"hash/crc32"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientPacketAuthenticationAndOwnership(t *testing.T) {
	for _, tc := range []struct {
		name string
		hash func() hash.Hash
	}{{"auth_aes128_md5", md5.New}, {"auth_aes128_sha1", sha1.New}} {
		t.Run(tc.name, func(t *testing.T) {
			codec := NewProtocol(tc.name)
			key := []byte("stream cipher key")
			if err := codec.InitWithServerInfo(&ServerInfo{Param: "1234:secret", Key: key}); err != nil {
				t.Fatal(err)
			}
			buf := bytes.NewBufferString("payload")
			if err := codec.EncodePkt(buf); err != nil {
				t.Fatal(err)
			}
			wire := buf.Bytes()
			if string(wire[:7]) != "payload" || binary.LittleEndian.Uint32(wire[7:11]) != 1234 {
				t.Fatalf("incorrect UDP request framing: %x", wire)
			}
			digest := tc.hash()
			digest.Write([]byte("secret"))
			mac := hmac.New(tc.hash, digest.Sum(nil))
			mac.Write(wire[:11])
			if !hmac.Equal(mac.Sum(nil)[:4], wire[11:]) {
				t.Fatal("incorrect request MAC")
			}
			response := append([]byte(nil), []byte("response")...)
			mac = hmac.New(tc.hash, key)
			mac.Write(response)
			response = append(response, mac.Sum(nil)[:4]...)
			decoded, err := codec.DecodePkt(response)
			if err != nil || string(decoded) != "response" {
				t.Fatalf("response: %q %v", decoded, err)
			}
			response[len(response)-1] ^= 1
			if _, err = codec.DecodePkt(response); err == nil {
				t.Fatal("corrupt packet accepted")
			}
		})
	}
}

func TestClientStreamFragmentationAndTruncation(t *testing.T) {
	for _, truncated := range []bool{false, true} {
		conn, peer := net.Pipe()
		codec := NewProtocol("auth_sha1_v4")
		if err := codec.InitWithServerInfo(&ServerInfo{Key: []byte("key"), AddrLen: 7}); err != nil {
			t.Fatal(err)
		}
		client := &Conn{Conn: conn, codec: codec}
		payload := []byte("fragmented response")
		frame := make([]byte, 5+len(payload)+4)
		binary.BigEndian.PutUint16(frame, uint16(len(frame)))
		binary.LittleEndian.PutUint16(frame[2:4], uint16(crc32.ChecksumIEEE(frame[:2])))
		frame[4] = 1
		copy(frame[5:], payload)
		binary.LittleEndian.PutUint32(frame[len(frame)-4:], adler32.Checksum(frame[:len(frame)-4]))
		if truncated {
			frame = frame[:len(frame)-1]
		}
		go func() {
			defer peer.Close()
			for _, b := range frame {
				if _, err := peer.Write([]byte{b}); err != nil {
					return
				}
			}
		}()
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		data, err := io.ReadAll(client)
		if truncated {
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("truncated frame error: %v", err)
			}
		} else if err != nil || !bytes.Equal(data, payload) {
			t.Fatalf("fragmented frame: %q %v", data, err)
		}
		_ = client.Close()
	}
}

type shortConn struct {
	net.Conn
	writes atomic.Int32
}

func (c *shortConn) Write(p []byte) (int, error) { c.writes.Add(1); return len(p) - 1, nil }
func TestClientStreamShortWriteIsTerminal(t *testing.T) {
	base := &shortConn{}
	conn := &Conn{Conn: base, codec: NewProtocol("origin")}
	for range 2 {
		if n, err := conn.Write([]byte("payload")); n != 0 || !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("short write: %d %v", n, err)
		}
	}
	if base.writes.Load() != 1 {
		t.Fatal("retried a partially written protocol frame")
	}
}
