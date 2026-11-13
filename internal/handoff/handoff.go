// SPDX-License-Identifier: AGPL-3.0-only

// Package handoff contains the local, descriptor-based process handoff protocol.
package handoff

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

const Protocol = 5

// Channel is private to a parent and the executable it starts. All descriptor
// transfers use ExtraFiles before exec; messages never name arbitrary paths.
type Channel struct {
	net.Conn
	encoder *jsontext.Encoder
	decoder *jsontext.Decoder
}

func newChannel(conn net.Conn) *Channel {
	return &Channel{Conn: conn, encoder: jsontext.NewEncoder(conn), decoder: jsontext.NewDecoder(conn)}
}

func SocketPair() (*Channel, *os.File, error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	parent := os.NewFile(uintptr(fds[0]), "handoff-parent")
	defer parent.Close()
	conn, err := net.FileConn(parent)
	if err != nil {
		_ = unix.Close(fds[1])
		return nil, nil, err
	}
	return newChannel(conn), os.NewFile(uintptr(fds[1]), "handoff-child"), nil
}

func FromFile(file *os.File) (*Channel, error) {
	conn, err := net.FileConn(file)
	if err != nil {
		return nil, err
	}
	return newChannel(conn), nil
}

func (c *Channel) Send(value any) error {
	return json.MarshalEncode(c.encoder, value)
}

func (c *Channel) Receive(value any) error {
	return json.UnmarshalDecode(c.decoder, value)
}

func Dup(fd int, name string) (*os.File, error) {
	copy, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("duplicate %s: %w", name, err)
	}
	return os.NewFile(uintptr(copy), name), nil
}

// net.Conn.File marks the file so Fd (including exec.ExtraFiles) clears
// O_NONBLOCK on the shared socket. Duplicate via RawConn to preserve deadlines
// in the serving process throughout candidate preparation.
func DupSocket(conn syscall.Conn, name string) (*os.File, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var file *os.File
	var copyErr error
	err = raw.Control(func(fd uintptr) { file, copyErr = Dup(int(fd), name) })
	return file, errors.Join(err, copyErr)
}

// Listener reserves an inherited address without accepting before publication.
type Listener struct {
	net.Listener
	ready  chan struct{}
	closed chan struct{}
	start  sync.Once
	close  sync.Once
}

func Hold(listener net.Listener) *Listener {
	return &Listener{Listener: listener, ready: make(chan struct{}), closed: make(chan struct{})}
}

func (l *Listener) Activate() { l.start.Do(func() { close(l.ready) }) }

func (l *Listener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	case <-l.ready:
	}
	return l.Listener.Accept()
}

func (l *Listener) Close() (err error) {
	l.close.Do(func() { close(l.closed); err = l.Listener.Close() })
	return err
}
