// SPDX-License-Identifier: AGPL-3.0-only

package jq

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	MaxExpression = 64 << 10
	MaxBody       = 256 << 20
	maxError      = 4096
	frameMagic    = 0x444a5131
)

const (
	statusOK = iota
	statusEmpty
	statusError
	statusLarge
)

var ErrUnavailable = errors.New("Surge jq worker pool is unavailable")
var ErrBusy = errors.New("Surge jq worker queue is full")
var ErrExpression = errors.New("Surge jq expression failed")

type frame struct {
	Magic      uint32
	Status     uint32
	Generation uint64
	Job        uint64
	Expression uint32
	Body       uint32
	Limit      uint32
	Validate   uint32
}

func writeFrame(w io.Writer, f frame) error { return binary.Write(w, binary.BigEndian, f) }
func readFrame(r io.Reader) (frame, error) {
	var f frame
	err := binary.Read(r, binary.BigEndian, &f)
	if err == nil && f.Magic != frameMagic {
		err = errors.New("invalid jq worker frame")
	}
	return f, err
}
