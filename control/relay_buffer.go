// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"io"

	"github.com/daeuniverse/outbound/pool"
)

const (
	relayBufferSmall = 8 << 10
	relayBufferLarge = 32 << 10
)

// copyRelay keeps quiet directions small and grows for sustained full reads.
// Sustained small reads return the large buffer before the next blocking read.
// It does not change deadlines or wait to fill a buffer before forwarding data.
func copyRelay(dst io.Writer, src io.Reader) error {
	buf := pool.GetBuffer(relayBufferSmall)
	defer func() { pool.PutBuffer(buf) }()
	fullReads, smallReads := 0, 0
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			written, err := dst.Write(buf[:n])
			if written < 0 || written > n {
				written = 0
				if err == nil {
					err = errors.New("invalid write result")
				}
			}
			if err != nil {
				return err
			}
			if written != n {
				return io.ErrShortWrite
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return nil
			}
			return readErr
		}
		if n == 0 {
			continue
		}
		size := len(buf)
		if size == relayBufferSmall {
			if n == size {
				fullReads++
			} else {
				fullReads = 0
			}
			if fullReads == 2 {
				size = relayBufferLarge
			}
		} else {
			if n < relayBufferSmall {
				smallReads++
			} else {
				smallReads = 0
			}
			if smallReads == 4 {
				size = relayBufferSmall
			}
		}
		if size != len(buf) {
			pool.PutBuffer(buf)
			buf = pool.GetBuffer(size)
			fullReads, smallReads = 0, 0
		}
	}
}
