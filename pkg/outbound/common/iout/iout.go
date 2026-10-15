/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2024, daeuniverse Organization <dae@v2raya.org>
 */

package iout

import (
	"io"

	"github.com/daeuniverse/dae/pkg/outbound/pool"
)

func MultiWrite(dst io.Writer, bs ...[]byte) (int64, error) {
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	for _, b := range bs {
		buf.Write(b)
	}
	n, err := dst.Write(buf.Bytes())
	if n < buf.Len() && err == nil {
		err = io.ErrShortWrite
	}
	return int64(n), err
}
