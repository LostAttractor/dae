// SPDX-License-Identifier: AGPL-3.0-only

// Package bpfobject loads losslessly compressed bpf2go objects.
package bpfobject

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// Load decompresses an embedded ELF, including its BTF and relocations. The
// uncompressed bytes are local to this load instead of retained in a global.
func Load(compressed []byte) (*ebpf.CollectionSpec, error) {
	r, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, fmt.Errorf("open compressed BPF object: %w", err)
	}
	defer r.Close()
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("decompress BPF object: %w", err)
	}
	return ebpf.LoadCollectionSpecFromReader(bytes.NewReader(data))
}
