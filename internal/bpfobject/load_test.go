// SPDX-License-Identifier: AGPL-3.0-only

package bpfobject

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
)

func TestLoadGeneratedObjects(t *testing.T) {
	var tested int
	for _, pattern := range []string{
		"../../control/bpf_bpf*.o",
		"../../control/internal/splice/bpf_splice_bpf*.o",
		"../../trace/bpf_*_bpf*.o",
	} {
		paths, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range paths {
			tested++
			t.Run(path, func(t *testing.T) {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				original, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(data))
				if err != nil {
					t.Fatal(err)
				}
				compressed, err := os.ReadFile(path + ".gz")
				if err != nil {
					t.Fatal(err)
				}
				r, err := gzip.NewReader(bytes.NewReader(compressed))
				if err != nil {
					t.Fatal(err)
				}
				defer r.Close()
				inflated, err := io.ReadAll(r)
				if err != nil || !bytes.Equal(data, inflated) {
					t.Fatalf("compression changed ELF bytes, including BTF and relocations: %v", err)
				}
				restored, err := Load(compressed)
				if err != nil {
					t.Fatal(err)
				}
				// btf.Spec contains lazy function closures that cannot be compared
				// with DeepEqual. Its serialized representation was checked above.
				if !reflect.DeepEqual(original.Programs, restored.Programs) || !reflect.DeepEqual(original.Maps, restored.Maps) || !reflect.DeepEqual(original.Variables, restored.Variables) || original.ByteOrder != restored.ByteOrder {
					t.Fatal("compression changed parsed programs, maps or variables")
				}
			})
		}
	}
	if tested == 0 {
		t.Skip("run make ebpf to generate objects")
	}
}

func TestRejectCorruptObject(t *testing.T) {
	if _, err := Load([]byte("not gzip")); err == nil {
		t.Fatal("accepted an invalid gzip header")
	}
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write([]byte("not ELF")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(buf.Bytes()); err == nil {
		t.Fatal("accepted an invalid ELF")
	}
	data := buf.Bytes()
	data[len(data)-8] ^= 1 // CRC32 in the gzip trailer.
	if _, err := Load(data); !errors.Is(err, gzip.ErrChecksum) {
		t.Fatalf("want gzip checksum failure, got %v", err)
	}
	if _, err := Load(data[:len(data)-4]); err == nil {
		t.Fatal("accepted a truncated object")
	}
}
