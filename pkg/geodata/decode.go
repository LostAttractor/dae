/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

// Modified from https://github.com/v2fly/v2ray-core/blob/42b166760b2ba8d984e514b830fcd44e23728e43/infra/conf/geodata/memconservative

package geodata

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/daeuniverse/dae/common/assets"
	"github.com/daeuniverse/dae/common/resource"
	"google.golang.org/protobuf/encoding/protowire"
)

var (
	errFailedToReadBytes            = errors.New("failed to read bytes")
	errFailedToReadExpectedLenBytes = errors.New("failed to read expected length of bytes")
	errInvalidGeodataFile           = errors.New("invalid geodata file")
	errInvalidGeodataVarintLength   = errors.New("invalid geodata varint length")
	errCodeNotFound                 = errors.New("code not found")
	errGeodataIndexLimit            = errors.New("geodata index exceeds its size limit")
)

// Read only the selected entry, while bounding every length by its enclosing
// message and the actual file. Unsupported protobuf layouts use the full decoder.
func emitBytes(f io.ReadSeeker, code string) ([]byte, error) {
	position, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, errFailedToReadBytes
	}
	fileEnd, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, errFailedToReadBytes
	}
	if _, err := f.Seek(position, io.SeekStart); err != nil {
		return nil, errFailedToReadBytes
	}
	for position < fileEnd {
		var tag [1]byte
		if _, err := io.ReadFull(f, tag[:]); err != nil {
			return nil, errFailedToReadExpectedLenBytes
		}
		position++
		if tag[0] != 10 {
			return nil, errInvalidGeodataFile
		}
		entryLength, n, err := readGeodataLength(f)
		if err != nil {
			return nil, err
		}
		position += int64(n)
		if entryLength == 0 || position > fileEnd || entryLength > uint64(fileEnd-position) || entryLength > uint64(^uint(0)>>1) {
			return nil, errInvalidGeodataFile
		}
		entryStart, entryEnd := position, position+int64(entryLength)
		if _, err := io.ReadFull(f, tag[:]); err != nil {
			return nil, errFailedToReadExpectedLenBytes
		}
		position++
		if tag[0] != 10 {
			return nil, errInvalidGeodataFile
		}
		codeLength, n, err := readGeodataLength(io.LimitReader(f, entryEnd-position))
		if err != nil {
			return nil, err
		}
		position += int64(n)
		if codeLength > uint64(entryEnd-position) {
			return nil, errInvalidGeodataFile
		}
		country := make([]byte, int(codeLength))
		if _, err := io.ReadFull(f, country); err != nil {
			return nil, errFailedToReadExpectedLenBytes
		}
		if strings.EqualFold(string(country), code) {
			if _, err := f.Seek(entryStart, io.SeekStart); err != nil {
				return nil, errFailedToReadBytes
			}
			entry := make([]byte, int(entryLength))
			if _, err := io.ReadFull(f, entry); err != nil {
				return nil, errFailedToReadExpectedLenBytes
			}
			return entry, nil
		}
		position = entryEnd
		if _, err := f.Seek(position, io.SeekStart); err != nil {
			return nil, errFailedToReadBytes
		}
	}
	return nil, errCodeNotFound
}

func readGeodataLength(r io.Reader) (uint64, int, error) {
	var encoded [10]byte
	for i := range encoded {
		if _, err := io.ReadFull(r, encoded[i:i+1]); err != nil {
			return 0, 0, errFailedToReadExpectedLenBytes
		}
		if encoded[i] < 128 {
			length, n := protowire.ConsumeVarint(encoded[:i+1])
			if n < 0 {
				return 0, 0, errInvalidGeodataVarintLength
			}
			return length, n, nil
		}
	}
	return 0, 0, errInvalidGeodataVarintLength
}

func Decode(filename, code string) ([]byte, error) {
	return DecodeContext(context.Background(), filename, code)
}

// Serialize index construction so parallel files cannot each spend the budget.
// Only this bookkeeping is mutable; published file bytes and indexes are not.
type frozenGeodataBudget chan int

// frozenGeodata owns a private, immutable copy shared only within this operation.
// Public decoders return independent entries, never slices of its backing bytes.
func frozenGeodata(ctx context.Context, filename string) (*indexedGeodata, error) {
	return resource.DeriveInput(ctx, "geodata/index:"+filename, func(ctx context.Context) (*indexedGeodata, error) {
		data, err := assets.ReadFileContext(ctx, filename)
		if err != nil {
			return nil, err
		}
		budget, err := resource.DeriveInput(ctx, "geodata/index-budget", func(context.Context) (frozenGeodataBudget, error) {
			budget := make(frozenGeodataBudget, 1)
			budget <- geodataCacheBytes
			return budget, nil
		})
		if err != nil {
			return nil, err
		}
		var remaining int
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case remaining = <-budget:
		}
		defer func() { budget <- remaining }()
		indexed := &indexedGeodata{data: data, err: errGeodataIndexLimit}
		if remaining > 0 {
			indexed.entries, indexed.err = indexGeodataBounded(data, remaining)
			for key := range indexed.entries {
				remaining -= len(key) + 128
			}
		}
		return indexed, nil
	})
}

// DecodeContext indexes the frozen file when an operation carries input snapshots.
func DecodeContext(ctx context.Context, filename, code string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if resource.HasInputs(ctx) {
		indexed, err := frozenGeodata(ctx, filename)
		if err != nil {
			return nil, err
		}
		return indexed.decode(code)
	}
	f, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v: %w", filename, err)
	}
	defer f.Close()

	return decodedFiles.decode(f, code)
}
