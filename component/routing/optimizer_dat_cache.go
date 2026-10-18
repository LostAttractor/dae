// SPDX-License-Identifier: AGPL-3.0-only

package routing

import (
	"crypto/sha256"
	"fmt"

	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/daeuniverse/dae/pkg/geodata"
	"google.golang.org/protobuf/proto"
)

const datParamsCacheBytes = 16 << 20
const datParamsCacheEntries = 128

type datParamsKey struct {
	digest          [32]byte
	kind, attribute string
}

type datParam struct{ key, value string }

// Hash bytes returned by the file cache after its synchronous invalidation
// check. Decode and expand this exact snapshot on a miss, even if the pathname
// is replaced concurrently. Unsupported layouts retain the original decoder.
func (o *DatReaderOptimizer) cachedDatParams(path, code, kind, attribute string, build func([]byte) ([]*config_parser.Param, error)) ([]*config_parser.Param, error) {
	if err := o.contextErr(); err != nil {
		return nil, err
	}
	data, err := geodata.Decode(path, code)
	if err != nil {
		return build(nil)
	}
	key := datParamsKey{sha256.Sum256(data), kind, attribute}
	if params, ok := o.datParams[key]; ok {
		if err := o.contextErr(); err != nil {
			return nil, err
		}
		return cloneDatParams(params), nil
	}
	params, err := build(data)
	if err != nil {
		return nil, err
	}
	// Retain only this preparation's expansions. Once the bounded memo is full,
	// later misses simply expand normally; no eviction or global state is needed.
	if len(o.datParams) >= datParamsCacheEntries {
		return params, nil
	}
	weight := 256 + len(kind) + len(attribute)
	for _, param := range params {
		weight += 32 + len(param.Key) + len(param.Val)
	}
	if weight <= datParamsCacheBytes-o.datParamsBytes {
		immutable := make([]datParam, len(params))
		for i, param := range params {
			immutable[i] = datParam{param.Key, param.Val}
		}
		if o.datParams == nil {
			o.datParams = make(map[datParamsKey][]datParam)
		}
		o.datParams[key] = immutable
		o.datParamsBytes += weight
	}
	return params, nil
}

func decodeDatEntry(data []byte, target proto.Message, path, code, kind string) error {
	if err := proto.Unmarshal(data, target); err != nil {
		return fmt.Errorf("decode %s entry %q from %q: invalid protobuf data (check file format and download integrity): %w", kind, code, path, err)
	}
	return nil
}

func cloneDatParams(params []datParam) []*config_parser.Param {
	if len(params) == 0 {
		return nil
	}
	values := make([]config_parser.Param, len(params))
	result := make([]*config_parser.Param, len(params))
	for i, param := range params {
		values[i].Key, values[i].Val = param.key, param.value
		result[i] = &values[i]
	}
	return result
}
