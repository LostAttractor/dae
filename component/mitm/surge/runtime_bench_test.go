// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/daeuniverse/dae/pkg/membuffer"
)

func BenchmarkRuntimeResponseBody(b *testing.B) {
	for _, binaryMode := range []bool{false, true} {
		for _, size := range []int{16 << 10, 256 << 10} {
			b.Run(fmt.Sprintf("binary=%t/%d", binaryMode, size), func(b *testing.B) {
				r, err := NewRuntime(RuntimeOptions{})
				if err != nil {
					b.Fatal(err)
				}
				in := Invocation{BodyMemory: membuffer.NewBudget(256 << 20), BodyLimit: 32 << 20, BinaryBodyMode: binaryMode, Response: &Message{Body: bytes.Repeat([]byte("x"), size)}}
				b.ReportAllocs()
				for b.Loop() {
					result, err := r.Run(b.Context(), `$done({body: $response.body});`, in)
					if err != nil || result.Body == nil || len(result.Body.Bytes()) != size {
						b.Fatalf("response body: result=%v, error=%v", result, err)
					}
					result.Close()
				}
			})
		}
	}
}

func BenchmarkRuntimeResponseBodyParallel(b *testing.B) {
	r, err := NewRuntime(RuntimeOptions{})
	if err != nil {
		b.Fatal(err)
	}
	in := Invocation{BodyMemory: membuffer.NewBudget(256 << 20), BodyLimit: 32 << 20, BinaryBodyMode: true, Response: &Message{Body: bytes.Repeat([]byte("x"), 256<<10)}}
	b.ReportAllocs()
	b.SetParallelism(4)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			result, err := r.Run(b.Context(), `$done({body: $response.body});`, in)
			if err != nil || result.Body == nil || len(result.Body.Bytes()) != len(in.Response.Body) {
				b.Errorf("response body: result=%v, error=%v", result, err)
				return
			}
			result.Close()
		}
	})
}
