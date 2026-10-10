// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/pkg/membuffer"
)

// Includes the Go bridge and a fresh context on every invocation. Node workers
// are warmed before timing; no third-party plugin code is used as a fixture.
func BenchmarkRuntimeBackend(b *testing.B) {
	var large strings.Builder
	for i := range 2048 {
		fmt.Fprintf(&large, "function item%d(v) { return (v + %d) | 0; }\n", i, i)
	}
	large.WriteString("$done({body:String(item2047(1))});")
	b.Run(compiledJSRuntime, func(b *testing.B) {
		for _, workload := range []struct {
			name, source string
			body         []byte
		}{
			{name: "empty", source: `$done()`},
			{name: "functions-2048", source: large.String()},
			{name: "compute", source: `let n = 0; for (let i = 0; i < 1000000; i++) n = (n + Math.imul(i, 31)) | 0; $done({body:String(n)})`},
			{name: "binary-256KiB", source: `$done({body:$response.body})`, body: bytes.Repeat([]byte("x"), 256<<10)},
			{name: "text-encodeInto", source: `const text = "Aé中🌏".repeat(4096); const dest = new Uint8Array(40960); const result = new TextEncoder().encodeInto(text, dest); if (result.written !== dest.length || result.read !== text.length) throw Error("incomplete encoding"); $done()`},
		} {
			b.Run(workload.name, func(b *testing.B) {
				r, err := NewRuntime(b.Context(), RuntimeOptions{NodeWorkers: 1})
				if err != nil {
					b.Fatal(err)
				}
				defer r.Close()
				in := Invocation{BodyMemory: membuffer.NewBudget(256 << 20), BodyLimit: 32 << 20, BinaryBodyMode: true, Response: &Message{Body: workload.body}}
				warm, err := r.Run(b.Context(), workload.source, in)
				if err != nil {
					b.Fatal(err)
				}
				warm.Close()
				b.ReportAllocs()
				for b.Loop() {
					result, err := r.Run(b.Context(), workload.source, in)
					if err != nil {
						b.Fatal(err)
					}
					result.Close()
				}
			})
		}
	})
}

func BenchmarkRuntimeResponseBody(b *testing.B) {
	for _, binaryMode := range []bool{false, true} {
		for _, size := range []int{16 << 10, 256 << 10} {
			b.Run(fmt.Sprintf("binary=%t/%d", binaryMode, size), func(b *testing.B) {
				r, err := NewRuntime(b.Context(), RuntimeOptions{})
				if err != nil {
					b.Fatal(err)
				}
				defer r.Close()
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
	r, err := NewRuntime(b.Context(), RuntimeOptions{})
	if err != nil {
		b.Fatal(err)
	}
	defer r.Close()
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
