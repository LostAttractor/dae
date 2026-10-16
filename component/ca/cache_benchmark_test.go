// SPDX-License-Identifier: AGPL-3.0-only

package ca

import (
	"fmt"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func BenchmarkCertificateMixed(b *testing.B) {
	dir := b.TempDir()
	cert, key := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
	if err := Generate(cert, key, "benchmark", time.Hour); err != nil {
		b.Fatal(err)
	}
	authority, err := Load(cert, key)
	if err != nil {
		b.Fatal(err)
	}
	if _, err := authority.ServerCertificate("cached.test"); err != nil {
		b.Fatal(err)
	}
	var count atomic.Uint64
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			n := count.Add(1)
			host := "cached.test"
			if n%10 == 0 {
				host = fmt.Sprintf("host%d.test", n)
			}
			if _, err := authority.ServerCertificate(host); err != nil {
				b.Error(err)
			}
		}
	})
}
