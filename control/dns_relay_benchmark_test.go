// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
)

// Includes receive/result storage and relay cancellation setup, without syscalls.
func BenchmarkDNSUDPBuffer(b *testing.B) {
	for _, size := range []int{128, 1232, 4096, consts.MaxDnsMessageSize} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			conn := &dnsBufferConn{payload: bytes.Repeat([]byte{0xa5}, size)}
			request := dnsBufferRequest(conn)
			b.ReportAllocs()
			for b.Loop() {
				response, err := relayDNSUDP(context.Background(), request)
				if err != nil || len(dnsTestWire(b, response)) != size {
					b.Fatal("incorrect response", err)
				}
			}
		})
	}
}
