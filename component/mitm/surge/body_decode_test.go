// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/pkg/membuffer"
)

func TestDecodeBodyViewCanceledReleasesInput(t *testing.T) {
	for _, encoding := range []string{"", "gzip", "deflate", "br", "gzip,br"} {
		t.Run(encoding, func(t *testing.T) {
			var layers []string
			if encoding != "" {
				layers = strings.Split(encoding, ",")
			}
			body := encodeRuntimeHTTPBody(t, []byte("decoded body"), layers...)
			budget := membuffer.NewBudget(1 << 20)
			view, err := membuffer.Copy(body, budget)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			decoded, err := decodeBodyView(ctx, view, encoding, 1024, budget)
			decoded.Close()
			if !errors.Is(err, context.Canceled) || decoded != nil {
				t.Fatalf("canceled decode returned %v, %v", decoded, err)
			}
			if budget.Status().Used != 0 {
				t.Fatal(budget.Status())
			}
		})
	}
}
