// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/daeuniverse/dae/api/client"
	"github.com/spf13/pflag"
)

func TestConnectionTimeoutFlags(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want time.Duration
	}{
		{name: "default", want: client.DefaultTimeout},
		{name: "explicit", args: []string{"--timeout=250ms"}, want: 250 * time.Millisecond},
		{name: "zero", args: []string{"--timeout=0s"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var connection Connection
			flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
			connection.Bind(flags)
			if err := flags.Parse(test.args); err != nil {
				t.Fatal(err)
			}
			if connection.timeout != test.want {
				t.Fatalf("timeout = %v, want %v", connection.timeout, test.want)
			}
			if got := flags.Lookup("timeout").DefValue; got != client.DefaultTimeout.String() {
				t.Fatalf("flag default = %q, want %q", got, client.DefaultTimeout.String())
			}
		})
	}
}

func TestConnectionExplicitTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	var connection Connection
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	connection.Bind(flags)
	if err := flags.Parse([]string{"--api=" + server.URL, "--timeout=20ms"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if _, err := connection.Status(ctx); !errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
		t.Fatalf("request error = %v, context error = %v; want the API timeout first", err, ctx.Err())
	}
}
