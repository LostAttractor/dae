// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	D "github.com/daeuniverse/dae/pkg/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
)

func TestNodeValidatorKeepsConstructionChecks(t *testing.T) {
	for _, test := range []struct {
		name, link string
		global     config.Global
		wantError  bool
	}{
		{name: "socks", link: "socks5://127.0.0.1:9"},
		{name: "trojan", link: "trojan://password@127.0.0.1:9"},
		{name: "hysteria2", link: "hysteria2://password@127.0.0.1:9"},
		{name: "cipher", link: "ss://unsupported:password@127.0.0.1:9", wantError: true},
		{name: "transport", link: "trojan://password@127.0.0.1:9?type=unsupported", wantError: true},
		{name: "bandwidth", link: "hysteria2://password@127.0.0.1:9", global: config.Global{BandwidthMaxTx: "invalid", BandwidthMaxRx: "invalid"}, wantError: true},
		{name: "resolver", link: "socks5://127.0.0.1:9", global: config.Global{DNSResolver: "invalid://resolver"}, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := NewNodeValidator(t.Context(), &test.global)(test.link)
			if (err != nil) != test.wantError {
				t.Fatalf("validation error = %v, want error = %t", err, test.wantError)
			}
		})
	}
}

type validationCloser func() error

func (close validationCloser) Close() error { return close() }

type validationBuilder struct{ owned io.Closer }

func (b validationBuilder) Build(_ *D.ExtraOption, upstream D.Upstream) (netproxy.Layer, error) {
	return netproxy.Layer{Data: upstream, Resources: []io.Closer{b.owned}}, nil
}

func TestNodeValidatorRetiresWithoutWaitingForClose(t *testing.T) {
	started, allowClose, closed := make(chan struct{}), make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(allowClose) })
	t.Cleanup(release)
	var closes atomic.Int32
	resource := validationCloser(func() error {
		if closes.Add(1) != 1 {
			return errors.New("resource closed twice")
		}
		close(started)
		<-allowClose
		close(closed)
		return nil
	})
	D.FromLinkRegister("validation-lifetime", func(link string) (D.Builder, *D.Property, error) {
		return validationBuilder{resource}, &D.Property{Name: "validation", Link: link}, nil
	})
	done := make(chan error, 1)
	go func() { done <- validateNodeDialer(new(dialer.GlobalOption), "validation-lifetime://node") }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("validation waited for transport cleanup")
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("validation leaked its transport")
	}
	release()
	<-closed
	if closes.Load() != 1 {
		t.Fatal("validation closed its transport more than once")
	}
}
