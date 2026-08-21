/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package outbound

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	D "github.com/daeuniverse/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
)

type testNodeDescriptor func(netproxy.Dialer) (netproxy.Dialer, error)

func (f testNodeDescriptor) Dialer(_ *D.ExtraOption, parent netproxy.Dialer) (netproxy.Dialer, error) {
	return f(parent)
}

type closeableTestDialer struct{ closed atomic.Bool }

func (*closeableTestDialer) Alive() bool    { return true }
func (*closeableTestDialer) Connect() error { return nil }
func (*closeableTestDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, errors.New("not implemented")
}
func (*closeableTestDialer) ListenPacket(context.Context, string) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}
func (d *closeableTestDialer) Close() error {
	d.closed.Store(true)
	return nil
}

func TestNewDialerSetFromLinksParsesSIP002UserinfoForms(t *testing.T) {
	legacyUserinfo := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:legacy-password"))
	shadowsocks2022 := url.URL{
		Scheme: "ss",
		User:   url.UserPassword("2022-blake3-aes-256-gcm", "RCF/0OOYmo6crue3LwlEyD8izLAbuUuyPic/vasJH/o="),
		Host:   "127.0.0.1:443",
	}
	secondShadowsocks2022 := url.URL{
		Scheme: "ss",
		User:   url.UserPassword("2022-blake3-aes-128-gcm", "c2Vjb25kLXBhc3N3b3Jk"),
		Host:   "127.0.0.2:8443",
	}
	tests := []struct {
		name        string
		link        string
		credentials string
		address     string
		displayName string
		dialers     int
	}{
		{name: "legacy Base64URL", link: "ss://" + legacyUserinfo + "@127.0.0.1:443", credentials: "aes-256-gcm:legacy-password", address: "127.0.0.1:443", dialers: 1},
		{name: "AEAD 2022 percent-escaped", link: shadowsocks2022.String(), credentials: "2022-blake3-aes-256-gcm:RCF/0OOYmo6crue3LwlEyD8izLAbuUuyPic/vasJH/o=", address: "127.0.0.1:443", dialers: 1},
		{name: "named AEAD 2022", link: "display-name:" + shadowsocks2022.String(), credentials: "2022-blake3-aes-256-gcm:RCF/0OOYmo6crue3LwlEyD8izLAbuUuyPic/vasJH/o=", address: "127.0.0.1:443", displayName: "display-name", dialers: 1},
		{name: "chained AEAD 2022", link: shadowsocks2022.String() + " -> " + secondShadowsocks2022.String(), credentials: "2022-blake3-aes-128-gcm:c2Vjb25kLXBhc3N3b3Jk", address: "127.0.0.2:8443", dialers: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			set := NewDialerSetFromLinks(&dialer.GlobalOption{}, nil, map[string][]string{"test": {tt.link}})
			if len(set.nodeInfos) != 1 {
				t.Fatalf("parsed %d nodes, want 1", len(set.nodeInfos))
			}
			nodeInfo := set.nodeInfos[0]
			if got := len(nodeInfo.Dialers); got != tt.dialers {
				t.Fatalf("dialers = %d, want %d", got, tt.dialers)
			}
			if got, want := nodeInfo.Property.Address, tt.address; got != want {
				t.Fatalf("address = %q, want %q", got, want)
			}
			if got := nodeInfo.Property.Name; got != tt.displayName {
				t.Fatalf("display name = %q, want %q", got, tt.displayName)
			}
			if nodeInfo.Link != tt.link {
				t.Fatalf("original link = %q, want %q", nodeInfo.Link, tt.link)
			}
			parsed, err := url.Parse(nodeInfo.Property.Link)
			if err != nil {
				t.Fatal(err)
			}
			credentials, err := base64.RawURLEncoding.DecodeString(parsed.User.Username())
			if err != nil {
				t.Fatal(err)
			}
			if got := string(credentials); got != tt.credentials {
				t.Fatalf("credentials = %q, want %q", got, tt.credentials)
			}
		})
	}
}

func TestValidateNodeLinkRejectsHTMLErrorPage(t *testing.T) {
	if err := ValidateNodeLink(`<a href="https://example.com/help">service unavailable</a>`); err == nil {
		t.Fatal("HTML error page was accepted as a node")
	}
}

func TestValidateNodeLinkAcceptsSIP002PluginWithoutOptions(t *testing.T) {
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:password"))
	link := "ss://" + userinfo + "@127.0.0.1:443/?plugin=v2ray-plugin"
	if err := ValidateNodeLink(link); err != nil {
		t.Fatalf("valid plugin-only link was rejected: %v", err)
	}
}

func TestNodeValidatorRejectsUnsupportedCipher(t *testing.T) {
	userinfo := base64.RawURLEncoding.EncodeToString([]byte("unsupported-cipher:password"))
	link := "ss://" + userinfo + "@127.0.0.1:8388"
	if err := ValidateNodeLink(link); err != nil {
		t.Fatalf("syntax validation unexpectedly failed: %v", err)
	}
	if err := NewNodeValidator(context.Background(), &config.Global{})(link); err == nil {
		t.Fatal("full validation accepted unsupported cipher")
	}
}

func TestNodeValidatorHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	validator := NewNodeValidator(ctx, &config.Global{})
	if err := validator("ss://unused"); !errors.Is(err, context.Canceled) {
		t.Fatalf("validator error = %v, want context cancellation", err)
	}
}

func TestNodeDialerClosesPartiallyConstructedTransport(t *testing.T) {
	transport := new(closeableTestDialer)
	buildErr := errors.New("construction failed")
	node := &NodeInfo{
		Property: &dialer.Property{},
		Dialers: []D.Dialer{
			testNodeDescriptor(func(netproxy.Dialer) (netproxy.Dialer, error) { return transport, nil }),
			testNodeDescriptor(func(netproxy.Dialer) (netproxy.Dialer, error) { return nil, buildErr }),
		},
	}
	if _, err := node.createDialerIfNeeded(&dialer.GlobalOption{}, nil); !errors.Is(err, buildErr) {
		t.Fatalf("createDialerIfNeeded error = %v, want %v", err, buildErr)
	}
	if !transport.closed.Load() {
		t.Fatal("partially constructed transport was not closed")
	}
}

func TestNodeValidatorBoundsPermanentlyBlockedConstruction(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, maxConcurrentNodeValidations)
	validate := func(*dialer.GlobalOption, string) error {
		started <- struct{}{}
		<-release
		return nil
	}
	validator := newNodeValidator(context.Background(), &dialer.GlobalOption{}, validate)
	var blocked sync.WaitGroup
	blocked.Add(maxConcurrentNodeValidations)
	for range maxConcurrentNodeValidations {
		go func() {
			defer blocked.Done()
			_ = validator("blocked")
		}()
	}
	for range maxConcurrentNodeValidations {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("validation worker did not start")
		}
	}

	var unexpected atomic.Int32
	for range 100 {
		ctx, cancel := context.WithCancel(context.Background())
		queued := newNodeValidator(ctx, &dialer.GlobalOption{}, func(*dialer.GlobalOption, string) error {
			unexpected.Add(1)
			return nil
		})
		done := make(chan error, 1)
		go func() { done <- queued("queued") }()
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("queued validation error = %v, want cancellation", err)
			}
		case <-time.After(time.Second):
			t.Fatal("queued validation ignored cancellation")
		}
	}
	if got := unexpected.Load(); got != 0 {
		t.Fatalf("started %d validations after all worker slots were blocked", got)
	}

	close(release)
	blocked.Wait()
	if got := len(nodeValidationSlots); got != 0 {
		t.Fatalf("validation slots still occupied after release: %d", got)
	}
}
