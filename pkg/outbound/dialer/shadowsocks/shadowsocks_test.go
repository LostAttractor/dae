package shadowsocks

import (
	"net/url"
	"testing"

	"github.com/daeuniverse/dae/pkg/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/direct"
	_ "github.com/daeuniverse/dae/pkg/outbound/protocol/shadowsocks"
	"github.com/daeuniverse/dae/pkg/outbound/transport/smux"
)

func TestParseSSURLPlainCredentialsAndBarePlugin(t *testing.T) {
	const password = "key/with+escaped:characters="
	u := &url.URL{Scheme: "ss", Host: "proxy.example:443", User: url.UserPassword("2022-blake3-aes-256-gcm", password), RawQuery: "plugin=v2ray-plugin"}
	parsed, err := ParseSSURL(u.String())
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Cipher != "2022-blake3-aes-256-gcm" || parsed.Password != password || parsed.Plugin.Name != "v2ray-plugin" {
		t.Fatal("plain credentials or plugin were not preserved")
	}
	roundTrip, err := ParseSSURL(parsed.ExportToURL())
	if err != nil || *roundTrip != *parsed {
		t.Fatalf("SS URL round trip changed parsed fields: %v", err)
	}
}

func TestNonSIP002MultiplexQueryIsIgnored(t *testing.T) {
	server, err := ParseSSURL("ss://YWVzLTEyOC1nY206cGFzcw@proxy.example.com:443?multiplex=1#node")
	if err != nil {
		t.Fatal(err)
	}
	built, err := server.Build(new(dialer.ExtraOption), dialer.NewUpstream(direct.NewDirectDialer(direct.Option{})))
	if err != nil {
		t.Fatal(err)
	}
	defer built.Close()
	if _, ok := built.Data.(*smux.Smux); ok {
		t.Fatal("non-SIP002 multiplex query enabled smux")
	}
}
