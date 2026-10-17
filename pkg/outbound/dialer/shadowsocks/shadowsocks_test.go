package shadowsocks

import (
	"net/url"
	"strings"
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

func TestShadowsocksPluginMustBeSupported(t *testing.T) {
	for _, plugin := range []string{"", "shadow-tls;host=example.test", "unknown", "simple-obfs;obfs=http", "obfs-local;obfs=tls", "v2ray-plugin;tls"} {
		t.Run(plugin, func(t *testing.T) {
			server, err := ParseSSURL("ss://YWVzLTEyOC1nY206cGFzcw@proxy.example:443?plugin=" + url.QueryEscape(plugin))
			if err != nil {
				t.Fatal(err)
			}
			layer, err := server.Build(new(dialer.ExtraOption), dialer.NewUpstream(direct.NewDirectDialer(direct.Option{})))
			defer layer.Close()
			unsupported := strings.HasPrefix(plugin, "shadow-tls") || plugin == "unknown"
			if unsupported {
				if err == nil || !strings.Contains(err.Error(), "unsupported shadowsocks plugin") || layer.Data != nil {
					t.Fatalf("unsupported plugin produced a layer: %+v, %v", layer, err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}
