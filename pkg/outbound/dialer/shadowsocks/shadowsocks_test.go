package shadowsocks

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/daeuniverse/dae/pkg/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/direct"
	_ "github.com/daeuniverse/dae/pkg/outbound/protocol/shadowsocks"
	"github.com/daeuniverse/dae/pkg/outbound/transport/singmux"
	"github.com/gorilla/websocket"
)

func TestV2rayPluginWebSocketPathAndHandshake(t *testing.T) {
	for _, path := range []string{"", "/custom"} {
		t.Run(path, func(t *testing.T) {
			want := path
			if want == "" {
				want = "/"
			}
			requested := make(chan string, 1)
			done := make(chan error, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requested <- r.URL.Path
				if r.URL.Path != want {
					http.NotFound(w, r)
					return
				}
				upgrader := websocket.Upgrader{}
				conn, err := upgrader.Upgrade(w, r, nil)
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				for range 2 { // New mux session, then the Shadowsocks request with the first payload.
					kind, data, err := conn.ReadMessage()
					if err != nil {
						done <- err
						return
					}
					if kind != websocket.BinaryMessage || len(data) == 0 {
						done <- fmt.Errorf("invalid handshake message: type=%d length=%d", kind, len(data))
						return
					}
				}
				done <- nil
			}))
			defer server.Close()
			plugin := "v2ray-plugin"
			if path != "" {
				plugin += ";path=" + path
			}
			builder, err := ParseSSURL("ss://YWVzLTEyOC1nY206cGFzcw@" + strings.TrimPrefix(server.URL, "http://") + "?plugin=" + url.QueryEscape(plugin))
			if err != nil {
				t.Fatal(err)
			}
			layer, err := builder.Build(new(dialer.ExtraOption), dialer.NewUpstream(direct.NewDirectDialer(direct.Option{})))
			if err != nil {
				t.Fatal(err)
			}
			defer layer.Close()
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			conn, err := layer.Data.DialContext(ctx, "tcp", "example.com:443")
			if conn != nil {
				defer conn.Close()
			}
			select {
			case got := <-requested:
				if got != want {
					t.Fatalf("WebSocket path = %q, want %q", got, want)
				}
			default:
				t.Fatalf("no WebSocket request: %v", err)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Write([]byte("request")); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

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
	if _, ok := built.Data.(*singmux.Mux); ok {
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

// SIP002 links often leave the plugin's ';' separators unescaped, and some
// providers name simple-obfs just "obfs".
func TestParseSSURLUnescapedPluginOptions(t *testing.T) {
	for _, link := range []string{
		"ss://YWVzLTEyOC1nY206cGFzcw@proxy.example:443/?plugin=obfs;obfs=http;obfs-host=cdn.example#node",
		"ss://YWVzLTEyOC1nY206cGFzcw@proxy.example:443/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dcdn.example#node",
	} {
		server, err := ParseSSURL(link)
		if err != nil {
			t.Fatal(err)
		}
		want := Sip003{Name: "simple-obfs", Opts: Sip003Opts{Obfs: "http", Host: "cdn.example"}}
		if server.Plugin != want || server.Name != "node" || server.UDP {
			t.Fatalf("%s: parsed %+v", link, server)
		}
	}
}

func TestParseSSURLBase64Forms(t *testing.T) {
	encoded := base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:pw@proxy.example:443"))
	for _, scheme := range []string{"ss://", "shadowsocks://"} {
		parsed, err := ParseSSURL(scheme + encoded + "#node")
		if err != nil || parsed.Cipher != "aes-128-gcm" || parsed.Password != "pw" || parsed.Port != 443 || parsed.Name != "node" {
			t.Fatalf("%s: %+v, %v", scheme, parsed, err)
		}
	}
	for _, link := range []string{"ss:", "ss:x"} {
		if _, err := ParseSSURL(link); err == nil {
			t.Fatalf("%q was accepted", link)
		}
	}
}
