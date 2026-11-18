package socks5

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/infra/socks"
)

func TestNewSocks5CredentialValidation(t *testing.T) {
	for _, tt := range []struct {
		name, userinfo string
		wantErr        bool
	}{
		{name: "no credentials"},
		{name: "complete credentials", userinfo: "user:pass@"},
		{name: "username only", userinfo: "user@", wantErr: true},
		{name: "password only", userinfo: ":pass@", wantErr: true},
		{name: "longest credentials", userinfo: strings.Repeat("u", 255) + ":" + strings.Repeat("p", 255) + "@"},
		{name: "username too long", userinfo: strings.Repeat("u", 256) + ":pass@", wantErr: true},
		{name: "password too long", userinfo: "user:" + strings.Repeat("p", 256) + "@", wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewSocks5("socks5://"+tt.userinfo+"proxy:1080", nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NewSocks5 error = %v, want error: %v", err, tt.wantErr)
			}
		})
	}
}

func TestConnectClassifiesUnsupportedReply(t *testing.T) {
	tests := []struct {
		name  string
		cmd   byte
		reply byte
		want  bool
	}{
		{name: "udp command unsupported", cmd: socks.CmdUDPAssociate, reply: replyCommandNotSupported, want: true},
		{name: "tcp command unsupported", cmd: socks.CmdConnect, reply: replyCommandNotSupported, want: true},
		{name: "address type unsupported", cmd: socks.CmdConnect, reply: replyAddressTypeNotSupported, want: true},
		{name: "transient failure", cmd: socks.CmdConnect, reply: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()

			serverErr := make(chan error, 1)
			go func() {
				greeting := make([]byte, 3)
				if _, err := io.ReadFull(server, greeting); err != nil {
					serverErr <- err
					return
				}
				if _, err := server.Write([]byte{Version, socks.AuthNone}); err != nil {
					serverErr <- err
					return
				}
				request := make([]byte, 10)
				if _, err := io.ReadFull(server, request); err != nil {
					serverErr <- err
					return
				}
				_, err := server.Write([]byte{Version, tt.reply, 0})
				serverErr <- err
			}()

			dialer := &Socks5{addr: "127.0.0.1:1080"}
			_, err := dialer.connect(client, "1.1.1.1:53", tt.cmd)
			if err == nil {
				t.Fatal("connect unexpectedly succeeded")
			}
			if got := errors.Is(err, netproxy.UnsupportedTunnelTypeError); got != tt.want {
				t.Fatalf("errors.Is(UnsupportedTunnelTypeError) = %v, want %v: %v", got, tt.want, err)
			}
			if err := <-serverErr; err != nil {
				t.Fatalf("fake server: %v", err)
			}
		})
	}
}
