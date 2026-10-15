package shadowsocks

import (
	"testing"

	"github.com/daeuniverse/dae/pkg/outbound/dialer"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/direct"
	_ "github.com/daeuniverse/dae/pkg/outbound/protocol/shadowsocks"
	"github.com/daeuniverse/dae/pkg/outbound/transport/smux"
)

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
