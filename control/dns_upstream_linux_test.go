// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"context"
	"crypto/aes"
	"errors"
	"net"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/pkg/outbound/ciphers"
	"github.com/daeuniverse/dae/pkg/outbound/netproxy"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/direct"
	"github.com/daeuniverse/dae/pkg/outbound/protocol/shadowsocks"
	ss2022 "github.com/daeuniverse/dae/pkg/outbound/protocol/shadowsocks_2022"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func TestDNSUpstreamSocketDropsAreNotUploaded(t *testing.T) {
	for _, transport := range []string{"ss", "ss2022"} {
		t.Run(transport, func(t *testing.T) {
			if os.Geteuid() != 0 {
				t.Skip("root required for an isolated unresolved neighbor")
			}
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			original, err := netns.Get()
			must(err)
			defer original.Close()
			isolated, err := netns.New()
			must(err)
			defer isolated.Close()
			defer func() { must(netns.Set(original)) }()
			link := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "sender"}, PeerName: "peer"}
			must(netlink.LinkAdd(link))
			peer, err := netlink.LinkByName("peer")
			must(err)
			must(netlink.LinkSetUp(link))
			must(netlink.LinkSetUp(peer))
			address, err := netlink.ParseAddr("192.0.2.1/24")
			must(err)
			must(netlink.AddrAdd(link, address))
			raw, err := direct.NewDirectDialer(direct.Option{}).DialContext(t.Context(), "udp", "192.0.2.2:8388")
			must(err)
			defer raw.Close()
			must(raw.(*net.UDPConn).SetWriteBuffer(4096))
			key := make([]byte, 16)
			var packet net.PacketConn
			if transport == "ss" {
				conf := ciphers.AeadCiphersConf["aes-128-gcm"]
				packet = shadowsocks.NewUdpConn(raw, conf, key, shadowsocks.RandomSaltGenerator(conf.SaltLen))
			} else {
				block, err := aes.NewCipher(key)
				must(err)
				packet = ss2022.NewUdpConn(raw, ciphers.Aead2022CiphersConf["2022-blake3-aes-128-gcm"], block, block, [][]byte{key}, key)
			}
			target := "198.51.100.53:53"
			bound := &netproxy.BindPacketConn{PacketConn: packet, Address: netproxy.NewAddr("udp", target)}
			group := downloadTestGroup(t, t.Name(), func(_ context.Context, network, address string) (net.Conn, error) {
				if network != "udp" || address != target {
					t.Fatalf("DNS dial = %s %s", network, address)
				}
				return netproxy.TrackConn(bound, func() {}), nil
			})
			option := &DialOption{Dialer: group.Dialers[0], Outbound: group, DialTarget: target, NetworkType: *common.NetworkUDP4.NetworkType()}
			plane := &ControlPlane{core: &controlPlaneCore{}}
			upstream, err := plane.dialDNSUpstream(t.Context(), "udp", option, routingResult{})
			must(err)
			defer upstream.Close()
			path, _ := option.trafficAttribution()
			beforeUpload := stats.DefaultStore.Snapshot()[path].UploadBytes
			payload := make([]byte, 1200)
			write := func() {
				t.Helper()
				if n, err := upstream.Write(payload); n != len(payload) || err != nil {
					t.Fatalf("DNS write = %d, %v", n, err)
				}
			}
			write()
			if uploaded := stats.DefaultStore.Snapshot()[path].UploadBytes - beforeUpload; uploaded != uint64(len(payload)) {
				t.Fatalf("accepted datagram uploaded %d bytes", uploaded)
			}
			for i := 0; ; i++ {
				_, err := netproxy.TryWrite(raw, payload)
				if errors.Is(err, netproxy.ErrPacketDropped) {
					break
				}
				must(err)
				if i == 64 {
					t.Fatal("fixture did not fill the send buffer")
				}
			}
			beforeDrop, start := countedDrops("socket_full"), time.Now()
			write()
			if elapsed := time.Since(start); elapsed > time.Second || countedDrops("socket_full")-beforeDrop != 1 {
				t.Fatalf("DNS write took %v, counted %d drops; want one drop without waiting", elapsed, countedDrops("socket_full")-beforeDrop)
			}
			if uploaded := stats.DefaultStore.Snapshot()[path].UploadBytes - beforeUpload; uploaded != uint64(len(payload)) {
				t.Fatalf("accepted plus dropped datagram uploaded %d bytes, want %d", uploaded, len(payload))
			}
		})
	}
}
