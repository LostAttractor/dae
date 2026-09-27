//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only

package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/pkg/config_parser"
	"github.com/miekg/dns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestEntryLoopbackDNSWithBoundInterface(t *testing.T) {
	// Discovery and net.Resolver use goroutines. Start the entire child process
	// in its own namespace so every worker sees the same isolated interfaces.
	if os.Getenv("DAE_ENTRY_DNS_NETNS") != "1" {
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(t.Context(), binary, "-test.run=^TestEntryLoopbackDNSWithBoundInterface$", "-test.v", "-test.timeout=30s")
		cmd.Env = append(os.Environ(), "DAE_ENTRY_DNS_NETNS=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET}
		output, err := cmd.CombinedOutput()
		if errors.Is(err, unix.EPERM) {
			t.Skip("network namespace requires privileges")
		}
		if err != nil {
			t.Fatalf("isolated DNS test: %v\n%s", err, output)
		}
		t.Logf("%s", output)
		return
	}
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatal(err)
	}
	for i, device := range []struct {
		name     string
		prefixes []string
	}{
		{"wan", []string{"192.0.2.1/24", "2001:db8:1::1/64"}},
		{"cu", []string{"192.168.1.7/24"}},
	} {
		link := &netlink.Dummy{Name: device.name}
		if err := netlink.LinkAdd(link); err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkSetUp(link); err != nil {
			t.Fatal(err)
		}
		for _, prefix := range device.prefixes {
			addr, err := netlink.ParseAddr(prefix)
			if err != nil {
				t.Fatal(err)
			}
			addr.Flags = unix.IFA_F_NODAD
			if err := netlink.AddrAdd(link, addr); err != nil {
				t.Fatal(err)
			}
			defaultPrefix := "::/0"
			if addr.IP.To4() != nil {
				defaultPrefix = "0.0.0.0/0"
			}
			_, dst, _ := net.ParseCIDR(defaultPrefix)
			if err := netlink.RouteAdd(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst, Priority: 10 + i}); err != nil {
				t.Fatal(err)
			}
		}
	}

	// A real loopback resolver forces UDP -> TCP retry and returns remote proxy
	// addresses, keeping DNS reachability separate from proxy egress support.
	tcp, err := net.Listen("tcp4", "127.0.0.53:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcp.Close() })
	udp, err := net.ListenPacket("udp4", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	var tcpQueries atomic.Int32
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg).SetReply(request)
		if w.LocalAddr().Network() == "udp" {
			response.Truncated = true
		} else {
			tcpQueries.Add(1)
			q := request.Question[0]
			hdr := dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: 1}
			switch q.Qtype {
			case dns.TypeA:
				response.Answer = []dns.RR{&dns.A{Hdr: hdr, A: net.ParseIP("198.51.100.2")}}
			case dns.TypeAAAA:
				response.Answer = []dns.RR{&dns.AAAA{Hdr: hdr, AAAA: net.ParseIP("2001:db8:2::2")}}
			}
		}
		_ = w.WriteMsg(response)
	})
	for _, server := range []*dns.Server{{Listener: tcp, Handler: handler}, {PacketConn: udp, Handler: handler}} {
		ready := make(chan struct{})
		server.NotifyStartedFunc = func() { close(ready) }
		go func() { _ = server.ActivateAndServe() }()
		<-ready
		t.Cleanup(func() { _ = server.Shutdown() })
	}
	t.Run("candidates", func(t *testing.T) {
		option := &dialer.GlobalOption{DNSResolver: tcp.Addr().String(), SoMarkFromDae: 0x100}
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		sections, err := config_parser.Parse(`global {}
group { proxy {
 filter: name(lightsail-hy2)
 filter: name(lightsail-hy2) && ipversion(4) [interface: cu, priority: 1]
 policy: min_moving_avg
} }
routing { fallback: proxy }`)
		if err != nil {
			t.Fatal(err)
		}
		conf, err := config.New(sections)
		if err != nil {
			t.Fatal(err)
		}
		set, err := NewDialerSet([]NodeDescriptor{{Name: "lightsail-hy2", Link: "hysteria2://pass@entry.test.:443"}})
		if err != nil {
			t.Fatal(err)
		}
		compiler, err := NewGroupCompiler(set, conf.Group, []string{"proxy"})
		if err != nil {
			t.Fatal(err)
		}
		paths, err := compiler.ExpandRoutable(&conf.Group[0])
		if err != nil {
			t.Fatal(err)
		}
		variants, err := ExpandIPVariants(ctx, paths, option)
		if err != nil || len(variants) != 3 {
			t.Fatalf("default v4/v6 plus cu v4: got %d candidates, error=%v", len(variants), err)
		}
		ids := make(map[string]bool)
		for i, want := range []string{"lightsail-hy2 [IPv4]", "lightsail-hy2 [IPv6]", "lightsail-hy2 [interface=cu]"} {
			d, err := set.BuildPath(variants[i], option, t.Name())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = d.Close() })
			if d.Name != want || ids[d.StatsID()] {
				t.Fatalf("candidate %d: name=%q, duplicate identity=%v", i, d.Name, ids[d.StatsID()])
			}
			ids[d.StatsID()] = true
		}
		if variants[2].IPVersion != 4 || variants[2].Annotation.PriorityAt(0) != 1 {
			t.Fatal("cu candidate lost family or priority")
		}
		if tcpQueries.Load() == 0 {
			t.Fatal("DNS TCP retry was not exercised")
		}
		base, err := variants[2].entryDialer(option)
		if err != nil {
			t.Fatal(err)
		}
		conn, err := base.DialContext(ctx, "udp", "entry.test.:443")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		assertEntrySocketEgress(t, conn, "cu", 0x100)
	})

	// The system-resolver callback and an explicit DNS override must both select
	// by the final server IP. Non-loopback DNS retains the configured interface.
	t.Run("sockets", func(t *testing.T) {
		for _, mark := range []struct {
			name  string
			value *uint32
			want  uint32
		}{
			{"inherit", nil, 0x100}, {"zero", new(uint32(0)), 0}, {"override", new(uint32(0x20)), 0x20},
		} {
			spec := &PathSpec{Entry: EntryOptions{Interface: "cu", Mark: mark.value}}
			for _, server := range []struct {
				address, iface string
			}{
				{"127.0.0.53:53", ""}, {"[::ffff:127.0.0.53]:53", ""}, {"[::1]:53", ""},
				{"198.51.100.53:53", "cu"}, {"192.168.1.1:53", "cu"},
			} {
				for _, explicit := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/explicit=%t", mark.name, server.address, explicit), func(t *testing.T) {
						opt := &dialer.GlobalOption{SoMarkFromDae: 0x100}
						resolverAddress := server.address
						if explicit {
							opt.DNSResolver = server.address
							resolverAddress = "127.0.0.54:53"
						}
						resolver, err := spec.entryResolver(opt)
						if err != nil {
							t.Fatal(err)
						}
						conn, err := resolver.Dial(t.Context(), "udp", resolverAddress)
						if err != nil {
							t.Fatalf("DNS transport: %v", err)
						}
						defer conn.Close()
						assertEntrySocketEgress(t, conn, server.iface, mark.want)
					})
				}
			}
		}
	})
}

func assertEntrySocketEgress(t *testing.T, conn net.Conn, iface string, mark uint32) {
	t.Helper()
	raw, err := conn.(syscall.Conn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.Control(func(fd uintptr) {
		gotMark, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK)
		if err != nil || uint32(gotMark) != mark {
			t.Errorf("SO_MARK = %#x, %v; want %#x", gotMark, err, mark)
		}
		gotIface, err := unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
		if err != nil || gotIface != iface {
			t.Errorf("SO_BINDTODEVICE = %q, %v; want %q", gotIface, err, iface)
		}
	}); err != nil {
		t.Fatal(err)
	}
}
