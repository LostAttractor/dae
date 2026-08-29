/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestSetHostSysctlWith(t *testing.T) {
	t.Run("same value does not write", func(t *testing.T) {
		writes := 0
		err := setHostSysctlWith("net.ipv4.ip_forward", "1", func() ([]byte, error) {
			return []byte("1\n"), nil
		}, func([]byte) error {
			writes++
			return nil
		})
		if err != nil || writes != 0 {
			t.Fatalf("same-value set = %v, writes = %d; want nil, 0", err, writes)
		}
	})

	t.Run("different value writes once", func(t *testing.T) {
		var writes [][]byte
		err := setHostSysctlWith("net.ipv4.ip_forward", "1", func() ([]byte, error) {
			return []byte("0\n"), nil
		}, func(value []byte) error {
			writes = append(writes, append([]byte(nil), value...))
			return nil
		})
		if err != nil || len(writes) != 1 || string(writes[0]) != "1" {
			t.Fatalf("changed-value set = %v, writes = %q; want nil, [1]", err, writes)
		}
	})

	for _, tc := range []struct {
		name      string
		readError bool
	}{
		{name: "read error", readError: true},
		{name: "write error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sentinel := errors.New("permission denied")
			err := setHostSysctlWith("net.ipv6.conf.all.forwarding", "1", func() ([]byte, error) {
				if tc.readError {
					return nil, sentinel
				}
				return []byte("0"), nil
			}, func([]byte) error {
				return sentinel
			})
			if !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "net.ipv6.conf.all.forwarding") {
				t.Fatalf("set error = %v; want wrapped error with exact sysctl name", err)
			}
		})
	}
}

func TestLinkSnapshotDisappeared(t *testing.T) {
	stale := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 2, Name: "eth0"}}
	for _, tc := range []struct {
		name      string
		cause     error
		current   netlink.Link
		lookupErr error
		want      bool
	}{
		{name: "removed", cause: fmt.Errorf("read sysctl: %w", unix.ENOENT), lookupErr: unix.ENODEV, want: true},
		{name: "replaced", cause: fmt.Errorf("read sysctl: %w", unix.ENOENT), current: &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Index: 3, Name: "eth0"}}, want: true},
		{name: "sysctl missing on live link", cause: fmt.Errorf("read sysctl: %w", unix.ENOENT), current: stale},
		{name: "permission denied", cause: fmt.Errorf("read sysctl: %w", unix.EACCES), lookupErr: unix.ENODEV},
		{name: "dual disappearance", cause: errors.Join(unix.ENOENT, unix.ENODEV), lookupErr: unix.ENODEV, want: true},
		{name: "rollback failure", cause: errors.Join(unix.ENOENT, unix.EIO), lookupErr: unix.ENODEV},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := linkSnapshotDisappeared(stale, tc.cause, func(name string) (netlink.Link, error) {
				if name != "eth0" {
					t.Fatalf("lookup name = %q, want eth0", name)
				}
				return tc.current, tc.lookupErr
			})
			if got != tc.want {
				t.Fatalf("linkSnapshotDisappeared() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDirectDialerForMarkCachesOverrides(t *testing.T) {
	c := &ControlPlane{soMarkFromDae: 7}
	if got := c.directDialerForMark(consts.OutboundUserDefinedMin, 8); got != nil {
		t.Fatal("non-direct outbound received a marked direct dialer")
	}
	if got := c.directDialerForMark(consts.OutboundDirect, 7); got != nil {
		t.Fatal("global mark unnecessarily replaced the configured direct dialer")
	}
	first := c.directDialerForMark(consts.OutboundDirect, 8)
	second := c.directDialerForMark(consts.OutboundDirect, 8)
	if first == nil || first != second {
		t.Fatal("marked direct dialer was not cached")
	}
}

func TestRoutingLogFieldsOmitUnavailableMetadata(t *testing.T) {
	if fields := routingLogFields(new(bpfRoutingResult), ""); len(fields) != 0 {
		t.Fatalf("zero routing metadata = %#v, want empty", fields)
	}

	result := &bpfRoutingResult{
		Pid:  42,
		Dscp: 4,
		Mac:  [6]uint8{0x02, 0x42, 0xac, 0x11, 0x00, 0x02},
	}
	copy(result.Pname[:], "curl")
	fields := routeLogFields(result, "lan0", "tcp4", "192.0.2.1:1234", "example.com:443")
	if len(fields) != 9 || fields["pid"] != uint32(42) || fields["pname"] != "curl" ||
		fields["interface"] != "lan0" || fields["dscp"] != uint8(4) || fields["mac"] != "02:42:ac:11:00:02" {
		t.Fatalf("routing metadata = %#v", fields)
	}
	if fields["action"] != "forward" || fields["network"] != "tcp4" ||
		fields["source"] != "192.0.2.1:1234" || fields["destination"] != "example.com:443" {
		t.Fatalf("route fields = %#v", fields)
	}
	if _, ok := fields["ifindex"]; ok {
		t.Fatal("routing metadata exposed a numeric ifindex")
	}
}
