//go:build linux && dae_bpf_tests

// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// Matches SOCKET_OWNER_PORT in bpf_test.c.
const socketOwnerPort = 18443

const mptcpUnavailableExit = 3

var errMPTCPUnavailable = errors.New("MPTCP unavailable")

// An MPTCP connection sends from kernel subflow sockets. The path manager's
// kworker connects the MP_JOIN subflow, which must still belong to the
// process that opened the connection. A child process in a private cgroup and
// network namespace opens the connection; the cgroup carries the ownership
// hooks and a probe that reads the owner of every segment's socket.
func TestMPTCPSubflowOwner(t *testing.T) {
	if os.Getenv("DAE_SOCKET_OWNER_CHILD") == "1" {
		err := mptcpJoinClient()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		if errors.Is(err, errMPTCPUnavailable) {
			os.Exit(mptcpUnavailableExit)
		}
		if err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	obj, err := loadTestObjects(t, "TproxyWanCgSockCreate", "TproxyWanCgConnect4", "TestSocketOwnerProbe")
	if err != nil {
		t.Fatal(err)
	}
	cgroup, err := os.MkdirTemp("/sys/fs/cgroup", "dae-socket-owner-test-")
	if err != nil {
		t.Skip("cgroup2 at /sys/fs/cgroup is required:", err)
	}
	t.Cleanup(func() {
		if err := os.Remove(cgroup); err != nil {
			t.Error(err)
		}
	})
	for _, prog := range []struct {
		program *ebpf.Program
		attach  ebpf.AttachType
	}{
		{obj.TproxyWanCgSockCreate, ebpf.AttachCGroupInetSockCreate},
		{obj.TproxyWanCgConnect4, ebpf.AttachCGroupInet4Connect},
		{obj.TestSocketOwnerProbe, ebpf.AttachCGroupInetEgress},
	} {
		attached, err := link.AttachCgroup(link.CgroupOptions{Path: cgroup, Attach: prog.attach, Program: prog.program})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { attached.Close() })
	}
	dir, err := os.Open(cgroup)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), binary, "-test.run=^TestMPTCPSubflowOwner$")
	cmd.Env = append(os.Environ(), "DAE_SOCKET_OWNER_CHILD=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNET, UseCgroupFD: true, CgroupFD: int(dir.Fd())}
	if output, err := cmd.CombinedOutput(); cmd.ProcessState != nil && cmd.ProcessState.ExitCode() == mptcpUnavailableExit {
		t.Skipf("MPTCP unavailable: %s", output)
	} else if err != nil {
		t.Fatalf("MPTCP client: %v\n%s", err, output)
	}
	for _, source := range []string{"127.0.0.1", "127.0.0.2"} {
		var probe bpftestSocketOwnerProbe
		if err := obj.SocketOwnerProbeMap.Lookup(netip.MustParseAddr(source).As4(), &probe); err != nil {
			t.Fatalf("no segments from %s: %v", source, err)
		}
		if probe.Owned == 0 || probe.Unowned != 0 || probe.Pid != uint32(cmd.Process.Pid) {
			t.Errorf("segments from %s: %+v, want all owned by %d", source, probe, cmd.Process.Pid)
		}
	}
}

// The client connects from 127.0.0.1, and its MP_JOIN subflow from the
// 127.0.0.2 endpoint. It sends until the join is established and has carried
// data, then returns while all sockets are still open.
func mptcpJoinClient() error {
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return err
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		return err
	}
	if err := addMPTCPSubflowEndpoint(netip.MustParseAddr("127.0.0.2")); err != nil {
		return fmt.Errorf("%w: add endpoint: %w", errMPTCPUnavailable, err)
	}
	var listenConfig net.ListenConfig
	listenConfig.SetMultipathTCP(true)
	listener, err := listenConfig.Listen(context.Background(), "tcp4", fmt.Sprintf("127.0.0.1:%d", socketOwnerPort))
	if err != nil {
		return err
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = conn.Read(make([]byte, 1<<16)) }()
		}
	}()
	var dialer net.Dialer
	dialer.SetMultipathTCP(true)
	conn, err := dialer.Dial("tcp4", listener.Addr().String())
	if err != nil {
		return err
	}
	defer conn.Close()
	if mptcp, err := conn.(*net.TCPConn).MultipathTCP(); err != nil || !mptcp {
		return fmt.Errorf("%w: connection fell back to TCP: %v", errMPTCPUnavailable, err)
	}
	raw, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		return err
	}
	for range 200 {
		var subflows byte
		var sockErr error
		if err := raw.Control(func(fd uintptr) {
			subflows, sockErr = unix.GetsockoptByte(int(fd), unix.SOL_MPTCP, 1 /* MPTCP_INFO */)
		}); err != nil {
			return err
		}
		if sockErr != nil {
			return fmt.Errorf("MPTCP_INFO: %w", sockErr)
		}
		if subflows > 0 {
			for range 32 {
				if _, err := conn.Write(make([]byte, 1024)); err != nil {
					return err
				}
			}
			time.Sleep(100 * time.Millisecond)
			return nil
		}
		if _, err := conn.Write([]byte{0}); err != nil {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
	return errors.New("no MP_JOIN subflow was established")
}

// ip mptcp endpoint add <address> subflow
func addMPTCPSubflowEndpoint(address netip.Addr) error {
	family, err := netlink.GenlFamilyGet("mptcp_pm")
	if err != nil {
		return err
	}
	const (
		cmdAddAddr    = 1 // MPTCP_PM_CMD_ADD_ADDR
		attrAddr      = 1 // MPTCP_PM_ATTR_ADDR
		addrFamily    = 1 // MPTCP_PM_ADDR_ATTR_FAMILY
		addrIPv4      = 3 // MPTCP_PM_ADDR_ATTR_ADDR4
		addrFlags     = 6 // MPTCP_PM_ADDR_ATTR_FLAGS
		endpointFlows = 1 << 1
	)
	request := nl.NewNetlinkRequest(int(family.ID), unix.NLM_F_ACK)
	request.AddData(&nl.Genlmsg{Command: cmdAddAddr, Version: 1})
	endpoint := nl.NewRtAttr(attrAddr|unix.NLA_F_NESTED, nil)
	endpoint.AddRtAttr(addrFamily, nl.Uint16Attr(unix.AF_INET))
	ip := address.As4()
	endpoint.AddRtAttr(addrIPv4, ip[:])
	endpoint.AddRtAttr(addrFlags, nl.Uint32Attr(endpointFlows))
	request.AddData(endpoint)
	_, err = request.Execute(unix.NETLINK_GENERIC, 0)
	return err
}
