// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
)

func TestTCPAbortReachesEveryReloadGeneration(t *testing.T) {
	state := NewRuntime()
	var clients []*net.TCPConn
	var finished []<-chan error
	var previous *ControlPlane
	for range 3 {
		plane := newLifecycleTestControlPlane(new(UdpEndpointPool))
		plane.tcpConnections.connections = &state.tcpConnections
		t.Cleanup(func() { _ = plane.retireTraffic() })
		if previous != nil {
			if err := previous.retireTraffic(); err != nil {
				t.Fatal(err)
			}
			plane.InheritConnections(previous)
		}
		accepted, client := relayTestTCPPair(t)
		remote, server := relayTestTCPPair(t)
		if !plane.tcpConnections.beginSetup(accepted) {
			t.Fatal("connection admission failed")
		}
		plane.tcpConnections.finishSetup()
		clients = append(clients, client)
		finished = append(finished, startTCPRelayTest(t, accepted, remote, time.Second))
		t.Cleanup(func() { plane.tcpConnections.removeConnection(accepted) })
		// Ordinary retirement must leave the socket usable.
		if err := plane.retireTraffic(); err != nil {
			t.Fatal(err)
		}
		if _, err := server.Write([]byte("ok")); err != nil {
			t.Fatal(err)
		}
		var data [2]byte
		if _, err := io.ReadFull(client, data[:]); err != nil || string(data[:]) != "ok" {
			t.Fatalf("ordinary reload interrupted TCP: %q, %v", data, err)
		}
		previous = plane
	}
	previous.StopAndAbortConnections()
	if err := previous.retireTraffic(); err != nil {
		t.Fatal(err)
	}
	for i, client := range clients {
		if _, err := client.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
			t.Errorf("generation %d: read = %v, want RST", i, err)
		}
		_ = waitTCPRelayTest(t, finished[i])
	}
}

func TestUnactivatedCandidateDoesNotAbortSharedTCP(t *testing.T) {
	state := NewRuntime()
	active := newLifecycleTestControlPlane(new(UdpEndpointPool))
	candidate := newLifecycleTestControlPlane(new(UdpEndpointPool))
	active.tcpConnections.connections = &state.tcpConnections
	candidate.tcpConnections.connections = &state.tcpConnections
	t.Cleanup(func() { _ = active.retireTraffic() })
	accepted, client := relayTestTCPPair(t)
	if !active.tcpConnections.beginSetup(accepted) {
		t.Fatal("connection admission failed")
	}
	active.tcpConnections.finishSetup()
	t.Cleanup(func() { active.tcpConnections.removeConnection(accepted) })
	if err := candidate.retireTraffic(); err != nil {
		t.Fatal(err)
	}
	if _, err := accepted.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	var data [2]byte
	if _, err := io.ReadFull(client, data[:]); err != nil || string(data[:]) != "ok" {
		t.Fatalf("failed candidate interrupted active plane: %q, %v", data, err)
	}
}

func TestShutdownResetsQueuedTCPBeforeDetachingKernel(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	packets, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packets.Close()
	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	state := NewRuntime()
	state.listener = &Listener{tcpListener: listener, packetConn: packets}
	state.kernelLinks.ownHostTCXLink(hostTCXLink{close: func() error {
		if _, err := client.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
			t.Errorf("queued connection remained open when kernel attachments closed: %v", err)
		}
		return nil
	}})
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
}
