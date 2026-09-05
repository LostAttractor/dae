/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/outbound/netproxy"
	quic "github.com/daeuniverse/quic-go"
	"github.com/prometheus/client_golang/prometheus"
)

func TestRelayTCPRetainsQUICConnectionErrorAfterAbort(t *testing.T) {
	left, right := relayTestNewConn(), relayTestNewConn()
	first := errors.New("client failed before upstream reported its own failure")
	fatal := &quic.TransportError{Remote: true, ErrorCode: 1, ErrorMessage: "independent connection failure"}
	started := make(chan struct{})
	left.read = func([]byte) (int, error) {
		<-started
		return 0, first
	}
	right.read = func([]byte) (int, error) {
		close(started)
		<-right.closed
		return 0, fatal
	}
	err := waitTCPRelayTest(t, startTCPRelayTest(t, left, right, time.Second))
	if !errors.Is(err, first) || !errors.Is(err, fatal) {
		t.Fatalf("relay discarded an independent cause: %v", err)
	}
	var found bool
	for _, failure := range netproxy.Failures(err) {
		if errors.Is(failure.Cause, fatal) {
			found = true
			if failure.Scope != netproxy.ScopeSharedResource || failure.Layer != netproxy.LayerQUIC || failure.Origin == netproxy.OriginLocalCleanup {
				t.Fatalf("QUIC failure was misclassified: %+v", failure)
			}
		}
	}
	if !found {
		t.Fatal("no QUIC failure observation")
	}
}

func TestRelayErrorsRecordActualEndpointAndOperation(t *testing.T) {
	left, right := relayTestNewConn(), relayTestNewConn()
	// Text and nested net.OpError.Op must not override the actual I/O boundary.
	want := errors.New("write: misleading text from a Read implementation")
	left.read = func([]byte) (int, error) { return 0, want }
	err := waitTCPRelayTest(t, startTCPRelayTest(t, left, right, time.Second))
	failures := netproxy.Failures(err)
	if len(failures) != 1 || !errors.Is(failures[0].Cause, want) {
		t.Fatalf("failures = %+v, want the client read failure", failures)
	}
	if failures[0].Origin != netproxy.OriginCaller || failures[0].Phase != netproxy.OpRead {
		t.Fatalf("wrong provenance: %+v", failures[0])
	}
}

func TestRecordDataPlaneErrorDoesNotLetTimeoutHideFatal(t *testing.T) {
	runtime := netproxy.NewRuntime(netproxy.Layer{Data: tcpTestDialer{}})
	reporter := dialer.NewDialer(runtime, &dialer.GlobalOption{}, &dialer.Property{Name: t.Name()}, false, t.TempDir())
	t.Cleanup(func() { _ = reporter.Close() })
	// Reconcile changes the shared DefaultStore; keep this test non-parallel.
	stats.DefaultStore.Reconcile(map[string]stats.NodeIdentity{reporter.StatsKey(): {Name: reporter.Name}}, nil)
	t.Cleanup(func() { stats.DefaultStore.Reconcile(nil, nil) })
	registry := prometheus.NewRegistry()
	registry.MustRegister(stats.DefaultStore)

	fatal := netproxy.WrapFailure(errors.New("session lost"), netproxy.Failure{
		Scope: netproxy.ScopeSharedResource, Layer: netproxy.LayerQUIC, Reason: netproxy.ReasonProtocol,
	})
	for index, reverse := range []bool{false, true} {
		deadline := netproxy.WrapFailure(context.DeadlineExceeded, netproxy.Failure{Scope: netproxy.ScopeOperation})
		causes := []error{deadline, fatal}
		if reverse {
			causes[0], causes[1] = causes[1], causes[0]
		}
		if !recordDataPlaneError(reporter, stats.Path{Dialer: t.Name()}, errors.Join(causes...)) {
			t.Fatal("connection failure was hidden by the operation timeout")
		}
		families, err := registry.Gather()
		if err != nil {
			t.Fatal(err)
		}
		counts := map[string]float64{}
		for _, family := range families {
			if family.GetName() != "dae_relay_failures_total" {
				continue
			}
			for _, metric := range family.Metric {
				labels := map[string]string{}
				for _, label := range metric.Label {
					labels[label.GetName()] = label.GetValue()
				}
				if labels["id"] == reporter.StatsID() {
					counts[labels["scope"]+"/"+labels["reason"]] += metric.GetCounter().GetValue()
				}
			}
		}
		// These counters are incremented only by the real dialer's consumption,
		// independently of recordDataPlaneError's path-level warning result.
		want := float64(index + 1)
		if len(counts) != 2 || counts["operation/deadline"] != want || counts["shared_resource/protocol"] != want {
			t.Fatalf("dialer did not consume every joined cause (reversed=%v): %v", reverse, counts)
		}
	}
}

func TestRelayWriteEOFIsAnError(t *testing.T) {
	left, right := net.Pipe()
	t.Cleanup(func() { _ = left.Close(); _ = right.Close() })
	if err := right.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _ = right.Write([]byte("request"))
		_ = right.Close()
	}()
	err := relayEndpointDirection(&relayEndpoint{conn: relayEOFWriter{}}, &relayEndpoint{conn: left}, func(uint64) {})
	if err == io.EOF || err == nil {
		t.Fatal("write EOF must carry failure metadata")
	}
	failure := netproxy.ClassifyFailure(err)
	if failure.Phase != netproxy.OpWrite || !errors.Is(err, io.EOF) {
		t.Fatalf("write EOF was not preserved: %+v", failure)
	}
}

type relayEOFWriter struct{ net.Conn }

func (relayEOFWriter) Write([]byte) (int, error) { return 0, io.EOF }

func TestUnknownWrapperClosedErrorIsNotCleanupEvidence(t *testing.T) {
	conn := relayTestNewConn()
	endpoint := &relayEndpoint{conn: conn}
	_ = endpoint.close()
	err := withoutCleanupErrors(endpoint.failure(net.ErrClosed, netproxy.OpRead))
	if !errors.Is(err, net.ErrClosed) || netproxy.ClassifyFailure(err).Origin == netproxy.OriginLocalCleanup {
		t.Fatalf("unknown wrapper's independent closed error was suppressed: %v", err)
	}
}

func TestRelayUnsupportedHalfCloseUsesDrainGrace(t *testing.T) {
	left, right := relayTestNewConn(), relayTestNewConn()
	left.read = func([]byte) (int, error) { return 0, io.EOF }
	right.closeWriteErr = errors.ErrUnsupported
	right.read = func(p []byte) (int, error) {
		<-right.writeClosed
		return copy(p, "reverse response"), io.EOF
	}
	if err := waitTCPRelayTest(t, startTCPRelayTest(t, left, right, time.Second)); err != nil {
		t.Fatalf("unsupported half-close interrupted reverse drain: %v", err)
	}
	fatal := &quic.TransportError{ErrorCode: 1}
	right.closeWriteErr = errors.Join(errors.ErrUnsupported, fatal)
	if drain, err := (&relayEndpoint{conn: right}).halfClose(); drain || !errors.Is(err, fatal) {
		t.Fatal("unsupported half-close hid an independent fatal error")
	}
}
