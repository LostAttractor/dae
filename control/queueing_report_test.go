// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"encoding/binary"
	"net"
	"testing"
	"testing/synctest"
	"time"
)

func TestQueueingExperimentUploadReportUsesReceivedBytes(t *testing.T) {
	// The sender offers 100 packets inside the window, but 40 are dropped.
	// Neither warmup nor packets drained after the window are goodput here.
	var flood, bulk qexpCounter
	flood.first.Store(20 * qexpFloodSize)
	flood.last.Store(80 * qexpFloodSize)
	flood.latest.Store(90 * qexpFloodSize)
	bulk.first.Store(1000)
	bulk.last.Store(2000)
	counters := map[string][]*qexpCounter{"flood": {&flood}, "bulk": {&bulk}}
	wantBytes := uint64(60*qexpFloodSize + 1000)
	for _, includeCPU := range []bool{true, false} {
		report := make(map[string]any)
		qexpReportUploads(report, counters, time.Second, 2*time.Millisecond, includeCPU)
		if report["uploaded_bytes"] != wantBytes || report["flood_mbit"] != float64(60*qexpFloodSize*8)/1e6 {
			t.Fatalf("report includes unreceived or out-of-window bytes: %v", report)
		}
		cpu, ok := report["cpu_ms_per_gb"]
		if ok != includeCPU || ok && cpu != 2/(float64(wantBytes)/1e9) {
			t.Fatalf("CPU per delivered GB = %v, present = %v; report %v", cpu, ok, report)
		}
	}
	flood.last.Store(flood.first.Load())
	bulk.last.Store(bulk.first.Load())
	report := make(map[string]any)
	qexpReportUploads(report, counters, time.Second, time.Millisecond, true)
	if _, ok := report["cpu_ms_per_gb"]; ok {
		t.Fatalf("reported CPU per GB with no delivered bytes: %v", report)
	}
}

func TestQueueingExperimentLossAttribution(t *testing.T) {
	for _, tt := range []struct {
		name         string
		udp          string
		workload     map[string]int
		download     bool
		lostUpload   int64
		wantUpload   any
		wantDownload any
	}{
		{"direct_udp", "direct", map[string]int{"game": 1, "flood": 60}, false, 1, int64(0), int64(0)},
		{"direct_bulk", "direct", map[string]int{"game": 1, "bulk": 4}, false, 0, nil, int64(0)},
		{"direct_itcp", "direct", map[string]int{"game": 1, "itcp": 1}, false, 0, nil, int64(0)},
		{"direct_ttfb", "direct", map[string]int{"game": 1, "ttfb": 1}, false, 0, nil, int64(0)},
		{"direct_download", "direct", map[string]int{"game": 1}, true, 0, nil, int64(0)},
		{"mux_bulk", "mux", map[string]int{"game": 1, "bulk": 4}, false, 0, int64(0), int64(0)},
		{"quic", "direct", map[string]int{"game": 1, "quic": 1}, false, 0, nil, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			report := make(map[string]any)
			// One qdisc drop: UDP in the pure-UDP case, a retransmitted TCP
			// segment in mixed workloads where all UDP probes arrived.
			qexpReportLoss(report, tt.workload, tt.udp, tt.download, tt.lostUpload, 0, 0, 0, 1)
			if report["upload_unaccounted"] != tt.wantUpload || report["download_unaccounted"] != tt.wantDownload {
				t.Fatalf("loss attribution = %v; want upload %v, download %v", report, tt.wantUpload, tt.wantDownload)
			}
		})
	}
}

func qexpProbeReply(sentAt int64, packets uint64) []byte {
	reply := make([]byte, 13)
	reply[0] = 'P'
	binary.BigEndian.PutUint64(reply[5:], uint64(sentAt))
	reply = binary.BigEndian.AppendUint64(reply, uint64(sentAt+1))
	return binary.BigEndian.AppendUint64(reply, packets)
}

func TestQueueingExperimentFloodSettlesUnderLoad(t *testing.T) {
	for _, names := range [][]string{{"flood"}, {"game", "flood"}} {
		t.Run(names[0], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				now := qexpNow()
				rec := &qexpRecorder{from: now - int64(time.Second), to: now, samples: make(map[string][]float64), late: make(map[string]int)}
				var flows []*qexpFlow
				for _, name := range names {
					flow := &qexpFlow{replies: make(chan []byte, 4)}
					defer close(flow.replies)
					flows = append(flows, flow)
					rec.followProbes(flow, name, 0, nil)
					flow.replies <- qexpProbeReply(now-10, 1)
				}
				done := make(chan bool, 1)
				go func() { done <- rec.waitSettled(time.Second) }()
				synctest.Wait()
				for _, flow := range flows {
					select {
					case <-done:
						t.Fatal("stopped the load before every flow's post-window reply")
					default:
					}
					flow.replies <- qexpProbeReply(now+1, 2)
					time.Sleep(qexpProbeInterval)
					synctest.Wait()
				}
				if !<-done {
					t.Fatal("settle timed out with every stream answered")
				}
				rec.stopped.Store(qexpNow())
				for _, name := range names {
					for _, direction := range []string{"_up_ms", "_down_ms"} {
						key := name + direction
						if rec.late[key] != 0 || len(rec.samples[key]) != 1 {
							t.Fatalf("%s: late=%d, samples=%v", key, rec.late[key], rec.samples[key])
						}
					}
				}
			})
		})
	}
	t.Run("timeout", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			now := qexpNow()
			rec := &qexpRecorder{from: now - int64(time.Second), to: now, samples: make(map[string][]float64), late: make(map[string]int)}
			flow := &qexpFlow{replies: make(chan []byte, 1)}
			defer close(flow.replies)
			rec.followProbes(flow, "flood", 0, nil)
			if rec.waitSettled(2 * qexpProbeInterval) {
				t.Fatal("unanswered flood reported a valid completion")
			}
			rec.stopped.Store(qexpNow())
			flow.replies <- qexpProbeReply(now-10, 1)
			synctest.Wait()
			if rec.late["flood_up_ms"] != 1 || rec.late["flood_down_ms"] != 1 {
				t.Fatalf("missing late flood samples: %v", rec.late)
			}
		})
	})
}

func TestQueueingExperimentReflectorCountsProbes(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); qexpReflect(server) }()
	defer func() { _ = server.Close(); <-done }()
	client, err := net.DialUDP("udp4", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	for _, packet := range [][]byte{{'F'}, qexpProbeReply(qexpNow(), 0)[:13], {'F'}, {'R'}} {
		if _, err := client.Write(packet); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range []struct {
		kind    byte
		offset  int
		packets uint64
		length  int
	}{{'P', 21, 2, 29}, {'R', 1, 3, 17}} {
		var reply [64]byte
		n, err := client.Read(reply[:])
		if err != nil || n != want.length || reply[0] != want.kind {
			t.Fatalf("reflector reply = %q, %v", reply[:n], err)
		}
		if packets := binary.BigEndian.Uint64(reply[want.offset:]); packets != want.packets {
			t.Fatalf("reflector counted %d packets, want %d", packets, want.packets)
		}
		if want.kind == 'R' && binary.BigEndian.Uint64(reply[9:]) != 1 {
			t.Fatal("report counted a non-probe as a reflected packet")
		}
	}
}

func TestQueueingExperimentFloodLANLossAccounting(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		report := make(map[string]any)
		workload := map[string]int{"flood": 60}
		flow := new(qexpFlow)
		flow.sent.Store(1100)
		flow.received.Store(1000) // ordinary flood packets do not produce replies
		flow.probes.Store(10)
		flow.echoed.Store(3)
		flow.dropped.Store(2)
		up, down := flow.reportLoss(report, "flood")
		drops := int64(5) // five flood replies dropped by the full LAN socket
		if mixed {
			workload["game"] = 1
			game := new(qexpFlow)
			game.sent.Store(100)
			game.received.Store(100)
			game.probes.Store(100)
			game.echoed.Store(80)
			game.dropped.Store(3)
			u, d := game.reportLoss(report, "game")
			up, down, drops = up+u, down+d, drops+17
		}
		qexpReportLoss(report, workload, "direct", false, up, down, 100, drops, 0)
		if report["upload_unaccounted"] != int64(0) || report["download_unaccounted"] != int64(0) || report["flood_probes_received"] != uint64(10) {
			t.Fatalf("mixed=%v: loss report = %v", mixed, report)
		}
	}
}

func TestQueueingExperimentWriterPreservesSocket(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()
	writer := &qexpBusyWriter{Conn: local}
	if writer.ReadPassthrough() != local {
		t.Fatal("writer-cost fixture hid its underlying socket")
	}
}
