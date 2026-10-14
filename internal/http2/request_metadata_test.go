// SPDX-License-Identifier: AGPL-3.0-only

package http2

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	wire "golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// The peer uses x/net's public frame encoder, independent of the pinned server.
// PING acknowledgements establish when preceding frames have been processed.
type metadataPeer struct {
	t        *testing.T
	conn     net.Conn
	framer   *wire.Framer
	writeMu  sync.Mutex
	pings    chan struct{}
	requests chan *http.Request
	block    bytes.Buffer
	encoder  *hpack.Encoder
}

func newMetadataPeer(t *testing.T) *metadataPeer {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	_ = clientConn.SetDeadline(time.Now().Add(5 * time.Second))
	p := &metadataPeer{
		t: t, conn: clientConn, framer: wire.NewFramer(clientConn, clientConn),
		pings: make(chan struct{}, 8), requests: make(chan *http.Request, 1),
	}
	p.encoder = hpack.NewEncoder(&p.block)
	release := make(chan struct{})
	server, err := NewHTTPServer(&http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case p.requests <- r:
		case <-r.Context().Done():
			return
		}
		select {
		case <-release:
		case <-r.Context().Done():
		}
		w.WriteHeader(http.StatusNoContent)
	})})
	if err != nil {
		t.Fatal(err)
	}
	serverDone, readerDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(serverDone)
		server.ServeConn(t.Context(), serverConn)
	}()
	go func() {
		defer close(readerDone)
		for {
			frame, err := p.framer.ReadFrame()
			if err != nil {
				return
			}
			switch frame := frame.(type) {
			case *wire.SettingsFrame:
				if !frame.IsAck() {
					p.writeMu.Lock()
					_ = p.framer.WriteSettingsAck()
					p.writeMu.Unlock()
				}
			case *wire.PingFrame:
				if frame.IsAck() {
					p.pings <- struct{}{}
				}
			}
		}
	}()
	t.Cleanup(func() {
		close(release)
		_ = clientConn.Close()
		_ = serverConn.Close()
		<-readerDone
		<-serverDone
	})
	p.writeMu.Lock()
	_, err = io.WriteString(clientConn, wire.ClientPreface)
	if err == nil {
		err = p.framer.WriteSettings()
	}
	p.writeMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func (p *metadataPeer) headers(ended bool, fields ...hpack.HeaderField) {
	p.t.Helper()
	p.block.Reset()
	for _, field := range fields {
		if err := p.encoder.WriteField(field); err != nil {
			p.t.Fatal(err)
		}
	}
	p.writeMu.Lock()
	err := p.framer.WriteHeaders(wire.HeadersFrameParam{StreamID: 1, BlockFragment: p.block.Bytes(), EndHeaders: true, EndStream: ended})
	p.writeMu.Unlock()
	if err != nil {
		p.t.Fatal(err)
	}
}

func (p *metadataPeer) synchronize() {
	p.t.Helper()
	p.writeMu.Lock()
	err := p.framer.WritePing(false, [8]byte{1})
	p.writeMu.Unlock()
	if err != nil {
		p.t.Fatal(err)
	}
	select {
	case <-p.pings:
	case <-time.After(5 * time.Second):
		p.t.Fatal("server did not acknowledge preceding frames")
	}
}

func TestRequestMetadataFromFrames(t *testing.T) {
	for _, kind := range []string{"ended_headers", "announced_trailers", "unannounced_trailers", "unread_data", "reset", "zero_length_violation"} {
		t.Run(kind, func(t *testing.T) {
			peer := newMetadataPeer(t)
			length := "0"
			if kind == "unread_data" {
				length = "1"
			}
			fields := []hpack.HeaderField{
				{Name: ":method", Value: "POST"}, {Name: ":scheme", Value: "http"},
				{Name: ":authority", Value: "example.com"}, {Name: ":path", Value: "/"},
				{Name: "content-length", Value: length},
			}
			if kind == "announced_trailers" {
				fields = append(fields, hpack.HeaderField{Name: "trailer", Value: "X-Checksum"})
			}
			peer.headers(kind == "ended_headers", fields...)
			var request *http.Request
			select {
			case request = <-peer.requests:
			case <-time.After(5 * time.Second):
				t.Fatal("request was not delivered before its body ended")
			}
			if request.URL.Scheme != "http" {
				t.Fatalf("lost wire scheme: %q", request.URL.Scheme)
			}
			body, ok := request.Body.(interface{ TryReadEOF() (bool, error) })
			if !ok {
				t.Fatal("selected server implementation has no EOF interface")
			}
			ended, err := body.TryReadEOF()
			if err != nil || ended != (kind == "ended_headers") {
				t.Fatalf("initial end state: %t, %v", ended, err)
			}
			switch kind {
			case "announced_trailers", "unannounced_trailers":
				peer.headers(true, hpack.HeaderField{Name: "x-checksum", Value: "one"}, hpack.HeaderField{Name: "x-checksum", Value: "two"})
			case "unread_data", "zero_length_violation":
				peer.writeMu.Lock()
				err = peer.framer.WriteData(1, true, []byte("x"))
				peer.writeMu.Unlock()
			case "reset":
				peer.writeMu.Lock()
				err = peer.framer.WriteRSTStream(1, wire.ErrCodeCancel)
				peer.writeMu.Unlock()
			}
			if err != nil {
				t.Fatal(err)
			}
			peer.synchronize()
			ended, err = body.TryReadEOF()
			if kind == "reset" || kind == "zero_length_violation" {
				if ended || err == nil {
					t.Fatalf("abnormal end treated as EOF: %t, %v", ended, err)
				}
				return
			}
			if kind == "unread_data" {
				if ended || err != nil {
					t.Fatalf("unread DATA treated as EOF: %t, %v", ended, err)
				}
				var data [1]byte
				if _, err := io.ReadFull(request.Body, data[:]); err != nil || data[0] != 'x' {
					t.Fatalf("probe consumed DATA: %q, %v", data, err)
				}
				ended, err = body.TryReadEOF()
			}
			if !ended || err != nil {
				t.Fatalf("complete request not recognized: %t, %v", ended, err)
			}
			if kind == "announced_trailers" || kind == "unannounced_trailers" {
				values := request.Trailer.Values("X-Checksum")
				if len(values) != 2 || values[0] != "one" || values[1] != "two" {
					t.Fatalf("EOF did not publish trailers: %v", request.Trailer)
				}
				request.Trailer.Set("X-Checksum", "rewritten")
				_, _ = body.TryReadEOF()
				if request.Trailer.Get("X-Checksum") != "rewritten" {
					t.Fatal("repeated EOF overwrote middleware's trailer edit")
				}
			}
		})
	}
}

func TestHTTPServerShutdownBeforeServe(t *testing.T) {
	server, err := NewHTTPServer(new(http.Server))
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	local, peer := net.Pipe()
	defer peer.Close()
	server.ServeConn(t.Context(), local)
	var data [1]byte
	if _, err := peer.Read(data[:]); err != io.EOF {
		t.Fatalf("connection admitted after shutdown: %v", err)
	}
}
