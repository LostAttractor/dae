// SPDX-License-Identifier: AGPL-3.0-only

package mitm

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/daeuniverse/quic-go"
	"github.com/daeuniverse/quic-go/http3"
)

func TestHTTP3RequestBodyCompletionInterface(t *testing.T) {
	authority, roots := http3TestAuthority(t)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	probed := make(chan struct{})
	upstream := http3TestUpstream(t, authority.TLSConfig("example.com"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := r.Body.(interface{ TryReadEOF() (bool, error) })
		if !ok {
			t.Error("selected HTTP/3 server has no EOF interface")
			close(probed)
			return
		}
		if ended, err := body.TryReadEOF(); ended || err != nil {
			t.Errorf("open upload end state: %t, %v", ended, err)
		}
		// The client waits for this probe before sending FIN. A blocking
		// implementation cannot make progress, even with zero Content-Length.
		close(probed)
		if data, err := io.ReadAll(r.Body); err != nil || len(data) != 0 {
			t.Errorf("empty upload: %q, %v", data, err)
		}
		if ended, err := body.TryReadEOF(); !ended || err != nil {
			t.Errorf("completed upload end state: %t, %v", ended, err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	conn, err := quic.DialAddr(ctx, upstream.String(), &tls.Config{RootCAs: roots, ServerName: "example.com", NextProtos: []string{"h3"}}, &quic.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "test complete")
	transport := new(http3.Transport)
	defer transport.Close()
	stream, err := transport.NewClientConn(conn).OpenRequestStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.SetReadDeadline(time.Now().Add(3 * time.Second))
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.SendRequestHeader(request); err != nil {
		t.Fatal(err)
	}
	select {
	case <-probed:
	case <-ctx.Done():
		t.Fatal("EOF inspection waited for an open upload")
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
	response, err := stream.ReadResponse()
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("response status: %d", response.StatusCode)
	}
}
