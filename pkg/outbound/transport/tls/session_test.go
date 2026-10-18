package tls

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/daeuniverse/dae/pkg/outbound/dialer"
)

func TestTLSSessionsAreResumedPerNode(t *testing.T) {
	for _, impl := range []string{"tls", "utls"} {
		for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
			// Browser fingerprints without a PSK extension intentionally skip
			// TLS 1.3 resumption. Keep their configured ClientHello unchanged.
			if impl == "utls" && version == tls.VersionTLS13 {
				continue
			}
			t.Run(fmt.Sprintf("%s/%x", impl, version), func(t *testing.T) {
				resumed := make(chan bool, 3)
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					resumed <- r.TLS.DidResume
					fmt.Fprint(w, "ok")
				}))
				server.TLS = &tls.Config{MinVersion: version, MaxVersion: version}
				server.StartTLS()
				defer server.Close()
				parent := &dependencyDialer{dial: (&net.Dialer{}).DialContext}
				build := func() *Tls {
					layer, err := (&TLSConfig{Host: server.Listener.Addr().String(), AllowInsecure: true}).Build(
						&dialer.ExtraOption{TlsImplementation: impl, UtlsImitate: "firefox"}, dialer.NewUpstream(parent))
					if err != nil {
						t.Fatal(err)
					}
					return layer.Data.(*Tls)
				}
				node := build()
				for i, client := range []*Tls{node, node, build()} {
					conn, err := client.DialContext(t.Context(), "tcp", "unused:443")
					if err != nil {
						t.Fatal(err)
					}
					_, err = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
					if err != nil {
						conn.Close()
						t.Fatal(err)
					}
					response, err := http.ReadResponse(bufio.NewReader(conn), nil)
					if err != nil {
						conn.Close()
						t.Fatal(err)
					}
					_, err = io.Copy(io.Discard, response.Body)
					response.Body.Close()
					conn.Close()
					if err != nil {
						t.Fatal(err)
					}
					if got := <-resumed; got != (i == 1) {
						t.Fatalf("connection %d resumed=%v", i, got)
					}
				}
			})
		}
	}
}
