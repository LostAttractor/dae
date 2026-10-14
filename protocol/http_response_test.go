package protocol

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/daeuniverse/outbound/netproxy"
)

func TestHTTPResponseHeadLimit(t *testing.T) {
	for _, head := range []string{
		"HTTP/1.1 200 " + strings.Repeat("x", MaxHTTPResponseHeaderBytes) + "\r\n\r\n",
		"HTTP/1.1 200 OK\r\nX-Flood: " + strings.Repeat("x", MaxHTTPResponseHeaderBytes) + "\r\n\r\n",
		"HTTP/1.1 200 OK\r\n" + strings.Repeat("X: y\r\n", MaxHTTPResponseHeaderBytes/6+1) + "\r\n",
	} {
		_, _, err := ReadHTTPResponse(strings.NewReader(head), &http.Request{Method: http.MethodConnect})
		if !errors.Is(err, ErrHTTPResponseHeaderTooLarge) {
			t.Fatalf("oversized head: %v", err)
		}
		failure := netproxy.ClassifyFailure(err)
		if failure.Origin != netproxy.OriginPeer || failure.Phase != netproxy.OpHandshake {
			t.Fatalf("lost handshake failure attribution: %+v", failure)
		}
	}
}

func TestHTTPResponseHeadBoundaryAndTunnel(t *testing.T) {
	const prefix = "HTTP/1.1 200 OK\r\nX: "
	payload := strings.Repeat("tunnel data", MaxHTTPResponseHeaderBytes/5)
	for _, size := range []int{128, MaxHTTPResponseHeaderBytes - 1, MaxHTTPResponseHeaderBytes} {
		head := prefix + strings.Repeat("x", size-len(prefix)-4) + "\r\n\r\n"
		response, reader, err := ReadHTTPResponse(strings.NewReader(head+payload), &http.Request{Method: http.MethodConnect})
		if err != nil || response.StatusCode != 200 {
			t.Fatalf("head size %d: %v", size, err)
		}
		data, err := io.ReadAll(reader)
		if err != nil || string(data) != payload {
			t.Fatalf("head size %d truncated tunnel to %d bytes: %v", size, len(data), err)
		}
	}
}
