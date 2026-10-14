package protocol

import (
	"bufio"
	"errors"
	"io"
	"net/http"

	"github.com/daeuniverse/outbound/netproxy"
)

const MaxHTTPResponseHeaderBytes = 1 << 20

var ErrHTTPResponseHeaderTooLarge = errors.New("proxy HTTP response headers exceed 1 MiB")

// ReadHTTPResponse bounds an HTTP/1 handshake head. After a successful parse,
// reader retains read-ahead and reads the tunnel without a byte limit. Callers
// must continue through reader, not raw, and close raw if the handshake fails.
func ReadHTTPResponse(raw io.Reader, request *http.Request) (*http.Response, *bufio.Reader, error) {
	head := &httpResponseHeadReader{reader: raw, remaining: MaxHTTPResponseHeaderBytes}
	reader := bufio.NewReader(head)
	response, err := http.ReadResponse(reader, request)
	if head.exceeded {
		// The MIME parser can replace a read error with a malformed-line
		// error. Preserve the actual reason and its peer attribution.
		err = netproxy.WrapFailure(ErrHTTPResponseHeaderTooLarge, netproxy.Failure{
			Scope: netproxy.ScopeOperation, Layer: netproxy.LayerProxy,
			Origin: netproxy.OriginPeer, Phase: netproxy.OpHandshake, Reason: netproxy.ReasonProtocol,
		})
	}
	if err != nil {
		return nil, nil, err
	}
	head.remaining = -1
	return response, reader, nil
}

type httpResponseHeadReader struct {
	reader    io.Reader
	remaining int
	exceeded  bool
}

func (r *httpResponseHeadReader) Read(p []byte) (int, error) {
	if r.remaining < 0 {
		return r.reader.Read(p)
	}
	if len(p) == 0 {
		return 0, nil
	}
	if r.remaining == 0 {
		r.exceeded = true
		return 0, ErrHTTPResponseHeaderTooLarge
	}
	n, err := r.reader.Read(p[:min(len(p), r.remaining)])
	r.remaining -= n
	return n, err
}
