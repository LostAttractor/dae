// Modified from https://github.com/Dreamacro/clash/blob/master/component/simple-obfs/http.go
// Wire format: shadowsocks/simple-obfs, src/obfs_http.c.
package simpleobfs

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/daeuniverse/dae/pkg/outbound/pkg/fastrand"
	"github.com/daeuniverse/dae/pkg/outbound/pool"
)

type HTTPObfs struct {
	net.Conn
	reader                      *bufio.Reader
	host, port, path            string
	header                      bytes.Buffer
	firstRequest, firstResponse bool
	rMu, wMu                    sync.Mutex
	readErr, writeErr           error
}

func (c *HTTPObfs) Read(p []byte) (int, error) {
	c.rMu.Lock()
	defer c.rMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if c.readErr != nil {
		return 0, c.readErr
	}
	for c.firstResponse {
		line, err := c.reader.ReadSlice('\n')
		c.header.Write(line)
		if c.header.Len() > 64<<10 {
			c.readErr = wireError("HTTP response header too large")
			return 0, c.readErr
		}
		if err != nil {
			if err == bufio.ErrBufferFull {
				continue
			}
			if !isTimeout(err) {
				c.readErr = err
				if err == io.EOF && c.header.Len() > 0 {
					c.readErr = io.ErrUnexpectedEOF
				}
				err = c.readErr
			}
			return 0, err
		}
		if !bytes.HasSuffix(c.header.Bytes(), []byte("\r\n\r\n")) {
			continue
		}
		response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(c.header.Bytes())), nil)
		if err != nil {
			c.readErr = wireError("invalid HTTP response")
			return 0, c.readErr
		}
		if response.StatusCode != http.StatusSwitchingProtocols {
			c.readErr = wireError(fmt.Sprintf("HTTP status %d", response.StatusCode))
			return 0, c.readErr
		}
		c.header = bytes.Buffer{}
		c.firstResponse = false
	}
	return c.reader.Read(p)
}

func (c *HTTPObfs) Write(p []byte) (int, error) {
	c.wMu.Lock()
	defer c.wMu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if len(p) == 0 {
		return 0, nil
	}
	if !c.firstRequest {
		return c.Conn.Write(p)
	}
	buf := pool.GetBytesBuffer()
	defer pool.PutBytesBuffer(buf)
	request, err := http.NewRequest(http.MethodGet, "http://"+c.host+c.path, bytes.NewReader(p))
	if err != nil {
		return 0, err
	}
	request.Header.Set("User-Agent", fmt.Sprintf("curl/7.%d.%d", fastrand.Intn(87), fastrand.Intn(2)))
	request.Header.Set("Upgrade", "websocket")
	request.Header.Set("Connection", "Upgrade")
	if c.port != "80" {
		request.Host = net.JoinHostPort(c.host, c.port)
	}
	var key [16]byte
	fastrand.Read(key[:])
	request.Header.Set("Sec-WebSocket-Key", base64.StdEncoding.EncodeToString(key[:]))
	if err := request.Write(buf); err != nil {
		return 0, err
	}
	if err := writeWire(c.Conn, buf.Bytes()); err != nil {
		c.writeErr = err
		return 0, err
	}
	c.firstRequest = false
	return len(p), nil
}

func NewHTTPObfs(conn net.Conn, host, port, path string) net.Conn {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return &HTTPObfs{Conn: conn, reader: bufio.NewReader(conn), host: host, port: port, path: path, firstRequest: true, firstResponse: true}
}
