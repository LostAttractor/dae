// SPDX-License-Identifier: AGPL-3.0-only

package daemon

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"

	"github.com/daeuniverse/dae/internal/apiserver"
	"github.com/daeuniverse/dae/internal/webui"
)

// Reserve a changed TCP port before retiring the active plane.
func prepareAPIServer(current *apiserver.Server, port uint16) (*apiserver.Server, error) {
	if port == 0 {
		return nil, nil
	}
	if current != nil && current.Addr().(*net.TCPAddr).Port == int(port) {
		return current, nil
	}
	server, err := apiserver.Listen("tcp", net.JoinHostPort("", strconv.Itoa(int(port))))
	if err != nil {
		return nil, fmt.Errorf("global.api_port: %w", err)
	}
	return server, nil
}

// The same api_port serves the API and Web application. Reserve API and
// certificate routes before the static file handler, including external bundles.
func daemonAPIHandler(api http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/api/", api)
	for _, path := range []string{"/ca.pem", "/ca.cer", "/ca.mobileconfig"} {
		mux.Handle(path, api)
	}
	mux.Handle("/", webui.Handler(os.Getenv("DAE_WEB_ROOT")))
	return mux
}
