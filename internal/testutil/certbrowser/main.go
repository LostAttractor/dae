// SPDX-License-Identifier: AGPL-3.0-only

// certbrowser serves the production certificate API and Web CSP for browser tests.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/daeuniverse/dae/component/ca"
	"github.com/daeuniverse/dae/internal/apiserver"
	"github.com/daeuniverse/dae/internal/webui"
)

func main() {
	if len(os.Args) != 4 {
		log.Fatal("usage: certbrowser ca.pem ca.key web-root")
	}
	authority, err := ca.Load(os.Args[1], os.Args[2])
	if err != nil {
		log.Fatal(err)
	}
	server, err := apiserver.Listen("tcp", ":0")
	if err != nil {
		log.Fatal(err)
	}
	defer server.Close()
	mux := http.NewServeMux()
	mux.Handle("/api/", apiserver.NewHandler(apiserver.Options{Certificates: &apiserver.Certificates{Identity: authority.Identity(), Handler: authority.Handler()}}))
	mux.Handle("/", webui.Handler(os.Args[3]))
	server.Configure(mux, authority, filepath.Join(filepath.Dir(os.Args[1]), "api-tls"))
	fmt.Println(server.Addr())
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	<-ctx.Done()
}
