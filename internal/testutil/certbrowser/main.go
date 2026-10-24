// SPDX-License-Identifier: AGPL-3.0-only

// certbrowser serves the production certificate API and Web CSP for browser tests.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	contract "github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/component/ca"
	"github.com/daeuniverse/dae/internal/apiserver"
	"github.com/daeuniverse/dae/internal/webui"
)

func main() {
	if len(os.Args) != 4 && (len(os.Args) != 5 || os.Args[4] != "session") {
		log.Fatal("usage: certbrowser ca.pem ca.key web-root [session]")
	}
	authority, err := ca.Load(os.Args[1], os.Args[2])
	if err != nil {
		log.Fatal(err)
	}
	if len(os.Args) == 5 {
		if err := sessionBrowser(authority); err != nil {
			log.Fatal(err)
		}
		return
	}
	server, err := apiserver.Listen("tcp", ":0")
	if err != nil {
		log.Fatal(err)
	}
	defer server.Close()
	mux := http.NewServeMux()
	mux.Handle("/api/", apiserver.NewHandler(apiserver.Options{AllowLANAnonymous: true, ResolveClient: func(netip.AddrPort, netip.AddrPort) (contract.ClientIdentity, error) {
		return contract.ClientIdentity{LinkType: "ip"}, nil
	}, Certificates: &apiserver.Certificates{Identity: authority.Identity(), Handler: authority.Handler()}}))
	mux.Handle("/", webui.Handler(os.Args[3]))
	server.Configure(mux, authority, filepath.Join(filepath.Dir(os.Args[1]), "api-tls"))
	fmt.Println(server.Addr())
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	<-ctx.Done()
}

// Session mode adds real same-site, proxy and cross-site browser entry points.
func sessionBrowser(authority *ca.Authority) error {
	backend, err := apiserver.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer backend.Close()
	upstream, err := url.Parse("https://" + backend.Addr().String())
	if err != nil {
		return err
	}
	pem, err := os.ReadFile(os.Args[1])
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return fmt.Errorf("invalid proxy upstream CA")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	defer transport.CloseIdleConnections()
	proxy := &httputil.ReverseProxy{Transport: transport, Rewrite: func(r *httputil.ProxyRequest) {
		r.SetURL(upstream)
		r.Out.Host = upstream.Host
		r.Out.Header.Set("X-Dae-Proxy", "1")
	}}
	origins := map[string]string{"direct": upstream.String()}
	var webOrigins []string
	for _, name := range []string{"same-site", "proxy", "cross-site"} {
		host := "127.0.0.1"
		if name == "cross-site" {
			host = "127.0.0.2"
		}
		listener, err := net.Listen("tcp", host+":0")
		if err != nil {
			return err
		}
		defer listener.Close()
		origins[name] = "https://" + listener.Addr().String()
		webOrigins = append(webOrigins, origins[name])
		mux := http.NewServeMux()
		if name == "proxy" {
			mux.Handle("/api/", proxy)
		}
		mux.Handle("/", webui.Handler(filepath.Join(os.Args[3], name)))
		server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		defer server.Close()
		go func() {
			if err := server.Serve(tls.NewListener(listener, authority.TLSConfig(host))); err != nil && err != http.ErrServerClosed {
				log.Print(err)
			}
		}()
	}
	mux := http.NewServeMux()
	mux.Handle("/api/", apiserver.NewHandler(apiserver.Options{
		UserKey: "test-user", AdminKey: "test-admin", WebOrigins: webOrigins,
		Status: func() *contract.StatusSnapshot {
			return &contract.StatusSnapshot{Schema: contract.StatusSchemaVersion, Version: "session-browser"}
		},
		ResolveClient: func(source, destination netip.AddrPort) (contract.ClientIdentity, error) {
			if !source.Addr().IsLoopback() || !destination.Addr().IsLoopback() {
				return contract.ClientIdentity{}, fmt.Errorf("fixture requires loopback ingress")
			}
			return contract.ClientIdentity{LinkType: "ethernet", MAC: [6]byte{2, 0, 0, 0, 0, 1}, IfIndex: 1}, nil
		},
		Certificates: &apiserver.Certificates{Identity: authority.Identity(), Handler: authority.Handler()},
	}))
	mux.Handle("/", webui.Handler(filepath.Join(os.Args[3], "direct")))
	backend.Configure(mux, authority, filepath.Join(filepath.Dir(os.Args[1]), "api-tls"))
	if err := json.MarshalWrite(os.Stdout, origins); err != nil {
		return err
	}
	fmt.Println()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	<-ctx.Done()
	return nil
}
