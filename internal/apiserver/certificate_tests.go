// SPDX-License-Identifier: AGPL-3.0-only

package apiserver

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common/persist"
	localca "github.com/daeuniverse/dae/component/ca"
)

const (
	maxCertificateTests          = 64
	maxCertificateTestsPerSource = 8
	maxAPICertificates           = 256
	certificateTestLifetime      = time.Minute
	// Match the signer's five-minute backdating allowance at the other end.
	// This does not extend the server-side challenge deadline.
	certificateTestLeafLifetime = certificateTestLifetime + 5*time.Minute
)

type certificateTest struct {
	api.CertificateTest
	source     netip.Addr
	local      netip.Addr
	origin     string
	generation uint64
	leaf       *tls.Certificate
}

// Management leaves are persistent. Challenges own separate, temporary leaves
// served only to their source/router IP pair until completed or expired.
// Existing connections keep serving ordinary requests but cannot prove a new test.
type apiTLSIdentity struct {
	authority  *localca.Authority
	config     *tls.Config
	directory  string
	mu         sync.Mutex
	retired    bool
	leaves     map[netip.Addr]*tls.Certificate
	tests      map[string]certificateTest
	generation uint64
}

func newAPITLSIdentity(authority *localca.Authority, directory string) *apiTLSIdentity {
	i := &apiTLSIdentity{authority: authority, directory: directory, leaves: make(map[netip.Addr]*tls.Certificate), tests: make(map[string]certificateTest)}
	i.config = &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, SessionTicketsDisabled: true, GetCertificate: i.getCertificate}
	return i
}

// retire joins certificate persistence before a replacement identity can use the
// same store. A handshake that already selected this config must not publish later.
func (i *apiTLSIdentity) retire() {
	if i == nil {
		return
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	i.retired = true
	clear(i.tests)
	clear(i.leaves)
}

func (i *apiTLSIdentity) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	local, ok := hello.Conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("API HTTPS requires a TCP connection")
	}
	ip := local.AddrPort().Addr().Unmap().WithZone("")
	if hello.ServerName != "" && hello.ServerName != ip.String() {
		return nil, fmt.Errorf("API TLS SNI differs from connected router IP")
	}
	remote, ok := hello.Conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("API HTTPS requires a TCP peer")
	}
	source := remote.AddrPort().Addr().Unmap()
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.retired {
		return nil, fmt.Errorf("API TLS identity is retired")
	}
	connection := hello.Context().Value(tlsGenerationKey{}).(*tlsConnectionGeneration)
	now := time.Now()
	i.expireTests(now)
	var newest certificateTest
	for _, test := range i.tests {
		if test.source == source && test.local == ip && test.generation > newest.generation {
			newest = test
		}
	}
	if newest.leaf != nil {
		connection.certificate = newest.generation
		return newest.leaf, nil
	}
	certificate, ok := i.leaves[ip]
	if !ok || !now.Before(certificate.Leaf.NotAfter) {
		var err error
		certificate, err = i.managementCertificate(ip)
		if err != nil {
			return nil, err
		}
	}
	// Persistent leaves never count as proof, even when loaded after a test.
	connection.certificate = 0
	return certificate, nil
}

// Caller holds mu. Issuance is serialized only on the API control path.
func (i *apiTLSIdentity) managementCertificate(ip netip.Addr) (*tls.Certificate, error) {
	if i.directory == "" {
		return nil, fmt.Errorf("API TLS requires a certificate store directory")
	}
	if _, exists := i.leaves[ip]; !exists && len(i.leaves) >= maxAPICertificates {
		return nil, fmt.Errorf("too many API TLS addresses")
	}
	path := filepath.Join(i.directory, strings.ReplaceAll(i.authority.Fingerprint(), ":", ""), ip.String()+".pem")
	leaf, err := i.authority.PersistentServerCertificate(path, ip.String())
	if err != nil && !persist.Published(err) {
		return nil, err
	}
	i.leaves[ip] = leaf
	return leaf, err
}

// Caller holds mu. Expiry is checked on both handshakes and challenge requests.
func (i *apiTLSIdentity) expireTests(now time.Time) {
	for id, test := range i.tests {
		if !now.Before(test.ExpiresAt) {
			delete(i.tests, id)
		}
	}
}

func (s *handler) serveCertificateTest(w http.ResponseWriter, r *http.Request, _ caller) {
	if !apiBody(w, r, nil) {
		return
	}
	identity, _ := r.Context().Value(tlsIdentityKey{}).(*apiTLSIdentity)
	local, tcp := r.Context().Value(http.LocalAddrContextKey).(*net.TCPAddr)
	source, err := netip.ParseAddrPort(r.RemoteAddr)
	if identity == nil || !tcp || err != nil {
		apiError(w, http.StatusServiceUnavailable, "certificate tests require the TCP API listener")
		return
	}
	ip := local.AddrPort().Addr().Unmap().WithZone("")
	identity.mu.Lock()
	defer identity.mu.Unlock()
	now := time.Now()
	identity.expireTests(now)
	if r.Method == http.MethodPost {
		pending := 0
		for _, test := range identity.tests {
			if test.source == source.Addr().Unmap() {
				pending++
			}
		}
		if pending >= maxCertificateTestsPerSource || len(identity.tests) >= maxCertificateTests {
			apiError(w, http.StatusTooManyRequests, "too many certificate tests; retry in one minute")
			return
		}
		leaf, err := identity.authority.TemporaryServerCertificate(ip.String(), certificateTestLeafLifetime)
		if err != nil {
			apiError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		identity.generation++
		test := certificateTest{
			ID: rand.Text(), CAFingerprint: identity.authority.Fingerprint(), ExpiresAt: now.Add(certificateTestLifetime),
			source: source.Addr().Unmap(), local: ip, origin: requestOrigin(r), generation: identity.generation, leaf: leaf,
		}
		identity.tests[test.ID] = test
		// A test started on HTTPS must not reuse this response's old handshake.
		w.Header().Set("Connection", "close")
		writeAPIStatus(w, test.CertificateTest, http.StatusCreated)
		return
	}
	test, exists := identity.tests[r.PathValue("id")]
	if !exists || test.source != source.Addr().Unmap() || test.local != ip {
		apiError(w, http.StatusNotFound, "certificate test expired or belongs to another connection address")
		return
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = requestOrigin(r)
	}
	if r.TLS == nil || origin != test.origin {
		apiError(w, http.StatusForbidden, "certificate proof requires HTTPS from the initiating page")
		return
	}
	connection, _ := r.Context().Value(tlsGenerationKey{}).(*tlsConnectionGeneration)
	w.Header().Set("Connection", "close")
	if connection == nil || connection.identity != identity || connection.certificate < test.generation {
		// Only this stale connection is retired. Other users can continue their
		// ordinary API requests; parallel challenges may use any newer leaf.
		apiError(w, http.StatusConflict, "certificate test requires a new TLS handshake; retry")
		return
	}
	delete(identity.tests, test.ID)
	writeAPI(w, test.CertificateTest)
}
