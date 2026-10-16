// SPDX-License-Identifier: AGPL-3.0-only

package ca

import (
	"context"
	"crypto"
	"crypto/tls"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type heldSigner struct {
	crypto.Signer
	entered chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (s *heldSigner) Sign(random io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.calls.Add(1)
	s.entered <- struct{}{}
	<-s.release
	return s.Signer.Sign(random, digest, opts)
}

func TestIssuanceDoesNotBlockHitsAndCoalescesHosts(t *testing.T) {
	a, _, _ := testAuthority(t)
	cached, err := a.ServerCertificate("cached.test")
	if err != nil {
		t.Fatal(err)
	}
	signer := &heldSigner{Signer: a.key.(crypto.Signer), entered: make(chan struct{}, 32), release: make(chan struct{})}
	a.key = signer
	release := sync.OnceFunc(func() { close(signer.release) })
	defer release()
	results := make(chan *tls.Certificate, 20)
	errs := make(chan error, 20)
	var workers sync.WaitGroup
	for range 20 {
		workers.Go(func() { cert, err := a.ServerCertificate("pending.test"); results <- cert; errs <- err })
	}
	<-signer.entered
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	got, err := a.serverCertificate(ctx, "cached.test")
	if err != nil || got != cached {
		t.Fatalf("cache hit blocked behind signer: %v", err)
	}
	canceled, stop := context.WithCancel(t.Context())
	stop()
	if _, err := a.serverCertificate(canceled, "pending.test"); err != context.Canceled {
		t.Fatalf("canceled waiter: %v", err)
	}
	release()
	workers.Wait()
	close(results)
	close(errs)
	var first *tls.Certificate
	for cert := range results {
		if first == nil {
			first = cert
		}
		if cert != first {
			t.Fatal("same host issued twice")
		}
	}
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if signer.calls.Load() != 1 {
		t.Fatalf("signatures = %d", signer.calls.Load())
	}
}

func TestIssuanceConcurrencyIsBounded(t *testing.T) {
	a, _, _ := testAuthority(t)
	signer := &heldSigner{Signer: a.key.(crypto.Signer), entered: make(chan struct{}, 32), release: make(chan struct{})}
	a.key = signer
	release := sync.OnceFunc(func() { close(signer.release) })
	defer release()
	var workers sync.WaitGroup
	for i := range 16 {
		workers.Go(func() {
			if _, err := a.ServerCertificate(fmt.Sprintf("host%d.test", i)); err != nil {
				t.Error(err)
			}
		})
	}
	for range maxConcurrentIssuances {
		select {
		case <-signer.entered:
		case <-time.After(5 * time.Second):
			t.Fatal("signers did not start")
		}
	}
	a.mu.Lock()
	pending := len(a.issuing)
	a.mu.Unlock()
	if pending != maxConcurrentIssuances || signer.calls.Load() != maxConcurrentIssuances {
		t.Fatalf("pending=%d signing=%d", pending, signer.calls.Load())
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := a.serverCertificate(ctx, "canceled.test"); err != context.Canceled {
		t.Fatalf("queued cancellation: %v", err)
	}
	release()
	workers.Wait()
}
