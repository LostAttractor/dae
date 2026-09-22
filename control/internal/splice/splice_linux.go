//go:build linux && dae_splice

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>

package splice

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/common/stats"
	internal "github.com/daeuniverse/dae/pkg/ebpf_internal"
)

var minimumSpliceKernelVersion = internal.Version{6, 18, 0}

// Runtime owns the optional sockhash relay and keeps its BPF objects alive until
// all active sessions finish, even if Close has stopped admitting new sessions.
type Runtime struct {
	objects     bpf_spliceObjects
	links       []link.Link
	idleTimeout time.Duration
	mu          sync.Mutex
	sessions    int
	closing     bool
	closeErr    error
}

func New(opts *ebpf.CollectionOptions, idleTimeout time.Duration) (_ *Runtime, err error) {
	kernelVersion, err := internal.KernelVersion()
	if err != nil {
		return nil, fmt.Errorf("detect kernel version: %w", err)
	}
	if kernelVersion.Less(minimumSpliceKernelVersion) {
		return nil, nil
	}

	spec, err := loadBpf_splice()
	if err != nil {
		return nil, fmt.Errorf("load splice collection spec: %w", err)
	}
	runtime := &Runtime{idleTimeout: idleTimeout}
	defer func() {
		if err != nil {
			_ = runtime.Close()
		}
	}()
	if err = spec.LoadAndAssign(&runtime.objects, opts); err != nil {
		return nil, fmt.Errorf("load splice objects: %w", err)
	}

	skbLink, err := link.AttachRawLink(link.RawLinkOptions{
		Target:  runtime.objects.SpliceSocks.FD(),
		Program: runtime.objects.SpliceStreamVerdict,
		Attach:  ebpf.AttachSkSKBStreamVerdict,
	})
	if err != nil {
		return nil, fmt.Errorf("attach splice SK_SKB verdict: %w", err)
	}
	runtime.links = append(runtime.links, skbLink)

	for _, tracing := range []struct {
		name    string
		program *ebpf.Program
	}{
		{"SK_SKB fault", runtime.objects.SpliceAccountSkbFault},
		{"egress", runtime.objects.SpliceAccountEgress},
	} {
		tracingLink, err := link.AttachTracing(link.TracingOptions{Program: tracing.program})
		if err != nil {
			return nil, fmt.Errorf("attach splice %s accounting: %w", tracing.name, err)
		}
		runtime.links = append(runtime.links, tracingLink)
	}

	return runtime, nil
}

func (r *Runtime) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closing {
		r.closing = true
		if r.sessions == 0 {
			r.closeLocked()
		}
	}
	return r.closeErr
}

func (r *Runtime) beginSession() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing {
		return false
	}
	r.sessions++
	return true
}

func (r *Runtime) endSession() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions--
	if r.closing && r.sessions == 0 {
		r.closeLocked()
	}
}

func (r *Runtime) closeLocked() {
	for i := len(r.links) - 1; i >= 0; i-- {
		r.closeErr = errors.Join(r.closeErr, r.links[i].Close())
	}
	r.links = nil
	r.closeErr = errors.Join(r.closeErr, r.objects.Close())
}

// Relay joins two already-connected TCP sockets. A false handled result means
// neither stream was consumed and the caller may use its ordinary relay. Once
// registered, the session owns any transition from kernel to userspace copying.
// The caller remains responsible for closing the connections.
func (r *Runtime) Relay(acceptedConn, remoteConn TCPConn, traffic *stats.Connection, observers ...func()) (handled bool, err error) {
	if !r.beginSession() {
		return false, nil
	}
	defer r.endSession()
	defer func() { err = runtimeFailure(err) }()
	if !spliceSocketEligible(acceptedConn) || !spliceSocketEligible(remoteConn) {
		return false, nil
	}

	acceptedCookie, err := r.registerSocket(acceptedConn)
	if err != nil {
		return false, nil
	}
	remoteCookie, err := r.registerSocket(remoteConn)
	if err != nil {
		r.cleanupMetadata(acceptedCookie)
		return false, nil
	}
	defer func() {
		// Read the final BPF counters before deleting their map entries.
		if traffic != nil {
			err = errors.Join(err, traffic.Close())
		}
		r.cleanupMetadata(acceptedCookie, remoteCookie)
	}()
	if traffic != nil {
		if err := r.attachTrafficCounters(traffic, acceptedCookie, remoteCookie); err != nil {
			return true, err
		}
	}

	activity := func() {
		for _, observe := range observers {
			if observe != nil {
				observe()
			}
		}
	}
	edges := [2]*spliceDirectEdge{
		{
			src: acceptedConn, dst: remoteConn,
			srcCookie: acceptedCookie, dstCookie: remoteCookie,
			activity: activity,
			recordBytes: func(bytes uint64) {
				if bytes > 0 {
					activity()
				}
				if traffic != nil {
					traffic.RecordUpload(bytes)
				}
			},
		},
		{
			src: remoteConn, dst: acceptedConn,
			srcCookie: remoteCookie, dstCookie: acceptedCookie,
			activity: activity,
			recordBytes: func(bytes uint64) {
				if bytes > 0 {
					activity()
				}
				if traffic != nil {
					traffic.RecordDownload(bytes)
				}
			},
		},
	}
	if err := r.pumpAndArm(edges); err != nil {
		_ = r.setPass(acceptedCookie)
		_ = r.setPass(remoteCookie)
		return true, err
	}
	return true, r.runDirectSession(edges)
}

func (r *Runtime) attachTrafficCounters(traffic *stats.Connection, acceptedCookie, remoteCookie uint64) error {
	return traffic.AttachExternalCounters(func() (api.TrafficCounters, error) {
		upload, err := r.stats(acceptedCookie)
		if err != nil {
			return api.TrafficCounters{}, err
		}
		download, err := r.stats(remoteCookie)
		if err != nil {
			return api.TrafficCounters{}, err
		}
		return api.TrafficCounters{
			UploadBytes:   upload.SkbRedirected,
			DownloadBytes: download.SkbRedirected,
		}, nil
	})
}
