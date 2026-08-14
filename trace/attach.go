//go:build trace && (amd64 || arm64 || riscv64 || loong64 || ppc64 || ppc64le)

/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package trace

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	log "github.com/sirupsen/logrus"
)

const maxDetachWorkers = 64

func closeLinksConcurrently(links []link.Link, maxWorkers int) error {
	closers := make([]func() error, 0, len(links))
	for _, lnk := range links {
		closers = append(closers, lnk.Close)
	}
	return runClosersConcurrently(closers, maxWorkers)
}

func runClosersConcurrently(closers []func() error, maxWorkers int) error {
	if len(closers) == 0 {
		return nil
	}
	workers := min(max(maxWorkers, 1), len(closers))
	jobs := make(chan func() error, len(closers))
	errs := make(chan error, len(closers))
	for _, closeFn := range closers {
		jobs <- closeFn
	}
	close(jobs)

	var workersDone sync.WaitGroup
	workersDone.Add(workers)
	for range workers {
		go func() {
			defer workersDone.Done()
			for closeFn := range jobs {
				if err := closeFn(); err != nil {
					errs <- err
				}
			}
		}()
	}
	workersDone.Wait()
	close(errs)

	var err error
	for closeErr := range errs {
		err = errors.Join(err, closeErr)
	}
	return err
}

type producerDetacher struct {
	control traceControl
	owner   io.Closer
	closers []func() error

	once        sync.Once
	releaseOnce sync.Once
	done        chan struct{}
	detached    chan struct{}
	release     chan struct{}
	stopErr     error
	linksErr    error
	ownerErr    error
}

type traceControl interface {
	Update(key, value any, flags ebpf.MapUpdateFlags) error
}

func setTraceProducers(control traceControl, stopped bool) error {
	key := uint32(0)
	value := uint32(0)
	operation := "enable"
	if stopped {
		value = 1
		operation = "disable"
	}
	if err := control.Update(&key, &value, ebpf.UpdateExist); err != nil {
		return fmt.Errorf("%s trace producers: %w", operation, err)
	}
	return nil
}

func stopTraceProducers(control traceControl) error {
	return setTraceProducers(control, true)
}

func newProducerDetacher(links []link.Link, control traceControl, owner io.Closer) *producerDetacher {
	closers := make([]func() error, 0, len(links))
	for _, lnk := range links {
		closers = append(closers, lnk.Close)
	}
	return &producerDetacher{
		control:  control,
		owner:    owner,
		closers:  closers,
		done:     make(chan struct{}),
		detached: make(chan struct{}),
		release:  make(chan struct{}),
	}
}

func (d *producerDetacher) start() error {
	d.once.Do(func() {
		d.stopErr = stopTraceProducers(d.control)
		go func() {
			fmt.Printf("\ndetaching %d trace probes\n", len(d.closers))
			d.linksErr = runClosersConcurrently(d.closers, maxDetachWorkers)
			close(d.detached)
			<-d.release
			if closeErr := d.owner.Close(); closeErr != nil {
				d.ownerErr = fmt.Errorf("close trace BPF objects: %w", closeErr)
			}
			if cleanupErr := errors.Join(d.linksErr, d.ownerErr); cleanupErr != nil {
				log.Errorf("failed to clean up trace probes: %+v", cleanupErr)
			}
			close(d.done)
		}()
	})
	return d.stopErr
}

func (d *producerDetacher) waitDetached() error {
	<-d.detached
	return d.linksErr
}

func (d *producerDetacher) releaseObjects() {
	d.releaseOnce.Do(func() { close(d.release) })
}

type probeAttachment interface {
	Close() error
}

func groupTargetsByPosition(targets []probeTarget) [5][]string {
	var groups [5][]string
	for _, target := range targets {
		if target.skbPosition >= 1 && target.skbPosition <= len(groups) {
			groups[target.skbPosition-1] = append(groups[target.skbPosition-1], target.name)
		}
	}
	return groups
}

func attachProbeGroup(
	symbols []string,
	useMulti bool,
	attachMulti func([]string) (probeAttachment, error),
	attachSingle func(string) (probeAttachment, error),
) ([]probeAttachment, int, error) {
	if len(symbols) == 0 {
		return nil, 0, nil
	}
	if !useMulti {
		return attachSingleProbes(symbols, attachSingle)
	}
	return attachMultiProbeBatch(symbols, attachMulti, attachSingle)
}

func attachSingleProbes(symbols []string, attachSingle func(string) (probeAttachment, error)) (attached []probeAttachment, attachedSymbols int, attachErr error) {
	for _, symbol := range symbols {
		singleLink, err := attachSingle(symbol)
		if err != nil {
			attachErr = errors.Join(attachErr, fmt.Errorf("%s: %w", symbol, err))
			continue
		}
		if singleLink == nil {
			attachErr = errors.Join(attachErr, fmt.Errorf("%s: attach returned no link", symbol))
			continue
		}
		attached = append(attached, singleLink)
		attachedSymbols++
	}
	return attached, attachedSymbols, attachErr
}

func attachMultiProbeBatch(
	symbols []string,
	attachMulti func([]string) (probeAttachment, error),
	attachSingle func(string) (probeAttachment, error),
) ([]probeAttachment, int, error) {
	multiLink, err := attachMulti(symbols)
	if err == nil {
		if multiLink == nil {
			return nil, 0, fmt.Errorf("multi-kprobe attach for %d symbols returned no link", len(symbols))
		}
		return []probeAttachment{multiLink}, len(symbols), nil
	}
	if multiLink != nil {
		if closeErr := multiLink.Close(); closeErr != nil {
			return nil, 0, errors.Join(err, fmt.Errorf("close failed multi-kprobe attachment before retry: %w", closeErr))
		}
	}
	if errors.Is(err, link.ErrNotSupported) {
		return attachSingleProbes(symbols, attachSingle)
	}
	if !isSplittableMultiAttachError(err) {
		return nil, 0, err
	}
	if len(symbols) == 1 {
		return nil, 0, fmt.Errorf("%s: %w", symbols[0], err)
	}

	middle := len(symbols) / 2
	leftLinks, leftCount, leftErr := attachMultiProbeBatch(symbols[:middle], attachMulti, attachSingle)
	rightLinks, rightCount, rightErr := attachMultiProbeBatch(symbols[middle:], attachMulti, attachSingle)
	return append(leftLinks, rightLinks...), leftCount + rightCount, errors.Join(leftErr, rightErr)
}

func isSplittableMultiAttachError(err error) bool {
	return errors.Is(err, os.ErrNotExist) ||
		errors.Is(err, syscall.E2BIG) ||
		errors.Is(err, syscall.EINVAL) ||
		errors.Is(err, syscall.ENOENT)
}

func skbProgramAt(objs *traceObjects, position int, multi bool) *ebpf.Program {
	if position < 1 || position > len(objs.skbPrograms[0]) {
		return nil
	}
	kind := singleProbeProgram
	if multi {
		kind = multiProbeProgram
	}
	return objs.skbPrograms[kind][position-1]
}

func probeKprobeMultiSupport(objs *traceObjects, targets []probeTarget) bool {
	for _, target := range targets {
		program := skbProgramAt(objs, target.skbPosition, true)
		if program == nil {
			continue
		}
		probe, err := link.KprobeMulti(program, link.KprobeMultiOptions{Symbols: []string{target.name}})
		if err != nil {
			if errors.Is(err, link.ErrNotSupported) {
				log.Debugf("multi-kprobe unavailable, using bounded legacy fallback: %v", err)
				return false
			}
			continue
		}
		if err := probe.Close(); err != nil {
			log.Debugf("failed to close multi-kprobe capability probe, using bounded legacy fallback: %v", err)
			return false
		}
		return true
	}
	return false
}

func attachBpfToTargets(objs *traceObjects, targets []probeTarget, useKfreeReason bool, useKprobeMulti bool) (links []link.Link, attachedTargets int, err error) {
	for _, symbol := range []string{"kfree_skbmem", "__napi_kfree_skb"} {
		lifetime, err := link.Kprobe(symbol, objs.lifetimeEnd, nil)
		if err != nil {
			_ = closeLinksConcurrently(links, maxDetachWorkers)
			return nil, 0, fmt.Errorf("failed to attach skb lifetime probe to %s: %w", symbol, err)
		}
		links = append(links, lifetime)
	}

	kfreeProgram := objs.kfreeSkb[legacyKfreeProgram]
	if useKfreeReason {
		kfreeProgram = objs.kfreeSkb[reasonKfreeProgram]
	}
	raw, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "kfree_skb", Program: kfreeProgram})
	if err != nil {
		_ = closeLinksConcurrently(links, maxDetachWorkers)
		return nil, 0, fmt.Errorf("failed to attach kfree_skb raw tracepoint: %w", err)
	}
	links = append(links, raw)
	raw, err = link.AttachRawTracepoint(link.RawTracepointOptions{Name: "consume_skb", Program: objs.consumeSkb})
	if err != nil {
		_ = closeLinksConcurrently(links, maxDetachWorkers)
		return nil, 0, fmt.Errorf("failed to attach consume_skb raw tracepoint: %w", err)
	}
	links = append(links, raw)
	for i, name := range []string{"napi_gro_receive", "napi_gro_frags"} {
		// Attach exits first so an entry can never be observed without its
		// matching cleanup hook during startup.
		raw, err = link.AttachRawTracepoint(link.RawTracepointOptions{Name: name + "_exit", Program: objs.groExit[i]})
		if err != nil {
			_ = closeLinksConcurrently(links, maxDetachWorkers)
			return nil, 0, fmt.Errorf("failed to attach %s_exit raw tracepoint: %w", name, err)
		}
		links = append(links, raw)
		raw, err = link.AttachRawTracepoint(link.RawTracepointOptions{Name: name + "_entry", Program: objs.groEntry[i]})
		if err != nil {
			_ = closeLinksConcurrently(links, maxDetachWorkers)
			return nil, 0, fmt.Errorf("failed to attach %s_entry raw tracepoint: %w", name, err)
		}
		links = append(links, raw)
	}

	attachedGeneric := 0
	groups := groupTargetsByPosition(targets)
	for i, symbols := range groups {
		position := i + 1
		if len(symbols) == 0 {
			continue
		}
		fmt.Printf("attaching skb-argument group %d/5 (%d symbols)\r", position, len(symbols))
		groupLinks, groupAttached, groupErr := attachProbeGroup(
			symbols,
			useKprobeMulti,
			func(symbols []string) (probeAttachment, error) {
				return link.KprobeMulti(skbProgramAt(objs, position, true), link.KprobeMultiOptions{Symbols: symbols})
			},
			func(symbol string) (probeAttachment, error) {
				return link.Kprobe(symbol, skbProgramAt(objs, position, false), nil)
			},
		)
		if groupErr != nil {
			log.Warnf("failed to attach some or all skb argument group %d probes: %+v", position, groupErr)
		}
		for _, attachedLink := range groupLinks {
			links = append(links, attachedLink.(link.Link))
		}
		attachedGeneric += groupAttached
	}
	if attachedGeneric == 0 {
		_ = closeLinksConcurrently(links, maxDetachWorkers)
		return nil, 0, fmt.Errorf("failed to attach kprobes to any target")
	}
	return links, attachedGeneric, nil
}

type probeCoverage struct {
	discovered int
	attached   int
}

func (c probeCoverage) omitted() int {
	return max(c.discovered-c.attached, 0)
}

func (c probeCoverage) incomplete() bool {
	return c.omitted() != 0
}
