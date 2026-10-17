package tls

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

const (
	realitySpiderLifetime  = 10 * time.Second
	realitySpiderBodyLimit = 1 << 20
	realitySpiderPathLimit = 4096
	realitySpiderPathCount = 256
	realitySpiderPathBytes = 256 << 10
)

// Bound concurrent camouflage across nodes as well as within each node. No
// worker or connection is retained waiting for admission.
var realitySpiderSlots = make(chan struct{}, 8)
var realitySpiderHref = regexp.MustCompile(`href="([/h].*?)"`)

type realitySpiderRange struct{ min, max int64 }
type realitySpiderConfig struct {
	padding, concurrency, requests, interval, returnDelay realitySpiderRange
}

func parseRealitySpider(path string) (string, realitySpiderConfig, error) {
	var cfg realitySpiderConfig
	if path == "" {
		path = "/"
	}
	if len(path) > realitySpiderPathLimit || !strings.HasPrefix(path, "/") {
		return "", cfg, errors.New("invalid REALITY spider path")
	}
	u, err := url.Parse(path)
	if err != nil {
		return "", cfg, fmt.Errorf("invalid REALITY spider path: %w", err)
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", cfg, fmt.Errorf("invalid REALITY spider query: %w", err)
	}
	for _, field := range []struct {
		name    string
		maximum int64
		dest    *realitySpiderRange
	}{
		{"p", 4096, &cfg.padding}, {"c", 8, &cfg.concurrency}, {"t", 8, &cfg.requests},
		{"i", 60000, &cfg.interval}, {"r", 5000, &cfg.returnDelay},
	} {
		values, present := q[field.name]
		if !present {
			continue
		}
		if len(values) != 1 {
			return "", cfg, fmt.Errorf("duplicate REALITY spider parameter %s", field.name)
		}
		lo, hi, ranged := strings.Cut(values[0], "-")
		if !ranged {
			hi = lo
		}
		left, leftErr := strconv.ParseInt(lo, 10, 64)
		right, rightErr := strconv.ParseInt(hi, 10, 64)
		if leftErr != nil || rightErr != nil || left < 0 || right < left || right > field.maximum {
			return "", cfg, fmt.Errorf("REALITY spider parameter %s must be an ordered range within 0..%d", field.name, field.maximum)
		}
		*field.dest = realitySpiderRange{left, right}
		q.Del(field.name)
	}
	u.RawQuery = q.Encode()
	return u.String(), cfg, nil
}

// startSpider takes ownership of conn only on success. The task has its own
// bounded lifetime because callers normally cancel the failed dial immediately.
func (x *Reality) startSpider(conn net.Conn) bool {
	x.spiderMu.Lock()
	defer x.spiderMu.Unlock()
	if x.spiderClosed || x.spiderCancel != nil {
		return false
	}
	select {
	case realitySpiderSlots <- struct{}{}:
	default:
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), realitySpiderLifetime)
	x.spiderCancel = cancel
	x.spiderWorkers.Go(func() {
		defer func() {
			cancel()
			x.spiderMu.Lock()
			x.spiderCancel = nil
			x.spiderMu.Unlock()
			<-realitySpiderSlots
		}()
		x.runSpider(ctx, conn)
	})
	return true
}

// Close releases only this layer's camouflage tasks, never its borrowed dialer.
func (x *Reality) Close() error {
	x.spiderMu.Lock()
	x.spiderClosed = true
	if x.spiderCancel != nil {
		x.spiderCancel()
	}
	x.spiderMu.Unlock()
	x.spiderWorkers.Wait()
	return nil
}

func (x *Reality) runSpider(ctx context.Context, conn net.Conn) {
	closeConn := sync.OnceFunc(func() { _ = conn.Close() })
	stopClose := context.AfterFunc(ctx, closeConn)
	defer stopClose()
	defer closeConn()
	transport := &http2.Transport{MaxHeaderListSize: 32 << 10}
	clientConn, err := transport.NewClientConn(conn)
	if err != nil {
		return
	}
	defer clientConn.Close()
	x.crawlSpider(ctx, &http.Client{Transport: clientConn, Timeout: realitySpiderLifetime})
}

// Paths belong to one bounded crawl, so no process-global history survives a
// failed connection or node reload. Workers share only this bounded set.
type realitySpiderPaths struct {
	sync.Mutex
	paths []string
	bytes int
}

func (p *realitySpiderPaths) choose() string {
	p.Lock()
	defer p.Unlock()
	if len(p.paths) == 0 {
		return "/"
	}
	return p.paths[randBetween(0, int64(len(p.paths)))]
}

func (p *realitySpiderPaths) add(path string) {
	if len(path) > realitySpiderPathLimit || path == "" {
		return
	}
	p.Lock()
	defer p.Unlock()
	if len(p.paths) >= realitySpiderPathCount || p.bytes+len(path) > realitySpiderPathBytes {
		return
	}
	if slices.Contains(p.paths, path) {
		return
	}
	p.paths = append(p.paths, strings.Clone(path))
	p.bytes += len(path)
}

func (x *Reality) crawlSpider(ctx context.Context, client *http.Client) {
	paths := new(realitySpiderPaths)
	paths.add(x.spiderX)
	prefix := "https://" + x.serverName
	firstURL := prefix + paths.choose()
	get := func(count int, referer string) bool {
		for i := range count {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, prefix+paths.choose(), nil)
			if err != nil {
				return false
			}
			req.Header.Set("User-Agent", x.fingerprint.Client)
			if referer != "" {
				req.Header.Set("Referer", referer)
			}
			req.AddCookie(&http.Cookie{Name: "padding", Value: strings.Repeat("0", int(randBetween(x.spider.padding.min, x.spider.padding.max)))})
			resp, err := client.Do(req)
			if err != nil {
				return false
			}
			// Read at most limit+1, including decoded bodies. Every outcome closes the
			// stream, and its request context interrupts both headers and slow bodies.
			body, err := io.ReadAll(io.LimitReader(resp.Body, realitySpiderBodyLimit+1))
			resp.Body.Close()
			if err != nil || len(body) > realitySpiderBodyLimit || ctx.Err() != nil {
				return false
			}
			for _, match := range realitySpiderHref.FindAllSubmatch(body, realitySpiderPathCount) {
				path := bytes.TrimPrefix(match[1], []byte(prefix))
				if !bytes.ContainsRune(path, '.') {
					paths.add(string(path))
				}
			}
			referer = req.URL.String()
			if i+1 < count && !waitRealitySpider(ctx, time.Duration(randBetween(x.spider.interval.min, x.spider.interval.max))*time.Millisecond) {
				return false
			}
		}
		return true
	}
	if !get(1, "") {
		return
	}
	var workers sync.WaitGroup
	for range int(randBetween(x.spider.concurrency.min, x.spider.concurrency.max)) {
		workers.Go(func() { get(int(randBetween(x.spider.requests.min, x.spider.requests.max)), firstURL) })
	}
	workers.Wait()
}

func waitRealitySpider(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return ctx.Err() == nil
	}
}
