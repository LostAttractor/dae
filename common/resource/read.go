// SPDX-License-Identifier: AGPL-3.0-only

package resource

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/daeuniverse/dae/common"
	"golang.org/x/sys/unix"
)

type ReadOptions struct {
	MaxBytes  int64
	UserAgent string
}

type Result struct {
	Data     []byte
	Location string
}

// Read reads one bounded resource without validating its content or caching it.
// The caller supplies network routing and timeouts through ctx and client.
func Read(ctx context.Context, client *http.Client, source Source, opts ReadOptions) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if opts.MaxBytes <= 0 || opts.MaxBytes == math.MaxInt64 {
		return Result{}, errors.New("resource byte limit must be positive and less than MaxInt64")
	}
	if source.Remote() {
		result, err := readRemote(ctx, client, source, opts)
		return result, RedactError(err)
	}
	if !filepath.IsAbs(source.Location) {
		return Result{}, errors.New("local resource location must be an absolute path")
	}
	// A FIFO must not block open before the regular-file check. Symlinks are
	// allowed here; callers handling credentials can use stricter file policies.
	fd, err := unix.Open(source.Location, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return Result{}, &os.PathError{Op: "open resource", Path: source.Location, Err: err}
	}
	f := os.NewFile(uintptr(fd), source.Location)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return Result{}, err
	}
	if !info.Mode().IsRegular() {
		return Result{}, errors.New("resource source must be a regular file")
	}
	if info.Size() > opts.MaxBytes {
		return Result{}, fmt.Errorf("resource file exceeds %d bytes", opts.MaxBytes)
	}
	data, err := readBounded(ctx, f, opts.MaxBytes)
	if err != nil {
		return Result{}, err
	}
	return Result{Data: data, Location: source.Location}, nil
}

func readRemote(ctx context.Context, client *http.Client, source Source, opts ReadOptions) (Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source.Location, nil)
	if err != nil {
		return Result{}, err
	}
	if opts.UserAgent != "" {
		req.Header.Set("User-Agent", opts.UserAgent)
	}
	if client == nil {
		client = http.DefaultClient
	}
	boundedClient := *client
	previousRedirect := client.CheckRedirect
	boundedClient.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		validate := func() error {
			if next.URL.Scheme != "http" && next.URL.Scheme != "https" {
				return errors.New("resource redirect must use HTTP or HTTPS")
			}
			if next.URL.Scheme == "http" && (strings.HasPrefix(source.Location, "https://") || len(via) > 0 && via[len(via)-1].URL.Scheme == "https") {
				return errors.New("HTTPS resource redirect cannot downgrade to HTTP")
			}
			return nil
		}
		if err := validate(); err != nil {
			return err
		}
		if len(via) >= 10 {
			return errors.New("resource download exceeded 10 redirects")
		}
		if previousRedirect != nil {
			if err := previousRedirect(next, via); err != nil {
				return err
			}
		}
		return validate()
	}
	response, err := boundedClient.Do(req)
	if err != nil {
		return Result{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return Result{}, fmt.Errorf("resource request returned HTTP status %d", response.StatusCode)
	}
	if response.ContentLength > opts.MaxBytes {
		return Result{}, fmt.Errorf("resource response exceeds %d bytes", opts.MaxBytes)
	}
	location := source.Location
	if response.Request != nil && response.Request.URL != nil {
		location = response.Request.URL.String()
	}
	final, err := Parse(location, "")
	if err != nil || !final.Remote() {
		return Result{}, errors.New("resource response location must use HTTP or HTTPS")
	}
	if strings.HasPrefix(source.Location, "https://") && !strings.HasPrefix(final.Location, "https://") {
		return Result{}, errors.New("HTTPS resource response cannot downgrade to HTTP")
	}
	data, err := readBounded(ctx, response.Body, opts.MaxBytes)
	if err != nil {
		return Result{}, err
	}
	return Result{Data: data, Location: final.Location}, nil
}

func readBounded(ctx context.Context, reader io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(common.NewContextReader(ctx, reader), limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("resource source exceeds %d bytes", limit)
	}
	return data, ctx.Err()
}
