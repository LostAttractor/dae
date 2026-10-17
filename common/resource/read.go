// SPDX-License-Identifier: AGPL-3.0-only

package resource

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common/fileio"
)

type ReadOptions struct {
	MaxBytes  int64
	UserAgent string
	// Nil uses the refresh session's default. Zero disables automatic checks.
	RefreshInterval *time.Duration
}

type Result struct {
	Data     []byte `json:"data"`
	Location string `json:"location"`
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
	f, info, err := OpenLocalFile(source.Location, "")
	if err != nil {
		return Result{}, err
	}
	defer f.Close()
	if info.Size() > opts.MaxBytes {
		return Result{}, fmt.Errorf("resource file exceeds %d bytes", opts.MaxBytes)
	}
	data, err := fileio.ReadBounded(ctx, f, opts.MaxBytes)
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
		// Resource URLs can contain credentials in both the path and query.
		// net/http derives this header on every hop; callbacks may also set it.
		next.Header.Del("Referer")
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
	data, err := fileio.ReadBounded(ctx, response.Body, opts.MaxBytes)
	if err != nil {
		return Result{}, err
	}
	return Result{Data: data, Location: final.Location}, nil
}
