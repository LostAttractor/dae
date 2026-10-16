// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"errors"
	"net/http"
	"slices"
)

// Redirect admission owns the callback order, hop limit and HTTPS boundary.
// Fetch only changes how the next request's method and body are prepared.
func (o scriptHTTPOptions) redirectPolicy(check func(*http.Request, []*http.Request) error) func(*http.Request, []*http.Request) error {
	if !o.AutoRedirect {
		return func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return func(req *http.Request, via []*http.Request) (err error) {
		previous := via[len(via)-1]
		previousHTTPS := previous.URL.Scheme == "https"
		if o.Fetch {
			// This body was replayed for Fetch and must be closed even when
			// the caller's policy returns the original redirect response.
			defer func() {
				if err != nil && req.Body != nil {
					req.Body.Close()
				}
			}()
			if err := prepareFetchRedirect(req, previous); err != nil {
				return err
			}
		}
		if check != nil {
			if err := check(req, via); err != nil {
				return err
			}
		} else if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		// The callback may replace the target URL. Validate what will be sent,
		// after honoring errors or a request to return the original response.
		if previousHTTPS && req.URL.Scheme == "http" {
			return errors.New("HTTPS script redirect cannot downgrade to HTTP")
		}
		return nil
	}
}

// Correct net/http's 301/302 method rewrite without changing its cookies,
// sensitive-header filtering or redirect admission decisions.
func prepareFetchRedirect(req, previous *http.Request) error {
	status := req.Response.StatusCode
	dropBody := (status == 301 || status == 302) && previous.Method == http.MethodPost ||
		status == 303 && previous.Method != http.MethodGet && previous.Method != http.MethodHead

	// net/http permanently drops its replay body after any 301/302, even when
	// Fetch preserves the method. Derive each hop from the preceding request.
	if req.Body != nil {
		req.Body.Close()
	}
	req.Method, req.Body, req.GetBody, req.ContentLength = previous.Method, nil, nil, 0
	if dropBody {
		req.Method = http.MethodGet
	} else {
		req.GetBody, req.ContentLength = previous.GetBody, previous.ContentLength
		if req.GetBody != nil {
			var err error
			req.Body, err = req.GetBody()
			if err != nil {
				return err
			}
		}
	}
	for _, name := range []string{"Content-Encoding", "Content-Language", "Content-Location", "Content-Type"} {
		req.Header.Del(name)
		if !dropBody {
			if values := previous.Header.Values(name); len(values) != 0 {
				req.Header[name] = slices.Clone(values)
			}
		}
	}
	return nil
}
