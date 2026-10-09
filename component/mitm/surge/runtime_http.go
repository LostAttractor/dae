// SPDX-License-Identifier: AGPL-3.0-only

package surge

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/daeuniverse/dae/pkg/membuffer"
)

type scriptHTTPOptions struct {
	URL          string      `json:"url"`
	Method       string      `json:"method"`
	Headers      http.Header `json:"headers"`
	Body         *string     `json:"body"`
	Binary       *string     `json:"bodyBase64"`
	Timeout      float64     `json:"timeout"`
	AutoRedirect bool        `json:"auto-redirect"`
	AutoCookie   bool        `json:"auto-cookie"`
	FullHeaders  bool        `json:"full-header-mode"`
	Policy       string      `json:"policy"`
	Fetch        bool        `json:"fetch"`
}

func scriptHTTP(ctx context.Context, client *http.Client, spec string, maxBody int64, budget *membuffer.Budget) (string, membuffer.Reservation, error) {
	options := scriptHTTPOptions{AutoRedirect: true, AutoCookie: true}
	if err := json.Unmarshal([]byte(spec), &options); err != nil {
		return "", membuffer.Reservation{}, err
	}
	timeout := 5 * time.Second
	if options.Fetch {
		timeout = 0 // Fetch uses the invocation deadline unless explicitly shortened.
	}
	if options.Timeout > 0 && options.Timeout < 86400 {
		timeout = time.Duration(options.Timeout * float64(time.Second))
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	var body []byte
	if options.Body != nil {
		body = []byte(*options.Body)
	}
	if options.Binary != nil {
		var err error
		body, err = base64.StdEncoding.DecodeString(*options.Binary)
		if err != nil {
			return "", membuffer.Reservation{}, err
		}
	}
	if int64(len(body)) > maxBody {
		return "", membuffer.Reservation{}, membuffer.ErrTooLarge
	}
	requestMemory, err := budget.Reserve(int64(len(body)))
	if err != nil {
		return "", membuffer.Reservation{}, err
	}
	defer requestMemory.Close()
	req, err := http.NewRequestWithContext(ctx, options.Method, options.URL, bytes.NewReader(body))
	if err != nil {
		return "", membuffer.Reservation{}, err
	}
	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		return "", membuffer.Reservation{}, errors.New("$httpClient only supports http and https")
	}
	req.Header, err = resultHeaders(options.Headers)
	if err != nil {
		return "", membuffer.Reservation{}, err
	}
	if host := req.Header.Get("Host"); host != "" {
		req.Host = host
		req.Header.Del("Host")
	}
	requestClient := *client
	if options.Policy != "" {
		transport, ok := client.Transport.(plugin.PolicyTransport)
		if !ok {
			return "", membuffer.Reservation{}, errors.New("HTTP client does not support policy selection")
		}
		requestClient.Transport = scriptPolicyTransport{transport, options.Policy}
	}
	if !options.AutoCookie {
		requestClient.Jar = nil
	}
	if !options.AutoRedirect {
		requestClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	} else if options.Fetch {
		requestClient.CheckRedirect = fetchRedirectPolicy(client.CheckRedirect)
	}
	resp, err := requestClient.Do(req)
	if err != nil {
		return "", membuffer.Reservation{}, err
	}
	return scriptHTTPResponse(ctx, req, resp, maxBody, budget, options.FullHeaders)
}

func scriptHTTPResponse(ctx context.Context, req *http.Request, resp *http.Response, maxBody int64, budget *membuffer.Budget, fullHeaders bool) (string, membuffer.Reservation, error) {
	defer resp.Body.Close()
	raw, err := membuffer.Read(common.NewContextReader(ctx, resp.Body), maxBody, budget)
	defer raw.Close()
	if err != nil {
		return "", membuffer.Reservation{}, err
	}
	data := raw
	encoding := strings.Join(resp.Header.Values("Content-Encoding"), ",")
	if encoding != "" && responseHasBody(req.Method, resp.StatusCode) && len(raw.Bytes()) != 0 {
		// Routed transports preserve wire bytes. Decode before text/binary
		// delivery, applying the same size and shared-memory limits to each layer.
		data, err = decodeBodyView(ctx, raw, encoding, maxBody, budget)
		defer data.Close()
		if err != nil {
			return "", membuffer.Reservation{}, fmt.Errorf("decode $httpClient response: %w", err)
		}
		resp.Header.Del("Content-Encoding")
		resp.Header.Del("Content-Length")
	}
	if err := ctx.Err(); err != nil {
		return "", membuffer.Reservation{}, err
	}
	responseURL, redirected := req.URL.String(), false
	if resp.Request != nil {
		responseURL, redirected = resp.Request.URL.String(), resp.Request.Response != nil
	}
	responseURL, _, _ = strings.Cut(responseURL, "#")
	_, statusText, _ := strings.Cut(resp.Status, " ")
	if resp.ProtoMajor >= 2 {
		statusText = ""
	}
	message := map[string]any{
		"status": resp.StatusCode, "statusText": statusText,
		"headers": runtimeHeaders(resp.Header, fullHeaders), "url": responseURL, "redirected": redirected,
	}
	if len(resp.Trailer) > 0 {
		message["h2_trailers"] = runtimeHeaders(resp.Trailer, fullHeaders)
	}
	// []byte is serialized as base64 by JSON without a separately retained
	// base64 string. Charge the event until Dispatch consumes it or cancellation.
	writer := &membuffer.Buffer{Budget: budget, Limit: 2*maxBody + 1<<20}
	defer writer.Close()
	if err := jsonv2.MarshalWrite(writer, map[string]any{"response": message, "bodyBase64": data.Bytes()}); err != nil {
		return "", membuffer.Reservation{}, err
	}
	view := writer.View()
	defer view.Close()
	memory, err := budget.Reserve(int64(len(view.Bytes())))
	if err != nil {
		return "", membuffer.Reservation{}, err
	}
	event := string(view.Bytes())
	// Serialization and the event copy also belong to the request's timeout.
	// Do not deliver a successful callback after that deadline or cancellation.
	if err := ctx.Err(); err != nil {
		memory.Close()
		return "", membuffer.Reservation{}, err
	}
	return event, memory, nil
}

// fetchRedirectPolicy corrects net/http's 301/302 method rewrite while retaining
// its cookie handling, sensitive-header filtering and client redirect policy.
func fetchRedirectPolicy(check func(*http.Request, []*http.Request) error) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		previous := via[len(via)-1]
		status := req.Response.StatusCode
		dropBody := (status == 301 || status == 302) && previous.Method == http.MethodPost ||
			status == 303 && previous.Method != http.MethodGet && previous.Method != http.MethodHead

		// Derive each hop from the preceding request: net/http permanently drops
		// its replay body after any 301/302, even when Fetch preserves the method.
		// A body removed by a POST rewrite or 303 must stay removed on later hops.
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
		var err error
		if check != nil {
			err = check(req, via)
		} else if len(via) >= 10 {
			err = errors.New("stopped after 10 redirects")
		}
		if err != nil && req.Body != nil {
			req.Body.Close()
		}
		return err
	}
}

type scriptPolicyTransport struct {
	plugin.PolicyTransport
	policy string
}

func (t scriptPolicyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return t.RoundTripPolicy(request, t.policy)
}
