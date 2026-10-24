// SPDX-License-Identifier: AGPL-3.0-only
package client

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/daeuniverse/dae/api"
)

func (c *Client) download(ctx context.Context, path string, out io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return err
	}
	response, err := c.send(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return responseError(response)
	}
	_, err = io.Copy(out, response.Body)
	return err
}
func responseError(response *http.Response) error {
	var detail struct {
		Error string `json:"error"`
	}
	_ = json.UnmarshalRead(io.LimitReader(response.Body, 8<<10), &detail)
	if detail.Error == "" {
		detail.Error = response.Status
	}
	return &Error{StatusCode: response.StatusCode, Message: detail.Error}
}
func (c *Client) DownloadCertificate(ctx context.Context, format string, out io.Writer) error {
	if !slices.Contains([]string{"pem", "cer", "mobileconfig"}, format) {
		return fmt.Errorf("certificate format must be pem, cer or mobileconfig")
	}
	return c.download(ctx, "/api/certificate/ca."+format, out)
}
func (c *Client) Profile(ctx context.Context, name string, seconds int, out io.Writer) error {
	if !slices.Contains([]string{"profile", "heap", "allocs", "goroutine", "block", "mutex", "threadcreate", "trace"}, name) {
		return fmt.Errorf("unsupported profile %q", name)
	}
	if seconds < 0 {
		return fmt.Errorf("profile duration must not be negative")
	}
	path := "/debug/pprof/" + name
	if seconds > 0 {
		path += "?seconds=" + strconv.Itoa(seconds)
	}
	if !c.timeoutExplicit {
		duration := seconds
		if name == "profile" && duration == 0 {
			duration = 30 // net/http/pprof's default CPU sampling interval.
		}
		if int64(duration) > int64((1<<63-1-DefaultTimeout)/time.Second) {
			return fmt.Errorf("profile duration is too large")
		}
		// Share the transport, not mutable per-request timeout state.
		copy, client := *c, *c.http
		client.Timeout = time.Duration(duration)*time.Second + DefaultTimeout
		copy.http = &client
		return copy.download(ctx, path, out)
	}
	return c.download(ctx, path, out)
}
func (c *Client) VerifyCertificate(ctx context.Context) (*api.CertificateTest, error) {
	if c.local {
		return nil, fmt.Errorf("certificate verification requires a direct TCP API endpoint")
	}
	test, err := c.requestStatus[api.CertificateTest](ctx, "POST", "/api/certificate/tests", nil, "", http.StatusCreated)
	if err != nil {
		return nil, err
	}
	target, err := url.Parse(c.base)
	if err != nil {
		return nil, err
	}
	if target.Port() == "" {
		port := "80"
		if strings.HasPrefix(c.base, "https:") {
			port = "443"
		}
		target.Host = net.JoinHostPort(target.Hostname(), port)
	}
	target.Scheme = "https"
	target.Path = "/api/certificate/tests/" + url.PathEscape(test.ID)
	proof, err := c.proof[api.CertificateTest](ctx, target.String())
	if err != nil {
		return nil, err
	}
	if proof.ID != test.ID || proof.CAFingerprint != test.CAFingerprint {
		return nil, fmt.Errorf("certificate proof does not match the challenge")
	}
	return proof, nil
}
func (c *Client) VerifyMITM(ctx context.Context) (*api.MITMTest, error) {
	certificate, err := c.Certificate(ctx)
	if err != nil {
		return nil, err
	}
	test, err := c.StartMITMTest(ctx)
	if err != nil {
		return nil, err
	}
	if !test.MITMEnabled {
		return nil, fmt.Errorf("MITM is disabled for this device")
	}
	target, err := url.Parse(test.MITMURL)
	if err != nil || target.Scheme != "https" || target.User != nil || target.RawQuery != "" || target.Fragment != "" || !strings.HasPrefix(target.Path, "/test/") || !slices.Contains(certificate.MITMTestOrigins, target.Scheme+"://"+target.Host) {
		return nil, fmt.Errorf("invalid MITM verification destination")
	}
	proof, err := c.proof[api.MITMTestProof](ctx, target.String())
	if err != nil {
		return nil, err
	}
	if proof.ID != test.ID || proof.CAFingerprint != test.CAFingerprint || proof.CAFingerprint != certificate.Fingerprint {
		return nil, fmt.Errorf("MITM proof does not match the challenge")
	}
	observed, err := c.MITMTest(ctx, test.ID)
	if err != nil {
		return nil, err
	}
	if !observed.MITMObserved {
		return nil, fmt.Errorf("MITM interception was not observed")
	}
	return observed, nil
}

// Challenges deliberately receive no API credentials, including on advertised
// virtual destinations. Fresh connections prove trust without a pooled leaf.
func (c *Client) proof[T any](ctx context.Context, target string) (*T, error) {
	transport := c.http.Transport.(*http.Transport).Clone()
	transport.DisableKeepAlives = true
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: c.http.Timeout, CheckRedirect: c.http.CheckRedirect}
	for range 8 {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Origin", c.origin)
		response, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		if response.StatusCode == http.StatusConflict {
			response.Body.Close()
			continue
		}
		if response.StatusCode != http.StatusOK {
			err = responseError(response)
			response.Body.Close()
			return nil, err
		}
		var result T
		err = json.UnmarshalRead(io.LimitReader(response.Body, 64<<10), &result)
		response.Body.Close()
		return &result, err
	}
	return nil, fmt.Errorf("could not establish a fresh verification connection")
}
