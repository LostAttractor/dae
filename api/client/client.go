// SPDX-License-Identifier: AGPL-3.0-only

// Package client implements the dae HTTP API without importing daemon code.
package client

import (
	"bytes"
	"cmp"
	"context"
	jsonv1 "encoding/json"
	json "encoding/json/v2"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/daeuniverse/dae/api"
)

const DefaultEndpoint = "unix:///var/run/dae.sock"
const maxResponseSize = 32 << 20

// Options are immutable after New. A Client can be shared by concurrent callers.
type Options struct {
	Endpoint string
	APIKey   string
	Timeout  time.Duration
}

type Client struct {
	base   string
	apiKey string
	http   *http.Client
}

// Error is a non-success API response. StatusCode can be used with errors.AsType
// to distinguish authentication failures, conflicts, and reloads (503).
type Error struct {
	StatusCode int
	Message    string
}

func (e *Error) Error() string { return fmt.Sprintf("dae API: HTTP %d: %s", e.StatusCode, e.Message) }

func New(options Options) (*Client, error) {
	endpoint := cmp.Or(options.Endpoint, DefaultEndpoint)
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("API endpoint: %w", err)
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, fmt.Errorf("API endpoint must not contain credentials, query parameters, or a fragment")
	}
	// Own the transport: process-wide wrappers and proxies must not affect LAN identity.
	transport := &http.Transport{IdleConnTimeout: 90 * time.Second, ForceAttemptHTTP2: true}
	switch u.Scheme {
	case "unix":
		if u.Host != "" || !strings.HasPrefix(u.Path, "/") || u.Path == "/" {
			return nil, fmt.Errorf("Unix endpoint must be unix:///absolute/socket/path")
		}
		socket := u.Path
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}
		endpoint = "http://localhost"
	case "http", "https":
		if u.Host == "" || (u.Path != "" && u.Path != "/") {
			return nil, fmt.Errorf("HTTP endpoint must be an origin without a path")
		}
		endpoint = strings.TrimSuffix(endpoint, "/")
	default:
		return nil, fmt.Errorf("API endpoint requires unix, http, or https scheme")
	}
	timeout := cmp.Or(options.Timeout, 10*time.Second)
	if timeout < 0 {
		return nil, fmt.Errorf("API timeout must be positive")
	}
	return &Client{base: endpoint, apiKey: options.APIKey, http: &http.Client{
		Transport: transport, Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

// Close releases idle connections. It does not cancel active requests.
func (c *Client) Close() { c.http.CloseIdleConnections() }

// request is the single HTTP/JSON path for all operations. It never retries writes.
func (c *Client) request[T any](ctx context.Context, method, path string, body any, fingerprint string) (*T, error) {
	return c.requestStatus[T](ctx, method, path, body, fingerprint, http.StatusOK)
}

func (c *Client) requestStatus[T any](ctx context.Context, method, path string, body any, fingerprint string, status int) (*T, error) {
	var payload []byte
	var err error
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if method == http.MethodPut || method == http.MethodDelete || method == http.MethodPost {
		req.Header.Set("X-Dae-API", "1")
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	if fingerprint != "" {
		req.Header.Set("X-Dae-MITM", fingerprint)
	}
	response, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("contact dae API: %w", err)
	}
	defer response.Body.Close()
	limit := int64(maxResponseSize)
	if response.StatusCode != status {
		limit = 8 << 10
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if response.StatusCode != status {
		var detail struct {
			Error string `json:"error"`
		}
		if int64(len(data)) > limit {
			detail.Error = fmt.Sprintf("error response exceeds %d bytes", limit)
		} else if json.Unmarshal(data, &detail) != nil || detail.Error == "" {
			detail.Error = strings.TrimSpace(string(data))
		}
		if detail.Error == "" {
			detail.Error = response.Status
		}
		return nil, &Error{StatusCode: response.StatusCode, Message: detail.Error}
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("dae API response exceeds %d bytes", limit)
	}
	var result *T
	if err := json.Unmarshal(data, &result, jsonv1.FormatDurationAsNano(true)); err != nil {
		return nil, fmt.Errorf("decode dae API response: %w", err)
	}
	if result == nil {
		return nil, fmt.Errorf("dae API returned null")
	}
	return result, nil
}

func (c *Client) Status(ctx context.Context) (*api.StatusSnapshot, error) {
	snapshot, err := c.request[api.StatusSnapshot](ctx, "GET", "/api/status", nil, "")
	if err != nil {
		return nil, err
	}
	if snapshot.Schema != api.StatusSchemaVersion {
		return nil, fmt.Errorf("unsupported status schema %d", snapshot.Schema)
	}
	for _, group := range snapshot.Groups {
		for _, node := range group.Nodes {
			if session := node.SessionDetail; session != nil {
				switch session.State {
				case "disconnected", "connecting", "connected", "closed":
				default:
					return nil, fmt.Errorf("node %q has invalid session state %q", node.ID, session.State)
				}
			}
			if !node.Recovery.RetryAt.IsZero() && node.Recovery.Phase != api.RecoveryBackoff {
				return nil, fmt.Errorf("node %q has inconsistent recovery retry time", node.ID)
			}
		}
	}
	return snapshot, nil
}

func (c *Client) Selectors(ctx context.Context) (*api.SelectorsResponse, error) {
	return c.request[api.SelectorsResponse](ctx, "GET", "/api/selectors", nil, "")
}

func (c *Client) SelectNode(ctx context.Context, group, nodeID string) (*api.SelectorState, error) {
	return c.request[api.SelectorState](ctx, "PUT", "/api/selectors/"+url.PathEscape(group), api.SelectNodeRequest{NodeID: nodeID}, "")
}

func (c *Client) ResetSelector(ctx context.Context, group string) (*api.SelectorState, error) {
	return c.request[api.SelectorState](ctx, "DELETE", "/api/selectors/"+url.PathEscape(group), nil, "")
}

// Probe queues one round of configured connectivity checks. HTTP 202 acknowledges
// acceptance, including coalescing with in-flight work; it is not a test result.
func (c *Client) Probe(ctx context.Context, request api.ProbeRequest) (*api.ProbeResponse, error) {
	return c.requestStatus[api.ProbeResponse](ctx, "POST", "/api/probes", request, "", http.StatusAccepted)
}

// TriggerScript accepts one execution. A 202 response is not the script's result;
// the plugin's status report tracks the returned run number and outcome.
func (c *Client) TriggerScript(ctx context.Context, instance string, request api.ScriptRunRequest) (*api.ScriptRunResponse, error) {
	return c.requestStatus[api.ScriptRunResponse](ctx, "POST", "/api/plugins/"+url.PathEscape(instance)+"/scripts/run", request, "", http.StatusAccepted)
}

func (c *Client) Device(ctx context.Context) (*api.DeviceState, error) {
	return c.request[api.DeviceState](ctx, "GET", "/api/device", nil, "")
}

func (c *Client) SetMembership(ctx context.Context, name string, joined bool) (*api.DeviceState, error) {
	method := "DELETE"
	if joined {
		method = "PUT"
	}
	return c.request[api.DeviceState](ctx, method, "/api/device/sets/"+url.PathEscape(name), nil, "")
}

// SetMITM explicitly enables or disables HTTPS modules for the calling device.
// Fingerprint must identify the CA certificate the user has verified.
func (c *Client) SetMITM(ctx context.Context, enabled bool, fingerprint string) (*api.DeviceState, error) {
	return c.request[api.DeviceState](ctx, "PUT", "/api/device/mitm", api.SetMITMRequest{Enabled: &enabled}, fingerprint)
}

func (c *Client) ResetMITM(ctx context.Context, fingerprint string) (*api.DeviceState, error) {
	return c.request[api.DeviceState](ctx, "DELETE", "/api/device/mitm", nil, fingerprint)
}

func (c *Client) Certificate(ctx context.Context) (*api.Certificate, error) {
	return c.request[api.Certificate](ctx, "GET", "/api/certificate", nil, "")
}
