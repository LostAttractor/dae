// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"fmt"
	"net/url"

	"github.com/daeuniverse/dae/api"
)

func (c *Client) Explain(ctx context.Context, request api.ExplainRequest, self bool) (*api.ExplainResponse, error) {
	path := "/api/diagnostics/explain"
	if self {
		path = "/api/device/diagnostics/explain"
	}
	response, err := c.request[api.ExplainResponse](ctx, "POST", path, request, "")
	if err != nil {
		return nil, err
	}
	if response.Schema != api.DiagnosticsSchemaVersion {
		return nil, fmt.Errorf("unsupported diagnostics schema %d", response.Schema)
	}
	return response, nil
}

func (c *Client) DeviceContext(ctx context.Context) (*api.DeviceContext, error) {
	return c.request[api.DeviceContext](ctx, "GET", "/api/device/context", nil, "")
}

func (c *Client) ClientGroups(ctx context.Context) (*api.ClientGroups, error) {
	return c.request[api.ClientGroups](ctx, "GET", "/api/clients", nil, "")
}

func (c *Client) ClientGroup(ctx context.Context, name string) (*api.ClientGroup, error) {
	return c.request[api.ClientGroup](ctx, "GET", "/api/clients/"+url.PathEscape(name), nil, "")
}

func (c *Client) ClientImpact(ctx context.Context, name string, request api.ClientImpactRequest, self bool) (*api.ClientImpact, error) {
	path := "/api/clients/" + url.PathEscape(name) + "/impact"
	if self {
		path = "/api/device/sets/" + url.PathEscape(name) + "/impact"
	}
	return c.request[api.ClientImpact](ctx, "POST", path, request, "")
}

func (c *Client) SetClientMember(ctx context.Context, name, mac string, joined bool) (*api.ClientGroup, error) {
	method := "DELETE"
	if joined {
		method = "PUT"
	}
	return c.request[api.ClientGroup](ctx, method, "/api/clients/"+url.PathEscape(name)+"/members/"+url.PathEscape(mac), nil, "")
}

func (c *Client) ManagedDevice(ctx context.Context, mac string) (*api.ManagedDevice, error) {
	return c.request[api.ManagedDevice](ctx, "GET", "/api/devices/"+url.PathEscape(mac), nil, "")
}

func (c *Client) SetManagedMITM(ctx context.Context, mac string, enabled *bool, fingerprint string) (*api.ManagedDevice, error) {
	method := "DELETE"
	var body any
	if enabled != nil {
		method, body = "PUT", api.SetMITMRequest{Enabled: enabled}
	}
	return c.request[api.ManagedDevice](ctx, method, "/api/devices/"+url.PathEscape(mac)+"/mitm", body, fingerprint)
}
