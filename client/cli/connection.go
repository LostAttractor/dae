// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"cmp"
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/api/client"
	"github.com/spf13/pflag"
)

// Connection binds a command's API options without opening a connection.
type Connection struct {
	endpoint string
	keyFile  string
	caFile   string
	timeout  time.Duration
}

func (c *Connection) Bind(flags *pflag.FlagSet) {
	endpoint := os.Getenv("DAE_API_ENDPOINT")
	if endpoint == "" {
		endpoint = client.DefaultEndpoint
	}
	flags.StringVar(&c.endpoint, "api", endpoint, "API origin or unix:///absolute/socket/path (DAE_API_ENDPOINT)")
	flags.StringVar(&c.keyFile, "api-key-file", os.Getenv("DAE_API_KEY_FILE"), "Read the user or administrator API key from a file (DAE_API_KEY_FILE)")
	flags.StringVar(&c.caFile, "api-ca", os.Getenv("DAE_API_CA"), "Trusted API CA PEM file (DAE_API_CA)")
	defaultTimeout := cmp.Or(c.timeout, client.DefaultTimeout)
	flags.DurationVar(&c.timeout, "timeout", defaultTimeout, "API request timeout")
}

func (c *Connection) Status(ctx context.Context) (*api.StatusSnapshot, error) {
	remote, err := c.Open()
	if err != nil {
		return nil, err
	}
	defer remote.Close()
	return remote.Status(ctx)
}

func (c *Connection) MITM(ctx context.Context) (api.PluginStatus, error) {
	snapshot, err := c.Status(ctx)
	if err != nil {
		return api.PluginStatus{}, err
	}
	return snapshot.PluginStatus, nil
}

func (c *Connection) TriggerScript(ctx context.Context, instance string, request api.ScriptRunRequest) (*api.ScriptRunResponse, error) {
	remote, err := c.Open()
	if err != nil {
		return nil, err
	}
	defer remote.Close()
	return remote.TriggerScript(ctx, instance, request)
}

func (c *Connection) MigrateScriptStore(ctx context.Context, instance string, request api.ScriptStoreMigrateRequest) (*api.ScriptStoreMigrateResponse, error) {
	remote, err := c.Open()
	if err != nil {
		return nil, err
	}
	defer remote.Close()
	return remote.MigrateScriptStore(ctx, instance, request)
}

// Open creates a client using the bound flags and API credentials. The caller closes it.
func (c *Connection) Open() (*client.Client, error) {
	options := client.Options{Endpoint: c.endpoint, Timeout: c.timeout}
	scheme, _, _ := strings.Cut(c.endpoint, ":")
	if c.endpoint == "" || strings.EqualFold(scheme, "unix") {
		return client.New(options)
	}
	key := os.Getenv("DAE_API_KEY")
	if c.keyFile != "" {
		data, err := os.ReadFile(c.keyFile)
		if err != nil {
			return nil, err
		}
		key = strings.TrimSpace(string(data))
		if key == "" {
			return nil, fmt.Errorf("API key file is empty")
		}
	}
	var roots *x509.CertPool
	if c.caFile != "" {
		data, err := os.ReadFile(c.caFile)
		if err != nil {
			return nil, err
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("API CA file contains no certificate")
		}
	}
	options.APIKey, options.RootCAs = key, roots
	return client.New(options)
}
