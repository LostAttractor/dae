// SPDX-License-Identifier: AGPL-3.0-only

package cli

import (
	"context"
	"os"
	"time"

	"github.com/daeuniverse/dae/api"
	"github.com/daeuniverse/dae/api/client"
	"github.com/spf13/pflag"
)

// Connection binds a command's API options without opening a connection.
type Connection struct {
	endpoint string
	timeout  time.Duration
}

func (c *Connection) Bind(flags *pflag.FlagSet) {
	endpoint := os.Getenv("DAE_API_ENDPOINT")
	if endpoint == "" {
		endpoint = client.DefaultEndpoint
	}
	flags.StringVar(&c.endpoint, "api", endpoint, "API origin or unix:///absolute/socket/path (DAE_API_ENDPOINT)")
	flags.DurationVar(&c.timeout, "timeout", 10*time.Second, "API request timeout")
}

func (c *Connection) Status(ctx context.Context) (*api.StatusSnapshot, error) {
	remote, err := client.New(client.Options{Endpoint: c.endpoint, Token: os.Getenv("DAE_API_TOKEN"), Timeout: c.timeout})
	if err != nil {
		return nil, err
	}
	defer remote.Close()
	return remote.Status(ctx)
}

func (c *Connection) MITM(ctx context.Context) ([]api.PluginInstanceStatus, error) {
	snapshot, err := c.Status(ctx)
	if err != nil {
		return nil, err
	}
	return snapshot.Plugins, nil
}
