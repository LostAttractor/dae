/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/daeuniverse/dae/cmd/internal"
	"github.com/daeuniverse/dae/control"
	"github.com/spf13/cobra"
)

const trafficRateWindowSeconds = 1

var statusNetworkNames = [...]string{"tcp4", "tcp6", "udp4", "udp6"}

var (
	statusVerbose bool
	statusRecent  bool
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show the status of the running dae daemon.",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		internal.AutoSu()
		snapshot, err := fetchStatus()
		if err != nil {
			return fmt.Errorf("failed to get status: %w", err)
		}
		if statusRecent {
			printRecentStatus(snapshot)
		} else {
			printStatus(snapshot)
		}
		return nil
	},
}

func fetchStatus() (*control.StatusSnapshot, error) {
	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", StatusSocketPath)
			},
		},
		Timeout: 10 * time.Second,
	}
	response, err := client.Get("http://unix/status")
	if err != nil {
		if os.IsNotExist(err) || strings.Contains(err.Error(), "no such file") {
			return nil, fmt.Errorf("is dae running? (%v)", err)
		}
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("daemon returned %v (daemon may be reloading)", response.Status)
	}
	return decodeStatus(response.Body)
}

func decodeStatus(reader io.Reader) (*control.StatusSnapshot, error) {
	var snapshot control.StatusSnapshot
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		return nil, err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, err
	}
	if err := validateStatus(&snapshot); err != nil {
		return nil, err
	}
	return &snapshot, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("status response contains multiple JSON values")
		}
		return err
	}
	return nil
}

func validateStatus(snapshot *control.StatusSnapshot) error {
	switch snapshot.Health {
	case control.HealthHealthy, control.HealthWarning, control.HealthDegraded:
	default:
		return fmt.Errorf("status response has invalid health %q", snapshot.Health)
	}
	if err := validateTrafficRate("traffic", snapshot.Traffic); err != nil {
		return err
	}
	if err := validateNetworkCount("networks", len(snapshot.Networks)); err != nil {
		return err
	}
	for index, network := range snapshot.Networks {
		if err := validateNetworkName("networks", index, network.Network); err != nil {
			return err
		}
	}
	for groupIndex := range snapshot.Groups {
		if err := validateGroupStatus(groupIndex, &snapshot.Groups[groupIndex]); err != nil {
			return err
		}
	}
	return nil
}

func validateGroupStatus(index int, group *control.GroupStatus) error {
	path := fmt.Sprintf("groups[%d]", index)
	switch group.Health {
	case control.HealthHealthy, control.HealthWarning, control.HealthDegraded:
	default:
		return fmt.Errorf("%s has invalid health %q", path, group.Health)
	}
	if err := validateTrafficRate(path+".traffic", group.Traffic); err != nil {
		return err
	}
	if err := validateGroupConnectivity(path, group.Connectivity); err != nil {
		return err
	}
	if err := validateNetworkCount(path+".networks", len(group.Networks)); err != nil {
		return err
	}
	for networkIndex, network := range group.Networks {
		if err := validateNetworkName(path+".networks", networkIndex, network.Network); err != nil {
			return err
		}
		if err := validateNetworkSupport(path+".networks", networkIndex, network.SupportState); err != nil {
			return err
		}
		if network.Selected != nil && (network.Selected.Index < 0 || network.Selected.Index >= len(group.Nodes)) {
			return fmt.Errorf("%s.networks[%d] selects node index %d outside nodes", path, networkIndex, network.Selected.Index)
		}
	}
	for nodeIndex, node := range group.Nodes {
		nodePath := fmt.Sprintf("%s.nodes[%d]", path, nodeIndex)
		if err := validateTrafficRate(nodePath+".traffic", node.Traffic); err != nil {
			return err
		}
		if err := validateNodeStatus(nodePath, &node); err != nil {
			return err
		}
	}
	return nil
}

func validateNodeStatus(path string, node *control.NodeStatus) error {
	if node.Session != nil {
		switch node.Session.State {
		case control.SessionDisconnected, control.SessionConnecting, control.SessionConnected, control.SessionClosed:
		default:
			return fmt.Errorf("%s has invalid session state %q", path, node.Session.State)
		}
	}
	if node.Health != nil {
		switch node.Health.State {
		case control.NodeHealthUnknown, control.NodeHealthHealthy, control.NodeHealthConfirming, control.NodeHealthUnhealthy:
		default:
			return fmt.Errorf("%s has invalid health state %q", path, node.Health.State)
		}
	}
	if err := validateNetworkCount(path+".networks", len(node.Networks)); err != nil {
		return err
	}
	for index, network := range node.Networks {
		if err := validateNetworkName(path+".networks", index, network.Network); err != nil {
			return err
		}
		if err := validateNetworkSupport(path+".networks", index, network.SupportState); err != nil {
			return err
		}
	}
	return nil
}

func validateNetworkCount(path string, count int) error {
	if count != len(statusNetworkNames) {
		return fmt.Errorf("%s has %d entries, want %d", path, count, len(statusNetworkNames))
	}
	return nil
}

func validateNetworkName(path string, index int, network string) error {
	if network != statusNetworkNames[index] {
		return fmt.Errorf("%s[%d] has network %q, want %q", path, index, network, statusNetworkNames[index])
	}
	return nil
}

func validateNetworkSupport(path string, index int, support control.NetworkSupportStatus) error {
	switch support {
	case control.NetworkSupportUnknown, control.NetworkSupportConfirmed, control.NetworkSupportUnsupported:
		return nil
	default:
		return fmt.Errorf("%s[%d] has invalid support state %q", path, index, support)
	}
}

func validateGroupConnectivity(path string, connectivity *control.GroupConnectivityStatus) error {
	if connectivity == nil {
		return nil
	}
	switch connectivity.State {
	case control.GroupConnectivityAvailable, control.GroupConnectivityChecking, control.GroupConnectivityUnavailable:
	default:
		return fmt.Errorf("%s has invalid connectivity state %q", path, connectivity.State)
	}
	for index, state := range connectivity.Recent.Buckets {
		switch state {
		case control.GroupBucketUnknown, control.GroupBucketAvailable, control.GroupBucketUnavailable:
		default:
			return fmt.Errorf("%s.connectivity.recent.buckets[%d] has invalid state %q", path, index, state)
		}
	}
	if connectivity.Recent.WindowSeconds <= 0 {
		return fmt.Errorf("%s has invalid recent window %d", path, connectivity.Recent.WindowSeconds)
	}
	if len(connectivity.Recent.Buckets) != control.GroupRecentBucketCount {
		return fmt.Errorf("%s has %d recent buckets, want %d", path, len(connectivity.Recent.Buckets), control.GroupRecentBucketCount)
	}
	return nil
}

func validateTrafficRate(path string, traffic control.TrafficStatus) error {
	if traffic.WindowSeconds != trafficRateWindowSeconds {
		return fmt.Errorf("%s has invalid window %d, want %d", path, traffic.WindowSeconds, trafficRateWindowSeconds)
	}
	return nil
}

func init() {
	statusCmd.Flags().BoolVar(&statusVerbose, "verbose", false, "show detailed path health history")
	statusCmd.Flags().BoolVar(&statusRecent, "recent", false, "show recent group connectivity")
	statusCmd.MarkFlagsMutuallyExclusive("verbose", "recent")
	rootCmd.AddCommand(statusCmd)
}
