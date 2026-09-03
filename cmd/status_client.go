/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"context"
	jsonv2 "encoding/json/v2"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/daeuniverse/dae/cmd/internal"
	"github.com/daeuniverse/dae/common"
	"github.com/daeuniverse/dae/common/stats"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	"github.com/daeuniverse/dae/control"
	"github.com/spf13/cobra"
)

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
			printStatus(snapshot, statusVerbose)
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
	if err := jsonv2.UnmarshalRead(reader, &snapshot); err != nil {
		return nil, err
	}
	if err := validateStatus(&snapshot); err != nil {
		return nil, err
	}
	return &snapshot, nil
}

func validateStatus(snapshot *control.StatusSnapshot) error {
	if snapshot.Schema != control.StatusSchemaVersion {
		return fmt.Errorf("unsupported status schema %d", snapshot.Schema)
	}
	if snapshot.Version == "" || snapshot.StartedAt.IsZero() {
		return fmt.Errorf("status response is missing process metadata")
	}
	if len(snapshot.Groups) == 0 {
		return fmt.Errorf("status response is missing groups")
	}
	for groupIndex := range snapshot.Groups {
		group := &snapshot.Groups[groupIndex]
		path := fmt.Sprintf("groups[%d]", groupIndex)
		if group.Name == "" {
			return fmt.Errorf("%s has no name", path)
		}
		switch group.TargetKind {
		case "group", "node", "builtin":
		default:
			return fmt.Errorf("%s has invalid target kind %q", path, group.TargetKind)
		}
		if group.ChecksConnectivity {
			switch group.Connectivity {
			case stats.GroupStateAvailable, stats.GroupStateChecking, stats.GroupStateUnavailable:
			default:
				return fmt.Errorf("%s has invalid connectivity %q", path, group.Connectivity)
			}
			if len(group.Availability.Recent.States) != stats.GroupStateBucketCount {
				return fmt.Errorf("%s availability has %d recent states, want %d", path, len(group.Availability.Recent.States), stats.GroupStateBucketCount)
			}
			for _, state := range group.Availability.Recent.States {
				switch state {
				case stats.GroupHistoryUnknown, stats.GroupHistoryAvailable, stats.GroupHistoryUnavailable:
				default:
					return fmt.Errorf("%s has invalid recent state %q", path, state)
				}
			}
		} else if group.Connectivity != "" {
			return fmt.Errorf("%s has connectivity state without checks", path)
		}

		nodesByID := make(map[string]*control.NodeStatus, len(group.Nodes))
		for nodeIndex := range group.Nodes {
			node := &group.Nodes[nodeIndex]
			nodePath := fmt.Sprintf("%s.nodes[%d]", path, nodeIndex)
			if node.ID == "" {
				return fmt.Errorf("%s has no id", nodePath)
			}
			if _, exists := nodesByID[node.ID]; exists {
				return fmt.Errorf("%s repeats node id %q", path, node.ID)
			}
			nodesByID[node.ID] = node
			for _, support := range node.Support {
				switch support {
				case dialer.NetworkSupportUnknown, dialer.NetworkSupportConfirmed, dialer.NetworkSupportUnsupported:
				default:
					return fmt.Errorf("%s has invalid network support %q", nodePath, support)
				}
			}
			switch node.Session {
			case "", "disconnected", "connecting", "connected", "closed":
			default:
				return fmt.Errorf("%s has invalid session state %q", nodePath, node.Session)
			}
		}
		for network, selectedID := range group.SelectedNodeIDs {
			if selectedID == "" {
				continue
			}
			node, exists := nodesByID[selectedID]
			if !exists {
				return fmt.Errorf("%s selects unknown node %q for %s", path, selectedID, common.NetworkIndex(network))
			}
			if !node.Healthy || node.Support[network] != dialer.NetworkSupportConfirmed {
				return fmt.Errorf("%s selects unusable node %q for %s", path, selectedID, common.NetworkIndex(network))
			}
		}
	}
	return nil
}

func init() {
	statusCmd.Flags().BoolVar(&statusVerbose, "verbose", false, "show detailed network and path health")
	statusCmd.Flags().BoolVar(&statusRecent, "recent", false, "show recent group connectivity")
	statusCmd.MarkFlagsMutuallyExclusive("verbose", "recent")
	rootCmd.AddCommand(statusCmd)
}
