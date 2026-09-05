// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/daeuniverse/dae/component/outbound"
	"github.com/daeuniverse/dae/component/outbound/dialer"
	log "github.com/sirupsen/logrus"
)

func (c *ControlPlane) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	if c.apiToken == "" {
		apiError(w, 403, "global.api_token is not configured; selector changes are disabled")
		return false
	}
	actual, bearer := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	got, want := sha256.Sum256([]byte(actual)), sha256.Sum256([]byte(c.apiToken))
	if !bearer || subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="dae"`)
		apiError(w, 401, "API token is missing or incorrect")
		return false
	}
	return true
}

type selectorNode struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Healthy   bool     `json:"healthy"`
	Checking  bool     `json:"checking"`
	LatencyMS *float64 `json:"latency_ms,omitempty"`
}

type selectorState struct {
	Name          string         `json:"name"`
	DefaultNodeID string         `json:"default_node_id"`
	NodeID        string         `json:"node_id"`
	Overridden    bool           `json:"overridden"`
	Nodes         []selectorNode `json:"nodes"`
}

func (c *ControlPlane) selectorState(group *outbound.DialerGroup) selectorState {
	state := selectorState{Name: group.Name, DefaultNodeID: group.DefaultSelection(), NodeID: group.Selection(), Nodes: make([]selectorNode, 0, len(group.Dialers))}
	state.Overridden = c.settings.Selection(group.Name) != ""
	for _, d := range group.Dialers {
		status := d.RuntimeStatus()
		node := selectorNode{ID: d.StatsID(), Name: d.Name, Healthy: status.Healthy, Checking: !d.ConnectivitySnapshot().InitialCheckDone}
		if status.Healthy && status.HasLatency {
			ms := float64(status.Latency.Last) / float64(time.Millisecond)
			node.LatencyMS = &ms
		}
		state.Nodes = append(state.Nodes, node)
	}
	return state
}

func (c *ControlPlane) serveSelectors(w http.ResponseWriter, r *http.Request) {
	if !apiBody(w, r, nil) {
		return
	}
	c.settingsMu.Lock()
	defer c.settingsMu.Unlock()
	states := make([]selectorState, 0)
	for _, group := range c.outbounds {
		if group.IsSelector() {
			states = append(states, c.selectorState(group))
		}
	}
	writeAPI(w, struct {
		Selectors    []selectorState `json:"selectors"`
		AdminEnabled bool            `json:"admin_enabled"`
	}{states, c.apiToken != ""})
}

func (c *ControlPlane) serveSelector(w http.ResponseWriter, r *http.Request) {
	if !c.requireAdmin(w, r) {
		return
	}
	id := ""
	if r.Method == http.MethodPut {
		var request struct {
			NodeID string `json:"node_id"`
		}
		if !apiBody(w, r, &request) {
			return
		}
		if request.NodeID == "" {
			apiError(w, 400, "node_id is required")
			return
		}
		id = request.NodeID
	} else if !apiBody(w, r, nil) {
		return
	}
	var group *outbound.DialerGroup
	for _, candidate := range c.outbounds {
		if candidate.Name == r.PathValue("group") && candidate.IsSelector() {
			group = candidate
			break
		}
	}
	if group == nil {
		apiError(w, 404, "selector group not found")
		return
	}
	if id != "" && !slices.ContainsFunc(group.Dialers, func(d *dialer.Dialer) bool { return d.StatsID() == id }) {
		apiError(w, 400, "node_id is not a path in this selector")
		return
	}
	// Keep the live choice and its saved override together, including rollback.
	c.settingsMu.Lock()
	defer c.settingsMu.Unlock()
	previous := group.Selection()
	if err := group.SetSelection(id); err != nil {
		apiSaveError(w, err)
		return
	}
	if err := c.settings.SetSelection(group.Name, id); err != nil {
		apiSaveError(w, errors.Join(err, group.SetSelection(previous)))
		return
	}
	log.WithFields(log.Fields{"event": "selector_update", "group": group.Name, "node_id": group.Selection(), "source_ip": r.RemoteAddr, "overridden": id != ""}).Info("API settings changed")
	writeAPI(w, c.selectorState(group))
}
