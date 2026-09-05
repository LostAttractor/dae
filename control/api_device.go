// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"slices"

	log "github.com/sirupsen/logrus"
)

type clientSetState struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Joined      bool   `json:"joined"`
}

type mitmState struct {
	Enabled       bool   `json:"enabled"`
	Override      *bool  `json:"override"`
	CAFingerprint string `json:"ca_fingerprint"`
}

type deviceState struct {
	SourceIP string           `json:"source_ip"`
	MAC      string           `json:"mac"`
	Sets     []clientSetState `json:"sets"`
	MITM     *mitmState       `json:"mitm,omitempty"`
}

func (c *ControlPlane) serveDevice(w http.ResponseWriter, r *http.Request, resolve func(netip.Addr) ([6]byte, error)) {
	if !apiBody(w, r, nil) {
		return
	}
	ip, mac, ok := apiDevice(w, r, resolve)
	if !ok {
		return
	}
	c.settingsMu.Lock()
	defer c.settingsMu.Unlock()
	writeAPI(w, c.deviceState(ip, mac))
}

func (c *ControlPlane) deviceState(ip netip.Addr, mac [6]byte) deviceState {
	state := deviceState{SourceIP: ip.String(), MAC: net.HardwareAddr(mac[:]).String(), Sets: make([]clientSetState, 0)}
	for _, name := range c.routingMatcherBuilder.ClientSets() {
		joined := slices.Contains(c.settings.Members(name), mac)
		state.Sets = append(state.Sets, clientSetState{
			Name: name, Description: c.clientDescriptions[name], Joined: joined,
		})
	}
	if c.surge != nil && c.surge.Authority() != nil {
		enabled, override := c.mitmSelection(ip, mac)
		state.MITM = &mitmState{Enabled: enabled, Override: override, CAFingerprint: c.surge.Authority().Fingerprint()}
	}
	return state
}

func (c *ControlPlane) serveClientSet(w http.ResponseWriter, r *http.Request, resolve func(netip.Addr) ([6]byte, error)) {
	if !apiBody(w, r, nil) {
		return
	}
	name := r.PathValue("name")
	if !slices.Contains(c.routingMatcherBuilder.ClientSets(), name) {
		apiError(w, 404, "client set not found")
		return
	}
	ip, mac, ok := apiDevice(w, r, resolve)
	if !ok {
		return
	}
	c.settingsMu.Lock()
	defer c.settingsMu.Unlock()
	joined := r.Method == http.MethodPut
	previous := c.settings.Members(name)
	if slices.Contains(previous, mac) == joined {
		writeAPI(w, c.deviceState(ip, mac))
		return
	}
	next := slices.Clone(previous)
	if joined {
		next = append(next, mac)
	} else {
		next = slices.DeleteFunc(next, func(m [6]byte) bool { return m == mac })
	}
	if err := c.routingMatcherBuilder.SetClientMembers(c.routingMatcher, name, next, c.apiActive); err != nil {
		apiSaveError(w, err)
		return
	}
	if err := c.settings.SetMembership(name, mac, joined); err != nil {
		apiSaveError(w, errors.Join(err, c.routingMatcherBuilder.SetClientMembers(c.routingMatcher, name, previous, c.apiActive)))
		return
	}
	log.WithFields(log.Fields{"event": "client_set_update", "set": name, "mac": net.HardwareAddr(mac[:]).String(), "source_ip": ip.String(), "joined": joined}).Info("API settings changed")
	writeAPI(w, c.deviceState(ip, mac))
}

func (c *ControlPlane) serveMITM(w http.ResponseWriter, r *http.Request, resolve func(netip.Addr) ([6]byte, error)) {
	if c.surge == nil || c.surge.Authority() == nil {
		apiError(w, 404, "HTTPS modules are disabled")
		return
	}
	fingerprint := r.Header.Get("X-Dae-MITM")
	if fingerprint == "" {
		apiError(w, 403, "MITM changes require X-Dae-MITM containing the CA SHA-256 fingerprint")
		return
	}
	if fingerprint != c.surge.Authority().Fingerprint() {
		apiError(w, 409, "the CA certificate changed; reload the page and verify the certificate")
		return
	}
	var enabled *bool
	if r.Method == http.MethodPut {
		var request struct {
			Enabled *bool `json:"enabled"`
		}
		if !apiBody(w, r, &request) {
			return
		}
		if request.Enabled == nil {
			apiError(w, 400, `expected {"enabled":true} or {"enabled":false}`)
			return
		}
		enabled = request.Enabled
	} else if !apiBody(w, r, nil) {
		return
	}
	ip, mac, ok := apiDevice(w, r, resolve)
	if !ok {
		return
	}
	c.settingsMu.Lock()
	defer c.settingsMu.Unlock()
	if err := c.settings.SetMITM(mac, enabled); err != nil {
		apiSaveError(w, err)
		return
	}
	state := c.deviceState(ip, mac)
	log.WithFields(log.Fields{"event": "mitm_client_update", "source_ip": ip.String(), "mac": net.HardwareAddr(mac[:]).String(), "enabled": state.MITM.Enabled}).Info("API settings changed")
	writeAPI(w, state)
}
