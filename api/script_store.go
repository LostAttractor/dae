// SPDX-License-Identifier: AGPL-3.0-only

package api

type ScriptStoreMigrateRequest struct {
	FromMAC string `json:"from_mac"`
	ToMAC   string `json:"to_mac"`
}

type ScriptStoreMigrateResponse struct {
	Instance  string `json:"instance"`
	FromMAC   string `json:"from_mac"`
	ToMAC     string `json:"to_mac"`
	KeysMoved int    `json:"keys_moved"`
}
