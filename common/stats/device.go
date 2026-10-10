// SPDX-License-Identifier: AGPL-3.0-only

package stats

import "github.com/daeuniverse/dae/api"

// OpenDeviceConnection mirrors an attributed connection into its ingress MAC's
// private counters. Device identities never become Prometheus path labels.
// An absent identity denotes daemon traffic, rather than a shared device.
func (s *Store) OpenDeviceConnection(path Path, fallback bool, mac [6]byte) *Connection {
	connection := s.OpenConnection(path, fallback)
	if mac == [6]byte{} || mac[0]&1 != 0 {
		return connection
	}
	// Use the process sampler's boundaries, including empty earlier samples,
	// so device and global histories describe the same five-second windows.
	s.samplingMu.RLock()
	s.devicesMu.Lock()
	device := s.devices[mac]
	if device == nil {
		device = newStoreAt(s.windowStartedAt)
		device.completedSamples = s.completedSamples
		if s.devices == nil {
			s.devices = make(map[[6]byte]*Store)
		}
		s.devices[mac] = device
	}
	s.devicesMu.Unlock()
	s.samplingMu.RUnlock()
	connection.device = device.OpenConnection(path, fallback)
	return connection
}

// DeviceSnapshot returns only the specified MAC's established upstream paths.
// External (splice) deltas are refreshed by their owning global connections.
// Reading an unseen device does not allocate counters.
func (s *Store) DeviceSnapshot(mac [6]byte) (map[Path]api.PathStats, int64) {
	s.refreshExternalCounters()
	s.devicesMu.RLock()
	device := s.devices[mac]
	s.devicesMu.RUnlock()
	if device == nil {
		return nil, 0
	}
	fallback := device.DirectFallbackConnections()
	return device.SnapshotWithHistory(), fallback
}
