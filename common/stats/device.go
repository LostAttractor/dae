// SPDX-License-Identifier: AGPL-3.0-only

package stats

import (
	"time"

	"github.com/daeuniverse/dae/api"
)

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
		device.startedAt = time.Now()
		if s.devices == nil {
			s.devices = make(map[[6]byte]*Store)
		}
		s.devices[mac] = device
		s.devicePeak = max(s.devicePeak, len(s.devices))
	}
	connection.device = device.OpenConnection(path, fallback)
	s.devicesMu.Unlock()
	s.samplingMu.RUnlock()
	return connection
}

// DeviceSnapshot returns only the specified MAC's established upstream paths.
// External deltas are published by their owning global connections.
// Reading an unseen device does not allocate counters.
func (s *Store) DeviceSnapshot(mac [6]byte) (map[Path]api.PathStats, int64) {
	snapshot := s.DeviceTrafficSnapshot(mac)
	return snapshot.Paths, snapshot.DirectFallbackConnections
}

// DeviceTrafficSnapshot describes the current observation period. Idle devices
// expire with their last minute of history; returning devices start a new period.
func (s *Store) DeviceTrafficSnapshot(mac [6]byte) TrafficSnapshot {
	s.devicesMu.RLock()
	defer s.devicesMu.RUnlock()
	device := s.devices[mac]
	if device == nil {
		return TrafficSnapshot{}
	}
	return device.TrafficSnapshot()
}
