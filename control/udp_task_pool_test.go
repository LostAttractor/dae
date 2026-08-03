/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"testing"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/stretchr/testify/require"
)

// Should run successfully in less than 3.2 seconds.
func TestUdpTaskPool(t *testing.T) {
	c, err := cpu.Times(false)
	require.NoError(t, err)
	t.Log(c)
	DefaultNatTimeoutUDP = 1000 * time.Millisecond

	// Test task execution
	for i := 0; i <= UdpTaskQueueLength; i++ {
		err = DefaultUdpTaskPool.EmitTask("testkey", func() { time.Sleep(500 * time.Millisecond) }, 5*time.Second)
		require.NoError(t, err)
	} // Fill the queue to full
	time.Sleep(400 * time.Millisecond) // Task should be executed
	err = DefaultUdpTaskPool.EmitTask("testkey", func() {}, 5*time.Second)
	require.NoError(t, err)

	// Test task timeout
	for i := 0; i <= UdpTaskQueueLength; i++ {
		err = DefaultUdpTaskPool.EmitTask("testkey2", func() { time.Sleep(500 * time.Millisecond) }, 100*time.Millisecond)
		require.NoError(t, err)
	} // Fill the queue to full
	time.Sleep(200 * time.Millisecond) // Task should be executed
	err = DefaultUdpTaskPool.EmitTask("testkey2", func() {}, 5*time.Second)
	require.NoError(t, err)

	// Test task gc with pending emit
	for i := 0; i <= UdpTaskQueueLength; i++ {
		err = DefaultUdpTaskPool.EmitTask("testkey3", func() { time.Sleep(100 * time.Second) }, 5*time.Second)
		require.NoError(t, err)
	} // Fill the queue
	err = DefaultUdpTaskPool.EmitTask("testkey3", func() {}, 5*time.Second)
	require.Error(t, err) // expect TaskPool is closed

	c, err = cpu.Times(false)
	require.NoError(t, err)
	t.Log(c)
}
