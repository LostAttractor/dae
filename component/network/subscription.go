// SPDX-License-Identifier: AGPL-3.0-only

package network

// restoreSubscription keeps an existing stream and publishes a replacement only
// after subscription succeeds. Owners retain their event processing and resync
// policies; callers serialize retries with channel-closure handling.
func restoreSubscription[T any](current *<-chan T, subscribe func() (<-chan T, error)) (bool, error) {
	if *current != nil || subscribe == nil {
		return false, nil
	}
	next, err := subscribe()
	if err != nil {
		return false, err
	}
	*current = next
	return true, nil
}
