// SPDX-License-Identifier: AGPL-3.0-only

package plugin

// Storage persists small opaque values in one plugin type/instance's namespace.
// Keys are 1..128 ASCII letters, digits, dots, underscores or hyphens, starting
// with a letter or digit. Values are limited to 8 MiB. Invalid keys or oversized
// values return errors matching fs.ErrInvalid. Get returns caller-owned bytes,
// or fs.ErrNotExist for a missing key. Delete of a missing key succeeds.
//
// Operations are concurrency-safe. Put atomically replaces one complete value;
// readers never see partial writes. Concurrent writes are last-commit-wins, with
// no read/modify/write or multi-key transactions. Do not mutate value during Put.
// Plugins own encoding, schema versions, expiry and write scheduling. The host
// owns the backend and its lifetime; plugins do not open or close stores.
type Storage interface {
	Get(key string) ([]byte, error)
	Put(key string, value []byte) error
	Delete(key string) error
}
