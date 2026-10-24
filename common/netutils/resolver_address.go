// SPDX-License-Identifier: AGPL-3.0-only

package netutils

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daeuniverse/dae/pkg/dnscache"
)

// addressCacheEntries bounds one cache. Keys are node names per DNS transport
// policy and address family, so configured nodes rarely reach it.
const addressCacheEntries = 1024

// netFileRefresh is how long net may keep answering from hosts, resolv.conf
// and nsswitch.conf as it read them before they changed.
const netFileRefresh = 5 * time.Second

type addressKey struct{ scope, network, host string }

type addressStore struct {
	*dnscache.Store[addressKey, []netip.Addr]
	// fresh is when net has certainly reread files edited before Reset.
	fresh time.Time
}

func newAddressStore(fresh time.Time) *addressStore {
	return &addressStore{Store: dnscache.NewStore[addressKey, []netip.Addr](addressCacheEntries, 0), fresh: fresh}
}

// AddressCache keeps the addresses net.Resolver returns for a name until the
// earliest expiry among the DNS answers that produced them; hits do not extend
// it. A hit skips the whole stub resolver, including the RFC 6724 sort that
// opens a UDP socket per address. Answers that did not come entirely from
// cacheable DNS exchanges are not kept: hosts entries, failures, uncacheable
// or unanswered queries. The zero value is ready to use.
type AddressCache struct {
	store atomic.Pointer[addressStore]
}

// Reset drops every entry. Lookups in flight complete into the dropped store,
// so they cannot repopulate the cache with answers obtained before Reset.
// Answers to lookups started within netFileRefresh after Reset are kept only
// until then: net may still have used the files as they were before Reset.
func (c *AddressCache) Reset() { c.store.Store(newAddressStore(time.Now().Add(netFileRefresh))) }

func (c *AddressCache) entries() *addressStore {
	if store := c.store.Load(); store != nil {
		return store
	}
	c.store.CompareAndSwap(nil, newAddressStore(time.Time{}))
	return c.store.Load()
}

// Lookup returns lookup answered through the cache. lookup is the LookupNetIP
// of a net.Resolver whose Dial goes through cacheDNSDial, which settles its
// exchanges. Resolvers sharing a scope must share their DNS transport policy.
func (c *AddressCache) Lookup(lookup func(context.Context, string, string) ([]netip.Addr, error), scope string) func(context.Context, string, string) ([]netip.Addr, error) {
	return func(ctx context.Context, network, host string) ([]netip.Addr, error) {
		if _, err := netip.ParseAddr(host); err == nil {
			return lookup(ctx, network, host)
		}
		store, key := c.entries(), addressKey{scope, network, strings.ToLower(host)}
		if record, ok := store.Get(key, time.Now()); ok {
			return slices.Clone(record.Value), nil
		}
		lifetime, started := new(addressLifetime), time.Now()
		ips, err := lookup(context.WithValue(ctx, addressLifetimeKey{}, lifetime), network, host)
		// After ctx ends, net.Resolver hides its values from later exchanges
		// but may still report success; those exchanges were never settled.
		expires, ok := lifetime.result()
		if started.Before(store.fresh) && store.fresh.Before(expires) {
			expires = store.fresh
		}
		if ok && err == nil && len(ips) > 0 && ctx.Err() == nil && time.Now().Before(expires) {
			store.Put(key, dnscache.Record[[]netip.Addr]{Value: slices.Clone(ips), ReceivedAt: time.Now(), Expires: expires}, 0)
		}
		return ips, err
	}
}

type addressLifetimeKey struct{}

// addressLifetime settles the DNS exchanges of one address lookup. Every
// transport net.Resolver opens settles exactly once: with the expiry of its
// cached answer, neutrally for a truncated datagram that TCP answers next, or
// as uncacheable. Methods accept a nil receiver for lookups without a cache.
type addressLifetime struct {
	mu      sync.Mutex
	pending int
	failed  bool
	expires time.Time
}

func addressLifetimeFrom(ctx context.Context) *addressLifetime {
	l, _ := ctx.Value(addressLifetimeKey{}).(*addressLifetime)
	return l
}

func (l *addressLifetime) open() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pending++
}

// settle completes an opened exchange. A zero expires is uncacheable unless
// the exchange is neutral.
func (l *addressLifetime) settle(expires time.Time, neutral bool) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pending--
	switch {
	case neutral:
	case expires.IsZero():
		l.failed = true
	case l.expires.IsZero() || expires.Before(l.expires):
		l.expires = expires
	}
}

func (l *addressLifetime) fail() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.failed = true
}

// result reports when the answer expires if every exchange settled cacheably.
func (l *addressLifetime) result() (time.Time, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.expires, l.pending == 0 && !l.failed && !l.expires.IsZero()
}
