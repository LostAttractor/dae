// SPDX-License-Identifier: AGPL-3.0-only

// Package happyeyeballs schedules address discovery and connection attempts
// without owning routing, protocol handshakes, or connection pools.
package happyeyeballs

import (
	"context"
	"errors"
	"iter"
	"net"
	"net/netip"
	"time"
)

const resolutionDelay = 50 * time.Millisecond

// Resolve queries both families independently, prefers IPv6, and interleaves
// available addresses without waiting for a slow family (RFC 8305 sections 3-4).
// network is ip, ip4, or ip6. The resolver supplies ordering within each family.
func Resolve(ctx context.Context, resolver *net.Resolver, network, host string) iter.Seq2[netip.Addr, error] {
	return func(yield func(netip.Addr, error) bool) {
		if resolver == nil {
			resolver = net.DefaultResolver
		}
		if network != "ip" && network != "ip4" && network != "ip6" {
			yield(netip.Addr{}, net.UnknownNetworkError(network))
			return
		}
		if ip, err := netip.ParseAddr(host); err == nil {
			ip = ip.Unmap()
			if network == "ip4" && !ip.Is4() || network == "ip6" && !ip.Is6() {
				yield(netip.Addr{}, &net.AddrError{Err: "address family mismatch", Addr: host})
			} else {
				yield(ip, ctx.Err())
			}
			return
		}
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		type answer struct {
			family int
			ips    []netip.Addr
			err    error
		}
		answers := make(chan answer, 2)
		var queues [2][]netip.Addr // IPv6, IPv4.
		var done [2]bool
		for family, query := range []string{"ip6", "ip4"} {
			if network != "ip" && network != query {
				done[family] = true
				continue
			}
			go func() {
				ips, err := resolver.LookupNetIP(ctx, query, host)
				answers <- answer{family, ips, err}
			}()
		}
		var failures []error
		accept := func(a answer) {
			done[a.family] = true
			if a.err != nil {
				failures = append(failures, a.err)
			}
			for _, ip := range a.ips {
				ip = ip.Unmap()
				if ip.IsValid() && ip.Is4() == (a.family == 1) {
					queues[a.family] = append(queues[a.family], ip)
				}
			}
		}
		var delay *time.Timer
		defer func() {
			if delay != nil {
				delay.Stop()
			}
		}()
		preferred, yielded, waited := 0, false, false
		for {
			if err := ctx.Err(); err != nil {
				yield(netip.Addr{}, err)
				return
			}
			// Answers arriving while the consumer dials join the remaining list.
			for len(answers) > 0 {
				accept(<-answers)
			}
			if !yielded && !waited && len(queues[0]) == 0 && !done[0] && len(queues[1]) > 0 {
				if delay == nil {
					delay = time.NewTimer(resolutionDelay)
				}
				select {
				case a := <-answers:
					accept(a)
				case <-delay.C:
					waited = true
				case <-ctx.Done():
				}
				continue
			}
			family := preferred
			if len(queues[family]) == 0 {
				family = 1 - family
			}
			if len(queues[family]) > 0 {
				ip := queues[family][0]
				queues[family] = queues[family][1:]
				preferred, yielded = 1-family, true
				if !yield(ip, nil) {
					return
				}
				continue
			}
			if done[0] && done[1] {
				if !yielded {
					yield(netip.Addr{}, errors.Join(&net.DNSError{Name: host, Err: "no suitable address", IsNotFound: true}, errors.Join(failures...)))
				}
				return
			}
			select {
			case a := <-answers:
				accept(a)
			case <-ctx.Done():
			}
		}
	}
}
