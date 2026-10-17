// SPDX-License-Identifier: AGPL-3.0-only

package plugin

import (
	"context"
	"errors"
	"net/netip"
	"sync"

	dns "github.com/miekg/dns"
)

// NormalizeDNSServer adds the DNS port to bare IP addresses, preserving explicit
// ports, hostnames and transport URLs for the resolver that understands them.
func NormalizeDNSServer(server string) string {
	if ip, err := netip.ParseAddr(server); err == nil {
		return netip.AddrPortFrom(ip, 53).String()
	}
	return server
}

// RaceDNSServers gives each server an independent invocation-scoped request.
// Valid NOERROR responses win immediately; otherwise NXDOMAIN outranks SERVFAIL
// and other errors. All workers stop before the caller regains request ownership.
func RaceDNSServers(ctx context.Context, request *DNSExchange, servers []string, exchange func(context.Context, *DNSExchange, string) (*DNSResponse, error)) (*DNSResponse, error) {
	if len(servers) == 0 || len(servers) > 16 {
		return nil, errors.New("expected 1..16 DNS servers")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	type result struct {
		response *DNSResponse
		err      error
	}
	results := make(chan result, len(servers))
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	for _, server := range servers {
		workers.Go(func() {
			query := request.Fork()
			response, err := exchange(ctx, query, NormalizeDNSServer(server))
			if err == nil {
				if response == nil {
					err = errors.New("DNS server returned an empty response")
				} else {
					err = query.ValidateResponse(response.DNSPacket, true)
				}
			}
			results <- result{response, err}
		})
	}
	var failures error
	var best *DNSResponse
	bestRank := 4
	for range servers {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case result := <-results:
			if result.err != nil {
				failures = errors.Join(failures, result.err)
				continue
			}
			header, _ := result.response.Header()
			rank := 3
			switch header.Rcode {
			case dns.RcodeSuccess:
				return result.response, nil
			case dns.RcodeNameError:
				rank = 1
			case dns.RcodeServerFailure:
				rank = 2
			}
			if rank < bestRank {
				best, bestRank = result.response, rank
			}
		}
	}
	if best != nil {
		return best, nil
	}
	return nil, failures
}
