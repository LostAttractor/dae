/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"math"
	"net/netip"
	"time"

	dnsmessage "github.com/miekg/dns"
)

const maxCNAMEChainDepth = 16

type plannedRR struct {
	rr               dnsmessage.RR
	absoluteDeadline time.Time
	exactLease       bool
}

// responseView is the cache and registration state derived for one name in a
// DNS response. A CNAME response has one view for every suffix of its chain.
type responseView struct {
	query             queryInfo
	answers           []plannedRR
	addresses         []netip.Addr
	validUntil        time.Time
	addressDeadline   time.Time
	addressExactLease bool
}

type responsePlan struct {
	observedAt    time.Time
	views         []responseView
	cacheEligible bool
}

type dnsRRSetKey struct {
	name   string
	rrtype uint16
}

type cnameLink struct {
	owner  string
	target string
	answer plannedRR
}

// planDNSResponse normalizes RRsets and classifies the response before
// constructing output. A nil plan means the CNAME structure is malformed and
// the response should pass through without cache or registry side effects.
func (c *DnsController) planDNSResponse(qi queryInfo, answers []dnsmessage.RR) *responsePlan {
	return c.planDNSResponseAt(qi, answers, time.Now())
}

func (c *DnsController) planDNSResponseAt(qi queryInfo, answers []dnsmessage.RR, observedAt time.Time) *responsePlan {
	qi.qname = dnsmessage.CanonicalName(qi.qname)
	for _, answer := range answers {
		if answer != nil && answer.Header().Class != dnsmessage.ClassINET {
			return nil
		}
	}
	normalized := normalizeDNSAnswers(answers, observedAt)
	normalized, signed := constrainSignedRRSetTTLs(normalized, observedAt)
	for i := range normalized {
		answer := &normalized[i]
		ttl := deadlineSeconds(answer.absoluteDeadline, observedAt)
		if fixedTTL, ok := c.fixedDomainTtl[dnsmessage.CanonicalName(answer.rr.Header().Name)]; ok &&
			(!answer.exactLease || fixedTTL <= ttl) {
			ttl = fixedTTL
		}
		answer.absoluteDeadline = observedAt.Add(time.Duration(ttl) * time.Second)
	}
	finish := func(plan *responsePlan) *responsePlan {
		if plan != nil {
			plan.observedAt = observedAt
			plan.cacheEligible = plan.cacheEligible && !signed
		}
		return plan
	}
	if len(normalized) == 0 {
		return finish(&responsePlan{views: []responseView{{query: qi}}, cacheEligible: true})
	}

	cnameByOwner := make(map[string][]cnameLink)
	for _, answer := range normalized {
		cname, ok := answer.rr.(*dnsmessage.CNAME)
		if !ok {
			continue
		}
		owner := dnsmessage.CanonicalName(cname.Hdr.Name)
		cnameByOwner[owner] = append(cnameByOwner[owner], cnameLink{
			owner:  owner,
			target: dnsmessage.CanonicalName(cname.Target),
			answer: answer,
		})
	}
	if len(cnameByOwner) == 0 {
		view := c.planDirectView(qi, normalized)
		return finish(&responsePlan{
			views:         []responseView{view},
			cacheEligible: !view.validUntil.IsZero(),
		})
	}
	if !cnameOwnersAreExclusive(normalized, cnameByOwner) {
		return nil
	}
	if !cnameGraphIsValid(cnameByOwner) {
		return nil
	}

	if len(cnameByOwner[qi.qname]) == 0 {
		if qi.qtype != dnsmessage.TypeA && qi.qtype != dnsmessage.TypeAAAA {
			requested := c.planDirectView(qi, normalized)
			return finish(&responsePlan{
				views:         []responseView{c.planAtomicView(qi, normalized)},
				cacheEligible: !requested.validUntil.IsZero(),
			})
		}
		// Ignore disconnected CNAME data when the response contains a direct
		// address RRset for the question. Otherwise it is not cacheable.
		direct := c.planDirectView(qi, answersOwnedBy(normalized, qi.qname))
		if len(direct.addresses) == 0 {
			return nil
		}
		return finish(&responsePlan{views: []responseView{direct}, cacheEligible: true})
	}

	links, terminalName := followCNAMEChain(qi.qname, cnameByOwner)
	if qi.qtype == dnsmessage.TypeCNAME {
		return finish(&responsePlan{views: []responseView{c.planAtomicView(qi, normalized)}, cacheEligible: true})
	}
	terminalRRSet := rrsetAnswersOwnedBy(normalized, terminalName, qi.qtype)
	if len(terminalRRSet) == 0 {
		// A connected CNAME-to-NODATA answer is valid wire data, but caching
		// only its Answer section would discard the authoritative denial and
		// turn it into a misleading positive CNAME cache entry.
		return finish(&responsePlan{
			views: []responseView{c.planAtomicView(qi, normalized)},
		})
	}
	if qi.qtype != dnsmessage.TypeA && qi.qtype != dnsmessage.TypeAAAA {
		return finish(&responsePlan{views: []responseView{c.planAtomicView(qi, normalized)}, cacheEligible: true})
	}
	terminalAnswers := addressAnswersOwnedBy(normalized, terminalName, qi.qtype)
	if len(terminalAnswers) == 0 {
		return finish(&responsePlan{
			views: []responseView{c.planAtomicView(qi, normalized)},
		})
	}

	views := c.planCNAMEViews(qi, normalized, links, terminalName, terminalAnswers)
	return finish(&responsePlan{views: views, cacheEligible: true})
}

func constrainSignedRRSetTTLs(answers []plannedRR, observedAt time.Time) ([]plannedRR, bool) {
	type signatureConstraint struct {
		usable bool
		ttl    int
	}
	rrsets := make(map[dnsRRSetKey]struct{})
	for _, answer := range answers {
		if answer.rr.Header().Rrtype != dnsmessage.TypeRRSIG {
			rrsets[dnsRRSetKeyFor(answer.rr)] = struct{}{}
		}
	}
	constraints := make(map[dnsRRSetKey]signatureConstraint)
	signed := false
	for i := range answers {
		answer := &answers[i]
		signature, ok := answer.rr.(*dnsmessage.RRSIG)
		if !ok {
			continue
		}
		signed = true
		answer.exactLease = true
		cap := min(deadlineSeconds(answer.absoluteDeadline, observedAt), normalizedDNSTTL(signature.OrigTtl))
		remaining, valid := rrsigRemainingTTL(signature, observedAt)
		if !valid {
			cap = 0
		} else {
			cap = min(cap, remaining)
		}
		answer.absoluteDeadline = observedAt.Add(time.Duration(cap) * time.Second)
		key := dnsRRSetKey{
			name:   dnsmessage.CanonicalName(signature.Hdr.Name),
			rrtype: signature.TypeCovered,
		}
		if _, exists := rrsets[key]; !exists {
			continue
		}
		constraint := constraints[key]
		if valid && (!constraint.usable || cap > constraint.ttl) {
			constraint.usable = true
			constraint.ttl = cap
		}
		constraints[key] = constraint
	}
	if !signed {
		return answers, false
	}
	for i := range answers {
		if answers[i].rr.Header().Rrtype == dnsmessage.TypeRRSIG {
			continue
		}
		header := answers[i].rr.Header()
		key := dnsRRSetKey{
			name:   dnsmessage.CanonicalName(header.Name),
			rrtype: header.Rrtype,
		}
		constraint, exists := constraints[key]
		if !exists {
			continue
		}
		answers[i].exactLease = true
		if !constraint.usable {
			answers[i].absoluteDeadline = observedAt
		} else if deadlineSeconds(answers[i].absoluteDeadline, observedAt) > constraint.ttl {
			answers[i].absoluteDeadline = observedAt.Add(time.Duration(constraint.ttl) * time.Second)
		}
	}
	return answers, true
}

// RRSIG timestamps use 32-bit serial arithmetic and can wrap. ValidityPeriod
// performs the RFC comparison; the unsigned subtraction then yields the
// remaining interval because a valid interval is shorter than half the serial
// space. TTLs are integral seconds, so a fractional current second rounds down.
func rrsigRemainingTTL(signature *dnsmessage.RRSIG, observedAt time.Time) (int, bool) {
	if signature == nil {
		return 0, false
	}
	now := uint32(observedAt.Unix())
	const halfRange = uint32(1) << 31
	if now-signature.Inception >= halfRange || signature.Expiration-now >= halfRange {
		return 0, false
	}
	remaining := signature.Expiration - now
	if observedAt.Nanosecond() != 0 && remaining > 0 {
		remaining--
	}
	return int(remaining), true
}

func cnameOwnersAreExclusive(answers []plannedRR, byOwner map[string][]cnameLink) bool {
	for _, answer := range answers {
		if len(byOwner[dnsmessage.CanonicalName(answer.rr.Header().Name)]) == 0 {
			continue
		}
		switch answer.rr.Header().Rrtype {
		case dnsmessage.TypeCNAME, dnsmessage.TypeRRSIG, dnsmessage.TypeNSEC:
		default:
			return false
		}
	}
	return true
}

func cnameGraphIsValid(byOwner map[string][]cnameLink) bool {
	for _, candidates := range byOwner {
		if len(candidates) != 1 {
			return false
		}
	}
	for root := range byOwner {
		current := root
		visited := make(map[string]struct{})
		for depth := 0; ; depth++ {
			if _, exists := visited[current]; exists || depth > maxCNAMEChainDepth {
				return false
			}
			visited[current] = struct{}{}
			candidates := byOwner[current]
			if len(candidates) == 0 {
				break
			}
			current = candidates[0].target
		}
	}
	return true
}

func normalizeDNSAnswers(answers []dnsmessage.RR, observedAt time.Time) []plannedRR {
	rrsetTTL := make(map[dnsRRSetKey]int)
	answerTTL := make(map[dnsAnswerKey]int)
	unique := make([]dnsmessage.RR, 0, len(answers))
	seen := make(map[dnsAnswerKey]struct{}, len(answers))
	for _, answer := range answers {
		if answer == nil {
			continue
		}
		header := answer.Header()
		rrset := dnsRRSetKeyFor(answer)
		ttl := normalizedDNSTTL(header.Ttl)
		if current, exists := rrsetTTL[rrset]; header.Rrtype != dnsmessage.TypeRRSIG && (!exists || ttl < current) {
			rrsetTTL[rrset] = ttl
		}
		identity := dnsAnswerIdentity(answer)
		if current, exists := answerTTL[identity]; !exists || ttl < current {
			answerTTL[identity] = ttl
		}
		if _, exists := seen[identity]; exists {
			continue
		}
		seen[identity] = struct{}{}
		unique = append(unique, answer)
	}

	normalized := make([]plannedRR, 0, len(unique))
	for _, answer := range unique {
		ttl := rrsetTTL[dnsRRSetKeyFor(answer)]
		if answer.Header().Rrtype == dnsmessage.TypeRRSIG {
			ttl = answerTTL[dnsAnswerIdentity(answer)]
		}
		normalized = append(normalized, plannedRR{
			rr:               answer,
			absoluteDeadline: observedAt.Add(time.Duration(ttl) * time.Second),
		})
	}
	return normalized
}

func dnsRRSetKeyFor(answer dnsmessage.RR) dnsRRSetKey {
	header := answer.Header()
	return dnsRRSetKey{
		name:   dnsmessage.CanonicalName(header.Name),
		rrtype: header.Rrtype,
	}
}

func normalizedDNSTTL(ttl uint32) int {
	if ttl > math.MaxInt32 {
		return 0
	}
	return int(ttl)
}

func deadlineSeconds(deadline, observedAt time.Time) int {
	remaining := deadline.Sub(observedAt)
	if remaining <= 0 {
		return 0
	}
	return int(remaining / time.Second)
}

func followCNAMEChain(root string, byOwner map[string][]cnameLink) ([]cnameLink, string) {
	current := root
	links := make([]cnameLink, 0)
	for {
		candidates := byOwner[current]
		if len(candidates) == 0 {
			return links, current
		}
		links = append(links, candidates[0])
		current = candidates[0].target
	}
}

func (c *DnsController) planDirectView(qi queryInfo, answers []plannedRR) responseView {
	view := responseView{query: qi, answers: make([]plannedRR, 0, len(answers))}
	for _, answer := range answers {
		view.answers = append(view.answers, answer)
		if dnsmessage.CanonicalName(answer.rr.Header().Name) != qi.qname {
			continue
		}
		if ip, ok := dnsAnswerAddress(qi.qtype, answer.rr); ok {
			view.addresses = append(view.addresses, ip)
			if view.addressDeadline.IsZero() || answer.absoluteDeadline.Before(view.addressDeadline) {
				view.addressDeadline = answer.absoluteDeadline
			}
			view.addressExactLease = view.addressExactLease || answer.exactLease
		}
	}
	dependencies := rrsetAnswersOwnedBy(answers, qi.qname, qi.qtype)
	if qi.qtype == dnsmessage.TypeANY {
		dependencies = answersOwnedBy(answers, qi.qname)
	}
	if len(dependencies) > 0 {
		view.validUntil = minimumPlanDeadline(dependencies)
	}
	return view
}

func (c *DnsController) planAtomicView(qi queryInfo, answers []plannedRR) responseView {
	return responseView{
		query:      qi,
		answers:    append([]plannedRR(nil), answers...),
		validUntil: minimumPlanDeadline(answers),
	}
}

func minimumPlanDeadline(answers []plannedRR) time.Time {
	minimum := answers[0].absoluteDeadline
	for _, answer := range answers[1:] {
		if answer.absoluteDeadline.Before(minimum) {
			minimum = answer.absoluteDeadline
		}
	}
	return minimum
}

func (c *DnsController) planCNAMEViews(
	qi queryInfo,
	rootAnswers []plannedRR,
	links []cnameLink,
	terminalName string,
	terminalAnswers []plannedRR,
) []responseView {
	views := make([]responseView, len(links)+1)
	terminal := responseView{
		query:   queryInfo{qname: terminalName, qtype: qi.qtype},
		answers: append([]plannedRR(nil), terminalAnswers...),
	}
	for _, answer := range terminalAnswers {
		if ip, ok := dnsAnswerAddress(qi.qtype, answer.rr); ok {
			terminal.addresses = append(terminal.addresses, ip)
			if terminal.addressDeadline.IsZero() || answer.absoluteDeadline.Before(terminal.addressDeadline) {
				terminal.addressDeadline = answer.absoluteDeadline
			}
			terminal.addressExactLease = terminal.addressExactLease || answer.exactLease
		}
	}
	views[len(links)] = terminal

	suffix := append([]plannedRR(nil), terminalAnswers...)
	for i := len(links) - 1; i >= 1; i-- {
		link := links[i]
		suffix = append([]plannedRR{link.answer}, suffix...)
		validUntil := minimumPlanDeadline(suffix)
		view := responseView{
			query:             queryInfo{qname: link.owner, qtype: qi.qtype},
			answers:           append([]plannedRR(nil), suffix...),
			addresses:         append([]netip.Addr(nil), terminal.addresses...),
			validUntil:        validUntil,
			addressDeadline:   validUntil,
			addressExactLease: containsExactLease(suffix),
		}
		views[i] = view
	}

	// The root cache preserves relevant ancillary records from the original
	// answer, but none may outlive the CNAME chain on which it depends.
	dependencies := make([]plannedRR, 0, len(links)+len(terminalAnswers))
	for _, link := range links {
		dependencies = append(dependencies, link.answer)
	}
	dependencies = append(dependencies, terminalAnswers...)
	rootValidUntil := minimumPlanDeadline(dependencies)
	root := responseView{
		query:             qi,
		answers:           append([]plannedRR(nil), rootAnswers...),
		addresses:         append([]netip.Addr(nil), terminal.addresses...),
		validUntil:        rootValidUntil,
		addressDeadline:   rootValidUntil,
		addressExactLease: containsExactLease(dependencies),
	}
	views[0] = root
	return views
}

func containsExactLease(answers []plannedRR) bool {
	for _, answer := range answers {
		if answer.exactLease {
			return true
		}
	}
	return false
}

func answersOwnedBy(answers []plannedRR, owner string) []plannedRR {
	filtered := make([]plannedRR, 0)
	for _, answer := range answers {
		if dnsmessage.CanonicalName(answer.rr.Header().Name) == owner {
			filtered = append(filtered, answer)
		}
	}
	return filtered
}

func rrsetAnswersOwnedBy(answers []plannedRR, owner string, qtype uint16) []plannedRR {
	filtered := make([]plannedRR, 0)
	for _, answer := range answers {
		header := answer.rr.Header()
		if dnsmessage.CanonicalName(header.Name) == owner && header.Rrtype == qtype {
			filtered = append(filtered, answer)
		}
	}
	return filtered
}

func addressAnswersOwnedBy(answers []plannedRR, owner string, qtype uint16) []plannedRR {
	filtered := make([]plannedRR, 0)
	for _, answer := range answers {
		if dnsmessage.CanonicalName(answer.rr.Header().Name) != owner {
			continue
		}
		switch answer.rr.(type) {
		case *dnsmessage.A:
			if qtype == dnsmessage.TypeA {
				filtered = append(filtered, answer)
			}
		case *dnsmessage.AAAA:
			if qtype == dnsmessage.TypeAAAA {
				filtered = append(filtered, answer)
			}
		}
	}
	return filtered
}
