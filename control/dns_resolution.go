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

type timedAnswer struct {
	answer     dnsmessage.RR
	ttlSeconds int
}

type timedAddress struct {
	ip            netip.Addr
	ttlSeconds    int
	exactDeadline bool
}

// responseView is the cache and registration state derived for one name in a
// DNS response. A CNAME response has one view for every suffix of its chain.
type responseView struct {
	query          queryInfo
	answers        []timedAnswer
	addresses      []timedAddress
	expiresAsUnit  bool
	unitTTLSeconds int
}

type responsePlan struct {
	views         []responseView
	suppressCache bool
	signed        bool
}

type normalizedAnswer struct {
	answer     dnsmessage.RR
	ttlSeconds int
	signed     bool
}

type dnsRRSetKey struct {
	name   string
	rrtype uint16
	class  uint16
	// covered distinguishes RRSIG records for different covered RRsets.
	covered uint16
}

type cnameLink struct {
	owner  string
	target string
	answer normalizedAnswer
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
	normalized := normalizeDNSAnswers(answers)
	normalized, signed := constrainSignedRRSetTTLs(normalized, observedAt)
	finish := func(plan *responsePlan) *responsePlan {
		if plan != nil {
			plan.signed = signed
		}
		return plan
	}
	if len(normalized) == 0 {
		return finish(&responsePlan{views: []responseView{{query: qi}}})
	}

	cnameByOwner := make(map[string][]cnameLink)
	for _, answer := range normalized {
		cname, ok := answer.answer.(*dnsmessage.CNAME)
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
			suppressCache: !view.expiresAsUnit,
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
				suppressCache: !requested.expiresAsUnit,
			})
		}
		// Ignore disconnected CNAME data when the response contains a direct
		// address RRset for the question. Otherwise it is not cacheable.
		direct := c.planDirectView(qi, answersOwnedBy(normalized, qi.qname))
		if len(direct.addresses) == 0 {
			return nil
		}
		return finish(&responsePlan{views: []responseView{direct}})
	}

	links, terminalName, ok := followCNAMEChain(qi.qname, cnameByOwner)
	if !ok {
		return nil
	}
	if qi.qtype == dnsmessage.TypeCNAME {
		return finish(&responsePlan{views: []responseView{c.planAtomicView(qi, normalized)}})
	}
	terminalRRSet := rrsetAnswersOwnedBy(normalized, terminalName, qi.qtype)
	if len(terminalRRSet) == 0 {
		// A connected CNAME-to-NODATA answer is valid wire data, but caching
		// only its Answer section would discard the authoritative denial and
		// turn it into a misleading positive CNAME cache entry.
		return finish(&responsePlan{
			views:         []responseView{c.planAtomicView(qi, normalized)},
			suppressCache: true,
		})
	}
	if qi.qtype != dnsmessage.TypeA && qi.qtype != dnsmessage.TypeAAAA {
		return finish(&responsePlan{views: []responseView{c.planAtomicView(qi, normalized)}})
	}
	terminalAnswers := addressAnswersOwnedBy(normalized, terminalName, qi.qtype)
	if len(terminalAnswers) == 0 {
		return finish(&responsePlan{
			views:         []responseView{c.planAtomicView(qi, normalized)},
			suppressCache: true,
		})
	}

	views := c.planCNAMEViews(qi, normalized, links, terminalName, terminalAnswers)
	return finish(&responsePlan{views: views})
}

func constrainSignedRRSetTTLs(answers []normalizedAnswer, observedAt time.Time) ([]normalizedAnswer, bool) {
	type signatureConstraint struct {
		present bool
		usable  bool
		ttl     int
	}
	rrsets := make(map[dnsRRSetKey]struct{})
	for _, answer := range answers {
		if answer.answer.Header().Rrtype != dnsmessage.TypeRRSIG {
			rrsets[dnsRRSetKeyFor(answer.answer)] = struct{}{}
		}
	}
	constraints := make(map[dnsRRSetKey]signatureConstraint)
	signed := false
	for i := range answers {
		answer := &answers[i]
		signature, ok := answer.answer.(*dnsmessage.RRSIG)
		if !ok {
			continue
		}
		signed = true
		answer.signed = true
		cap := min(answer.ttlSeconds, normalizedDNSTTL(signature.OrigTtl))
		remaining, valid := rrsigRemainingTTL(signature, observedAt)
		if !valid {
			cap = 0
		} else {
			cap = min(cap, remaining)
		}
		answer.ttlSeconds = cap
		key := dnsRRSetKey{
			name:   dnsmessage.CanonicalName(signature.Hdr.Name),
			rrtype: signature.TypeCovered,
			class:  signature.Hdr.Class,
		}
		if _, exists := rrsets[key]; !exists {
			continue
		}
		constraint := constraints[key]
		constraint.present = true
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
		if answers[i].answer.Header().Rrtype == dnsmessage.TypeRRSIG {
			continue
		}
		header := answers[i].answer.Header()
		key := dnsRRSetKey{
			name:   dnsmessage.CanonicalName(header.Name),
			rrtype: header.Rrtype,
			class:  header.Class,
		}
		constraint, exists := constraints[key]
		if !exists || !constraint.present {
			continue
		}
		answers[i].signed = true
		if !constraint.usable {
			answers[i].ttlSeconds = 0
		} else if answers[i].ttlSeconds > constraint.ttl {
			answers[i].ttlSeconds = constraint.ttl
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

func cnameOwnersAreExclusive(answers []normalizedAnswer, byOwner map[string][]cnameLink) bool {
	for _, answer := range answers {
		if len(byOwner[dnsmessage.CanonicalName(answer.answer.Header().Name)]) == 0 {
			continue
		}
		switch answer.answer.Header().Rrtype {
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

func normalizeDNSAnswers(answers []dnsmessage.RR) []normalizedAnswer {
	rrsetTTL := make(map[dnsRRSetKey]int)
	answerTTL := make(map[dnsAnswerKey]int)
	unique := make([]dnsmessage.RR, 0, len(answers))
	seen := make(map[dnsAnswerKey]struct{}, len(answers))
	for _, answer := range answers {
		if answer == nil {
			continue
		}
		header := answer.Header()
		if header.Class != dnsmessage.ClassINET {
			continue
		}
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

	normalized := make([]normalizedAnswer, 0, len(unique))
	for _, answer := range unique {
		ttl := rrsetTTL[dnsRRSetKeyFor(answer)]
		if answer.Header().Rrtype == dnsmessage.TypeRRSIG {
			ttl = answerTTL[dnsAnswerIdentity(answer)]
		}
		normalized = append(normalized, normalizedAnswer{
			answer:     answer,
			ttlSeconds: ttl,
		})
	}
	return normalized
}

func dnsRRSetKeyFor(answer dnsmessage.RR) dnsRRSetKey {
	header := answer.Header()
	key := dnsRRSetKey{
		name:   dnsmessage.CanonicalName(header.Name),
		rrtype: header.Rrtype,
		class:  header.Class,
	}
	if signature, ok := answer.(*dnsmessage.RRSIG); ok {
		key.covered = signature.TypeCovered
	}
	return key
}

func normalizedDNSTTL(ttl uint32) int {
	if ttl > math.MaxInt32 {
		return 0
	}
	return int(ttl)
}

func followCNAMEChain(root string, byOwner map[string][]cnameLink) ([]cnameLink, string, bool) {
	current := root
	visited := make(map[string]struct{})
	links := make([]cnameLink, 0)
	for {
		if _, exists := visited[current]; exists {
			return nil, "", false
		}
		visited[current] = struct{}{}
		candidates := byOwner[current]
		if len(candidates) == 0 {
			return links, current, true
		}
		if len(candidates) != 1 || len(links) >= maxCNAMEChainDepth {
			return nil, "", false
		}
		links = append(links, candidates[0])
		current = candidates[0].target
	}
}

func (c *DnsController) effectivePlanTTL(fqdn string, ttl int, signed bool) int {
	effective := c.effectiveTTL(fqdn, ttl)
	if signed && effective > ttl {
		return ttl
	}
	return effective
}

func (c *DnsController) effectiveAnswerTTL(answer normalizedAnswer) int {
	return c.effectivePlanTTL(
		dnsmessage.CanonicalName(answer.answer.Header().Name),
		answer.ttlSeconds,
		answer.signed,
	)
}

func (c *DnsController) planDirectView(qi queryInfo, answers []normalizedAnswer) responseView {
	view := responseView{query: qi, answers: make([]timedAnswer, 0, len(answers))}
	for _, answer := range answers {
		ttl := c.effectiveAnswerTTL(answer)
		view.answers = append(view.answers, timedAnswer{answer: answer.answer, ttlSeconds: ttl})
		if dnsmessage.CanonicalName(answer.answer.Header().Name) != qi.qname {
			continue
		}
		if ip, ok := dnsAnswerAddress(qi.qtype, answer.answer); ok {
			view.addresses = append(view.addresses, timedAddress{
				ip: ip, ttlSeconds: ttl, exactDeadline: answer.signed,
			})
		}
	}
	dependencies := rrsetAnswersOwnedBy(answers, qi.qname, qi.qtype)
	if qi.qtype == dnsmessage.TypeANY {
		dependencies = answersOwnedBy(answers, qi.qname)
	}
	if len(dependencies) > 0 {
		view.expiresAsUnit = true
		view.unitTTLSeconds = c.minimumPlanTTL(dependencies)
	}
	return view
}

func (c *DnsController) planAtomicView(qi queryInfo, answers []normalizedAnswer) responseView {
	view := responseView{
		query:          qi,
		answers:        make([]timedAnswer, 0, len(answers)),
		expiresAsUnit:  true,
		unitTTLSeconds: c.minimumPlanTTL(answers),
	}
	for _, answer := range answers {
		ttl := c.effectiveAnswerTTL(answer)
		view.answers = append(view.answers, timedAnswer{
			answer:     answer.answer,
			ttlSeconds: ttl,
		})
	}
	return view
}

func (c *DnsController) minimumPlanTTL(answers []normalizedAnswer) int {
	minimum := c.effectiveAnswerTTL(answers[0])
	for _, answer := range answers[1:] {
		if ttl := c.effectiveAnswerTTL(answer); ttl < minimum {
			minimum = ttl
		}
	}
	return minimum
}

func (c *DnsController) planCNAMEViews(
	qi queryInfo,
	rootAnswers []normalizedAnswer,
	links []cnameLink,
	terminalName string,
	terminalAnswers []normalizedAnswer,
) []responseView {
	views := make([]responseView, len(links)+1)
	terminal := responseView{
		query:   queryInfo{qname: terminalName, qtype: qi.qtype},
		answers: make([]timedAnswer, 0, len(terminalAnswers)),
	}
	for _, answer := range terminalAnswers {
		ttl := c.effectiveAnswerTTL(answer)
		terminal.answers = append(terminal.answers, timedAnswer{answer: answer.answer, ttlSeconds: ttl})
		if ip, ok := dnsAnswerAddress(qi.qtype, answer.answer); ok {
			terminal.addresses = append(terminal.addresses, timedAddress{
				ip: ip, ttlSeconds: ttl, exactDeadline: answer.signed,
			})
		}
	}
	views[len(links)] = terminal

	suffix := append([]normalizedAnswer(nil), terminalAnswers...)
	for i := len(links) - 1; i >= 1; i-- {
		link := links[i]
		suffix = append([]normalizedAnswer{link.answer}, suffix...)
		unitTTL := c.minimumPlanTTL(suffix)
		exactDeadline := containsSignedAnswer(suffix)
		view := responseView{
			query:          queryInfo{qname: link.owner, qtype: qi.qtype},
			answers:        make([]timedAnswer, 0, len(suffix)),
			addresses:      make([]timedAddress, 0, len(terminal.addresses)),
			expiresAsUnit:  true,
			unitTTLSeconds: unitTTL,
		}
		for _, answer := range suffix {
			view.answers = append(view.answers, timedAnswer{
				answer:     answer.answer,
				ttlSeconds: c.effectiveAnswerTTL(answer),
			})
		}
		for _, address := range terminal.addresses {
			view.addresses = append(view.addresses, timedAddress{
				ip: address.ip, ttlSeconds: unitTTL, exactDeadline: exactDeadline,
			})
		}
		views[i] = view
	}

	// The root cache preserves relevant ancillary records from the original
	// answer, but none may outlive the CNAME chain on which it depends.
	dependencies := make([]normalizedAnswer, 0, len(links)+len(terminalAnswers))
	for _, link := range links {
		dependencies = append(dependencies, link.answer)
	}
	dependencies = append(dependencies, terminalAnswers...)
	rootUnitTTL := c.minimumPlanTTL(dependencies)
	rootExactDeadline := containsSignedAnswer(dependencies)
	root := responseView{
		query:          qi,
		answers:        make([]timedAnswer, 0, len(rootAnswers)),
		addresses:      make([]timedAddress, 0, len(terminal.addresses)),
		expiresAsUnit:  true,
		unitTTLSeconds: rootUnitTTL,
	}
	for _, answer := range rootAnswers {
		root.answers = append(root.answers, timedAnswer{
			answer:     answer.answer,
			ttlSeconds: c.effectiveAnswerTTL(answer),
		})
	}
	for _, address := range terminal.addresses {
		root.addresses = append(root.addresses, timedAddress{
			ip: address.ip, ttlSeconds: rootUnitTTL, exactDeadline: rootExactDeadline,
		})
	}
	views[0] = root
	return views
}

func containsSignedAnswer(answers []normalizedAnswer) bool {
	for _, answer := range answers {
		if answer.signed {
			return true
		}
	}
	return false
}

func answersOwnedBy(answers []normalizedAnswer, owner string) []normalizedAnswer {
	filtered := make([]normalizedAnswer, 0)
	for _, answer := range answers {
		if dnsmessage.CanonicalName(answer.answer.Header().Name) == owner {
			filtered = append(filtered, answer)
		}
	}
	return filtered
}

func rrsetAnswersOwnedBy(answers []normalizedAnswer, owner string, qtype uint16) []normalizedAnswer {
	filtered := make([]normalizedAnswer, 0)
	for _, answer := range answers {
		header := answer.answer.Header()
		if dnsmessage.CanonicalName(header.Name) == owner && header.Rrtype == qtype {
			filtered = append(filtered, answer)
		}
	}
	return filtered
}

func addressAnswersOwnedBy(answers []normalizedAnswer, owner string, qtype uint16) []normalizedAnswer {
	filtered := make([]normalizedAnswer, 0)
	for _, answer := range answers {
		if dnsmessage.CanonicalName(answer.answer.Header().Name) != owner {
			continue
		}
		switch answer.answer.(type) {
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
