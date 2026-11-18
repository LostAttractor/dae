// SPDX-License-Identifier: AGPL-3.0-only

package control

import (
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/daeuniverse/dae/common/persist"
	dnsmessage "github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// Evidence is persisted as a baseline and a journal in one directory. Both
// files start with an 8-byte magic and the baseline's epoch (u64 LE).
//
// The baseline lists every pair with its exact deadline, grouped by domain:
// uvarint name length and name, uvarint address count, then per address its
// length byte (4 or 16), bytes and the varint delta of its deadline (Unix ns)
// from the previous one. The CRC32C (u32 LE) of everything before it ends the
// file. A pair's ordinal is its position.
//
// Journal frames are a u32 LE payload length, the payload and the CRC32C of
// (epoch, frame offset, length, payload), so a frame is valid only at its own
// position in a journal of the baseline's epoch. Replay stops at the first
// invalid frame, including the zeros after the last one. Payloads:
//
//	NEW    1, then per pair: name, address, varint exact deadline. Pairs take
//	       the next ordinals. Appended after DNS delivery, without fdatasync.
//	RENEW  2, varint bound, uvarint n and n ascending ordinals (delta coded),
//	       uvarint m and m (ordinal delta, varint deadline) exact renewals.
//	       Closes one renewal window and is followed by fdatasync, which also
//	       makes the NEW frames before it durable.
//
// Deadlines only move forward and pairs are deleted only by expiry, so replay
// folds with max and expiry needs no records. A pair renewed in a window that
// opened at T recovers the bound T+domainRenewInterval+window, overestimating
// by at most one interval; a pair whose final deadline in the window the bound
// would not cover that tightly is written exactly. A crash loses the renewals
// of the open window: those pairs recover the deadline persisted before it.
const (
	domainBaseFile      = "domain-registry.base"
	domainJournalFile   = "domain-registry.journal"
	domainTempSuffix    = ".tmp"
	domainRenewInterval = 10 * time.Minute
	// The journal grows in zero-filled chunks. Frames then overwrite allocated
	// blocks without changing the file size, so fdatasync writes only data,
	// and a journal shorter than one chunk is never compacted.
	domainJournalChunk = 64 << 10
	domainHeaderSize   = 16
	domainFrameNew     = 1
	domainFrameRenew   = 2
)

var (
	domainBaseMagic    = [8]byte{'D', 'A', 'E', 'R', 'E', 'G', 'B', 1}
	domainJournalMagic = [8]byte{'D', 'A', 'E', 'R', 'E', 'G', 'J', 1}
	domainCRC          = crc32.MakeTable(crc32.Castagnoli)
)

type domainLogEntry struct {
	name     string
	ip       netip.Addr
	deadline int64 // Unix ns
}

type domainLogExact struct {
	ordinal  uint32
	deadline int64
}

// domainLog is the persistence state of the registry that owns the files.
// The owner's DomainRegistry.mu guards every field except io and disk, and
// each mutation costs O(1) under it. io serializes the journal writers: a
// mutation appending its new pairs, the owner's worker and Close. Its holder
// owns disk. Lock order: io, then DomainRegistry.mu.
type domainLog struct {
	io                sync.Mutex
	enabled           bool // writing starts after activation
	disabled          bool // the files could not be read; this run leaves them untouched
	rebuild           bool // the files do not describe memory; the next write compacts
	next              uint32
	window            uint32    // id of the open renewal window; pairs keep their last listing
	due               time.Time // when the open window closes; moves with the files on reload
	lo, hi            int64     // final deadlines in [lo, hi] are listed and recover hi
	renewed           []*domainPair
	fresh             []domainLogEntry
	disk              domainDisk
	capacityPath      string
	capacityDurable   [domainCapacityBuckets]time.Time
	capacityRetry     time.Time
	capacityDirSynced bool
}

type domainDisk struct {
	dir   string
	epoch uint64
	file  *os.File // journal, opened by the first append
	size  int64    // header and valid frames
	end   int64    // zero-filled file length; zero until a recovered tail is dropped
	base  int64    // baseline bytes; a journal reaching them is compacted
	dirty bool     // frames written since the last fdatasync
	retry time.Time
}

func newDomainLog(dir string, now time.Time, window time.Duration) *domainLog {
	l := &domainLog{rebuild: true, disk: domainDisk{dir: dir}, capacityPath: filepath.Join(dir, domainCapacityFile)}
	l.open(now, window)
	return l
}

// add gives a new pair the next ordinal and queues its NEW record.
func (l *domainLog) add(name string, ip netip.Addr, pair *domainPair) {
	pair.ordinal = l.next
	l.next++
	if !l.rebuild {
		l.fresh = append(l.fresh, domainLogEntry{name, ip, pair.retainUntil.UnixNano()})
	}
}

// renew lists a renewed pair once per window; the window's end classifies it
// by its final deadline.
func (l *domainLog) renew(pair *domainPair) {
	if !l.rebuild && pair.listed != l.window {
		pair.listed = l.window
		l.renewed = append(l.renewed, pair)
	}
}

// rotate opens a renewal window and returns the records of the previous one:
// the ordinals its bound covers within one interval, and exact deadlines for
// the rest (TTLs longer than the window, activity observed before the window
// opened or applied after it was due, clock steps).
func (l *domainLog) rotate(now time.Time, window time.Duration) (renewed []uint32, exact []domainLogExact, fresh []domainLogEntry, bound int64) {
	for _, pair := range l.renewed {
		if deadline := pair.retainUntil.UnixNano(); deadline >= l.lo && deadline <= l.hi {
			renewed = append(renewed, pair.ordinal)
		} else {
			exact = append(exact, domainLogExact{pair.ordinal, deadline})
		}
	}
	fresh, bound = l.fresh, l.hi
	l.open(now, window)
	return renewed, exact, fresh, bound
}

// open starts an empty renewal window. Window ids wrap after 2^32 intervals,
// about 80,000 years.
func (l *domainLog) open(now time.Time, window time.Duration) {
	l.renewed, l.fresh = nil, nil
	l.window++
	l.due = now.Add(domainRenewInterval)
	l.lo = now.UnixNano() + int64(window)
	l.hi = l.lo + int64(domainRenewInterval)
}

func (g *DomainRegistry) EnablePersistence(dir string) {
	g.mu.Lock()
	if g.persist == nil {
		g.persist = newDomainLog(dir, time.Now(), g.window)
	}
	g.persist.enabled = !g.persist.disabled
	g.capacityWriting = g.persist.enabled
	g.persistActiveCapacity()
	g.mu.Unlock()
	g.wakePersistence()
}

func (g *DomainRegistry) wakePersistence() {
	select {
	case g.persistWake <- struct{}{}:
	default:
	}
}

// renewalDue reports whether the open window has ended. Its close time moves
// with the files on reload, so reloads cannot postpone it.
func (g *DomainRegistry) renewalDue(now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.persist != nil && g.persist.enabled && !now.Before(g.persist.due)
}

// lockLog returns the log this registry writes, with io held, or nil before
// activation and after the files moved to another registry or were closed.
func (g *DomainRegistry) lockLog() *domainLog {
	g.mu.Lock()
	l := g.persist
	g.mu.Unlock()
	if l == nil {
		return nil
	}
	l.io.Lock()
	g.mu.Lock()
	owned := g.persist == l && l.enabled
	g.mu.Unlock()
	if !owned {
		l.io.Unlock()
		return nil
	}
	return l
}

// appendNew journals the pairs a mutation queued in l from the mutation's
// goroutine, without waiting: a writer already holding io appends them before
// it releases io. The worker takes over a pending rebuild and pairs left by a
// writer whose files moved to a successor.
func (g *DomainRegistry) appendNew(l *domainLog) {
	if !l.io.TryLock() || g.drainNew(l) {
		g.wakePersistence()
	}
}

// drainNew appends queued pairs as NEW frames in ordinal order, then releases
// io. Once the queue is empty it releases io under the registry lock, so a
// mutation queuing later finds io free or held by a writer that sees its
// pairs. It reports a rebuild left to the worker.
func (g *DomainRegistry) drainNew(l *domainLog) (rebuild bool) {
	for {
		g.mu.Lock()
		owned := g.persist == l && l.enabled
		if !owned || l.rebuild || len(l.fresh) == 0 {
			rebuild = owned && l.rebuild
			l.io.Unlock()
			g.mu.Unlock()
			return rebuild
		}
		fresh := l.fresh
		l.fresh = nil
		g.mu.Unlock()
		if err := l.disk.append(encodeDomainNew(fresh)); err != nil {
			g.persistFailed(l, err)
		}
	}
}

// writeNew is the worker's share of new pairs: it writes the baseline the
// files need, then appends what mutations could not. After a failed
// compaction it waits for the retry time.
func (g *DomainRegistry) writeNew(now time.Time) {
	l := g.lockLog()
	if l == nil {
		return
	}
	g.mu.Lock()
	rebuild := l.rebuild
	g.mu.Unlock()
	if rebuild && !now.Before(l.disk.retry) {
		g.compact(l, now)
	}
	g.drainNew(l)
}

// writeRenewals closes the renewal window and makes every written frame
// durable, then compacts a journal that has grown to the baseline's size. The
// worker calls it when the window is due and Close for the final write; both
// rewrite the baseline if the files need it.
func (g *DomainRegistry) writeRenewals(now time.Time) {
	l := g.lockLog()
	if l == nil {
		return
	}
	g.mu.Lock()
	if g.closed {
		l.capacityRetry = time.Time{} // One final attempt before releasing the files.
	}
	g.persistActiveCapacity()
	if l.rebuild {
		g.mu.Unlock()
		g.compact(l, now)
		g.drainNew(l)
		return
	}
	renewed, exact, fresh, bound := l.rotate(now, g.window)
	g.mu.Unlock()
	d := &l.disk
	err := d.append(encodeDomainNew(fresh), encodeDomainRenew(bound, renewed, exact))
	if err != nil {
		g.persistFailed(l, err)
	}
	file, flush, full := d.file, d.dirty && err == nil, d.size >= max(d.base, domainJournalChunk)
	d.dirty = false
	// Mutations keep appending during fdatasync. Frames written before it
	// starts become durable with this window; later ones set dirty again.
	g.drainNew(l)
	if flush {
		if err = unix.Fdatasync(int(file.Fd())); err != nil {
			g.persistFailed(l, err)
		}
	}
	if err == nil && full {
		if l = g.lockLog(); l != nil {
			g.compact(l, now)
			g.drainNew(l)
		}
	}
}

// persistFailed drops journal state that may not have reached the files; the
// next attempt writes memory as a new baseline. The caller holds io or is the
// owner's worker, so the files cannot move meanwhile.
func (g *DomainRegistry) persistFailed(l *domainLog, err error) {
	log.WithError(err).WithField("dir", l.disk.dir).Warn("Persist domain registry; rewriting its baseline")
	g.mu.Lock()
	l.rebuild = true
	l.renewed, l.fresh = nil, nil
	g.mu.Unlock()
}

// compact writes memory as the baseline of a new epoch. The caller holds io
// for the whole compaction, so pairs created meanwhile wait in the queue and
// go to the new journal; only the flat copy and renumbering hold the registry
// lock. A failure sets the retry time for writeNew.
func (g *DomainRegistry) compact(l *domainLog, now time.Time) {
	d := &l.disk
	g.mu.Lock()
	if !g.persistActiveCapacity() {
		// Replacing the baseline would discard the only recovery source for
		// pairs omitted while restoring a larger registry.
		d.retry = now.Add(domainRenewInterval)
		g.mu.Unlock()
		return
	}
	// Reuse renewal marks from this or the just-closed window; reads stay cold.
	hot := func(pair *domainPair) bool { return pair.listed != 0 && l.window-pair.listed <= 1 }
	entries := make([]domainLogEntry, g.pairs)
	front, back := 0, len(entries)
	for name, r := range g.byName {
		active := false
		for _, pair := range r.addresses {
			if hot(pair) {
				active = true
				break
			}
		}
		// Partition whole domain groups without a sort or another allocation.
		start := front
		if active {
			front += len(r.addresses)
		} else {
			back -= len(r.addresses)
			start = back
		}
		end := start + len(r.addresses)
		for ip, pair := range r.addresses {
			index := start
			if hot(pair) {
				start++
			} else {
				end--
				index = end
			}
			pair.ordinal = uint32(index)
			entries[index] = domainLogEntry{name, ip, pair.retainUntil.UnixNano()}
		}
	}
	l.next, l.rebuild = uint32(len(entries)), false
	l.open(now, g.window)
	g.mu.Unlock()
	epoch := rand.Uint64()
	base := encodeDomainBase(epoch, entries)
	var err error
	for _, step := range domainCompaction(d.dir, base, epoch) {
		if err = step(); err != nil {
			break
		}
	}
	if err != nil {
		d.retry = now.Add(domainRenewInterval)
		g.persistFailed(l, err)
		return
	}
	if d.file != nil {
		_ = d.file.Close()
	}
	*d = domainDisk{dir: d.dir, epoch: epoch, size: domainHeaderSize, end: domainJournalChunk, base: int64(len(base))}
}

// domainCompaction replaces the baseline, then starts an empty journal of its
// epoch. Interrupted between steps, the directory holds the old baseline and
// journal, the new baseline with an ignored old journal, or the new pair; a
// complete temporary baseline is adopted if the published one is unreadable.
func domainCompaction(dir string, base []byte, epoch uint64) []func() error {
	basePath, journalPath := filepath.Join(dir, domainBaseFile), filepath.Join(dir, domainJournalFile)
	journal := domainHeader(domainJournalMagic, epoch)
	journal = append(journal, make([]byte, domainJournalChunk-len(journal))...)
	return []func() error{
		func() error { return persist.MkdirAll(dir, 0700) },
		func() error { return writeSynced(basePath+domainTempSuffix, base) },
		func() error { return renameSynced(basePath+domainTempSuffix, basePath) },
		func() error { return writeSynced(journalPath+domainTempSuffix, journal) },
		func() error { return renameSynced(journalPath+domainTempSuffix, journalPath) },
	}
}

func writeSynced(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}

func renameSynced(from, to string) error {
	if err := os.Rename(from, to); err != nil {
		return err
	}
	return persist.SyncDir(filepath.Dir(to))
}

// append writes the non-nil payloads as frames with one pwrite, extending the
// zero-filled region as needed. The first append to a recovered journal drops
// anything after its last valid frame.
func (d *domainDisk) append(payloads ...[]byte) error {
	var frames []byte
	for _, payload := range payloads {
		if payload == nil {
			continue
		}
		offset := d.size + int64(len(frames))
		frames = binary.LittleEndian.AppendUint32(frames, uint32(len(payload)))
		frames = append(frames, payload...)
		frames = binary.LittleEndian.AppendUint32(frames, domainFrameCRC(d.epoch, offset, payload))
	}
	if len(frames) == 0 {
		return nil
	}
	if d.file == nil {
		f, err := os.OpenFile(filepath.Join(d.dir, domainJournalFile), os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		if d.end == 0 {
			if err := f.Truncate(d.size); err != nil {
				return errors.Join(err, f.Close())
			}
			d.end = d.size
		}
		d.file = f
	}
	written := len(frames)
	if end := d.size + int64(written); end > d.end {
		d.end = (end + domainJournalChunk - 1) / domainJournalChunk * domainJournalChunk
		frames = append(frames, make([]byte, d.end-end)...)
	}
	if _, err := d.file.WriteAt(frames, d.size); err != nil {
		return err
	}
	d.size += int64(written)
	d.dirty = true
	return nil
}

// closePersistence releases the journal after the final write, once writers
// still holding io are done.
func (g *DomainRegistry) closePersistence() {
	l := g.lockLog()
	g.mu.Lock()
	g.persist = nil
	g.mu.Unlock()
	if l != nil {
		if l.disk.file != nil {
			_ = l.disk.file.Close()
		}
		l.io.Unlock()
	}
}

func domainHeader(magic [8]byte, epoch uint64) []byte {
	return binary.LittleEndian.AppendUint64(magic[:], epoch)
}

func domainFrameCRC(epoch uint64, offset int64, payload []byte) uint32 {
	var prefix [20]byte
	binary.LittleEndian.PutUint64(prefix[:], epoch)
	binary.LittleEndian.PutUint64(prefix[8:], uint64(offset))
	binary.LittleEndian.PutUint32(prefix[16:], uint32(len(payload)))
	return crc32.Update(crc32.Checksum(prefix[:], domainCRC), domainCRC, payload)
}

func appendDomainName(b []byte, name string) []byte {
	return append(binary.AppendUvarint(b, uint64(len(name))), name...)
}

func appendDomainAddr(b []byte, ip netip.Addr) []byte {
	raw := ip.AsSlice()
	return append(append(b, byte(len(raw))), raw...)
}

// encodeDomainBase groups consecutive entries of one domain; the compaction
// snapshot lists each record's addresses together.
func encodeDomainBase(epoch uint64, entries []domainLogEntry) []byte {
	b := domainHeader(domainBaseMagic, epoch)
	var previous int64
	for i := 0; i < len(entries); {
		j := i + 1
		for j < len(entries) && entries[j].name == entries[i].name {
			j++
		}
		b = binary.AppendUvarint(appendDomainName(b, entries[i].name), uint64(j-i))
		for _, e := range entries[i:j] {
			b = binary.AppendVarint(appendDomainAddr(b, e.ip), e.deadline-previous)
			previous = e.deadline
		}
		i = j
	}
	return binary.LittleEndian.AppendUint32(b, crc32.Checksum(b, domainCRC))
}

func encodeDomainNew(fresh []domainLogEntry) []byte {
	if len(fresh) == 0 {
		return nil
	}
	b := []byte{domainFrameNew}
	for _, e := range fresh {
		b = binary.AppendVarint(appendDomainAddr(appendDomainName(b, e.name), e.ip), e.deadline)
	}
	return b
}

func encodeDomainRenew(bound int64, renewed []uint32, exact []domainLogExact) []byte {
	if len(renewed) == 0 && len(exact) == 0 {
		return nil
	}
	// A window lists each pair once, so ordinals ascend strictly.
	slices.Sort(renewed)
	slices.SortFunc(exact, func(a, b domainLogExact) int { return cmp.Compare(a.ordinal, b.ordinal) })
	b := binary.AppendVarint([]byte{domainFrameRenew}, bound)
	b = binary.AppendUvarint(b, uint64(len(renewed)))
	var previous uint32
	for _, ordinal := range renewed {
		b = binary.AppendUvarint(b, uint64(ordinal-previous))
		previous = ordinal
	}
	b = binary.AppendUvarint(b, uint64(len(exact)))
	previous = 0
	for _, e := range exact {
		b = binary.AppendVarint(binary.AppendUvarint(b, uint64(e.ordinal-previous)), e.deadline)
		previous = e.ordinal
	}
	return b
}

// domainReader decodes untrusted bytes; the first error sticks.
type domainReader struct {
	buf []byte
	err error
}

var errDomainTruncated = errors.New("truncated record")

func (r *domainReader) uvarint() uint64 {
	if r.err != nil {
		return 0
	}
	v, n := binary.Uvarint(r.buf)
	if n <= 0 {
		r.err = errDomainTruncated
		return 0
	}
	r.buf = r.buf[n:]
	return v
}

func (r *domainReader) varint() int64 {
	if r.err != nil {
		return 0
	}
	v, n := binary.Varint(r.buf)
	if n <= 0 {
		r.err = errDomainTruncated
		return 0
	}
	r.buf = r.buf[n:]
	return v
}

func (r *domainReader) bytes(n uint64) []byte {
	if r.err == nil && n > uint64(len(r.buf)) {
		r.err = errDomainTruncated
	}
	if r.err != nil {
		return nil
	}
	b := r.buf[:n]
	r.buf = r.buf[n:]
	return b
}

func (r *domainReader) name() string {
	name := string(r.bytes(r.uvarint()))
	if _, valid := dnsmessage.IsDomainName(name); r.err == nil && (!valid || name != dnsmessage.CanonicalName(name)) {
		r.err = fmt.Errorf("invalid domain %q", name)
	}
	return name
}

func (r *domainReader) addr() netip.Addr {
	length := r.bytes(1)
	if r.err != nil {
		return netip.Addr{}
	}
	ip, ok := netip.AddrFromSlice(r.bytes(uint64(length[0])))
	if r.err == nil && (!ok || ip.IsUnspecified() || ip != ip.Unmap()) {
		r.err = fmt.Errorf("invalid address %v", ip)
	}
	return ip
}

// domainRecovery is evidence read back from disk, indexed by ordinal.
type domainRecovery struct {
	records  map[string]*domainRecord
	ordinals []*domainPair
	epoch    uint64
	base     int64
	journal  int64 // end of the last valid frame; zero if the journal is unusable
}

func decodeDomainBase(data []byte) (*domainRecovery, error) {
	if len(data) < domainHeaderSize+4 || [8]byte(data) != domainBaseMagic {
		return nil, errors.New("domain registry baseline has no valid header")
	}
	body := data[:len(data)-4]
	if crc32.Checksum(body, domainCRC) != binary.LittleEndian.Uint32(data[len(body):]) {
		return nil, errors.New("domain registry baseline checksum mismatch")
	}
	rec := &domainRecovery{records: make(map[string]*domainRecord), epoch: binary.LittleEndian.Uint64(data[8:]), base: int64(len(data))}
	r := domainReader{buf: body[domainHeaderSize:]}
	var deadline int64
	for len(r.buf) != 0 && r.err == nil {
		name := r.name()
		count := r.uvarint()
		if r.err == nil && (count == 0 || count > uint64(len(r.buf)) || rec.records[name] != nil) {
			r.err = fmt.Errorf("invalid entry for %q", name)
		}
		record := &domainRecord{addresses: make(map[netip.Addr]*domainPair, min(count, uint64(len(r.buf))))}
		rec.records[name] = record
		for range count {
			ip := r.addr()
			deadline += r.varint()
			if r.err != nil {
				break
			}
			if record.addresses[ip] != nil {
				r.err = fmt.Errorf("duplicate address %v for %q", ip, name)
				break
			}
			pair := &domainPair{retainUntil: time.Unix(0, deadline), ordinal: uint32(len(rec.ordinals))}
			record.addresses[ip] = pair
			rec.ordinals = append(rec.ordinals, pair)
		}
	}
	if r.err != nil {
		return nil, fmt.Errorf("domain registry baseline: %w", r.err)
	}
	return rec, nil
}

func raiseDomainDeadline(pair *domainPair, deadline int64) {
	if deadline > pair.retainUntil.UnixNano() {
		pair.retainUntil = time.Unix(0, deadline)
	}
}

// replay applies the frames of the baseline's epoch up to the first invalid
// one and records where the valid frames end.
func (rec *domainRecovery) replay(journal []byte) {
	if len(journal) < domainHeaderSize || [8]byte(journal) != domainJournalMagic || binary.LittleEndian.Uint64(journal[8:]) != rec.epoch {
		return
	}
	offset := domainHeaderSize
	for len(journal)-offset >= 8 {
		// Compare before converting: a damaged length overflows a 32-bit int.
		length := binary.LittleEndian.Uint32(journal[offset:])
		if uint64(length) > uint64(len(journal)-offset-8) {
			break
		}
		n := int(length)
		payload := journal[offset+4 : offset+4+n]
		if domainFrameCRC(rec.epoch, int64(offset), payload) != binary.LittleEndian.Uint32(journal[offset+4+n:]) || !rec.apply(payload) {
			break
		}
		offset += n + 8
	}
	rec.journal = int64(offset)
}

// apply validates a whole frame before changing any evidence.
func (rec *domainRecovery) apply(payload []byte) bool {
	if len(payload) == 0 {
		return false
	}
	r := domainReader{buf: payload[1:]}
	switch payload[0] {
	case domainFrameNew:
		var fresh []domainLogEntry
		for len(r.buf) != 0 && r.err == nil {
			name, ip := r.name(), r.addr()
			fresh = append(fresh, domainLogEntry{name, ip, r.varint()})
		}
		if r.err != nil || len(fresh) == 0 {
			return false
		}
		for _, e := range fresh {
			record := rec.records[e.name]
			if record == nil {
				record = &domainRecord{addresses: make(map[netip.Addr]*domainPair)}
				rec.records[e.name] = record
			}
			// A pair collected and observed again has a newer ordinal.
			pair := record.addresses[e.ip]
			if pair == nil {
				pair = &domainPair{retainUntil: time.Unix(0, e.deadline)}
				record.addresses[e.ip] = pair
			}
			raiseDomainDeadline(pair, e.deadline)
			pair.ordinal = uint32(len(rec.ordinals))
			rec.ordinals = append(rec.ordinals, pair)
		}
	case domainFrameRenew:
		bound := r.varint()
		// Ordinals ascend strictly and refer to pairs recovered so far.
		next := func(first bool, previous uint64) uint64 {
			delta := r.uvarint()
			if r.err == nil && (!first && delta == 0 || delta >= uint64(len(rec.ordinals))-previous) {
				r.err = errors.New("invalid ordinal")
			}
			return previous + delta
		}
		var renewed []uint64
		var previous uint64
		for i := range r.uvarint() {
			if previous = next(i == 0, previous); r.err != nil {
				return false
			}
			renewed = append(renewed, previous)
		}
		var exact []domainLogExact
		previous = 0
		for i := range r.uvarint() {
			if previous = next(i == 0, previous); r.err != nil {
				return false
			}
			exact = append(exact, domainLogExact{uint32(previous), r.varint()})
		}
		if r.err != nil || len(r.buf) != 0 {
			return false
		}
		for _, ordinal := range renewed {
			raiseDomainDeadline(rec.ordinals[ordinal], bound)
		}
		for _, e := range exact {
			raiseDomainDeadline(rec.ordinals[e.ordinal], e.deadline)
		}
	default:
		return false
	}
	return true
}

// recoverDomainEvidence reads the baseline, adopting a complete temporary one
// left by an interrupted compaction, and replays its journal. Missing files
// yield nil without error. A file that exists but cannot be read, or a failed
// adoption, sets unreadable: the files may hold evidence a rebuild would lose.
func recoverDomainEvidence(dir string) (rec *domainRecovery, unreadable bool, err error) {
	failed := func(err error) bool { return err != nil && !errors.Is(err, os.ErrNotExist) }
	basePath := filepath.Join(dir, domainBaseFile)
	data, err := os.ReadFile(basePath)
	if failed(err) {
		return nil, true, err
	}
	if err == nil {
		rec, err = decodeDomainBase(data)
	}
	if err != nil {
		temporary, tmpErr := os.ReadFile(basePath + domainTempSuffix)
		if failed(tmpErr) {
			return nil, true, tmpErr
		}
		if tmpErr == nil {
			rec, tmpErr = decodeDomainBase(temporary)
		}
		if tmpErr != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, false, nil
			}
			return nil, false, err
		}
		if err := renameSynced(basePath+domainTempSuffix, basePath); err != nil {
			return nil, true, err
		}
	}
	journal, err := os.ReadFile(filepath.Join(dir, domainJournalFile))
	if failed(err) {
		return nil, true, err
	}
	if err == nil {
		rec.replay(journal)
	}
	return rec, false, nil
}

// Restore loads the baseline and journal in dir and validates them before
// publishing anything. Like reload adoption it rebuilds complete shared-IP
// states with current rules; expired pairs are collected without extending
// their deadlines. The registry then owns the files, even missing or corrupt
// ones, which its first write after activation replaces by compacting. Files
// that cannot be read may still be intact: this run then restores and writes
// nothing.
// The startup owner calls only on a fresh registry before publication, while
// holding the control-plane lifecycle lock that excludes concurrent shutdown.
func (g *DomainRegistry) Restore(dir string, matchBitmap func(string) []uint32, now time.Time) error {
	// Earlier versions wrote a gzip JSON snapshot; it is discarded, not imported.
	_ = os.Remove(filepath.Join(dir, "domain-registry.json.gz"))
	rec, unreadable, err := recoverDomainEvidence(dir)
	g.mu.Lock()
	defer g.mu.Unlock()
	now = g.clock(now)
	l := newDomainLog(dir, now, g.window)
	g.persist = l
	capacityErr := g.restoreCapacity(l)
	err = errors.Join(err, capacityErr)
	if unreadable {
		l.disabled = true
		g.indexIncomplete()
		return fmt.Errorf("%w; not writing the domain registry until restart", err)
	}
	if rec == nil {
		g.indexIncomplete()
		return err
	}
	l.next, l.rebuild = uint32(len(rec.ordinals)), rec.journal == 0
	l.disk.epoch, l.disk.size, l.disk.base = rec.epoch, rec.journal, rec.base
	// Avoid allocating reverse indexes and evaluating current rules for
	// evidence that cold restore collects.
	cutoff := now.Add(-g.activityLag)
	namePeak := len(rec.records)
	for name, record := range rec.records {
		record.addressPeak = len(record.addresses)
		for ip, pair := range record.addresses {
			if !pair.retainUntil.After(cutoff) {
				delete(record.addresses, ip)
				g.gcCount++
			}
		}
		if len(record.addresses) == 0 {
			delete(rec.records, name)
		} else {
			record.addresses = trimDomainIndex(record.addresses, &record.addressPeak)
		}
	}
	rec.records = trimDomainIndex(rec.records, &namePeak)
	if g.limitRestoredCapacity(rec, matchBitmap) {
		l.rebuild = true
	}
	g.installRecords(rec.records, nil)
	g.indexIncomplete()
	return errors.Join(g.rebuildProjection(now), err)
}
