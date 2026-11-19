// Package restrictedreplay is an explicitly armed, one-session forensic sink.
// It accepts ONLY complete s2c gameplay messages, not HTTP requests or key material.
// Files contain sensitive gameplay plaintext; they are NOT safe diagnostic exports.
package restrictedreplay

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const (
	MaxBytes    = 8 << 20
	MaxDuration = 10 * time.Minute
	MaxMessage  = 128 << 10
	headerBytes = 128
	recordBytes = 56
	maxRecords  = 4096
)

// Config is not an HTTP/API structure. The caller must obtain separate consent.
// Directory must already be a private, dedicated, service-owned job directory.
// The durable claimed directory makes this job non-renewable across restarts.
type Config struct {
	Directory             string
	DevicePublicKeySHA256 string
	Expires               time.Time
}
type Record struct {
	FirstInput                                                                                    uint64
	FirstFault, BaseKnown, MissingKind, MissingCode, OuterFlags, OuterReason, NetFlags, NetReason uint8
	Sequence, Episode, Input, ElapsedNS                                                           uint64
	Reason, Stage, Fault, Active                                                                  uint8
	Body                                                                                          []byte
}
type Result struct {
	Reason                                        uint8 // 1 deadline, 2 persistent desync, 3 closed/revoked, 4 queue overflow
	Bytes, Records, Evicted, Oversize, QueueDrops uint64
	WriteFailed                                   bool
}
type Capture struct {
	mu              sync.Mutex
	bound           bool
	selector        [32]byte
	start, deadline time.Time
	file            *os.File
	queue           chan Record
	stop            chan struct{}
	done            chan struct{}
	once            sync.Once
	reason          atomic.Uint32
	oversize, drops atomic.Uint64
	result          Result
}

func New(cfg Config) (*Capture, error) {
	now := time.Now()
	b, e := hex.DecodeString(cfg.DevicePublicKeySHA256)
	if e != nil || len(b) != 32 || cfg.DevicePublicKeySHA256 != hex.EncodeToString(b) || !filepath.IsAbs(cfg.Directory) || !cfg.Expires.After(now) || cfg.Expires.Sub(now) > MaxDuration {
		return nil, errors.New("invalid restricted replay scope")
	}
	fi, e := os.Lstat(cfg.Directory)
	if e != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 || !privateDirectory(fi) {
		return nil, errors.New("private existing replay directory required")
	}
	root, e := os.OpenRoot(cfg.Directory)
	if e != nil {
		return nil, errors.New("replay directory unavailable")
	}
	defer root.Close()
	opened, e := root.Stat(".")
	if e != nil || !os.SameFile(fi, opened) {
		return nil, errors.New("replay directory replaced")
	}
	if e = root.Mkdir("claimed", 0700); e != nil {
		return nil, errors.New("replay job already consumed or unavailable")
	}
	f, e := root.OpenFile("claimed/replay.bin", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return nil, errors.New("private replay output unavailable")
	}
	c := &Capture{start: now, deadline: cfg.Expires, file: f, queue: make(chan Record, 16), stop: make(chan struct{}), done: make(chan struct{})}
	copy(c.selector[:], b)
	go c.work()
	return c, nil
}

// Bind must be called only AFTER the production authorization boundary succeeds.
// It never selects the first arbitrary user and never accepts a second session.
func (c *Capture) Bind(session string, deviceSelector [32]byte) bool {
	if c == nil || session == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.stop:
		return false
	case <-c.done:
		return false
	default:
	}
	if c.bound || !time.Now().Before(c.deadline) || deviceSelector != c.selector || deviceSelector == [32]byte{} {
		return false
	}
	c.bound = true
	return true
}

// Observe cannot block decoding on disk I/O. Overflow ends the capture and marks
// it incomplete; it does not change admission, decryption or player state.
func (c *Capture) Observe(body []byte, meta Record) {
	if c == nil {
		return
	}
	c.mu.Lock()
	if !c.bound {
		c.mu.Unlock()
		return
	}
	select {
	case <-c.stop:
		c.mu.Unlock()
		return
	case <-c.done:
		c.mu.Unlock()
		return
	default:
	}
	if !time.Now().Before(c.deadline) {
		c.mu.Unlock()
		c.stopAs(1)
		return
	}
	if len(body) == 0 || len(body) > MaxMessage {
		c.oversize.Add(1)
		c.mu.Unlock()
		return
	}
	if meta.Reason > 6 || meta.Stage > 9 || meta.Fault > 7 || meta.Active > 1 || meta.FirstFault > 7 || meta.BaseKnown > 1 || meta.MissingKind > 5 || meta.MissingCode > 7 || meta.OuterFlags > 63 || meta.NetFlags > 63 || meta.OuterReason > 6 || meta.NetReason > 6 {
		c.mu.Unlock()
		return
	}
	meta.Body = append([]byte(nil), body...)
	meta.ElapsedNS = uint64(time.Since(c.start))
	overflow := false
	select {
	case c.queue <- meta:
	default:
		clear(meta.Body)
		c.drops.Add(1)
		overflow = true
	}
	c.mu.Unlock()
	if overflow {
		c.stopAs(4)
	}
}
func (c *Capture) stopAs(reason uint8) {
	c.once.Do(func() { c.mu.Lock(); defer c.mu.Unlock(); c.reason.Store(uint32(reason)); close(c.stop) })
}
func (c *Capture) Stop() {
	if c != nil {
		c.stopAs(3)
	}
}
func (c *Capture) Close() Result {
	if c == nil {
		return Result{}
	}
	c.stopAs(3)
	<-c.done
	return c.result
}

type ring struct {
	records      []Record
	bytes, limit int
	evicted      uint64
}

func (r *ring) push(v Record) {
	n := len(v.Body) + recordBytes
	for len(r.records) > 0 && (r.bytes+n > r.limit || len(r.records) >= maxRecords) {
		old := r.records[0]
		clear(old.Body)
		r.bytes -= len(old.Body) + recordBytes
		r.records[0] = Record{}
		r.records = r.records[1:]
		r.evicted++
	}
	r.records = append(r.records, v)
	r.bytes += n
}
func (c *Capture) work() {
	defer close(c.done)
	normal := ring{limit: 5 << 20}
	rejected := ring{limit: (3 << 20) - headerBytes}
	timer := time.NewTimer(time.Until(c.deadline))
	defer timer.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	var seq uint64
	var seenReady bool
	var faultSince time.Time
	accept := func(v Record) {
		seq++
		v.Sequence = seq
		if v.Stage == 9 {
			seenReady = true
			faultSince = time.Time{}
		}
		if v.Stage == 6 && seenReady && faultSince.IsZero() {
			faultSince = time.Now()
		}
		if v.Stage != 6 {
			faultSince = time.Time{}
		}
		if v.Reason != 0 {
			rejected.push(v)
		} else {
			normal.push(v)
		}
	}
loop:
	for {
		select {
		case v := <-c.queue:
			accept(v)
		case <-timer.C:
			c.stopAs(1)
			break loop
		case <-c.stop:
			break loop
		case <-tick.C:
			if !faultSince.IsZero() && time.Since(faultSince) >= 5*time.Second {
				c.stopAs(2)
				break loop
			}
		}
	}
	// Bound the drain to the channel capacity; concurrent producers see stop.
	for n := 0; n < cap(c.queue); n++ {
		select {
		case v := <-c.queue:
			accept(v)
		default:
			break
		}
	}
	all := append(normal.records, rejected.records...)
	sort.Slice(all, func(i, j int) bool { return all[i].Sequence < all[j].Sequence })
	h := make([]byte, headerBytes)
	copy(h, "GSRPLY01")
	h[8] = byte(c.reason.Load())
	vals := []uint64{uint64(len(all)), normal.evicted + rejected.evicted, c.oversize.Load(), c.drops.Load(), uint64(time.Since(c.start))}
	for i, v := range vals {
		binary.LittleEndian.PutUint64(h[16+i*8:], v)
	}
	write := func(b []byte) {
		if c.result.WriteFailed {
			return
		}
		n, e := c.file.Write(b)
		c.result.Bytes += uint64(n)
		if e != nil || n != len(b) {
			c.result.WriteFailed = true
		}
	}
	write(h)
	digest := sha256.New()
	for _, v := range all {
		b := make([]byte, recordBytes)
		binary.LittleEndian.PutUint32(b, uint32(len(v.Body)))
		b[4], b[5], b[6], b[7] = v.Reason, v.Stage, v.Fault, v.Active
		for i, x := range []uint64{v.Sequence, v.Episode, v.Input, v.ElapsedNS} {
			binary.LittleEndian.PutUint64(b[8+i*8:], x)
		}
		binary.LittleEndian.PutUint64(b[40:], v.FirstInput)
		b[48], b[49], b[50], b[51], b[52], b[53], b[54], b[55] = v.FirstFault, v.BaseKnown, v.MissingKind, v.MissingCode, v.OuterFlags, v.OuterReason, v.NetFlags, v.NetReason
		digest.Write(b)
		digest.Write(v.Body)
		write(b)
		write(v.Body)
		clear(v.Body)
	}
	if !c.result.WriteFailed {
		if _, e := c.file.Seek(64, 0); e != nil {
			c.result.WriteFailed = true
		} else {
			sum := digest.Sum(nil)
			n, e := c.file.Write(sum)
			if e != nil || n != len(sum) {
				c.result.WriteFailed = true
			}
		}
	}
	if c.file.Sync() != nil {
		c.result.WriteFailed = true
	}
	if c.file.Close() != nil {
		c.result.WriteFailed = true
	}
	c.result.Reason = byte(c.reason.Load())
	c.result.Records = uint64(len(all))
	c.result.Evicted = normal.evicted + rejected.evicted
	c.result.Oversize = c.oversize.Load()
	c.result.QueueDrops = c.drops.Load()
	clear(all)
	clear(normal.records)
	clear(rejected.records)
}

// Read parses only the bounded forensic format. It does NOT restore entity
// state; callers must not treat a rolling classifier sample as a full session.
func Read(r io.Reader) ([]Record, Result, error) {
	fail := func() ([]Record, Result, error) { return nil, Result{}, errors.New("invalid restricted replay file") }
	b, e := io.ReadAll(io.LimitReader(r, MaxBytes+1))
	if e != nil || len(b) > MaxBytes || len(b) < headerBytes || string(b[:8]) != "GSRPLY01" {
		return fail()
	}
	if b[8] < 1 || b[8] > 4 {
		return fail()
	}
	checksum := sha256.Sum256(b[headerBytes:])
	if !bytes.Equal(checksum[:], b[64:96]) {
		return fail()
	}
	count := binary.LittleEndian.Uint64(b[16:])
	if count > 2*maxRecords {
		return fail()
	}
	result := Result{Reason: b[8], Bytes: uint64(len(b)), Records: count, Evicted: binary.LittleEndian.Uint64(b[24:]), Oversize: binary.LittleEndian.Uint64(b[32:]), QueueDrops: binary.LittleEndian.Uint64(b[40:])}
	var out []Record
	at := headerBytes
	var prev uint64
	for i := uint64(0); i < count; i++ {
		if len(b)-at < recordBytes {
			return fail()
		}
		h := b[at : at+recordBytes]
		at += recordBytes
		n := int(binary.LittleEndian.Uint32(h))
		if n < 1 || n > MaxMessage || n > len(b)-at || h[4] > 6 || h[5] > 9 || h[6] > 7 || h[7] > 1 || h[48] > 7 || h[49] > 1 || h[50] > 5 || h[51] > 7 || h[52] > 63 || h[54] > 63 || h[53] > 6 || h[55] > 6 {
			return fail()
		}
		v := Record{Reason: h[4], Stage: h[5], Fault: h[6], Active: h[7], Sequence: binary.LittleEndian.Uint64(h[8:]), Episode: binary.LittleEndian.Uint64(h[16:]), Input: binary.LittleEndian.Uint64(h[24:]), ElapsedNS: binary.LittleEndian.Uint64(h[32:]), Body: b[at : at+n]}
		v.FirstInput = binary.LittleEndian.Uint64(h[40:])
		v.FirstFault, v.BaseKnown, v.MissingKind, v.MissingCode, v.OuterFlags, v.OuterReason, v.NetFlags, v.NetReason = h[48], h[49], h[50], h[51], h[52], h[53], h[54], h[55]
		at += n
		if v.Sequence <= prev {
			return fail()
		}
		prev = v.Sequence
		out = append(out, v)
	}
	if at != len(b) {
		return fail()
	}
	return out, result, nil
}
