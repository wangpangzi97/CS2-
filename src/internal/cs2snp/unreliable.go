package cs2snp

import (
	"bytes"
	"sort"
	"time"
)

const unrelMaxBytes = 1 << 20
const unrelMaxPending = 128
const unrelBudget = 8 << 20

type unrelKey struct {
	lane int
	num  int64
}
type unrelAssembly struct {
	at    time.Time
	end   int
	parts map[int][]byte
}
type UnrelReassembler struct {
	pending                               map[unrelKey]*unrelAssembly
	done                                  map[unrelKey]time.Time
	Complete, Expired, Invalid, Conflicts uint64
}

func NewUnrelReassembler() *UnrelReassembler {
	return &UnrelReassembler{pending: map[unrelKey]*unrelAssembly{}, done: map[unrelKey]time.Time{}}
}
func (r *UnrelReassembler) Feed(u UnrelMsg, now time.Time) ([]byte, bool) {
	used := 0
	for k, a := range r.pending {
		if now.Sub(a.at) > 2*time.Second {
			delete(r.pending, k)
			r.Expired++
		} else {
			for _, b := range a.parts {
				used += len(b)
			}
		}
	}
	for k, t := range r.done {
		if now.Sub(t) > 2*time.Second {
			delete(r.done, k)
		}
	}
	key := unrelKey{u.Lane, u.Num}
	if _, ok := r.done[key]; ok {
		return nil, false
	}
	if u.Offset < 0 || u.Offset > unrelMaxBytes || len(u.Data) > unrelMaxBytes-int(u.Offset) || len(u.Data) == 0 {
		delete(r.pending, key)
		r.Invalid++
		return nil, false
	}
	a := r.pending[key]
	if a == nil {
		if len(r.pending) >= unrelMaxPending || used+len(u.Data) > unrelBudget {
			r.Invalid++
			return nil, false
		}
		a = &unrelAssembly{at: now, end: -1, parts: map[int][]byte{}}
		r.pending[key] = a
	}
	off, end := int(u.Offset), int(u.Offset)+len(u.Data)
	fail := func() ([]byte, bool) { delete(r.pending, key); r.Conflicts++; return nil, false }
	if a.end >= 0 && (end > a.end || (u.Last && end != a.end)) {
		return fail()
	}
	if u.Last {
		a.end = end
	}
	for p, b := range a.parts {
		lo, hi := off, end
		if p > lo {
			lo = p
		}
		if p+len(b) < hi {
			hi = p + len(b)
		}
		if hi > lo && !bytes.Equal(u.Data[lo-off:hi-off], b[lo-p:hi-p]) {
			return fail()
		}
		if a.end >= 0 && p+len(b) > a.end {
			return fail()
		}
	}
	if old, ok := a.parts[off]; !ok || len(old) < len(u.Data) {
		if len(a.parts) >= 1024 || used+len(u.Data) > unrelBudget {
			delete(r.pending, key)
			r.Invalid++
			return nil, false
		}
		a.parts[off] = append([]byte(nil), u.Data...)
	}
	if a.end < 0 {
		return nil, false
	}
	offsets := make([]int, 0, len(a.parts))
	for p := range a.parts {
		offsets = append(offsets, p)
	}
	sort.Ints(offsets)
	pos := 0
	for _, p := range offsets {
		if p > pos {
			return nil, false
		}
		if e := p + len(a.parts[p]); e > pos {
			pos = e
		}
	}
	if pos != a.end {
		return nil, false
	}
	out := make([]byte, a.end)
	for _, p := range offsets {
		copy(out[p:], a.parts[p])
	}
	delete(r.pending, key)
	if len(r.done) >= 4096 {
		r.done = map[unrelKey]time.Time{}
	}
	r.done[key] = now
	r.Complete++
	return out, true
}
