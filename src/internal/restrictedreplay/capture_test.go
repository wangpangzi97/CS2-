package restrictedreplay

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func fixture(t *testing.T, duration time.Duration) (*Capture, string) {
	t.Helper()
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256([]byte("synthetic-authorized-session"))
	c, e := New(Config{Directory: dir, DevicePublicKeySHA256: hex.EncodeToString(sum[:]), Expires: time.Now().Add(duration)})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	return c, filepath.Join(dir, "claimed", "replay.bin")
}
func readFixture(t *testing.T, p string) ([]Record, Result, []byte) {
	t.Helper()
	b, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	r, s, e := Read(bytes.NewReader(b))
	if e != nil {
		t.Fatal(e)
	}
	return r, s, b
}
func TestRestrictedReplayDefaultOffScopeAndOneShot(t *testing.T) {
	c, p := fixture(t, time.Minute)
	c.Observe([]byte("unbound must not persist"), Record{})
	if c.Bind("other-session", sha256.Sum256([]byte("other-session"))) {
		t.Fatal("wrong session selected")
	}
	if !c.Bind("synthetic-authorized-session", sha256.Sum256([]byte("synthetic-authorized-session"))) || c.Bind("synthetic-authorized-session", sha256.Sum256([]byte("synthetic-authorized-session"))) {
		t.Fatal("not one session")
	}
	body := []byte("synthetic-gameplay-only")
	c.Observe(body, Record{Stage: 9, Episode: 2, FirstInput: 42, FirstFault: 3, OuterFlags: 10, OuterReason: 6})
	clear(body)
	result := c.Close()
	r, _, b := readFixture(t, p)
	if result.WriteFailed || len(r) != 1 || r[0].FirstInput != 42 || r[0].FirstFault != 3 || r[0].OuterReason != 6 || string(r[0].Body) != "synthetic-gameplay-only" || bytes.Contains(b, []byte("synthetic-authorized-session")) {
		t.Fatal("boundary/copy/identity failure")
	}
	if c.Bind("synthetic-authorized-session", sha256.Sum256([]byte("synthetic-authorized-session"))) {
		t.Fatal("rebound after close")
	}
	sum := sha256.Sum256([]byte("synthetic-authorized-session"))
	_, e := New(Config{Directory: filepath.Dir(filepath.Dir(p)), DevicePublicKeySHA256: hex.EncodeToString(sum[:]), Expires: time.Now().Add(time.Minute)})
	if e == nil {
		t.Fatal("consumed job rearmed")
	}
}
func TestRestrictedReplayHardLimitsAndRejectedRetention(t *testing.T) {
	c, p := fixture(t, time.Minute)
	if !c.Bind("synthetic-authorized-session", sha256.Sum256([]byte("synthetic-authorized-session"))) {
		t.Fatal("bind")
	}
	for i := 0; i < 180; i++ {
		reason := uint8(0)
		if i%2 == 0 {
			reason = 6
		}
		c.Observe(bytes.Repeat([]byte{byte(i)}, 100<<10), Record{Stage: 9, Reason: reason})
		for len(c.queue) > 4 {
			time.Sleep(time.Millisecond)
		}
	}
	c.Observe(make([]byte, MaxMessage+1), Record{})
	got := c.Close()
	r, s, b := readFixture(t, p)
	if got.WriteFailed || len(b) > MaxBytes || s.Oversize != 1 || s.Evicted == 0 || s.QueueDrops != 0 {
		t.Fatal("hard cap or evidence loss accounting failure", got)
	}
	var rejected, normal int
	var last uint64
	for _, v := range r {
		if v.Sequence <= last {
			t.Fatal("order")
		}
		last = v.Sequence
		if v.Reason == 6 {
			rejected++
		} else {
			normal++
		}
	}
	if rejected == 0 || normal == 0 || r[len(r)-1].Sequence != 180 {
		t.Fatal("rolling retention lost latest or all rejects")
	}
	t.Logf("FILE_BYTES=%d LIMIT=%d RECORDS=%d EVICTED=%d REJECTED_RETAINED=%d OVERSIZE=%d", len(b), MaxBytes, len(r), s.Evicted, rejected, s.Oversize)
}
func TestRestrictedReplayDeadlineAndNoRenewal(t *testing.T) {
	c, p := fixture(t, 40*time.Millisecond)
	c.Bind("synthetic-authorized-session", sha256.Sum256([]byte("synthetic-authorized-session")))
	c.Observe([]byte{2, 1, 2}, Record{Stage: 9})
	select {
	case <-c.done:
	case <-time.After(time.Second):
		t.Fatal("deadline did not close")
	}
	if s := c.Close(); s.Reason != 1 {
		t.Fatal("wrong deadline reason")
	}
	before, _ := os.ReadFile(p)
	c.Observe([]byte("late"), Record{})
	after, _ := os.ReadFile(p)
	if !bytes.Equal(before, after) {
		t.Fatal("write after deadline")
	}
	_, e := New(Config{Directory: t.TempDir(), DevicePublicKeySHA256: string(bytes.Repeat([]byte{'a'}, 64)), Expires: time.Now().Add(MaxDuration + time.Second)})
	if e == nil {
		t.Fatal("10-minute limit bypassed")
	}
}
func TestRestrictedReplayRecoveredThenLaterPersistentEpisode(t *testing.T) {
	c, p := fixture(t, 15*time.Second)
	c.Bind("synthetic-authorized-session", sha256.Sum256([]byte("synthetic-authorized-session")))
	c.Observe([]byte("healthy"), Record{Stage: 9})
	c.Observe([]byte("first-transient"), Record{Stage: 6, Fault: 5, Active: 1, Episode: 1})
	c.Observe([]byte("recovered"), Record{Stage: 9, Episode: 1})
	c.Observe([]byte("later-fault"), Record{Stage: 6, Fault: 3, Active: 1, Episode: 2, Reason: 6})
	select {
	case <-c.done:
	case <-time.After(7 * time.Second):
		t.Fatal("persistent episode not frozen")
	}
	r, s, _ := readFixture(t, p)
	if s.Reason != 2 || len(r) != 4 || r[3].Episode != 2 || r[3].Fault != 3 || r[3].Reason != 6 {
		t.Fatal("later episode tied to first fault")
	}
	t.Log("TRANSIENT_RECOVERY_RETAINED=true LATER_EPISODE=2 PERSISTENT_FREEZE=true")
}
func TestRestrictedReplayDeterministicQueueOverflow(t *testing.T) {
	c := &Capture{bound: true, start: time.Now(), deadline: time.Now().Add(time.Minute), queue: make(chan Record, 1), stop: make(chan struct{}), done: make(chan struct{})}
	c.Observe([]byte("first"), Record{Stage: 9})
	c.Observe([]byte("second"), Record{Stage: 9})
	if c.reason.Load() != 4 || c.drops.Load() != 1 {
		t.Fatal("overflow not explicit")
	}
	select {
	case <-c.stop:
	default:
		t.Fatal("overflow did not stop")
	}
	v := <-c.queue
	clear(v.Body)
}
func TestRestrictedReplayConcurrentCloseDoesNotBlock(t *testing.T) {
	c, p := fixture(t, time.Minute)
	c.Bind("synthetic-authorized-session", sha256.Sum256([]byte("synthetic-authorized-session")))
	var wg sync.WaitGroup
	for n := 0; n < 16; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				c.Observe(make([]byte, MaxMessage), Record{Stage: 9})
			}
		}()
	}
	wg.Wait()
	s := c.Close()
	_, _, _ = readFixture(t, p)
	if (s.Reason != 3 && s.Reason != 4) || (s.Reason == 4 && s.QueueDrops == 0) || s.Bytes > MaxBytes || s.WriteFailed {
		t.Fatal("overflow missing", s)
	}
}
func TestRestrictedReplayStrictBoundedReader(t *testing.T) {
	c, p := fixture(t, time.Minute)
	c.Bind("synthetic-authorized-session", sha256.Sum256([]byte("synthetic-authorized-session")))
	c.Observe([]byte("game"), Record{Stage: 9})
	c.Close()
	_, _, b := readFixture(t, p)
	cases := [][]byte{nil, b[:127], b[:len(b)-1], append(append([]byte(nil), b...), 0), make([]byte, MaxBytes+1)}
	corrupt := append([]byte(nil), b...)
	corrupt[len(corrupt)-1] ^= 1
	cases = append(cases, corrupt)
	bad := append([]byte(nil), b...)
	binary.LittleEndian.PutUint64(bad[16:], 1<<32)
	cases = append(cases, bad)
	bad = append([]byte(nil), b...)
	binary.LittleEndian.PutUint32(bad[128:], MaxMessage+1)
	cases = append(cases, bad)
	for _, v := range cases {
		if _, _, e := Read(bytes.NewReader(v)); e == nil {
			t.Fatal("malformed file accepted")
		}
	}
}
func TestRestrictedReplayConfigRejectsUnsafeParameters(t *testing.T) {
	for _, hash := range []string{"", "a", string(bytes.Repeat([]byte{'G'}, 64))} {
		if _, e := New(Config{Directory: t.TempDir(), DevicePublicKeySHA256: hash, Expires: time.Now().Add(time.Minute)}); e == nil {
			t.Fatal("invalid selector")
		}
	}
	if _, e := Load("relative.json"); e == nil {
		t.Fatal("relative consent accepted")
	}
	dir := t.TempDir()
	sum := sha256.Sum256([]byte("test"))
	file := filepath.Join(dir, "not-directory")
	os.WriteFile(file, []byte{}, 0600)
	if _, e := New(Config{Directory: file, DevicePublicKeySHA256: hex.EncodeToString(sum[:]), Expires: time.Now().Add(time.Minute)}); e == nil {
		t.Fatal("regular file used as directory")
	}
}

func TestRestrictedReplayConsentGrammarAndWriteFailure(t *testing.T) {
	valid := `{"scope":"one_session_gameplay_plaintext_v1","directory":"/private-test","device_public_key_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","expires":"2026-10-25T15:00:00Z"}`
	if _, e := decodeConsent(bytes.NewBufferString(valid)); e != nil {
		t.Fatal(e)
	}
	for _, s := range []string{valid + `{}`, `{"scope":"wrong"}`, valid[:len(valid)-1] + `,"token":"not-allowed"}`, valid[:len(valid)-1] + `,"max_bytes":999999999}`} {
		if _, e := decodeConsent(bytes.NewBufferString(s)); e == nil {
			t.Fatal("consent grammar loosened")
		}
	}
	c, _ := fixture(t, time.Minute)
	c.Bind("synthetic-authorized-session", sha256.Sum256([]byte("synthetic-authorized-session")))
	c.file.Close()
	c.Observe([]byte("synthetic"), Record{Stage: 9})
	if !c.Close().WriteFailed {
		t.Fatal("write failure hidden")
	}
}
