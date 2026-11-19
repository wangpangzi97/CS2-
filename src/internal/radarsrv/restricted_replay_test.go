package radarsrv

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/msg"
	"google.golang.org/protobuf/proto"
	"local/cs2-radar/internal/dataauth"
	"local/cs2-radar/internal/restrictedreplay"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRestrictedReplayAuthorizedBindingAndNoPublicDownload(t *testing.T) {
	if DefaultConfig().RestrictedReplay != nil {
		t.Fatal("not default off")
	}
	s, _, srv, ca := secureStoreFixture(t)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x47}, 32))
	client, e := dataauth.NewClient(srv.URL+"/api/v1/ingest", ca, key)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(client.Close)
	e = client.Login(context.Background(), dataauth.Credential{SessionID: strings.Repeat("aa", 32), Device: strings.Repeat("ab", 32), MAC: func(string) (string, error) { return strings.Repeat("aa", 32), nil }})
	if e != nil {
		t.Fatal(e)
	}
	other := nativeClient(t, srv, ca, strings.Repeat("ac", 32))
	selectedID, otherID := client.SessionID(), other.SessionID()
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	sum := sha256.Sum256(key.Public().(ed25519.PublicKey))
	c, e := restrictedreplay.New(restrictedreplay.Config{Directory: dir, DevicePublicKeySHA256: hex.EncodeToString(sum[:]), Expires: time.Now().Add(time.Minute)})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close() })
	s.cfg.RestrictedReplay = c
	for _, path := range []string{"/api/v1/ingest", "/replay.bin", "/claimed/replay.bin", "/api/v1/replay"} {
		r := httptest.NewRequest("POST", "https://example.invalid"+path, nil)
		r.Body = panicRead{}
		w := httptest.NewRecorder()
		s.SecureHandler(nil).ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("public boundary")
		}
	}
	body := []byte(`{"session":"","packets":[]}`)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/ingest", nil)
	if resp, err := other.DoBody(req, body); err != nil {
		t.Fatal(err)
	} else {
		resp.Body.Close()
	}
	if s.Get(other.SessionID()).replay != nil {
		t.Fatal("captured other user")
	}
	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/api/v1/ingest", nil)
	if resp, err := client.DoBody(req, body); err != nil {
		t.Fatal(err)
	} else {
		resp.Body.Close()
	}
	sess := s.Get(client.SessionID())
	if sess.replay != c {
		t.Fatal("selected authorized session not attached")
	}
	sess.clientPriv = []byte("SYNTHETIC_PRIVATE_KEY_MUST_NOT_PERSIST")
	sess.serverPub = []byte("SYNTHETIC_OTHER_KEY_MUST_NOT_PERSIST")
	dep, _ := proto.Marshal(&msg.CSVCMsg_PacketEntities{LegacyIsDelta: proto.Bool(true), DeltaFrom: proto.Int32(74515), ServerTick: proto.Uint32(74521)})
	wire := phase64ProbeWire(dep, 74521)
	wire[11] = 8 // genuine ambiguity, still rejected
	before := sess.pipeline.unrelRejected.Load()
	sess.noteGNSUnrel(wire)
	if sess.pipeline.unrelRejected.Load() != before+1 {
		t.Fatal("sampling changed admission")
	}
	for _, path := range []string{"/replay.bin", "/api/v1/replay", "/claimed/replay.bin"} {
		check := nativeClient(t, srv, ca, strings.Repeat("ad", 32))
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		if resp, err := check.DoBody(req, nil); err == nil {
			resp.Body.Close()
			t.Fatal("private replay publicly available")
		}
	}
	s.DropAuthorizedSession(selectedID)
	c.Close()
	raw, e := os.ReadFile(filepath.Join(dir, "claimed", "replay.bin"))
	if e != nil {
		t.Fatal(e)
	}
	records, result, e := restrictedreplay.Read(bytes.NewReader(raw))
	if e != nil || len(records) != 1 || result.WriteFailed || !bytes.Equal(records[0].Body, wire) || records[0].Reason != 6 {
		t.Fatal("exact classifier replay capture missing", e)
	}
	for _, secret := range []string{string(sess.clientPriv), string(sess.serverPub), selectedID, otherID} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("non-gameplay sensitive value leaked")
		}
	}
	got, reason := gnsDecodeUnrelReason(records[0].Body)
	if got != nil || reason != records[0].Reason {
		t.Fatal("saved frame not reproducible")
	}
	audit, err := AuditRestrictedReplay(bytes.NewReader(raw))
	if err != nil || audit.Records != 1 || audit.RejectedByReason[6] != 1 || audit.ClassificationMismatches != 0 || audit.FullEntityReplay {
		t.Fatal("offline aggregate audit", err)
	}
	if dest := os.Getenv("GS_TEST_REPLAY_EXPORT"); dest != "" {
		if filepath.Base(dest) != "synthetic-replay.bin" {
			t.Fatal("synthetic export filename")
		}
		if e := os.WriteFile(dest, raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if c.Bind(selectedID, sum) {
		t.Fatal("revoked job rebound")
	}
	t.Log("AUTHENTICATED_SELECTED_SESSION_ONLY=true EXACT_CLASSIFIER_REPLAY=true REASON=6 KEYS_AND_SESSION_IDENTIFIERS_ABSENT=true PRIVATE_PATHS_DENIED=true")
}
