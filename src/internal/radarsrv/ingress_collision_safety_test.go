package radarsrv

import (
	"bytes"
	"encoding/base64"
	"local/cs2-radar/internal/cs2crypto"
	"local/cs2-radar/internal/cs2proto"
	"local/cs2-radar/internal/uplink"
	"testing"
	"time"
)

func TestKnownGNSPlaintextPrecedenceKeepsConnectionAndGCMGates(t *testing.T) {
	key := bytes.Repeat([]byte{0x35}, 32)
	iv := bytes.Repeat([]byte{0x28}, 12)
	pt := []byte{0x27, 1, 0, 2, 1, 1, 0, 0, 0, 0, 0, 0}
	conn := []byte{1, byte(7 + len(pt) + 16 - 3), 0, 0}
	frame := sealGNSFrameForTest(t, key, iv, 1, conn, pt)
	if _, yes := cs2proto.Score(frame, cs2proto.MaxCmd); !yes {
		t.Fatal("missing controlled collision")
	}
	for _, mode := range []string{"plaintext", "unknown_connection", "other_connection", "wrong_direction", "tampered_ciphertext"} {
		t.Run(mode, func(t *testing.T) {
			st := NewStore(DefaultConfig())
			sess := st.Get("controlled-ingress-gates")
			sess.gns = &cs2crypto.GNSHandshake{ClientConnID: conn, ServerConnID: []byte{7, 8, 9, 10}}
			sess.entityDecoder = emptyDeltaTestDecoder(t, time.Now())
			scheme, e := cs2crypto.SchemeFromGNS(key, iv)
			if e != nil {
				t.Fatal(e)
			}
			sess.setSchemeLocked("s2c", scheme)
			raw := append([]byte{}, frame...)
			dir := "s2c"
			expected := 0
			switch mode {
			case "plaintext":
				raw = []byte{1, 1, 1}
			case "unknown_connection":
				sess.gns = nil
			case "other_connection":
				raw[1] ^= 2
			case "wrong_direction":
				dir = "c2s"
			case "tampered_ciphertext":
				raw[len(raw)-1] ^= 1
				expected = 1
			}
			n, e := st.Ingest(&uplink.Batch{Session: sess.id, Packets: []uplink.Packet{{Dir: dir, Data: base64.StdEncoding.EncodeToString(raw)}}})
			if e != nil || n != expected {
				t.Fatal("connection/plaintext acceptance boundary changed")
			}
			sess.decodeDir("s2c")
			if sess.pipeline.decryptOK.Load() != 0 || sess.entityDecoder.NumericStatus(time.Now()).InputPackets != 1 {
				t.Fatal("invalid packet reached SNP or entity parsing")
			}
			if mode == "tampered_ciphertext" && sess.pipeline.decryptFailed.Load() != 1 {
				t.Fatal("GCM was bypassed")
			}
		})
	}
}
