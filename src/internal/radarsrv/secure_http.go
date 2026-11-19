package radarsrv

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"local/cs2-radar/internal/dataauth"
	"local/cs2-radar/internal/uplink"
	"local/cs2-radar/internal/viewframe"
)

func (s *Store) DropAuthorizedSession(id string) {
	s.mu.Lock()
	sess := s.sessions[id]
	delete(s.sessions, id)
	s.mu.Unlock()
	if sess != nil {
		sess.cycleMu.Lock()
		if sess.replay != nil {
			sess.replay.Stop()
		}
		sess.cycleMu.Unlock()
	}
}

// SecureHandler is the sole runnable server boundary. The old Handler denies
// everything except minimal liveness. Historical raw/UI routes are test-only.
func (s *Store) SecureHandler(auth *dataauth.Broker) http.Handler {
	slots := make(chan struct{}, 4)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.URL.Path == "/health" && r.Method == "GET" {
			writeJSON(w, map[string]bool{"ok": true})
			return
		}
		if auth == nil {
			dataauth.Deny(w)
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.RawPath != "" || r.URL.Path == "/api/v1/probe" || r.URL.Path == "/api/v1/sessions" {
			dataauth.Deny(w)
			return
		}
		if r.URL.Path == "/api/v2/auth/challenge" || r.URL.Path == "/api/v2/auth/login" {
			auth.AuthHandler(w, r)
			return
		}
		// No body is read for missing/malformed credentials. No business operation or
		// work item can start before the proof and live entitlement have been checked.
		if !strings.HasPrefix(r.Header.Get("Authorization"), "PoP ") || len(r.Header.Get("X-Data-Proof")) != 86 {
			dataauth.Deny(w)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "busy", 429)
			return
		}
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, dataauth.MaxBody))
		if e != nil {
			http.Error(w, "request too large", 413)
			return
		}
		permit, e := auth.Authorize(r, raw)
		if e != nil {
			dataauth.Deny(w)
			return
		}
		if r.URL.Path == "/api/v2/auth/heartbeat" {
			if r.Method != "POST" || string(raw) != "{}" {
				dataauth.Deny(w)
				return
			}
			grant, e := auth.Heartbeat(permit)
			if e != nil {
				dataauth.Deny(w)
				return
			}
			writeJSON(w, grant)
			return
		}
		if !permit.Enter() {
			http.Error(w, "session busy", 429)
			return
		}
		defer permit.Leave()
		switch {
		case r.URL.Path == "/api/v1/radar" && r.Method == "GET":
			if len(raw) != 0 {
				http.Error(w, "GET body forbidden", 400)
				return
			}
			if permit.Alive(r.Context()) != nil {
				dataauth.Deny(w)
				return
			}
			version := viewframe.Version
			if h := r.Header.Get("X-Gamesense-View-Version"); h == "2" {
				version = viewframe.TeamVersion
			} else if h == "3" {
				version = viewframe.NameVersion
			} else if h != "" && h != "1" {
				http.Error(w, "unsupported drawing version", 400)
				return
			}
			frame, e := s.Get(permit.SessionID()).PixelViewVersion(version)
			if e != nil {
				http.Error(w, "view unavailable", 503)
				return
			}
			// Recheck after projection: a concurrent revoke must not publish a frame.
			if permit.Alive(r.Context()) != nil {
				s.DropAuthorizedSession(permit.SessionID())
				dataauth.Deny(w)
				return
			}
			writeJSON(w, frame)
		case r.URL.Path == "/api/v1/ingest" && r.Method == "POST":
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				http.Error(w, "JSON required", 415)
				return
			}
			var batch uplink.Batch
			d := json.NewDecoder(bytes.NewReader(raw))
			d.DisallowUnknownFields()
			if d.Decode(&batch) != nil || d.Decode(new(any)) != io.EOF || len(batch.Packets) > 256 {
				http.Error(w, "invalid batch", 400)
				return
			}
			if batch.Session != "" && batch.Session != permit.SessionID() {
				dataauth.Deny(w)
				return
			}
			batch.Session = permit.SessionID()
			// Keep existing acquisition and decoder semantics unchanged. This only caps
			// admission: reject malformed/oversized packet material before Ingest.
			for _, p := range batch.Packets {
				if (p.Dir != "s2c" && p.Dir != "c2s") || len(p.Src) > 128 || len(p.Dst) > 128 || len(p.Data) > 87344 {
					http.Error(w, "invalid packet", 400)
					return
				}
				b, e := base64.StdEncoding.Strict().DecodeString(p.Data)
				if e != nil || len(b) > 65507 {
					http.Error(w, "invalid packet", 400)
					return
				}
			}
			if permit.Alive(r.Context()) != nil {
				dataauth.Deny(w)
				return
			}
			if s.cfg.RestrictedReplay != nil {
				s.attachRestrictedReplay(batch.Session, permit.DevicePublicKeySelector())
			}
			accepted, e := s.Ingest(&batch)
			if e != nil {
				http.Error(w, "batch rejected", 400)
				return
			}
			// Bound concurrency; never create an unbounded goroutine per client batch.
			// Empty synthetic batches need no decoder work.
			if len(batch.Packets) > 0 {
				s.Process(batch.Session)
			}
			if permit.Alive(r.Context()) != nil {
				s.DropAuthorizedSession(batch.Session)
				dataauth.Deny(w)
				return
			}
			writeJSON(w, map[string]any{"ok": true, "accepted": accepted})
		case r.URL.Path == "/api/v1/maps" && r.Method == "GET":
			if len(raw) != 0 {
				http.Error(w, "GET body forbidden", 400)
				return
			}
			writeJSON(w, map[string]any{"ids": s.MapIDs()})
		case r.URL.Path == "/api/v1/map" && r.Method == "POST":
			if len(raw) > 2048 {
				http.Error(w, "request too large", 413)
				return
			}
			var in struct {
				Session string `json:"session"`
				Name    string `json:"name"`
			}
			d := json.NewDecoder(bytes.NewReader(raw))
			d.DisallowUnknownFields()
			if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF {
				http.Error(w, "invalid map request", 400)
				return
			}
			if in.Session != "" && in.Session != permit.SessionID() {
				dataauth.Deny(w)
				return
			}
			if permit.Alive(r.Context()) != nil {
				dataauth.Deny(w)
				return
			}
			state, _ := s.SetMapName(permit.SessionID(), in.Name)
			if permit.Alive(r.Context()) != nil {
				s.DropAuthorizedSession(permit.SessionID())
				dataauth.Deny(w)
				return
			}
			if state == "invalid" {
				http.Error(w, "invalid map", 400)
				return
			}
			writeJSON(w, map[string]any{"ok": true, "state": state})
		case strings.HasPrefix(r.URL.Path, "/mapimg/") && r.Method == "GET":
			if len(raw) != 0 {
				http.Error(w, "GET body forbidden", 400)
				return
			}
			s.handleMapImage(w, r)
		default:
			// Public HTML/raw diagnostics remain denied. Only the native loopback
			// bridge renders the whitelist view, never the old Snapshot.
			dataauth.Deny(w)
		}
	})
}
