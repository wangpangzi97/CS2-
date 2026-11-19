package radarsrv

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"local/cs2-radar/internal/uplink"
	"net/http"
	"strings"
)

// Historical decoder/UI fixtures only. This file is never linked into a binary.
// Handler 返回完整的 HTTP 路由。
//
//	token 非空时，除 /health 外所有接口都要校验（接受 X-Auth-Token 头、
//	Authorization: Bearer、?token= 三种携带方式）。本机模式传空串即可 ——
//	监听地址本来就是 127.0.0.1，只有本机能访问。
//
// 路由：
//
//	POST /api/v1/ingest              上行入口（服务端模式用；本机模式不需要）
//	GET  /api/v1/sessions            会话列表
//	GET  /api/v1/radar?session=<id>  当前雷达画面（JSON）
//	GET  /api/v1/probe?session=<id>  加解密方案搜索结果
//	GET  /api/v1/maps                已知地图 ID 列表
//	POST /api/v1/map (JSON session/name) 手动指定/清除会话地图名
//	GET  /mapimg/{id}/{file}         底图（overview.png / density.png）
//	GET  /radar?session=<id>         雷达页面
//	GET  /health
func (s *Store) fixtureHandler(token string) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/v1/ingest", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var b uplink.Batch
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
			return
		}
		added, err := s.Ingest(&b)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		sess := s.Get(b.Session)
		go func() {
			s.Process(sess.id)
		}()
		_, total, _ := s.Stats()
		writeJSON(w, map[string]any{"ok": true, "accepted": added, "total_packets": total})
	})

	mux.HandleFunc("/api/v1/radar", func(w http.ResponseWriter, r *http.Request) {
		sess := s.Get(r.URL.Query().Get("session"))
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, sess.Snapshot())
	})

	mux.HandleFunc("/api/v1/probe", func(w http.ResponseWriter, r *http.Request) {
		sess := s.Get(r.URL.Query().Get("session"))
		writeJSON(w, sess.Probe())
	})

	mux.HandleFunc("/api/v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		_, packets, batches := s.Stats()
		writeJSON(w, map[string]any{
			"sessions": s.SessionIDs(),
			"batches":  batches,
			"packets":  packets,
		})
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		n, p, _ := s.Stats()
		writeJSON(w, map[string]any{"ok": true, "sessions": n, "packets": p})
	})

	mux.HandleFunc("/api/v1/maps", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"ids": s.MapIDs()})
	})

	// 手动指定地图名。ServerInfo 还没接通时，这是唯一能确定图名的途径。
	// 传空 name 表示清掉手动指定，回到自动判断。
	mux.HandleFunc("/api/v1/map", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			http.Error(w, "JSON required", http.StatusUnsupportedMediaType)
			return
		}
		var in struct {
			Session string `json:"session"`
			Name    string `json:"name"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&in); err != nil {
			http.Error(w, "invalid map request", http.StatusBadRequest)
			return
		}
		var extra any
		if dec.Decode(&extra) != io.EOF || in.Session == "" || len(in.Session) > 128 {
			http.Error(w, "invalid map request", http.StatusBadRequest)
			return
		}
		state, msg := s.SetMapName(in.Session, in.Name)
		if state == "invalid" {
			w.WriteHeader(http.StatusBadRequest)
			writeJSON(w, map[string]any{"ok": false, "state": state, "message": msg})
			return
		}
		writeJSON(w, map[string]any{"ok": true, "state": state, "message": msg})

	})

	mux.HandleFunc("/mapimg/", s.handleMapImage)

	mux.HandleFunc("/radar", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(RadarPage))
	})

	return fixtureAuthed(token, mux)
}

// authed 包一层鉴权：/health 永远放行；配了 token 时其余接口都要校验。
func fixtureAuthed(token string, next http.Handler) http.Handler {
	if token == "" {
		return next
	}
	want := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}
		got := r.Header.Get("X-Auth-Token")
		if got == "" {
			if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
				got = strings.TrimPrefix(h, "Bearer ")
			}
		}
		if got == "" {
			got = r.URL.Query().Get("token")
		}
		if subtle.ConstantTimeCompare([]byte(got), want) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
