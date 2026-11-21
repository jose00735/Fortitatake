// Package server serves the embedded UI and the JSON API on 127.0.0.1.
package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jose00735/fortitatake/internal/store"
)

// Server is the local HTTP server.
type Server struct {
	Store   *store.Store
	UI      fs.FS
	Version string
	Token   string
	Native  bool
	Quit    func()
	ln      net.Listener
}

// New creates a server with a random per-launch token.
func New(st *store.Store, ui fs.FS, version string) *Server {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return &Server{Store: st, UI: ui, Version: version, Token: hex.EncodeToString(b)}
}

// Listen binds 127.0.0.1 on port (0 = random) and returns the URL to open.
func (s *Server) Listen(port string) (string, error) {
	if port == "" {
		port = "0"
	}
	ln, err := net.Listen("tcp", "127.0.0.1:"+port)
	if err != nil {
		return "", err
	}
	s.ln = ln
	return "http://" + ln.Addr().String() + "/#t=" + s.Token, nil
}

// Serve blocks serving requests.
func (s *Server) Serve() error { return http.Serve(s.ln, s.Handler()) }

// Handler returns the full HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/api/", s.auth(http.HandlerFunc(s.api)))
	static := http.FileServer(http.FS(s.UI))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'")
		static.ServeHTTP(w, r)
	})
	return mux
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-FT-Token")
		if got == "" {
			got = r.URL.Query().Get("t") // for plain downloads (backup link)
		}
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.Token)) != 1 {
			http.Error(w, "missing or wrong token", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) api(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/"), "/")
	switch {
	case path == "info" && r.Method == http.MethodGet:
		writeJSON(w, 200, map[string]any{"version": s.Version, "native": s.Native, "dir": s.Store.Dir, "device": s.Store.DeviceID})

	case path == "events" && r.Method == http.MethodGet:
		writeJSON(w, 200, map[string]any{"events": s.Store.Events()})

	case path == "events" && r.Method == http.MethodPost:
		var in struct {
			Events []store.In `json:"events"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 8<<20)).Decode(&in); err != nil {
			writeJSON(w, 400, map[string]string{"error": "events are not valid JSON"})
			return
		}
		out, err := s.Store.Append(in.Events)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"events": out})

	case path == "export" && r.Method == http.MethodGet:
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition", `attachment; filename="fortitatake-backup-`+time.Now().Format("2006-01-02")+`.ftbackup.jsonl"`)
		http.ServeFile(w, r, s.Store.ExportPath())

	case path == "quit" && r.Method == http.MethodPost:
		writeJSON(w, 200, map[string]bool{"quitting": true})
		if s.Quit != nil {
			go s.Quit()
		}

	default:
		writeJSON(w, 404, map[string]string{"error": "unknown endpoint"})
	}
}
