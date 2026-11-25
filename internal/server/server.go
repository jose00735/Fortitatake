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
	"strconv"
	"strings"
	"time"

	"github.com/jose00735/fortitatake/internal/ftkos"
	"github.com/jose00735/fortitatake/internal/ftsp"
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
	Content *Content
	Hub     *ftsp.Hub   // set on the PC
	Spoke   *ftsp.Spoke // set on the phone
	Android bool
	Engine  *ftkos.Manager // FortiTatake OS
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
		if r.URL.Path == "/content/bundle.json" && s.Content != nil {
			data, _ := s.Content.Current()
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_, _ = w.Write(data)
			return
		}
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
		info := map[string]any{"version": s.Version, "native": s.Native, "dir": s.Store.Dir, "device": s.Store.DeviceID,
			"count": s.Store.Count(), "role": s.role(), "android": s.Android}
		if s.Content != nil {
			_, p := s.Content.Current()
			info["content"] = p.Version
		}
		writeJSON(w, 200, info)

	case path == "events" && r.Method == http.MethodGet:
		n, _ := strconv.Atoi(r.URL.Query().Get("since"))
		writeJSON(w, 200, map[string]any{"events": s.Store.Since(n), "count": s.Store.Count()})

	case strings.HasPrefix(path, "engine/") && s.Engine != nil:
		s.Engine.API(w, r, strings.TrimPrefix(path, "engine/"))

	case strings.HasPrefix(path, "sync"):
		s.syncAPI(w, r, strings.TrimPrefix(strings.TrimPrefix(path, "sync"), "/"))

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

func (s *Server) role() string {
	switch {
	case s.Hub != nil:
		return "hub"
	case s.Spoke != nil:
		return "spoke"
	}
	return "off"
}

func decode(r *http.Request, v any) error {
	return json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v)
}

func (s *Server) syncAPI(w http.ResponseWriter, r *http.Request, sub string) {
	bad := func(err error) { writeJSON(w, 400, map[string]string{"error": err.Error()}) }
	post := r.Method == http.MethodPost
	switch {
	case sub == "" && r.Method == http.MethodGet:
		switch {
		case s.Hub != nil:
			writeJSON(w, 200, s.Hub.Status())
		case s.Spoke != nil:
			writeJSON(w, 200, s.Spoke.Status())
		default:
			writeJSON(w, 200, map[string]any{"role": "off"})
		}

	// ----- PC (hub) -----
	case s.Hub != nil && sub == "hub" && post:
		var in struct {
			Enabled bool   `json:"enabled"`
			Port    int    `json:"port"`
			Name    string `json:"name"`
		}
		if err := decode(r, &in); err != nil {
			bad(err)
			return
		}
		if err := s.Hub.Configure(in.Enabled, in.Port, in.Name); err != nil {
			bad(err)
			return
		}
		writeJSON(w, 200, s.Hub.Status())
	case s.Hub != nil && sub == "pair/open" && post:
		info, err := s.Hub.OpenPairing()
		if err != nil {
			bad(err)
			return
		}
		writeJSON(w, 200, info)
	case s.Hub != nil && sub == "pair/close" && post:
		s.Hub.ClosePairing()
		writeJSON(w, 200, map[string]bool{"closed": true})
	case s.Hub != nil && sub == "devices/revoke" && post:
		var in struct {
			ID string `json:"id"`
		}
		_ = decode(r, &in)
		writeJSON(w, 200, map[string]bool{"revoked": s.Hub.Revoke(in.ID)})

	// ----- phone (spoke) -----
	case s.Spoke != nil && sub == "probe" && post:
		var in struct {
			Host string `json:"host"`
			Port int    `json:"port"`
		}
		if err := decode(r, &in); err != nil {
			bad(err)
			return
		}
		res, err := s.Spoke.Probe(strings.TrimSpace(in.Host), in.Port)
		if err != nil {
			bad(err)
			return
		}
		writeJSON(w, 200, res)
	case s.Spoke != nil && sub == "pair" && post:
		var in ftsp.PairRequest
		if err := decode(r, &in); err != nil {
			bad(err)
			return
		}
		res, err := s.Spoke.Pair(in)
		if err != nil {
			bad(err)
			return
		}
		writeJSON(w, 200, res)
	case s.Spoke != nil && sub == "now" && post:
		res, err := s.Spoke.SyncNow()
		if err != nil {
			bad(err)
			return
		}
		writeJSON(w, 200, res)
	case s.Spoke != nil && sub == "unpair" && post:
		s.Spoke.Unpair()
		writeJSON(w, 200, map[string]bool{"unpaired": true})
	case s.Spoke != nil && sub == "hosts" && post:
		var in struct {
			Hub   string   `json:"hub"`
			Hosts []string `json:"hosts"`
			Port  int      `json:"port"`
		}
		_ = decode(r, &in)
		writeJSON(w, 200, map[string]bool{"updated": s.Spoke.SetHosts(in.Hub, in.Hosts, in.Port)})

	default:
		writeJSON(w, 404, map[string]string{"error": "unknown sync endpoint"})
	}
}
