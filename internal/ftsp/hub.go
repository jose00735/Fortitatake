package ftsp

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/jose00735/fortitatake/internal/store"
)

// Device is a paired phone as the hub remembers it. Only a hash of its token is kept.
type Device struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Platform  string    `json:"platform"`
	TokenHash string    `json:"token_hash,omitempty"`
	Paired    time.Time `json:"paired"`
	LastSeen  time.Time `json:"last_seen"`
	LastAddr  string    `json:"last_addr"`
	Revoked   bool      `json:"revoked"`
}

type hubFile struct {
	Enabled bool      `json:"enabled"`
	Port    int       `json:"port"`
	Name    string    `json:"name"`
	Devices []*Device `json:"devices"`
}

type pairWindow struct {
	token, code string
	exp         time.Time
	fails       int
}

type bucket struct {
	tokens float64
	last   time.Time
}

// Hub is the Windows side of FTSP/1.
type Hub struct {
	Store   *store.Store
	Dir     string
	Content ContentSource
	AppVer  string
	OnOS    func(ev string, data map[string]any) // FortiTatake OS transfer progress

	mu        sync.Mutex
	cfg       hubFile
	cert      tls.Certificate
	fp        string
	srv       *http.Server
	running   bool
	listenErr string
	mdns      *mdnsResponder
	mdnsErr   string
	pair      *pairWindow
	limits    map[string]*bucket
	lastSync  time.Time
}

// NewHub loads hub settings from dir. Call Start to listen if sync is enabled.
func NewHub(st *store.Store, dir string, content ContentSource, appVer string) *Hub {
	h := &Hub{Store: st, Dir: dir, Content: content, AppVer: appVer, limits: map[string]*bucket{}}
	if b, err := os.ReadFile(h.path()); err == nil {
		_ = json.Unmarshal(b, &h.cfg)
	}
	if h.cfg.Port == 0 {
		h.cfg.Port = DefaultPort
	}
	if h.cfg.Name == "" {
		n, _ := os.Hostname()
		if n == "" {
			n = "PC"
		}
		h.cfg.Name = n
	}
	return h
}

func (h *Hub) path() string { return filepath.Join(h.Dir, "hub.json") }

func (h *Hub) saveLocked() {
	b, _ := json.MarshalIndent(h.cfg, "", "  ")
	_ = writeFileAtomic(h.path(), b)
}

// Start begins listening when sync is enabled. It is safe to call more than once.
func (h *Hub) Start() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.cfg.Enabled || h.running {
		return nil
	}
	return h.startLocked()
}

func (h *Hub) startLocked() error {
	if h.fp == "" {
		c, fp, err := loadOrCreateCert(h.Dir)
		if err != nil {
			h.listenErr = "could not create the sync certificate: " + err.Error()
			return err
		}
		h.cert, h.fp = c, fp
	}
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(h.cfg.Port))
	if err != nil {
		h.listenErr = fmt.Sprintf("port %d is busy or blocked: %v", h.cfg.Port, err)
		return err
	}
	tl := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{h.cert}, MinVersion: tls.VersionTLS12})
	h.srv = &http.Server{
		Handler:           h.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          nil,
	}
	srv := h.srv
	go func() { _ = srv.Serve(tl) }()
	h.running, h.listenErr = true, ""
	h.mdns = newMDNS(h.cfg.Name, h.Store.DeviceID, h.cfg.Port, []string{
		"v=1", "id=" + h.Store.DeviceID, "name=" + h.cfg.Name, "fp=" + h.fp[:16],
	})
	if err := h.mdns.start(); err != nil {
		h.mdnsErr = err.Error()
	} else {
		h.mdnsErr = ""
	}
	return nil
}

func (h *Hub) stopLocked() {
	if h.srv != nil {
		_ = h.srv.Close()
		h.srv = nil
	}
	if h.mdns != nil {
		h.mdns.close()
		h.mdns = nil
	}
	h.running, h.pair = false, nil
}

// Configure turns sync on or off and sets the port and the name phones see.
func (h *Hub) Configure(enabled bool, port int, name string) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if port <= 0 || port > 65535 {
		port = h.cfg.Port
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = h.cfg.Name
	}
	changed := port != h.cfg.Port || name != h.cfg.Name
	h.cfg.Enabled, h.cfg.Port, h.cfg.Name = enabled, port, name
	h.saveLocked()
	if h.running && (!enabled || changed) {
		h.stopLocked()
	}
	if enabled && !h.running {
		return h.startLocked()
	}
	return nil
}

// Close stops the listener (used at exit and in tests).
func (h *Hub) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.stopLocked()
}

// PairInfo is what the PC shows while the pairing window is open.
type PairInfo struct {
	Payload string   `json:"payload"`
	QRSVG   string   `json:"qr_svg"`
	Code    string   `json:"code"`
	Words   string   `json:"words"`
	Exp     int64    `json:"exp"`
	Hosts   []string `json:"hosts"`
	Port    int      `json:"port"`
}

// OpenPairing opens a five-minute single-use pairing window.
func (h *Hub) OpenPairing() (*PairInfo, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.running {
		return nil, errors.New("turn on sync first")
	}
	pw := &pairWindow{token: randToken(16), code: randToken(5), exp: time.Now().Add(5 * time.Minute)}
	h.pair = pw
	hosts := LANAddrs()
	host := ""
	if len(hosts) > 0 {
		host = hosts[0]
	}
	payload, _ := json.Marshal(map[string]any{
		"ftsp": 1, "host": host, "hosts": hosts, "port": h.cfg.Port, "hub": h.Store.DeviceID,
		"name": h.cfg.Name, "cert": "sha256:" + h.fp, "pt": pw.token, "exp": pw.exp.Unix(),
	})
	svg, err := qrSVG(string(payload))
	if err != nil {
		return nil, err
	}
	return &PairInfo{
		Payload: string(payload), QRSVG: svg, Code: pw.code[:4] + "-" + pw.code[4:],
		Words: Words(h.fp), Exp: pw.exp.Unix(), Hosts: hosts, Port: h.cfg.Port,
	}, nil
}

// ClosePairing closes the pairing window early.
func (h *Hub) ClosePairing() {
	h.mu.Lock()
	h.pair = nil
	h.mu.Unlock()
}

// Revoke forgets a device's token; it must pair again.
func (h *Hub) Revoke(id string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, d := range h.cfg.Devices {
		if d.ID == id && !d.Revoked {
			d.Revoked, d.TokenHash = true, ""
			h.saveLocked()
			return true
		}
	}
	return false
}

// Status is the hub state for the local UI.
func (h *Hub) Status() map[string]any {
	h.mu.Lock()
	defer h.mu.Unlock()
	var devs []Device
	for _, d := range h.cfg.Devices {
		if d.Revoked {
			continue
		}
		c := *d
		c.TokenHash = ""
		devs = append(devs, c)
	}
	st := map[string]any{
		"role": "hub", "enabled": h.cfg.Enabled, "running": h.running, "port": h.cfg.Port, "name": h.cfg.Name,
		"hosts": LANAddrs(), "devices": devs, "error": h.listenErr, "mdns_error": h.mdnsErr,
		"pairing": h.pair != nil && time.Now().Before(h.pair.exp),
	}
	if h.fp != "" {
		st["fingerprint"], st["words"] = h.fp, Words(h.fp)
	}
	if !h.lastSync.IsZero() {
		st["last_sync"] = h.lastSync.UnixMilli()
	}
	return st
}

// ----- protocol handler -----

// Handler serves FTSP/1. Requests from non-LAN addresses are refused.
func (h *Hub) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/hello", h.hello)
	mux.HandleFunc("POST /v1/pair", h.pairHandler)
	mux.Handle("POST /v1/sync/pull", h.auth(h.pull))
	mux.Handle("POST /v1/sync/push", h.auth(h.push))
	mux.Handle("GET /v1/packs", h.auth(h.packs))
	mux.Handle("GET /v1/packs/{id}/{version}", h.auth(h.packGet))
	mux.Handle("DELETE /v1/devices/self", h.auth(h.unpairSelf))
	mux.Handle("GET /v1/os", h.auth(h.osList))
	mux.Handle("GET /v1/os/{id}/{file}", h.auth(h.osFile))
	mux.Handle("POST /v1/os/report", h.auth(h.osReport))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		if !IsLAN(net.ParseIP(host)) {
			fail(w, http.StatusForbidden, "unauthorized", "FortiTatake sync only answers devices on your local network")
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (h *Hub) catalogHash() string {
	if h.Content == nil {
		return ""
	}
	_, p := h.Content.Current()
	return p.SHA256
}

func (h *Hub) hello(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	name := h.cfg.Name
	h.mu.Unlock()
	writeJSON(w, 200, map[string]any{
		"ftsp": Version, "hub": h.Store.DeviceID, "name": name, "time": time.Now().UnixMilli(),
		"catalog_hash": h.catalogHash(), "min_client": 1, "app": h.AppVer,
	})
}

func (h *Hub) pairHandler(w http.ResponseWriter, r *http.Request) {
	var in struct {
		PT       string `json:"pt"`
		DeviceID string `json:"device_id"`
		Name     string `json:"name"`
		Platform string `json:"platform"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in); err != nil || in.DeviceID == "" || len(in.DeviceID) > 40 {
		fail(w, 400, "bad_request", "pairing request is incomplete")
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	pw := h.pair
	if pw == nil {
		fail(w, 403, "pairing_closed", "pairing isn't open on the PC; open Settings → Sync → Pair a phone")
		return
	}
	if time.Now().After(pw.exp) {
		h.pair = nil
		fail(w, 403, "token_expired", "the pairing code expired; open a new one on the PC")
		return
	}
	okTok := subtle.ConstantTimeCompare([]byte(in.PT), []byte(pw.token)) == 1
	okCode := subtle.ConstantTimeCompare([]byte(NormCode(in.PT)), []byte(pw.code)) == 1
	if !okTok && !okCode {
		pw.fails++
		if pw.fails >= 5 {
			h.pair = nil
			fail(w, 403, "pairing_closed", "too many wrong codes; pairing closed on the PC")
			return
		}
		fail(w, 403, "unauthorized", "wrong pairing code")
		return
	}
	h.pair = nil // single use
	tok := randToken(32)
	sum := sha256.Sum256([]byte(tok))
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = "Phone"
	}
	if len(name) > 60 {
		name = name[:60]
	}
	addr, _, _ := net.SplitHostPort(r.RemoteAddr)
	var dev *Device
	for _, d := range h.cfg.Devices {
		if d.ID == in.DeviceID {
			dev = d
		}
	}
	if dev == nil {
		dev = &Device{ID: in.DeviceID}
		h.cfg.Devices = append(h.cfg.Devices, dev)
	}
	dev.Name, dev.Platform, dev.TokenHash, dev.Revoked = name, in.Platform, hex.EncodeToString(sum[:]), false
	dev.Paired, dev.LastSeen, dev.LastAddr = time.Now(), time.Now(), addr
	h.saveLocked()
	writeJSON(w, 200, map[string]any{"device_token": tok, "hub": h.Store.DeviceID, "name": h.cfg.Name})
}

func (h *Hub) auth(next func(http.ResponseWriter, *http.Request, *Device)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-FT-Device")
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		sum := sha256.Sum256([]byte(tok))
		want := hex.EncodeToString(sum[:])
		h.mu.Lock()
		var dev *Device
		for _, d := range h.cfg.Devices {
			if d.ID == id && !d.Revoked && d.TokenHash != "" && subtle.ConstantTimeCompare([]byte(d.TokenHash), []byte(want)) == 1 {
				dev = d
			}
		}
		if dev == nil {
			h.mu.Unlock()
			fail(w, 401, "unauthorized", "this phone isn't paired with the PC (or was removed); pair again")
			return
		}
		b := h.limits[dev.ID]
		now := time.Now()
		if b == nil {
			b = &bucket{tokens: 40, last: now}
			h.limits[dev.ID] = b
		}
		b.tokens += now.Sub(b.last).Seconds() * 20
		if b.tokens > 40 {
			b.tokens = 40
		}
		b.last = now
		if b.tokens < 1 {
			h.mu.Unlock()
			fail(w, 429, "rate_limited", "too many requests; slow down")
			return
		}
		b.tokens--
		addr, _, _ := net.SplitHostPort(r.RemoteAddr)
		persist := now.Sub(dev.LastSeen) > time.Minute || dev.LastAddr != addr
		dev.LastSeen, dev.LastAddr = now, addr
		if persist {
			h.saveLocked()
		}
		d := *dev
		h.mu.Unlock()
		next(w, r, &d)
	})
}

type pullReq struct {
	Vector store.Vector `json:"vector"`
	Limit  int          `json:"limit"`
}

type pullResp struct {
	Events []store.Event `json:"events"`
	Vector store.Vector  `json:"vector"`
	More   bool          `json:"more"`
}

func (h *Hub) pull(w http.ResponseWriter, r *http.Request, _ *Device) {
	var in pullReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		fail(w, 400, "bad_request", "pull body is not valid JSON")
		return
	}
	evs, more := h.Store.Missing(in.Vector, in.Limit)
	if evs == nil {
		evs = []store.Event{}
	}
	h.touch()
	writeJSON(w, 200, pullResp{Events: evs, Vector: h.Store.Vector(), More: more})
}

type pushReq struct {
	Events []store.Event `json:"events"`
}

type pushResp struct {
	Accepted   int          `json:"accepted"`
	Duplicates int          `json:"duplicates"`
	Vector     store.Vector `json:"vector"`
}

func (h *Hub) push(w http.ResponseWriter, r *http.Request, _ *Device) {
	var in pushReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 32<<20)).Decode(&in); err != nil {
		fail(w, 400, "bad_event", "push body is not valid JSON")
		return
	}
	if len(in.Events) > 5000 {
		fail(w, 400, "bad_event", "send at most 5,000 events per push")
		return
	}
	for _, e := range in.Events {
		// Only the hub writes the hub's own events; a phone can echo them but not invent new ones.
		if e.Dev == h.Store.DeviceID && !h.Store.Has(e.Dev, e.Seq) {
			fail(w, 400, "bad_event", "event claims to come from the PC")
			return
		}
	}
	acc, dup, err := h.Store.Merge(in.Events)
	if err != nil {
		if errors.Is(err, store.ErrBadEvent) {
			fail(w, 400, "bad_event", err.Error())
			return
		}
		fail(w, 500, "internal", err.Error())
		return
	}
	h.touch()
	writeJSON(w, 200, pushResp{Accepted: acc, Duplicates: dup, Vector: h.Store.Vector()})
}

func (h *Hub) touch() {
	h.mu.Lock()
	h.lastSync = time.Now()
	h.mu.Unlock()
}

func (h *Hub) packs(w http.ResponseWriter, r *http.Request, _ *Device) {
	if h.Content == nil {
		writeJSON(w, 200, []Pack{})
		return
	}
	_, p := h.Content.Current()
	writeJSON(w, 200, []Pack{p})
}

func (h *Hub) packGet(w http.ResponseWriter, r *http.Request, _ *Device) {
	if h.Content == nil {
		fail(w, 404, "not_found", "no packs")
		return
	}
	data, p := h.Content.Current()
	if r.PathValue("id") != p.ID || r.PathValue("version") != p.Version {
		fail(w, 404, "not_found", "that pack version is not on the PC")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-FT-SHA256", p.SHA256)
	http.ServeContent(w, r, p.ID+".json", time.Time{}, bytes.NewReader(data))
}

func (h *Hub) unpairSelf(w http.ResponseWriter, r *http.Request, d *Device) {
	h.Revoke(d.ID)
	writeJSON(w, 200, map[string]bool{"unpaired": true})
}

// qrSVG renders text as a QR code in SVG (dark modules on a white quiet zone).
func qrSVG(text string) (string, error) {
	q, err := qrcode.New(text, qrcode.Medium)
	if err != nil {
		return "", err
	}
	q.DisableBorder = true
	bm := q.Bitmap()
	n := len(bm)
	var sb strings.Builder
	quiet := 4
	size := n + 2*quiet
	fmt.Fprintf(&sb, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges"><rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="`, size, size, size, size)
	for y, row := range bm {
		for x, on := range row {
			if on {
				fmt.Fprintf(&sb, "M%d %dh1v1h-1z", x+quiet, y+quiet)
			}
		}
	}
	sb.WriteString(`"/></svg>`)
	return sb.String(), nil
}
