package ftsp

import (
	"bytes"
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

	"github.com/jose00735/fortitatake/internal/store"
)

type spokeFile struct {
	HubID      string   `json:"hub_id,omitempty"`
	HubName    string   `json:"hub_name,omitempty"`
	Hosts      []string `json:"hosts,omitempty"`
	Port       int      `json:"port,omitempty"`
	FP         string   `json:"fp,omitempty"`
	Token      string   `json:"token,omitempty"`
	LastSync   int64    `json:"last_sync,omitempty"`
	LastError  string   `json:"last_error,omitempty"`
	LastPulled int      `json:"last_pulled"`
	LastPushed int      `json:"last_pushed"`
	ContentAt  int64    `json:"content_at,omitempty"`
}

// Spoke is the phone side of FTSP/1.
type Spoke struct {
	Store    *store.Store
	Dir      string
	Content  ContentSource
	Name     string
	Platform string
	OnOS     func(ev string, data map[string]any) // FortiTatake OS transfer progress

	mu      sync.Mutex
	syncMu  sync.Mutex // one sync at a time; a second caller waits and then runs its own
	cfg     spokeFile
	busy    bool
	kick    chan struct{}
	started bool
	// Interval between automatic syncs (5 minutes; shorter in tests).
	Interval time.Duration
}

// NewSpoke loads the pairing saved in dir (app-private storage on Android).
func NewSpoke(st *store.Store, dir string, content ContentSource, name, platform string) *Spoke {
	s := &Spoke{Store: st, Dir: dir, Content: content, Name: name, Platform: platform, kick: make(chan struct{}, 1), Interval: 5 * time.Minute}
	if b, err := os.ReadFile(s.path()); err == nil {
		_ = json.Unmarshal(b, &s.cfg)
	}
	return s
}

func (s *Spoke) path() string { return filepath.Join(s.Dir, "spoke.json") }

func (s *Spoke) saveLocked() {
	b, _ := json.MarshalIndent(s.cfg, "", "  ")
	_ = writeFileAtomic(s.path(), b)
}

// Paired reports whether a hub is configured.
func (s *Spoke) Paired() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg.Token != ""
}

// Status is the spoke state for the local UI.
func (s *Spoke) Status() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := map[string]any{
		"role": "spoke", "paired": s.cfg.Token != "", "busy": s.busy, "name": s.Name,
		"hub_name": s.cfg.HubName, "hub_id": s.cfg.HubID, "hosts": s.cfg.Hosts, "port": s.cfg.Port,
		"last_error": s.cfg.LastError, "last_pulled": s.cfg.LastPulled, "last_pushed": s.cfg.LastPushed,
	}
	if s.cfg.LastSync > 0 {
		st["last_sync"] = s.cfg.LastSync
	}
	if s.cfg.ContentAt > 0 {
		st["content_at"] = s.cfg.ContentAt
	}
	if s.cfg.FP != "" {
		st["words"] = Words(s.cfg.FP)
	}
	return st
}

// ProbeResult is what the phone learns about a hub before trusting it.
type ProbeResult struct {
	FP    string `json:"fp"`
	Words string `json:"words"`
	Hub   string `json:"hub"`
	Name  string `json:"name"`
}

func baseURL(host string, port int) string {
	return "https://" + net.JoinHostPort(host, strconv.Itoa(port))
}

// Probe connects without a pin and returns the hub's fingerprint for the user to compare.
func (s *Spoke) Probe(host string, port int) (*ProbeResult, error) {
	if port == 0 {
		port = DefaultPort
	}
	var seen string
	c := pinnedClient("", &seen, 6*time.Second)
	var hello struct {
		Hub  string `json:"hub"`
		Name string `json:"name"`
		FTSP int    `json:"ftsp"`
	}
	if err := doJSON(c, "GET", baseURL(host, port)+"/v1/hello", nil, nil, &hello); err != nil {
		return nil, friendly(err, host, port)
	}
	if hello.FTSP != Version {
		return nil, fmt.Errorf("the PC speaks sync protocol %d; update both apps", hello.FTSP)
	}
	return &ProbeResult{FP: seen, Words: Words(seen), Hub: hello.Hub, Name: hello.Name}, nil
}

// PairRequest comes from the UI: either a scanned QR payload, or a typed address,
// code and the fingerprint the user confirmed after Probe.
type PairRequest struct {
	QR   string `json:"qr"`
	Host string `json:"host"`
	Port int    `json:"port"`
	Code string `json:"code"`
	FP   string `json:"fp"`
}

type qrPayload struct {
	FTSP  int      `json:"ftsp"`
	Host  string   `json:"host"`
	Hosts []string `json:"hosts"`
	Port  int      `json:"port"`
	Hub   string   `json:"hub"`
	Name  string   `json:"name"`
	Cert  string   `json:"cert"`
	PT    string   `json:"pt"`
	Exp   int64    `json:"exp"`
}

// Pair registers this phone with the hub and saves the pinned certificate and token.
func (s *Spoke) Pair(req PairRequest) (*ProbeResult, error) {
	var hosts []string
	var port int
	var pin, pt string
	if strings.TrimSpace(req.QR) != "" {
		var q qrPayload
		if err := json.Unmarshal([]byte(req.QR), &q); err != nil || q.FTSP != Version || q.PT == "" || q.Cert == "" {
			return nil, errors.New("that QR code isn't a FortiTatake pairing code")
		}
		if q.Exp > 0 && time.Now().Unix() > q.Exp+60 {
			return nil, errors.New("that pairing code expired; open a new one on the PC")
		}
		if q.Host != "" {
			hosts = append(hosts, q.Host)
		}
		for _, h := range q.Hosts {
			if h != q.Host {
				hosts = append(hosts, h)
			}
		}
		port, pin, pt = q.Port, strings.TrimPrefix(q.Cert, "sha256:"), q.PT
	} else {
		if req.Host == "" || req.Code == "" || req.FP == "" {
			return nil, errors.New("enter the PC's address and code, then confirm the four words")
		}
		hosts, port, pin, pt = []string{strings.TrimSpace(req.Host)}, req.Port, strings.TrimPrefix(req.FP, "sha256:"), req.Code
	}
	if port == 0 {
		port = DefaultPort
	}
	body := map[string]string{"pt": pt, "device_id": s.Store.DeviceID, "name": s.Name, "platform": s.Platform}
	var out struct {
		DeviceToken string `json:"device_token"`
		Hub         string `json:"hub"`
		Name        string `json:"name"`
	}
	c := pinnedClient(pin, nil, 8*time.Second)
	var lastErr error
	var good string
	for _, h := range hosts {
		err := doJSON(c, "POST", baseURL(h, port)+"/v1/pair", nil, body, &out)
		if err == nil {
			good = h
			break
		}
		lastErr = friendly(err, h, port)
		var ae *APIError
		if errors.As(err, &ae) || errors.Is(err, ErrPinMismatch) {
			break // the hub answered; trying other addresses won't help
		}
	}
	if good == "" {
		if lastErr == nil {
			lastErr = errors.New("the QR code has no address for the PC")
		}
		return nil, lastErr
	}
	ordered := []string{good}
	for _, h := range hosts {
		if h != good {
			ordered = append(ordered, h)
		}
	}
	s.mu.Lock()
	s.cfg = spokeFile{HubID: out.Hub, HubName: out.Name, Hosts: ordered, Port: port, FP: strings.ToUpper(pin), Token: out.DeviceToken}
	s.saveLocked()
	s.mu.Unlock()
	s.Kick()
	return &ProbeResult{FP: pin, Words: Words(pin), Hub: out.Hub, Name: out.Name}, nil
}

// Unpair tells the hub (best effort) and forgets it.
func (s *Spoke) Unpair() {
	s.mu.Lock()
	cfg := s.cfg
	s.cfg = spokeFile{}
	s.saveLocked()
	s.mu.Unlock()
	if cfg.Token == "" || len(cfg.Hosts) == 0 {
		return
	}
	c := pinnedClient(cfg.FP, nil, 4*time.Second)
	_ = doJSON(c, "DELETE", baseURL(cfg.Hosts[0], cfg.Port)+"/v1/devices/self", s.headers(cfg), nil, nil)
}

// SetHosts updates the hub's addresses (from Android's network service discovery).
func (s *Spoke) SetHosts(hubID string, hosts []string, port int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cfg.Token == "" || hubID != s.cfg.HubID || len(hosts) == 0 {
		return false
	}
	seen := map[string]bool{}
	var merged []string
	for _, h := range append(hosts, s.cfg.Hosts...) {
		if h != "" && !seen[h] && IsLAN(net.ParseIP(h)) {
			seen[h] = true
			merged = append(merged, h)
		}
	}
	if len(merged) > 6 {
		merged = merged[:6]
	}
	s.cfg.Hosts = merged
	if port > 0 {
		s.cfg.Port = port
	}
	s.saveLocked()
	return true
}

func (s *Spoke) headers(cfg spokeFile) map[string]string {
	return map[string]string{"Authorization": "Bearer " + cfg.Token, "X-FT-Device": s.Store.DeviceID}
}

// Kick asks the background loop to sync soon.
func (s *Spoke) Kick() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// Run syncs at start, every Interval, and whenever kicked. It never returns.
func (s *Spoke) Run() {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return
	}
	s.started = true
	s.mu.Unlock()
	t := time.NewTimer(2 * time.Second)
	for {
		select {
		case <-t.C:
		case <-s.kick:
		}
		if s.Paired() {
			_, _ = s.SyncNow()
		}
		t.Reset(s.Interval)
	}
}

// Result summarizes one sync.
type Result struct {
	Pulled         int  `json:"pulled"`
	Pushed         int  `json:"pushed"`
	ContentUpdated bool `json:"content_updated"`
}

// SyncNow runs one full catch-up: hello, pull until done, push what the hub lacks, packs.
func (s *Spoke) SyncNow() (*Result, error) {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	s.mu.Lock()
	if s.cfg.Token == "" {
		s.mu.Unlock()
		return nil, errors.New("pair with the PC first")
	}
	s.busy = true
	cfg := s.cfg
	s.mu.Unlock()

	res, host, err := s.syncOnce(cfg)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.busy = false
	if s.cfg.Token != cfg.Token { // unpaired meanwhile
		return res, err
	}
	if err != nil {
		s.cfg.LastError = err.Error()
	} else {
		s.cfg.LastError, s.cfg.LastSync = "", time.Now().UnixMilli()
		s.cfg.LastPulled, s.cfg.LastPushed = res.Pulled, res.Pushed
		if res.ContentUpdated {
			s.cfg.ContentAt = time.Now().UnixMilli()
		}
		if host != "" && len(s.cfg.Hosts) > 0 && s.cfg.Hosts[0] != host { // remember the address that worked
			h := []string{host}
			for _, x := range s.cfg.Hosts {
				if x != host {
					h = append(h, x)
				}
			}
			s.cfg.Hosts = h
		}
	}
	s.saveLocked()
	return res, err
}

func (s *Spoke) syncOnce(cfg spokeFile) (*Result, string, error) {
	c := pinnedClient(cfg.FP, nil, 60*time.Second)
	hdr := s.headers(cfg)
	var base, host string
	var lastErr error
	for _, h := range cfg.Hosts {
		var hello struct {
			Hub  string `json:"hub"`
			FTSP int    `json:"ftsp"`
		}
		hc := pinnedClient(cfg.FP, nil, 5*time.Second)
		err := doJSON(hc, "GET", baseURL(h, cfg.Port)+"/v1/hello", nil, nil, &hello)
		if err != nil {
			lastErr = friendly(err, h, cfg.Port)
			if errors.Is(err, ErrPinMismatch) {
				return nil, "", lastErr
			}
			continue
		}
		if hello.Hub != cfg.HubID {
			lastErr = fmt.Errorf("%s is a different FortiTatake PC than the one paired", h)
			continue
		}
		base, host = baseURL(h, cfg.Port), h
		break
	}
	if base == "" {
		if lastErr == nil {
			lastErr = errors.New("no address saved for the PC; pair again")
		}
		return nil, "", lastErr
	}
	res := &Result{}

	// 1. pull until the hub has nothing more
	var hubVec store.Vector
	for i := 0; i < 1000; i++ {
		var pr pullResp
		if err := doJSON(c, "POST", base+"/v1/sync/pull", hdr, pullReq{Vector: s.Store.Vector(), Limit: 2000}, &pr); err != nil {
			return res, host, friendly(err, host, cfg.Port)
		}
		acc, _, err := s.Store.Merge(pr.Events)
		if err != nil {
			return res, host, fmt.Errorf("the PC sent data this phone couldn't store: %v", err)
		}
		res.Pulled += acc
		hubVec = pr.Vector
		if !pr.More {
			break
		}
	}

	// 2. push what the hub lacks, in batches
	for i := 0; i < 1000; i++ {
		missing, more := s.Store.Missing(hubVec, 2000)
		if len(missing) == 0 {
			break
		}
		var ps pushResp
		if err := doJSON(c, "POST", base+"/v1/sync/push", hdr, pushReq{Events: missing}, &ps); err != nil {
			return res, host, friendly(err, host, cfg.Port)
		}
		res.Pushed += ps.Accepted
		hubVec = ps.Vector
		if !more {
			break
		}
	}

	// 3. content packs: take the hub's bundle when it is newer than ours
	if s.Content != nil {
		var cat []Pack
		if err := doJSON(c, "GET", base+"/v1/packs", hdr, nil, &cat); err == nil {
			_, mine := s.Content.Current()
			for _, p := range cat {
				if p.ID != mine.ID || p.SHA256 == mine.SHA256 || p.Version < mine.Version {
					continue
				}
				data, err := getBytes(c, base+"/v1/packs/"+p.ID+"/"+p.Version, hdr, 64<<20)
				if err != nil {
					return res, host, friendly(err, host, cfg.Port)
				}
				if sha256Hex(data) != strings.ToUpper(p.SHA256) {
					return res, host, errors.New("the content download was corrupted; it will retry next sync")
				}
				if err := s.Content.Install(data, p); err != nil {
					return res, host, fmt.Errorf("could not install new content: %v", err)
				}
				res.ContentUpdated = true
			}
		}
	}
	// 4. FortiTatake OS: new signed ARM64 builds down, this phone's report up
	s.syncOS(pinnedClient(cfg.FP, nil, 30*time.Minute), base, hdr)
	return res, host, nil
}

// ----- HTTP helpers -----

// APIError is an error answer from the hub.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("the PC answered %d %s", e.Status, e.Code)
}

func doJSON(c *http.Client, method, url string, hdr map[string]string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var ae apiError
		_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&ae)
		return &APIError{Status: resp.StatusCode, Code: ae.Error.Code, Message: ae.Error.Message}
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(out)
}

func getBytes(c *http.Client, url string, hdr map[string]string, max int64) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return nil, &APIError{Status: resp.StatusCode, Code: "download_failed"}
	}
	return io.ReadAll(io.LimitReader(resp.Body, max))
}

// friendly turns network errors into something a person can act on.
func friendly(err error, host string, port int) error {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae
	}
	if errors.Is(err, ErrPinMismatch) || strings.Contains(err.Error(), ErrPinMismatch.Error()) {
		return ErrPinMismatch
	}
	var ne net.Error
	if errors.As(err, &ne) || strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "no route") {
		return fmt.Errorf("can't reach the PC at %s:%d. Check that both are on the same Wi-Fi, FortiTatake is open on the PC and sync is on", host, port)
	}
	return err
}
