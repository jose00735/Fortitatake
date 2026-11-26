package ftkos

// Threat-intel feeds for the SecOps labs. The app (not the VM) downloads public feeds once a
// day and keeps dated snapshots in <data>/ftkos/feeds, each with its source and terms. Labs
// pick indicators from a snapshot with their seed; inside the lab every feed address and
// domain is answered by a sinkhole in the lab Internet, so nothing ever reaches the real one.
// Snapshots stay on this device: they are never written into the app's repository.

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type FeedSource struct {
	Name  string `json:"name"`
	URL   string `json:"url"`
	Terms string `json:"terms"`
	Count int    `json:"count"`
	Error string `json:"error,omitempty"`
}

type FeedC2 struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Family string `json:"family"`
	Source string `json:"source"`
}

type FeedDomain struct {
	Domain string `json:"domain"`
	Family string `json:"family"`
	Source string `json:"source"`
}

type FeedURL struct {
	URL    string `json:"url"`
	Host   string `json:"host"`
	Threat string `json:"threat"`
	Source string `json:"source"`
}

type FeedSnapshot struct {
	Date    string       `json:"date"`
	Fetched string       `json:"fetched"`
	Sources []FeedSource `json:"sources"`
	C2      []FeedC2     `json:"c2"`
	Domains []FeedDomain `json:"domains"`
	URLs    []FeedURL    `json:"urls"`
	Phish   []FeedURL    `json:"phish"`
}

// the public feeds; FeedBase lets tests point them at a local server
var (
	FeedBase = map[string]string{
		"feodo":     "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
		"threatfox": "https://threatfox.abuse.ch/export/json/recent/",
		"urlhaus":   "https://urlhaus.abuse.ch/downloads/csv_recent/",
		"openphish": "https://openphish.com/feed.txt",
	}
	feedTerms = map[string]string{
		"feodo":     "abuse.ch Feodo Tracker: free for commercial and non-commercial use (abuse.ch terms of use)",
		"threatfox": "abuse.ch ThreatFox: free for commercial and non-commercial use (abuse.ch terms of use)",
		"urlhaus":   "abuse.ch URLhaus: free for commercial and non-commercial use (abuse.ch terms of use)",
		"openphish": "OpenPhish community feed: see openphish.com for its terms",
	}
	feedMu sync.Mutex
)

const feedMax = 400 // entries kept per kind

func (m *Manager) feedDir() string { return filepath.Join(m.Dir, "feeds") }

func feedGet(client *http.Client, u string) ([]byte, error) {
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", "FortiTatake study app (feed snapshot, once a day)")
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", res.StatusCode)
	}
	return io.ReadAll(io.LimitReader(res.Body, 32<<20))
}

func hostOf(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// FetchFeeds downloads every feed and writes today's snapshot. A failing source is recorded, not fatal.
func (m *Manager) FetchFeeds() (*FeedSnapshot, error) {
	feedMu.Lock()
	defer feedMu.Unlock()
	client := &http.Client{Timeout: 45 * time.Second}
	now := time.Now().UTC()
	s := &FeedSnapshot{Date: now.Format("2006-01-02"), Fetched: now.Format(time.RFC3339)}
	src := func(name string, f func([]byte) int) {
		fs := FeedSource{Name: name, URL: FeedBase[name], Terms: feedTerms[name]}
		b, err := feedGet(client, FeedBase[name])
		if err == nil {
			fs.Count = f(b)
			if fs.Count == 0 {
				err = errors.New("no entries in the response")
			}
		}
		if err != nil {
			fs.Error = err.Error()
		}
		s.Sources = append(s.Sources, fs)
	}
	src("feodo", func(b []byte) int {
		var rows []map[string]any
		if json.Unmarshal(b, &rows) != nil {
			return 0
		}
		for _, r := range rows {
			ip, _ := r["ip_address"].(string)
			if net.ParseIP(ip) == nil || len(s.C2) >= feedMax {
				continue
			}
			port := 443
			if p, ok := r["port"].(float64); ok {
				port = int(p)
			}
			fam, _ := r["malware"].(string)
			s.C2 = append(s.C2, FeedC2{IP: ip, Port: port, Family: fam, Source: "Feodo Tracker"})
		}
		return len(rows)
	})
	src("threatfox", func(b []byte) int {
		var rows map[string][]map[string]any
		if json.Unmarshal(b, &rows) != nil {
			return 0
		}
		n := 0
		for _, list := range rows {
			for _, r := range list {
				n++
				v, _ := r["ioc_value"].(string)
				typ, _ := r["ioc_type"].(string)
				fam, _ := r["malware_printable"].(string)
				switch typ {
				case "ip:port":
					h, p, err := net.SplitHostPort(v)
					pn, _ := strconv.Atoi(p)
					if err == nil && net.ParseIP(h) != nil && len(s.C2) < 2*feedMax {
						s.C2 = append(s.C2, FeedC2{IP: h, Port: pn, Family: fam, Source: "ThreatFox"})
					}
				case "domain":
					if len(s.Domains) < feedMax {
						s.Domains = append(s.Domains, FeedDomain{Domain: strings.ToLower(v), Family: fam, Source: "ThreatFox"})
					}
				}
			}
		}
		return n
	})
	src("urlhaus", func(b []byte) int {
		r := csv.NewReader(strings.NewReader(string(b)))
		r.Comment = '#'
		r.FieldsPerRecord = -1
		n := 0
		for {
			rec, err := r.Read()
			if err != nil {
				break
			}
			if len(rec) < 6 {
				continue
			}
			n++
			if len(s.URLs) < feedMax {
				s.URLs = append(s.URLs, FeedURL{URL: rec[2], Host: hostOf(rec[2]), Threat: rec[5], Source: "URLhaus"})
			}
		}
		return n
	})
	src("openphish", func(b []byte) int {
		n := 0
		sc := bufio.NewScanner(strings.NewReader(string(b)))
		for sc.Scan() {
			l := strings.TrimSpace(sc.Text())
			if !strings.HasPrefix(l, "http") {
				continue
			}
			n++
			if len(s.Phish) < feedMax {
				s.Phish = append(s.Phish, FeedURL{URL: l, Host: hostOf(l), Threat: "phishing", Source: "OpenPhish"})
			}
		}
		return n
	})
	ok := false
	for _, x := range s.Sources {
		if x.Error == "" {
			ok = true
		}
	}
	if !ok {
		return s, errors.New("no feed could be downloaded (no Internet, or the sources refused)")
	}
	os.MkdirAll(m.feedDir(), 0o755)
	b, _ := json.Marshal(s)
	return s, os.WriteFile(filepath.Join(m.feedDir(), s.Date+".json"), b, 0o644)
}

// FeedDates lists the snapshots on this device, newest first.
func (m *Manager) FeedDates() []string {
	files, _ := filepath.Glob(filepath.Join(m.feedDir(), "*.json"))
	var out []string
	for _, f := range files {
		out = append(out, strings.TrimSuffix(filepath.Base(f), ".json"))
	}
	sort.Sort(sort.Reverse(sort.StringSlice(out)))
	return out
}

// LoadFeed returns a snapshot by date ("" or "latest" = newest), or nil.
func (m *Manager) LoadFeed(date string) *FeedSnapshot {
	if date == "" || date == "latest" {
		d := m.FeedDates()
		if len(d) == 0 {
			return nil
		}
		date = d[0]
	}
	if len(date) != 10 || strings.ContainsAny(date, "/\\.") {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(m.feedDir(), date+".json"))
	if err != nil {
		return nil
	}
	var s FeedSnapshot
	if json.Unmarshal(b, &s) != nil {
		return nil
	}
	return &s
}

// FeedLoop refreshes the snapshot once a day while the app runs (desktop only: the phone gets
// snapshots from the PC on sync, or fetches on demand).
func (m *Manager) FeedLoop() {
	for {
		d := m.FeedDates()
		if len(d) == 0 || d[0] != time.Now().UTC().Format("2006-01-02") {
			if _, err := m.FetchFeeds(); err != nil {
				m.emit("feeds", map[string]any{"error": err.Error()})
			} else {
				m.emit("feeds", map[string]any{"ok": true})
			}
		}
		time.Sleep(6 * time.Hour)
	}
}

func (m *Manager) feedsAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s, err := m.FetchFeeds()
		if err != nil {
			writeJSON(w, 502, map[string]any{"error": err.Error(), "snapshot": s})
			return
		}
		writeJSON(w, 200, map[string]any{"snapshot": s, "dates": m.FeedDates()})
		return
	}
	s := m.LoadFeed(r.URL.Query().Get("date"))
	writeJSON(w, 200, map[string]any{"snapshot": s, "dates": m.FeedDates()})
}
