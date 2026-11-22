// Package store keeps FortiTatake's append-only event log on disk.
//
// Every study action is an immutable event. The UI rebuilds all state
// (FSRS cards, XP, mastery, medals) by replaying the log, which is what
// makes LAN sync conflict-free (see docs/SYNC-PROTOCOL.md).
package store

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Event is one immutable study action.
type Event struct {
	ID   string          `json:"id"`
	Dev  string          `json:"dev"`
	Seq  int64           `json:"seq"`
	HLC  string          `json:"hlc"`
	TS   int64           `json:"ts"` // unix milliseconds, used by the UI
	Type string          `json:"type"`
	V    int             `json:"v"`
	Body json.RawMessage `json:"body"`
}

// Store is the event log plus device identity.
type Store struct {
	Dir      string
	DeviceID string
	mu       sync.Mutex
	seq      int64
	lastMS   int64
	counter  int
	events   []Event
	seen     map[string]map[int64]struct{} // dev -> seqs held
	contig   map[string]int64              // dev -> highest contiguous seq
}

// DefaultDir is %APPDATA%\FortiTatake on Windows and ~/.fortitatake elsewhere.
func DefaultDir() string {
	if runtime.GOOS == "windows" {
		if d := os.Getenv("APPDATA"); d != "" {
			return filepath.Join(d, "FortiTatake")
		}
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return ".fortitatake"
	}
	return filepath.Join(h, ".fortitatake")
}

func (s *Store) logPath() string { return filepath.Join(s.Dir, "events.jsonl") }

// Open loads (or creates) the store in dir.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{Dir: dir, seen: map[string]map[int64]struct{}{}, contig: map[string]int64{}}
	idPath := filepath.Join(dir, "device.json")
	if b, err := os.ReadFile(idPath); err == nil {
		var d struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(b, &d) == nil && d.ID != "" {
			s.DeviceID = d.ID
		}
	}
	if s.DeviceID == "" {
		s.DeviceID = newID()
		b, _ := json.Marshal(map[string]string{"id": s.DeviceID, "created": time.Now().UTC().Format(time.RFC3339)})
		if err := os.WriteFile(idPath, b, 0o600); err != nil {
			return nil, err
		}
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	f, err := os.Open(s.logPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e Event
		if json.Unmarshal([]byte(line), &e) != nil {
			continue // a torn last line after a crash is skipped, never fatal
		}
		if s.has(e.Dev, e.Seq) {
			continue
		}
		s.track(e)
	}
	return sc.Err()
}

// In is an event as sent by the UI (identity and clocks are filled in here).
type In struct {
	Type string          `json:"type"`
	V    int             `json:"v"`
	TS   int64           `json:"ts"`
	Body json.RawMessage `json:"body"`
}

// Append stamps and durably appends events, returning them as stored.
func (s *Store) Append(in []In) ([]Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(s.logPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	out := make([]Event, 0, len(in))
	for _, x := range in {
		if x.Type == "" || len(x.Type) > 40 {
			return nil, fmt.Errorf("bad event type %q", x.Type)
		}
		now := time.Now().UnixMilli()
		if now > s.lastMS {
			s.lastMS, s.counter = now, 0
		} else {
			s.counter++
		}
		ts := x.TS
		if ts == 0 {
			ts = now
		}
		s.seq++
		v := x.V
		if v == 0 {
			v = 1
		}
		body := x.Body
		if len(body) == 0 {
			body = json.RawMessage("{}")
		}
		e := Event{
			ID: newID(), Dev: s.DeviceID, Seq: s.seq, TS: ts, Type: x.Type, V: v, Body: body,
			HLC: fmt.Sprintf("%s/%04d", time.UnixMilli(s.lastMS).UTC().Format("2006-01-02T15:04:05.000Z"), s.counter),
		}
		b, err := json.Marshal(e)
		if err != nil {
			return nil, err
		}
		w.Write(b)
		w.WriteByte('\n')
		out = append(out, e)
	}
	if err := w.Flush(); err != nil {
		return nil, err
	}
	if err := f.Sync(); err != nil {
		return nil, err
	}
	for _, e := range out {
		s.track(e)
	}
	return out, nil
}

// Events returns a copy of all events in log order.
func (s *Store) Events() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Event(nil), s.events...)
}

// ExportPath is the raw log file, used for backups.
func (s *Store) ExportPath() string { return s.logPath() }

// newID returns a 26-char time-sortable ID (ULID-like, Crockford base32).
func newID() string {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	var b [16]byte
	ms := uint64(time.Now().UnixMilli())
	for i := 5; i >= 0; i-- {
		b[i] = byte(ms)
		ms >>= 8
	}
	_, _ = rand.Read(b[6:])
	// encode 128 bits as 26 base32 chars
	out := make([]byte, 26)
	var acc uint64
	bits, j := 0, 0
	for _, c := range b {
		acc = acc<<8 | uint64(c)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out[j] = alphabet[(acc>>uint(bits))&31]
			j++
		}
	}
	if bits > 0 {
		out[j] = alphabet[(acc<<uint(5-bits))&31]
	}
	return string(out)
}
