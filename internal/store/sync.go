package store

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"time"
)

// Vector summarizes what a store holds: device id -> highest contiguous seq.
type Vector map[string]int64

var hlcRe = regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z/\d{4,}$`)

// has reports whether dev+seq is already stored. Caller holds mu (or is loading).
func (s *Store) has(dev string, seq int64) bool {
	_, ok := s.seen[dev][seq]
	return ok
}

// track adds an event to the in-memory indexes. Caller holds mu (or is loading).
func (s *Store) track(e Event) {
	s.events = append(s.events, e)
	m := s.seen[e.Dev]
	if m == nil {
		m = map[int64]struct{}{}
		s.seen[e.Dev] = m
	}
	m[e.Seq] = struct{}{}
	c := s.contig[e.Dev]
	for {
		if _, ok := m[c+1]; !ok {
			break
		}
		c++
	}
	s.contig[e.Dev] = c
	if e.Dev == s.DeviceID && e.Seq > s.seq {
		s.seq = e.Seq // e.g. our own events coming back from a backup restore
	}
	// Hybrid logical clock receive rule: never stamp new events before what we've seen.
	if ms := hlcMillis(e.HLC); ms > s.lastMS {
		s.lastMS, s.counter = ms, 0
	}
	if e.TS > s.lastMS && e.Dev == s.DeviceID {
		s.lastMS = e.TS
	}
}

func hlcMillis(h string) int64 {
	if len(h) < 24 {
		return 0
	}
	t, err := time.Parse("2006-01-02T15:04:05.000Z", h[:24])
	if err != nil {
		return 0
	}
	return t.UnixMilli()
}

// Vector returns the store's version vector.
func (s *Store) Vector() Vector {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := Vector{}
	for d, c := range s.contig {
		if c > 0 {
			v[d] = c
		}
	}
	return v
}

// Count is the number of events held (the UI polls it to notice merges).
func (s *Store) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.events)
}

// Since returns events from log position n onwards (log order).
func (s *Store) Since(n int) []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n < 0 || n > len(s.events) {
		n = 0
	}
	return append([]Event(nil), s.events[n:]...)
}

// Missing returns up to limit events the holder of v lacks, ordered by (hlc, dev, seq),
// which keeps every device's events in ascending seq order.
func (s *Store) Missing(v Vector, limit int) (out []Event, more bool) {
	if limit <= 0 || limit > 5000 {
		limit = 2000
	}
	s.mu.Lock()
	for _, e := range s.events {
		if e.Seq > v[e.Dev] {
			out = append(out, e)
		}
	}
	s.mu.Unlock()
	SortEvents(out)
	if len(out) > limit {
		return out[:limit], true
	}
	return out, false
}

// SortEvents orders events by (hlc, dev, seq): the replay order every device shares.
func SortEvents(evs []Event) {
	sort.SliceStable(evs, func(i, j int) bool {
		a, b := evs[i], evs[j]
		if a.HLC != b.HLC {
			return a.HLC < b.HLC
		}
		if a.Dev != b.Dev {
			return a.Dev < b.Dev
		}
		return a.Seq < b.Seq
	})
}

// ErrBadEvent marks an event that fails validation.
var ErrBadEvent = errors.New("bad_event")

// Validate checks an event received from another device.
func Validate(e Event) error {
	switch {
	case len(e.ID) < 10 || len(e.ID) > 40:
		return fmt.Errorf("%w: id", ErrBadEvent)
	case e.Dev == "" || len(e.Dev) > 40:
		return fmt.Errorf("%w: dev", ErrBadEvent)
	case e.Seq <= 0:
		return fmt.Errorf("%w: seq", ErrBadEvent)
	case !hlcRe.MatchString(e.HLC):
		return fmt.Errorf("%w: hlc", ErrBadEvent)
	case e.Type == "" || len(e.Type) > 40:
		return fmt.Errorf("%w: type", ErrBadEvent)
	case len(e.Body) > 64<<10 || (len(e.Body) > 0 && !json.Valid(e.Body)):
		return fmt.Errorf("%w: body", ErrBadEvent)
	}
	return nil
}

// Merge durably appends events from other devices, skipping ones already held.
// It is idempotent: merging the same batch twice changes nothing.
func (s *Store) Merge(evs []Event) (accepted, duplicates int, err error) {
	for _, e := range evs {
		if err := Validate(e); err != nil {
			return 0, 0, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var fresh []Event
	batch := map[string]map[int64]bool{}
	for _, e := range evs {
		if s.has(e.Dev, e.Seq) || batch[e.Dev][e.Seq] {
			duplicates++
			continue
		}
		if batch[e.Dev] == nil {
			batch[e.Dev] = map[int64]bool{}
		}
		batch[e.Dev][e.Seq] = true
		if len(e.Body) == 0 {
			e.Body = json.RawMessage("{}")
		}
		fresh = append(fresh, e)
	}
	if len(fresh) == 0 {
		return 0, duplicates, nil
	}
	f, err := os.OpenFile(s.logPath(), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, e := range fresh {
		b, err := json.Marshal(e)
		if err != nil {
			return 0, 0, err
		}
		w.Write(b)
		w.WriteByte('\n')
	}
	if err := w.Flush(); err != nil {
		return 0, 0, err
	}
	if err := f.Sync(); err != nil {
		return 0, 0, err
	}
	for _, e := range fresh {
		s.track(e)
	}
	return len(fresh), duplicates, nil
}

// Has reports whether the event dev+seq is stored.
func (s *Store) Has(dev string, seq int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.has(dev, seq)
}
