package ftsp

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jose00735/fortitatake/internal/store"
)

type memContent struct {
	mu   sync.Mutex
	data []byte
	p    Pack
}

func newMem(version, body string) *memContent {
	b := []byte(fmt.Sprintf(`{"version":%q,"modules":[%s]}`, version, body))
	return &memContent{data: b, p: Pack{ID: "bundle", Version: version, SHA256: sha256Hex(b), Size: len(b)}}
}
func (m *memContent) Current() ([]byte, Pack) { m.mu.Lock(); defer m.mu.Unlock(); return m.data, m.p }
func (m *memContent) Install(b []byte, p Pack) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data, m.p = b, p
	return nil
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func openStore(t *testing.T) (*store.Store, string) {
	d := t.TempDir()
	st, err := store.Open(d)
	if err != nil {
		t.Fatal(err)
	}
	return st, d
}

func addEvents(t *testing.T, st *store.Store, n int, tag string) {
	var in []store.In
	for i := 0; i < n; i++ {
		in = append(in, store.In{Type: "review", Body: json.RawMessage(fmt.Sprintf(`{"item":"%s-%d","rating":3}`, tag, i))})
	}
	if _, err := st.Append(in); err != nil {
		t.Fatal(err)
	}
}

func startHub(t *testing.T, content ContentSource) (*Hub, *store.Store) {
	st, dir := openStore(t)
	h := NewHub(st, dir, content, "test")
	if err := h.Configure(true, freePort(t), "Test PC"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	return h, st
}

// qrFor rewrites the QR host to loopback so tests don't depend on the machine's LAN.
func qrFor(t *testing.T, h *Hub) string {
	info, err := h.OpenPairing()
	if err != nil {
		t.Fatal(err)
	}
	var q map[string]any
	_ = json.Unmarshal([]byte(info.Payload), &q)
	q["host"], q["hosts"] = "127.0.0.1", []string{"10.255.255.1", "127.0.0.1"}
	b, _ := json.Marshal(q)
	return string(b)
}

func newSpoke(t *testing.T, content ContentSource, name string) *Spoke {
	st, dir := openStore(t)
	return NewSpoke(st, dir, content, name, "test")
}

func ids(st *store.Store) []string {
	var out []string
	for _, e := range st.Events() {
		out = append(out, e.ID)
	}
	sort.Strings(out)
	return out
}

func TestPairSyncBothWaysAndPacks(t *testing.T) {
	h, hst := startHub(t, newMem("2026-11-22.0900", `{"id":"NEW"}`))
	addEvents(t, hst, 30, "pc")
	sp := newSpoke(t, newMem("2026-11-21.1800", `{"id":"OLD"}`), "Pixel")
	addEvents(t, sp.Store, 12, "phone")

	if _, err := sp.Pair(PairRequest{QR: qrFor(t, h)}); err != nil {
		t.Fatal("pair:", err)
	}
	res, err := sp.SyncNow()
	if err != nil {
		t.Fatal("sync:", err)
	}
	if res.Pulled != 30 || res.Pushed != 12 || !res.ContentUpdated {
		t.Fatalf("unexpected result %+v", res)
	}
	if strings.Join(ids(hst), ",") != strings.Join(ids(sp.Store), ",") {
		t.Fatal("hub and phone hold different events")
	}
	// idempotent: a second sync moves nothing
	res, err = sp.SyncNow()
	if err != nil || res.Pulled != 0 || res.Pushed != 0 || res.ContentUpdated {
		t.Fatalf("second sync should be a no-op: %+v %v", res, err)
	}
	// the phone's next events continue its own seq and reach the hub
	addEvents(t, sp.Store, 3, "phone2")
	if res, err = sp.SyncNow(); err != nil || res.Pushed != 3 {
		t.Fatalf("expected 3 pushed: %+v %v", res, err)
	}
	// persistence: reopen both stores from disk and compare
	h2, _ := store.Open(hst.Dir)
	p2, _ := store.Open(sp.Store.Dir)
	if len(h2.Events()) != 45 || len(p2.Events()) != 45 {
		t.Fatalf("after reopen: hub %d phone %d", len(h2.Events()), len(p2.Events()))
	}
	// pairing state persisted
	sp2 := NewSpoke(p2, sp.Dir, nil, "Pixel", "test")
	if !sp2.Paired() {
		t.Fatal("pairing not persisted")
	}
}

func TestCodePairingWithProbe(t *testing.T) {
	h, _ := startHub(t, nil)
	info, err := h.OpenPairing()
	if err != nil {
		t.Fatal(err)
	}
	sp := newSpoke(t, nil, "Phone")
	pr, err := sp.Probe("127.0.0.1", h.cfg.Port)
	if err != nil {
		t.Fatal(err)
	}
	if pr.Words != info.Words || pr.Words == "" {
		t.Fatalf("words differ: phone %q pc %q", pr.Words, info.Words)
	}
	code := strings.ToLower(info.Code) // people type lowercase and keep the dash
	if _, err := sp.Pair(PairRequest{Host: "127.0.0.1", Port: h.cfg.Port, Code: code, FP: pr.FP}); err != nil {
		t.Fatal(err)
	}
	if _, err := sp.SyncNow(); err != nil {
		t.Fatal(err)
	}
}

func TestPairingTokenSingleUseAndExpiry(t *testing.T) {
	h, _ := startHub(t, nil)
	qr := qrFor(t, h)
	a := newSpoke(t, nil, "A")
	if _, err := a.Pair(PairRequest{QR: qr}); err != nil {
		t.Fatal(err)
	}
	b := newSpoke(t, nil, "B")
	if _, err := b.Pair(PairRequest{QR: qr}); err == nil {
		t.Fatal("reused pairing token was accepted")
	}
	// expired window
	qr = qrFor(t, h)
	h.mu.Lock()
	h.pair.exp = time.Now().Add(-time.Second)
	h.mu.Unlock()
	if _, err := b.Pair(PairRequest{QR: qr}); err == nil {
		t.Fatal("expired pairing token was accepted")
	}
}

func TestFiveWrongCodesClosePairing(t *testing.T) {
	h, _ := startHub(t, nil)
	if _, err := h.OpenPairing(); err != nil {
		t.Fatal(err)
	}
	sp := newSpoke(t, nil, "X")
	pr, _ := sp.Probe("127.0.0.1", h.cfg.Port)
	var last error
	for i := 0; i < 5; i++ {
		_, last = sp.Pair(PairRequest{Host: "127.0.0.1", Port: h.cfg.Port, Code: "ZZZZ-ZZZZ", FP: pr.FP})
	}
	if last == nil || !strings.Contains(last.Error(), "too many") {
		t.Fatalf("expected the window to close, got %v", last)
	}
	if h.Status()["pairing"].(bool) {
		t.Fatal("pairing window still open")
	}
}

func TestWrongCertificateRejected(t *testing.T) {
	h, _ := startHub(t, nil)
	var q map[string]any
	_ = json.Unmarshal([]byte(qrFor(t, h)), &q)
	q["cert"] = "sha256:" + strings.Repeat("AB", 32)
	b, _ := json.Marshal(q)
	sp := newSpoke(t, nil, "Evil twin test")
	_, err := sp.Pair(PairRequest{QR: string(b)})
	if err == nil || err != ErrPinMismatch {
		t.Fatalf("expected pin mismatch, got %v", err)
	}
}

func TestRevokedTokenRejected(t *testing.T) {
	h, _ := startHub(t, nil)
	sp := newSpoke(t, nil, "P")
	if _, err := sp.Pair(PairRequest{QR: qrFor(t, h)}); err != nil {
		t.Fatal(err)
	}
	if !h.Revoke(sp.Store.DeviceID) {
		t.Fatal("revoke failed")
	}
	if _, err := sp.SyncNow(); err == nil || !strings.Contains(err.Error(), "pair again") {
		t.Fatalf("revoked phone could still sync: %v", err)
	}
}

func TestPublicSourceRefused(t *testing.T) {
	h, _ := startHub(t, nil)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/v1/hello", nil)
	req.RemoteAddr = "8.8.8.8:5555"
	h.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("public source got %d", rr.Code)
	}
	req.RemoteAddr = "192.168.1.30:5555"
	rr = httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("LAN source got %d", rr.Code)
	}
}

func TestPhoneCannotForgeHubEvents(t *testing.T) {
	h, hst := startHub(t, nil)
	sp := newSpoke(t, nil, "P")
	if _, err := sp.Pair(PairRequest{QR: qrFor(t, h)}); err != nil {
		t.Fatal(err)
	}
	forged := store.Event{ID: "01JFORGEDFORGEDFORGEDFORGE", Dev: hst.DeviceID, Seq: 999, HLC: "2026-11-21T22:41:07.123Z/0004", Type: "review", Body: json.RawMessage(`{}`)}
	c := pinnedClient(sp.cfg.FP, nil, 5*time.Second)
	err := doJSON(c, "POST", baseURL("127.0.0.1", sp.cfg.Port)+"/v1/sync/push", sp.headers(sp.cfg), pushReq{Events: []store.Event{forged}}, nil)
	if err == nil {
		t.Fatal("forged hub event accepted")
	}
}

// Property test: two phones and the PC study offline at random, then sync in a
// random order with tiny batches. Everyone must end with the same events.
func TestRandomOfflineActivityConverges(t *testing.T) {
	for seed := int64(1); seed <= 5; seed++ {
		rng := rand.New(rand.NewSource(seed))
		h, hst := startHub(t, nil)
		a, b := newSpoke(t, nil, "A"), newSpoke(t, nil, "B")
		for _, s := range []*Spoke{a, b} {
			if _, err := s.Pair(PairRequest{QR: qrFor(t, h)}); err != nil {
				t.Fatal(err)
			}
		}
		stores := []*store.Store{hst, a.Store, b.Store}
		for round := 0; round < 12; round++ {
			addEvents(t, stores[rng.Intn(3)], 1+rng.Intn(40), fmt.Sprintf("r%d", round))
			if rng.Intn(2) == 0 {
				s := []*Spoke{a, b}[rng.Intn(2)]
				if _, err := s.SyncNow(); err != nil {
					t.Fatal(err)
				}
			}
		}
		// final rounds: A, B, A brings everyone level
		for _, s := range []*Spoke{a, b, a} {
			if _, err := s.SyncNow(); err != nil {
				t.Fatal(err)
			}
		}
		want := strings.Join(ids(hst), ",")
		if strings.Join(ids(a.Store), ",") != want || strings.Join(ids(b.Store), ",") != want {
			t.Fatalf("seed %d: devices diverged", seed)
		}
		// same replay order everywhere
		order := func(st *store.Store) string {
			evs := st.Events()
			store.SortEvents(evs)
			var o []string
			for _, e := range evs {
				o = append(o, e.ID)
			}
			return strings.Join(o, ",")
		}
		if order(hst) != order(a.Store) || order(a.Store) != order(b.Store) {
			t.Fatalf("seed %d: replay order differs", seed)
		}
	}
}

func TestMDNSAnswerParses(t *testing.T) {
	m := newMDNS("DESKTOP-1", "01JD3X0Q8W9W3C1A9V6K0Y4ZQH", 47431, []string{"v=1", "id=01JD3X0Q8W9W3C1A9V6K0Y4ZQH"})
	msg := m.answer(net.IPv4(192, 168, 1, 20), 0)
	name, _, ok := readName(msg, 12)
	if !ok || name != "_fortitatake._tcp.local" {
		t.Fatalf("bad PTR owner %q", name)
	}
	// a PTR query for our service is wanted
	q := []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	q = putName(q, "_fortitatake._tcp.local")
	q = append(q, 0, typePTR, 0, 1)
	if !m.wanted(q) {
		t.Fatal("PTR query not recognized")
	}
	_ = os.Getenv
	_ = filepath.Join
}
