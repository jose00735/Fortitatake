package ftsp

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// The PC offers a signed ARM64 build; the phone downloads it, verifies it, keeps it,
// resumes a half-finished file, refuses a tampered one, and reports its CPU back.
func TestOSBuildSync(t *testing.T) {
	h, _ := startHub(t, nil)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bd := filepath.Join(h.Dir, "ftkos", "builds", "aarch64-generic")
	os.MkdirAll(bd, 0755)
	kernel := make([]byte, 3<<20)
	rand.Read(kernel)
	rootfs := make([]byte, 5<<20)
	rand.Read(rootfs)
	os.WriteFile(filepath.Join(bd, "kernel"), kernel, 0644)
	os.WriteFile(filepath.Join(bd, "rootfs.erofs"), rootfs, 0644)
	hx := func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
	mf, _ := json.Marshal(map[string]any{"arch": "aarch64", "files": map[string]any{
		"kernel":       map[string]any{"sha256": hx(kernel), "bytes": len(kernel)},
		"rootfs.erofs": map[string]any{"sha256": hx(rootfs), "bytes": len(rootfs)}}})
	os.WriteFile(filepath.Join(bd, "manifest.json"), mf, 0644)
	os.WriteFile(filepath.Join(bd, "manifest.sig"), ed25519.Sign(priv, mf), 0644)
	os.WriteFile(filepath.Join(h.Dir, "ftkos", "signing.pub"), pub, 0644)

	var mu sync.Mutex
	var phases []string
	var outBytes int64
	h.OnOS = func(ev string, d map[string]any) {
		mu.Lock()
		defer mu.Unlock()
		if n, ok := d["done"].(int64); ok && ev == "sync" {
			outBytes = n
		}
	}
	sp := newSpoke(t, nil, "Phone")
	sp.OnOS = func(ev string, d map[string]any) {
		mu.Lock()
		defer mu.Unlock()
		if e, ok := d["error"]; ok {
			t.Log("os error:", e)
		}
		if p, ok := d["phase"].(string); ok && (len(phases) == 0 || phases[len(phases)-1] != p) {
			phases = append(phases, p)
		}
	}
	// a half-downloaded kernel from an interrupted sync
	inc := filepath.Join(sp.Dir, "ftkos", "incoming", "aarch64-generic")
	os.MkdirAll(inc, 0755)
	os.WriteFile(filepath.Join(inc, "kernel.part"), kernel[:1<<20], 0644)
	// the phone's report, waiting to go up
	os.WriteFile(filepath.Join(sp.Dir, "ftkos", "phone-report.json"), []byte(`{"device":{"cpu_parts":{"0xd87":4}}}`), 0644)

	if _, err := sp.Pair(PairRequest{QR: qrFor(t, h)}); err != nil {
		t.Fatal(err)
	}
	if _, err := sp.SyncNow(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(sp.Dir, "ftkos", "builds", "aarch64-generic", "rootfs.erofs"))
	if err != nil || hx(got) != hx(rootfs) {
		t.Fatalf("rootfs not delivered intact: %v", err)
	}
	if k, _ := os.ReadFile(filepath.Join(sp.Dir, "ftkos", "builds", "aarch64-generic", "kernel")); hx(k) != hx(kernel) {
		t.Fatal("resumed kernel is corrupt")
	}
	mu.Lock()
	t.Logf("phases %v, PC sent up to %d bytes", phases, outBytes)
	if len(phases) < 3 || phases[len(phases)-1] != "charged" {
		t.Fatalf("expected transfer → verify → charged, got %v", phases)
	}
	mu.Unlock()
	if b, err := os.ReadFile(filepath.Join(h.Dir, "ftkos", "phone-device.json")); err != nil || len(b) == 0 {
		t.Fatal("PC didn't receive the phone's CPU")
	}

	// a tampered build is refused and the good one stays
	mf2, _ := json.Marshal(map[string]any{"arch": "aarch64", "files": map[string]any{"kernel": map[string]any{"sha256": hx(kernel), "bytes": len(kernel)}}})
	os.WriteFile(filepath.Join(bd, "manifest.json"), mf2, 0644) // signature no longer matches
	phases = nil
	sp.SyncNow()
	if len(phases) == 0 || phases[len(phases)-1] != "failed" {
		t.Fatalf("tampered manifest should fail, got %v", phases)
	}
	if _, err := os.Stat(filepath.Join(sp.Dir, "ftkos", "builds", "aarch64-generic", "rootfs.erofs")); err != nil {
		t.Fatal("good build was lost")
	}
}
