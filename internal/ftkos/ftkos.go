// Package ftkos runs FortiTatake OS from the app: it drives the build in WSL2 (on the
// PC), signs and packs the results, boots them in QEMU, talks to the lab agent, and
// writes the stage 0 report.
package ftkos

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Event is one line of progress for the engine screen.
type Event struct {
	Seq  int            `json:"seq"`
	T    float64        `json:"t"`
	Ev   string         `json:"ev"`
	Data map[string]any `json:"data,omitempty"`
	Line string         `json:"line,omitempty"`
}

// Manager owns the engine's state. One job (setup, build or test) runs at a time.
type Manager struct {
	Dir     string // <data>/ftkos
	Assets  fs.FS  // build tree, driver and agent binaries (PC only)
	Version string
	ExeDir  string

	labMu   sync.Mutex
	lab     *VM
	labUsed time.Time

	mu     sync.Mutex
	events []Event
	seq    int
	job    *job
}

type job struct {
	kind    string
	started time.Time
	cancel  func()
	done    bool
	err     string
}

// New prepares the engine folder.
func New(dataDir string, assets fs.FS, version string) *Manager {
	m := &Manager{Dir: filepath.Join(dataDir, "ftkos"), Assets: assets, Version: version}
	if exe, err := os.Executable(); err == nil {
		m.ExeDir = filepath.Dir(exe)
	}
	os.MkdirAll(m.Dir, 0755)
	// A phone tells the PC its CPU on the next sync, so the PC can build a tuned ARM64 OS.
	if runtime.GOOS == "android" {
		if _, err := os.Stat(filepath.Join(m.Dir, "phone-report.json")); err != nil {
			b, _ := json.MarshalIndent(map[string]any{"device": deviceInfo(), "app": version}, "", " ")
			os.WriteFile(filepath.Join(m.Dir, "phone-report.json"), b, 0644)
		}
	}
	// Development aid: replay a saved driver log into the screen.
	if p := os.Getenv("FTK_ENGINE_REPLAY"); p != "" {
		if f, err := os.Open(p); err == nil {
			go func() { defer f.Close(); m.pipeEvents(f, nil) }()
		}
	}
	return m
}

// Emit lets other parts of the app (sync) add events to the engine screen.
func (m *Manager) Emit(ev string, data map[string]any) { m.emit(ev, data) }

func (m *Manager) emit(ev string, data map[string]any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	m.events = append(m.events, Event{Seq: m.seq, T: float64(time.Now().UnixMilli()) / 1000, Ev: ev, Data: data})
	m.trim()
}

func (m *Manager) logLine(line string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	m.events = append(m.events, Event{Seq: m.seq, T: float64(time.Now().UnixMilli()) / 1000, Ev: "log", Line: line})
	m.trim()
}

func (m *Manager) trim() {
	if len(m.events) > 6000 {
		m.events = append([]Event(nil), m.events[len(m.events)-4000:]...)
	}
}

// pipeEvents reads a driver's stdout: "FTK {json}" lines are events, the rest is log.
func (m *Manager) pipeEvents(r io.Reader, onEvent func(map[string]any)) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 4<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.HasPrefix(line, "FTK ") {
			var d map[string]any
			if json.Unmarshal([]byte(line[4:]), &d) == nil {
				ev, _ := d["ev"].(string)
				delete(d, "ev")
				delete(d, "t")
				m.emit(ev, d)
				if onEvent != nil {
					onEvent(map[string]any{"ev": ev, "data": d})
				}
				continue
			}
		}
		m.logLine(line)
	}
}

// startJob runs f in the background unless another job is running.
func (m *Manager) startJob(kind string, f func(j *job) error) error {
	m.mu.Lock()
	if m.job != nil && !m.job.done {
		m.mu.Unlock()
		return fmt.Errorf("%s is already running", m.job.kind)
	}
	j := &job{kind: kind, started: time.Now()}
	m.job = j
	m.mu.Unlock()
	m.emit("job", map[string]any{"kind": kind, "state": "start"})
	go func() {
		err := f(j)
		m.mu.Lock()
		j.done = true
		if err != nil {
			j.err = err.Error()
		}
		m.mu.Unlock()
		st := map[string]any{"kind": kind, "state": "done", "seconds": int(time.Since(j.started).Seconds())}
		if err != nil {
			st["state"], st["error"] = "failed", err.Error()
		}
		m.emit("job", st)
	}()
	return nil
}

func (m *Manager) stopJob() {
	m.mu.Lock()
	j := m.job
	m.mu.Unlock()
	if j != nil && !j.done && j.cancel != nil {
		j.cancel()
	}
}

// ---------------------------------------------------------------- signing and bundles

func (m *Manager) signingKey() (ed25519.PrivateKey, error) {
	p := filepath.Join(m.Dir, "signing.key")
	if b, err := os.ReadFile(p); err == nil && len(b) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(b), nil
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(p, priv, 0600); err != nil {
		return nil, err
	}
	os.WriteFile(filepath.Join(m.Dir, "signing.pub"), pub, 0644)
	return priv, nil
}

// Manifest describes one signed build.
type Manifest struct {
	Format    int                       `json:"format"`
	App       string                    `json:"app"`
	Arch      string                    `json:"arch"`
	Variant   string                    `json:"variant"`
	Opt       string                    `json:"opt,omitempty"`
	BuildID   string                    `json:"build_id"`
	Created   string                    `json:"created"`
	Kernel    string                    `json:"kernel"`
	Cmdline   string                    `json:"cmdline"`
	Files     map[string]map[string]any `json:"files"`
	BuildInfo map[string]any            `json:"build_info,omitempty"`
}

func cmdlineFor(arch string) string {
	con := "ttyS0"
	if arch == "aarch64" {
		con = "ttyAMA0"
	}
	return "console=" + con + " root=/dev/vda ro rootfstype=erofs panic=-1 quiet"
}

// seal writes manifest.json and manifest.sig next to a finished build.
func (m *Manager) seal(dir string) (*Manifest, error) {
	var bi map[string]any
	b, err := os.ReadFile(filepath.Join(dir, "build-info.json"))
	if err != nil {
		return nil, err
	}
	json.Unmarshal(b, &bi)
	mf := &Manifest{Format: 1, App: m.Version, Created: time.Now().UTC().Format(time.RFC3339), Files: map[string]map[string]any{}, BuildInfo: bi}
	mf.Arch, _ = bi["arch"].(string)
	mf.Variant, _ = bi["variant"].(string)
	mf.Opt, _ = bi["opt"].(string)
	mf.BuildID, _ = bi["build_id"].(string)
	mf.Kernel, _ = bi["kernel_version"].(string)
	mf.Cmdline = cmdlineFor(mf.Arch)
	for _, f := range []string{"kernel", "rootfs.erofs"} {
		sum, n, err := sha256File(filepath.Join(dir, f))
		if err != nil {
			return nil, err
		}
		mf.Files[f] = map[string]any{"sha256": sum, "bytes": n}
	}
	key, err := m.signingKey()
	if err != nil {
		return nil, err
	}
	body, _ := json.MarshalIndent(mf, "", " ")
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), body, 0644); err != nil {
		return nil, err
	}
	sig := ed25519.Sign(key, body)
	return mf, os.WriteFile(filepath.Join(dir, "manifest.sig"), sig, 0644)
}

// Verify checks a build folder against its manifest and a public key.
func Verify(dir string, pub ed25519.PublicKey) (*Manifest, error) {
	body, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	sig, err := os.ReadFile(filepath.Join(dir, "manifest.sig"))
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(pub, body, sig) {
		return nil, errors.New("signature does not match")
	}
	var mf Manifest
	if err := json.Unmarshal(body, &mf); err != nil {
		return nil, err
	}
	for f, meta := range mf.Files {
		sum, _, err := sha256File(filepath.Join(dir, f))
		if err != nil || sum != meta["sha256"] {
			return nil, fmt.Errorf("%s does not match its manifest", f)
		}
	}
	return &mf, nil
}

// Builds lists the sealed builds on this device.
func (m *Manager) Builds() []map[string]any {
	var out []map[string]any
	dirs, _ := filepath.Glob(filepath.Join(m.Dir, "builds", "*"))
	sort.Strings(dirs)
	for _, d := range dirs {
		b, err := os.ReadFile(filepath.Join(d, "manifest.json"))
		if err != nil {
			continue
		}
		var mf Manifest
		if json.Unmarshal(b, &mf) != nil {
			continue
		}
		var size int64
		for _, f := range mf.Files {
			if n, ok := f["bytes"].(float64); ok {
				size += int64(n)
			}
		}
		row := map[string]any{"id": filepath.Base(d), "arch": mf.Arch, "variant": mf.Variant, "opt": mf.Opt,
			"created": mf.Created, "bytes": size, "kernel": mf.Kernel, "seconds": mf.BuildInfo["seconds"]}
		if c := m.bootCandidates(mf.Arch); len(c) > 0 && c[0] == d && mf.Arch == hostArch() {
			row["in_use"] = true
		} else if mf.Arch == hostArch() {
			row["unused"] = true
		}
		if bf, err := os.ReadFile(filepath.Join(d, "boot-failed")); err == nil {
			row["boot_failed"] = strings.TrimSpace(string(bf))
		}
		out = append(out, row)
	}
	return out
}

var buildIDok = regexp.MustCompile(`^(x86_64|aarch64)-(generic|tuned)$`)

// deleteBuild removes one OS build from this device (POST engine/build/delete {"id": …}).
// The lab VM is stopped first so Windows doesn't hold its files open.
func (m *Manager) deleteBuild(id string) error {
	if !buildIDok.MatchString(id) {
		return errors.New("no such build")
	}
	d := filepath.Join(m.Dir, "builds", id)
	if !fileExists(d) {
		return errors.New("no such build")
	}
	m.mu.Lock()
	busy := m.job != nil && !m.job.done
	m.mu.Unlock()
	if busy {
		return errors.New("a build or test is running: stop it first")
	}
	m.labStop()
	var err error
	for i := 0; i < 10; i++ { // QEMU can take a moment to let go of the files
		if err = os.RemoveAll(d); err == nil {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if err != nil {
		return fmt.Errorf("couldn't delete %s: %v", id, err)
	}
	// forget its build report too
	rp := filepath.Join(m.Dir, "report.json")
	if b, e := os.ReadFile(rp); e == nil {
		var rep map[string]any
		if json.Unmarshal(b, &rep) == nil {
			delete(rep, "build."+id)
			if nb, e := json.MarshalIndent(rep, "", " "); e == nil {
				os.WriteFile(rp, nb, 0644)
			}
		}
	}
	m.emit("build_deleted", map[string]any{"id": id})
	return nil
}

// pickBuild returns the build folder for this device's architecture, tuned first.
func (m *Manager) pickBuild(arch string) string {
	if c := m.bootCandidates(arch); len(c) > 0 {
		return c[0]
	}
	for _, v := range []string{"tuned", "generic"} {
		d := filepath.Join(m.Dir, "builds", arch+"-"+v)
		if _, err := os.Stat(filepath.Join(d, "manifest.json")); err == nil {
			return d
		}
	}
	return ""
}

func hostArch() string {
	if runtime.GOARCH == "arm64" {
		return "aarch64"
	}
	return "x86_64"
}

// ---------------------------------------------------------------- HTTP API

// API serves /api/engine/<sub>.
func (m *Manager) API(w http.ResponseWriter, r *http.Request, sub string) {
	post := r.Method == http.MethodPost
	bad := func(code int, err error) { writeJSON(w, code, map[string]string{"error": err.Error()}) }
	switch {
	case sub == "feeds":
		m.feedsAPI(w, r)
	case sub == "status" && !post:
		writeJSON(w, 200, m.status())
	case sub == "events" && !post:
		since, _ := strconv.Atoi(r.URL.Query().Get("since"))
		m.mu.Lock()
		var out []Event
		for _, e := range m.events {
			if e.Seq > since {
				out = append(out, e)
			}
		}
		seq := m.seq
		m.mu.Unlock()
		if len(out) > 1500 {
			out = out[len(out)-1500:]
		}
		writeJSON(w, 200, map[string]any{"events": out, "seq": seq})
	case sub == "setup" && post:
		if err := m.startJob("setup", m.setupJob); err != nil {
			bad(409, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"started": true})
	case sub == "build" && post:
		var in struct{ Arch, Variant string }
		json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in)
		if in.Arch != "x86_64" && in.Arch != "aarch64" {
			bad(400, errors.New("arch must be x86_64 or aarch64"))
			return
		}
		// PC builds are always generic: the VM sees QEMU's CPU model, so tuning for the host gains nothing.
		if in.Variant != "tuned" || in.Arch == "x86_64" {
			in.Variant = "generic"
		}
		if err := m.startJob("build", func(j *job) error { return m.buildJob(j, in.Arch, in.Variant) }); err != nil {
			bad(409, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"started": true})
	case sub == "test" && post:
		if err := m.startJob("test", m.testJob); err != nil {
			bad(409, err)
			return
		}
		writeJSON(w, 200, map[string]bool{"started": true})
	case sub == "stop" && post:
		m.stopJob()
		writeJSON(w, 200, map[string]bool{"stopping": true})
	case sub == "build/delete" && post:
		var in struct {
			ID string `json:"id"`
		}
		json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in)
		if err := m.deleteBuild(in.ID); err != nil {
			writeJSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"deleted": in.ID})
	case sub == "lab/call" && post:
		m.labCall(w, r)
	case sub == "lab/stop" && post:
		m.labStop()
		writeJSON(w, 200, map[string]bool{"stopped": true})
	case sub == "report" && !post:
		b, err := os.ReadFile(filepath.Join(m.Dir, "report.json"))
		if err != nil {
			writeJSON(w, 200, map[string]any{})
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Write(b)
	default:
		writeJSON(w, 404, map[string]string{"error": "unknown engine endpoint"})
	}
}

func (m *Manager) status() map[string]any {
	m.mu.Lock()
	var j map[string]any
	if m.job != nil {
		j = map[string]any{"kind": m.job.kind, "done": m.job.done, "error": m.job.err, "seconds": int(time.Since(m.job.started).Seconds())}
	}
	seq := m.seq
	m.mu.Unlock()
	st := map[string]any{
		"platform": runtime.GOOS, "arch": hostArch(), "can_build": canBuild(), "job": j, "seq": seq,
		"builds": m.Builds(), "dir": m.Dir, "runner": m.runnerInfo(), "lab": m.labInfo(),
	}
	if canBuild() {
		st["builder"] = m.builderInfo()
	}
	return st
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// SealForTest signs a build folder (development tools only).
func (m *Manager) SealForTest(dir string) error { _, err := m.seal(dir); return err }
