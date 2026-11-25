package ftsp

// FortiTatake OS over sync: the PC offers its signed ARM64 builds, the phone downloads them
// in resumable pieces, checks the signature and every hash, and reports its CPU and test
// results back so the PC can tune the next build. Both sides can show the transfer as
// power flowing from the PC to the phone (OnOS).

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// OSBuild is one build the PC offers.
type OSBuild struct {
	ID       string `json:"id"`
	Manifest string `json:"manifest"` // base64 of manifest.json, exactly as signed
	Sig      string `json:"sig"`      // base64 of manifest.sig
	Pub      string `json:"pub"`      // base64 of the PC's signing key
}

type osFiles struct {
	Files map[string]struct {
		SHA256 string  `json:"sha256"`
		Bytes  float64 `json:"bytes"`
	} `json:"files"`
	Arch string `json:"arch"`
}

var osIDok = func(s string) bool {
	if s == "" || len(s) > 40 || strings.ContainsAny(s, `/\.`) {
		return false
	}
	return true
}

func osDir(dataDir string) string { return filepath.Join(dataDir, "ftkos") }

// ---------------------------------------------------------------- PC side

func (h *Hub) osList(w http.ResponseWriter, r *http.Request, _ *Device) {
	pub, _ := os.ReadFile(filepath.Join(osDir(h.Dir), "signing.pub"))
	var out []OSBuild
	dirs, _ := filepath.Glob(filepath.Join(osDir(h.Dir), "builds", "aarch64-*"))
	for _, d := range dirs {
		mf, err1 := os.ReadFile(filepath.Join(d, "manifest.json"))
		sig, err2 := os.ReadFile(filepath.Join(d, "manifest.sig"))
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, OSBuild{ID: filepath.Base(d), Manifest: base64.StdEncoding.EncodeToString(mf),
			Sig: base64.StdEncoding.EncodeToString(sig), Pub: base64.StdEncoding.EncodeToString(pub)})
	}
	writeJSON(w, 200, out)
}

type countingWriter struct {
	http.ResponseWriter
	n, total int64
	file     string
	last     time.Time
	emit     func(string, map[string]any)
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.ResponseWriter.Write(p)
	c.n += int64(n)
	if c.emit != nil && time.Since(c.last) > 250*time.Millisecond {
		c.last = time.Now()
		c.emit("sync", map[string]any{"dir": "out", "phase": "transfer", "file": c.file, "done": c.n, "total": c.total})
	}
	return n, err
}

func (h *Hub) osFile(w http.ResponseWriter, r *http.Request, _ *Device) {
	id, f := r.PathValue("id"), r.PathValue("file")
	if !osIDok(id) || (f != "kernel" && f != "rootfs.erofs") {
		fail(w, 404, "not_found", "no such build file")
		return
	}
	p := filepath.Join(osDir(h.Dir), "builds", id, f)
	st, err := os.Stat(p)
	if err != nil {
		fail(w, 404, "not_found", "no such build file")
		return
	}
	cw := &countingWriter{ResponseWriter: w, total: st.Size(), file: f, emit: h.OnOS}
	if rg := r.Header.Get("Range"); rg != "" {
		var from int64
		fmt.Sscanf(rg, "bytes=%d-", &from)
		cw.n = from
	}
	http.ServeFile(cw, r, p)
	if h.OnOS != nil {
		// the last event of every file says how it ended, so the PC's animation stops
		phase := "sent"
		if cw.n < cw.total {
			phase = "paused"
		}
		h.OnOS("sync", map[string]any{"dir": "out", "phase": phase, "file": f, "done": cw.n, "total": cw.total})
	}
}

// osReport receives the phone's device info and stage 0 result.
func (h *Hub) osReport(w http.ResponseWriter, r *http.Request, d *Device) {
	var in map[string]any
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
		fail(w, 400, "bad_request", "report is not valid JSON")
		return
	}
	dir := osDir(h.Dir)
	os.MkdirAll(dir, 0755)
	if dev, ok := in["device"]; ok {
		b, _ := json.MarshalIndent(dev, "", " ")
		os.WriteFile(filepath.Join(dir, "phone-device.json"), b, 0644)
	}
	rep := map[string]any{}
	if b, err := os.ReadFile(filepath.Join(dir, "report.json")); err == nil {
		json.Unmarshal(b, &rep)
	}
	rep["phone"] = in
	rep["phone_name"] = d.Name
	b, _ := json.MarshalIndent(rep, "", " ")
	os.WriteFile(filepath.Join(dir, "report.json"), b, 0644)
	if h.OnOS != nil {
		h.OnOS("phone_report", map[string]any{"device": d.Name})
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// ---------------------------------------------------------------- phone side

var osMu sync.Mutex

// syncOS downloads new ARM64 builds and posts the phone's report. Errors are reported
// through OnOS; they never fail the rest of the sync.
func (s *Spoke) syncOS(c *http.Client, base string, hdr map[string]string) {
	osMu.Lock()
	defer osMu.Unlock()
	emit := func(ev string, d map[string]any) {
		if s.OnOS != nil {
			s.OnOS(ev, d)
		}
	}
	dir := osDir(s.Dir)
	os.MkdirAll(dir, 0755)
	var builds []OSBuild
	if err := doJSON(c, "GET", base+"/v1/os", hdr, nil, &builds); err != nil {
		return // an older PC app: nothing to do
	}
	for _, b := range builds {
		if !osIDok(b.ID) {
			continue
		}
		if err := s.fetchBuild(c, base, hdr, dir, b, emit); err != nil {
			emit("sync", map[string]any{"dir": "in", "phase": "failed", "error": err.Error(), "build": b.ID})
		}
	}
	if rep, err := os.ReadFile(filepath.Join(dir, "phone-report.json")); err == nil {
		sum := sha256.Sum256(rep)
		mark := filepath.Join(dir, "phone-report.sent")
		if old, _ := os.ReadFile(mark); string(old) != hex.EncodeToString(sum[:]) {
			var v any
			if json.Unmarshal(rep, &v) == nil && doJSON(c, "POST", base+"/v1/os/report", hdr, v, nil) == nil {
				os.WriteFile(mark, []byte(hex.EncodeToString(sum[:])), 0644)
			}
		}
	}
}

func (s *Spoke) fetchBuild(c *http.Client, base string, hdr map[string]string, dir string, b OSBuild, emit func(string, map[string]any)) error {
	mf, err1 := base64.StdEncoding.DecodeString(b.Manifest)
	sig, err2 := base64.StdEncoding.DecodeString(b.Sig)
	pub, err3 := base64.StdEncoding.DecodeString(b.Pub)
	if err1 != nil || err2 != nil || err3 != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("the PC sent a malformed build offer")
	}
	// Trust on first use: the phone pins the PC's signing key the first time it sees one.
	pinned := filepath.Join(dir, "signing.pub")
	if old, err := os.ReadFile(pinned); err == nil {
		if !bytes.Equal(old, pub) {
			return errors.New("the PC's signing key changed; remove ftkos/signing.pub on the phone if you reinstalled the PC app")
		}
	} else {
		os.WriteFile(pinned, pub, 0644)
	}
	if !ed25519.Verify(pub, mf, sig) {
		return errors.New("the build's signature is invalid")
	}
	final := filepath.Join(dir, "builds", b.ID)
	if cur, err := os.ReadFile(filepath.Join(final, "manifest.json")); err == nil && bytes.Equal(cur, mf) {
		return nil // already have exactly this build
	}
	var files osFiles
	if err := json.Unmarshal(mf, &files); err != nil || files.Arch != "aarch64" {
		return errors.New("the build's manifest isn't an ARM64 build")
	}
	inc := filepath.Join(dir, "incoming", b.ID)
	os.MkdirAll(inc, 0755)
	var total, done int64
	for _, f := range files.Files {
		total += int64(f.Bytes)
	}
	emit("sync", map[string]any{"dir": "in", "phase": "transfer", "build": b.ID, "done": 0, "total": total})
	for name, meta := range files.Files {
		if name != "kernel" && name != "rootfs.erofs" {
			continue
		}
		dst := filepath.Join(inc, name)
		if sum, _ := fileSHA(dst); sum == meta.SHA256 {
			done += int64(meta.Bytes)
			continue
		}
		part := dst + ".part"
		have := int64(0)
		if st, err := os.Stat(part); err == nil {
			have = st.Size()
		}
		req, _ := http.NewRequest("GET", base+"/v1/os/"+b.ID+"/"+name, nil)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		if have > 0 {
			req.Header.Set("Range", "bytes="+strconv.FormatInt(have, 10)+"-")
		}
		resp, err := c.Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode != 200 && resp.StatusCode != 206 {
			resp.Body.Close()
			return fmt.Errorf("download %s: HTTP %d", name, resp.StatusCode)
		}
		flag := os.O_CREATE | os.O_WRONLY | os.O_APPEND
		if resp.StatusCode == 200 {
			flag = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
			have = 0
		}
		f, err := os.OpenFile(part, flag, 0644)
		if err != nil {
			resp.Body.Close()
			return err
		}
		buf := make([]byte, 256<<10)
		last := time.Now()
		for {
			n, rerr := resp.Body.Read(buf)
			if n > 0 {
				if _, werr := f.Write(buf[:n]); werr != nil {
					f.Close()
					resp.Body.Close()
					return werr
				}
				have += int64(n)
				if time.Since(last) > 250*time.Millisecond {
					last = time.Now()
					emit("sync", map[string]any{"dir": "in", "phase": "transfer", "build": b.ID, "file": name, "done": done + have, "total": total})
				}
			}
			if rerr == io.EOF {
				break
			}
			if rerr != nil {
				f.Close()
				resp.Body.Close()
				return fmt.Errorf("transfer interrupted; it resumes next sync (%v)", rerr)
			}
		}
		f.Close()
		resp.Body.Close()
		if sum, _ := fileSHA(part); sum != meta.SHA256 {
			os.Remove(part)
			return fmt.Errorf("%s doesn't match its signed hash; it will download again", name)
		}
		os.Rename(part, dst)
		done += int64(meta.Bytes)
	}
	emit("sync", map[string]any{"dir": "in", "phase": "verify", "build": b.ID, "done": total, "total": total})
	os.WriteFile(filepath.Join(inc, "manifest.json"), mf, 0644)
	os.WriteFile(filepath.Join(inc, "manifest.sig"), sig, 0644)
	os.MkdirAll(filepath.Dir(final), 0755)
	os.RemoveAll(final + ".old")
	os.Rename(final, final+".old")
	if err := os.Rename(inc, final); err != nil {
		os.Rename(final+".old", final)
		return err
	}
	os.RemoveAll(final + ".old")
	emit("sync", map[string]any{"dir": "in", "phase": "charged", "build": b.ID, "done": total, "total": total})
	return nil
}

func fileSHA(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
