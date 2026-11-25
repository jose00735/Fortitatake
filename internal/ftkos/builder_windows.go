//go:build windows

package ftkos

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

const builderDistro = "FortiTatake-Builder"

func canBuild() bool { return true }

func wslCmd(ctx context.Context, args ...string) *exec.Cmd {
	c := exec.CommandContext(ctx, "wsl.exe", args...)
	hideWindow(c)
	return c
}

// wsl.exe prints its own messages in UTF-16LE; output from Linux commands is UTF-8.
func decodeWSL(b []byte) string {
	if len(b) >= 2 && b[1] == 0 {
		u := make([]uint16, len(b)/2)
		for i := range u {
			u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
		}
		return strings.ReplaceAll(string(utf16.Decode(u)), "\x00", "")
	}
	return string(b)
}

func listDistros() ([]string, error) {
	out, err := wslCmd(context.Background(), "--list", "--quiet").Output()
	if err != nil {
		return nil, err
	}
	var ds []string
	for _, l := range strings.Split(decodeWSL(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			ds = append(ds, l)
		}
	}
	return ds, nil
}

type builderCfg struct {
	Distro string `json:"distro"`
	Ready  bool   `json:"ready"`
}

func (m *Manager) builderCfg() builderCfg {
	c := builderCfg{Distro: builderDistro}
	if b, err := os.ReadFile(filepath.Join(m.Dir, "builder.json")); err == nil {
		json.Unmarshal(b, &c)
	}
	return c
}

func (m *Manager) saveBuilderCfg(c builderCfg) {
	b, _ := json.Marshal(c)
	os.WriteFile(filepath.Join(m.Dir, "builder.json"), b, 0644)
}

var (
	infoMu   sync.Mutex
	infoAt   time.Time
	infoLast map[string]any
)

func (m *Manager) builderInfo() map[string]any {
	infoMu.Lock()
	defer infoMu.Unlock()
	if time.Since(infoAt) < 8*time.Second && infoLast != nil {
		return infoLast
	}
	c := m.builderCfg()
	ds, err := listDistros()
	has := false
	for _, d := range ds {
		has = has || d == c.Distro
	}
	infoLast = map[string]any{"wsl": err == nil, "distro": c.Distro, "exists": has, "ready": has && c.Ready, "cpus": runtime.NumCPU()}
	infoAt = time.Now()
	return infoLast
}

func (m *Manager) wslPath(ctx context.Context, distro, win string) (string, error) {
	out, err := wslCmd(ctx, "-d", distro, "-u", "root", "--", "wslpath", "-u", win).Output()
	if err != nil {
		return "", fmt.Errorf("wslpath: %v", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func (m *Manager) runLogged(ctx context.Context, args ...string) error {
	c := wslCmd(ctx, args...)
	out, err := c.CombinedOutput()
	for _, l := range strings.Split(decodeWSL(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			m.logLine(l)
		}
	}
	return err
}

func (m *Manager) setupJob(j *job) error {
	ctx, cancel := context.WithCancel(context.Background())
	j.cancel = cancel
	defer cancel()
	m.emit("phase", map[string]any{"phase": "setup", "state": "start", "label": "Preparing the builder"})
	if err := wslCmd(ctx, "--status").Run(); err != nil {
		return errors.New("WSL isn't installed. Open PowerShell as administrator, run: wsl --install --no-distribution, restart Windows, then press Set up again")
	}
	c := m.builderCfg()
	ds, _ := listDistros()
	has := false
	for _, d := range ds {
		has = has || d == c.Distro
	}
	if !has {
		m.emit("step", map[string]any{"label": "Installing Ubuntu 24.04 as " + builderDistro + " (a few minutes)"})
		if err := m.runLogged(ctx, "--install", "Ubuntu-24.04", "--name", builderDistro, "--no-launch"); err != nil {
			// Older WSL without --name: install Ubuntu-24.04 under its own name.
			m.emit("step", map[string]any{"label": "This WSL can't name distros; using Ubuntu-24.04"})
			if err2 := m.runLogged(ctx, "--install", "-d", "Ubuntu-24.04", "--no-launch"); err2 != nil {
				return fmt.Errorf("could not install Ubuntu in WSL: %v", err2)
			}
			c.Distro = "Ubuntu-24.04"
		}
		m.saveBuilderCfg(c)
	}
	src, err := m.extractAssets()
	if err != nil {
		return err
	}
	wsrc, err := m.wslPath(ctx, c.Distro, src)
	if err != nil {
		return err
	}
	m.emit("step", map[string]any{"label": "Installing build tools inside Linux"})
	cmd := wslCmd(ctx, "-d", c.Distro, "-u", "root", "--", "python3", wsrc+"/builder/ftkbuild.py", "setup")
	if err := m.pipeRun(cmd); err != nil {
		return fmt.Errorf("builder setup failed: %v", err)
	}
	m.runLogged(ctx, "--terminate", c.Distro)
	c.Ready = true
	m.saveBuilderCfg(c)
	infoMu.Lock()
	infoLast = nil
	infoMu.Unlock()
	m.emit("phase", map[string]any{"phase": "setup", "state": "done", "label": "Builder ready"})
	return nil
}

func (m *Manager) pipeRun(cmd *exec.Cmd) error {
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return err
	}
	m.pipeEvents(out, nil)
	return cmd.Wait()
}

func (m *Manager) buildJob(j *job, arch, variant string) error {
	ctx, cancel := context.WithCancel(context.Background())
	c := m.builderCfg()
	j.cancel = func() {
		cancel()
		// wsl.exe going away doesn't stop Linux processes: stop the build explicitly.
		wslCmd(context.Background(), "-d", c.Distro, "-u", "root", "--", "pkill", "-f", "ftkbuild.py|make -C").Run()
	}
	defer cancel()
	if !c.Ready {
		return errors.New("set up the builder first")
	}
	opt := ""
	if variant == "tuned" {
		if arch == "x86_64" {
			opt = "-march=native" // the build runs on the same CPU that will run it
		} else {
			o, err := m.phoneTuning()
			if err != nil {
				return err
			}
			opt = o
		}
	}
	src, err := m.extractAssets()
	if err != nil {
		return err
	}
	agent := filepath.Join(src, "bin", "ftk-agent-"+arch)
	if _, err := os.Stat(agent); err != nil {
		return fmt.Errorf("agent for %s missing from this copy", arch)
	}
	out := filepath.Join(m.Dir, "builds", arch+"-"+variant)
	os.MkdirAll(out, 0755)
	os.Remove(filepath.Join(out, "manifest.json"))
	os.Remove(filepath.Join(out, "manifest.sig"))
	var wsrc, wout string
	if wsrc, err = m.wslPath(ctx, c.Distro, src); err != nil {
		return err
	}
	if wout, err = m.wslPath(ctx, c.Distro, out); err != nil {
		return err
	}
	id := fmt.Sprintf("%s-%s-%s", m.Version, arch, time.Now().Format("20060102-1504"))
	m.emit("build", map[string]any{"arch": arch, "variant": variant, "opt": opt, "jobs": runtime.NumCPU(), "id": id})
	cmd := wslCmd(ctx, "-d", c.Distro, "-u", "ftk", "--cd", "~", "--", "python3", wsrc+"/builder/ftkbuild.py", "build",
		"--arch", arch, "--variant", variant, "--opt", opt, "--jobs", fmt.Sprint(runtime.NumCPU()),
		"--src", wsrc+"/buildroot-external", "--agent", wsrc+"/bin/ftk-agent-"+arch, "--out", wout, "--build-id", id)
	if err := m.pipeRun(cmd); err != nil {
		if ctx.Err() != nil {
			return errors.New("stopped; press Build again to resume where it stopped")
		}
		return fmt.Errorf("the build stopped: %v", err)
	}
	m.emit("phase", map[string]any{"phase": "sign", "state": "start", "label": "Signing"})
	mf, err := m.seal(out)
	if err != nil {
		return fmt.Errorf("signing: %v", err)
	}
	m.emit("phase", map[string]any{"phase": "sign", "state": "done", "label": "Signed"})
	m.emit("ready", map[string]any{"arch": arch, "variant": variant, "files": mf.Files})
	m.saveReport("build."+arch+"-"+variant, mf.BuildInfo)
	return nil
}
