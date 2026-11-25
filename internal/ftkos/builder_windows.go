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
	hostCPU  map[string]any
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
	if hostCPU == nil {
		hostCPU = deviceInfo()
	}
	infoLast = map[string]any{"wsl": err == nil, "distro": c.Distro, "exists": has, "ready": has && c.Ready, "cpus": runtime.NumCPU(),
		"cpu": hostCPU["cpu"], "ram_bytes": hostCPU["ram_bytes"]}
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

// runOut is runLogged that also returns what wsl.exe said.
func (m *Manager) runOut(ctx context.Context, args ...string) (string, error) {
	c := wslCmd(ctx, args...)
	b, err := c.CombinedOutput()
	out := decodeWSL(b)
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			m.logLine(l)
		}
	}
	return out, err
}

// a failed import can leave a half-registered distro behind
func wslListClear(ctx context.Context) {
	if ds, _ := listDistros(); slicesContains(ds, builderDistro) {
		wslCmd(ctx, "--unregister", builderDistro).Run()
	}
}

func slicesContains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// WSL 2 needs Windows features that only an administrator can turn on. The app runs as you,
// so it asks Windows for permission (the UAC prompt) to run that one command, then asks for
// a restart.
func (m *Manager) wslMissingParts(ctx context.Context, out string, err error) error {
	low := strings.ToLower(out)
	missing := strings.Contains(low, "virtual machine platform") || strings.Contains(low, "wsl 2") || strings.Contains(low, "wsl2") ||
		strings.Contains(low, "0x80370102") || strings.Contains(low, "hcs_e") || strings.Contains(low, "virtualization") ||
		strings.Contains(low, "elevation") || strings.Contains(low, "optional component") || strings.Contains(low, "wsl_e_wsl2_needed")
	last := ""
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			last = l
		}
	}
	if !missing {
		return fmt.Errorf("WSL couldn't create the builder: %s (%v)", last, err)
	}
	m.emit("step", map[string]any{"label": "WSL 2 needs Windows features turned on: approve the Windows prompt"})
	// One prompt for everything: WSL 2 (Virtual Machine Platform) for the builder, and Windows
	// Hypervisor Platform so the lab VM runs on hardware virtualization instead of emulation.
	m.logLine("Asking Windows for administrator permission to turn on Virtual Machine Platform, WSL and Windows Hypervisor Platform")
	script := `wsl.exe --install --no-distribution; $a = $LASTEXITCODE; ` +
		`dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart | Out-Null; ` +
		`dism.exe /online /enable-feature /featurename:HypervisorPlatform /all /norestart | Out-Null; ` +
		`if ($LASTEXITCODE -eq 3010) { exit 0 } else { exit $LASTEXITCODE }`
	res := powershell(`try { $p = Start-Process -FilePath powershell.exe -ArgumentList '-NoProfile','-Command','` + strings.ReplaceAll(script, "'", "''") + `' -Verb RunAs -Wait -PassThru -WindowStyle Hidden; "exit:" + $p.ExitCode } catch { "declined" }`)
	m.logLine("Elevated install: " + res)
	switch {
	case res == "declined":
		return errors.New("WSL 2 is missing parts that need administrator permission, and the Windows prompt was declined. Press Set up again and choose Yes")
	case res == "exit:0" || res == "exit:3010":
		return errors.New("Virtual Machine Platform and Windows Hypervisor Platform are now turned on. Restart Windows, then press Set up again (the Ubuntu download is kept)")
	}
	return fmt.Errorf("WSL couldn't create the builder: %s. Turning on WSL 2's features also failed (%s); check that virtualization (SVM on your Ryzen) is enabled in the BIOS", last, res)
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
		// Import our own Ubuntu instead of `wsl --install`: works on every WSL 2 version,
		// needs no Microsoft Store and no administrator, and lets us name the distro.
		c.Distro = builderDistro
		tar, err := m.fetchUbuntu(ctx)
		if err != nil {
			return err
		}
		m.emit("step", map[string]any{"label": "Creating " + builderDistro + " (Ubuntu 24.04)"})
		home := filepath.Join(m.Dir, "builder", "distro")
		os.MkdirAll(home, 0755)
		out, err := m.runOut(ctx, "--import", builderDistro, home, tar, "--version", "2")
		if err != nil {
			wslListClear(ctx)
			return m.wslMissingParts(ctx, out, err)
		}
		os.Remove(tar) // 340 MB we don't need any more
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

// Ubuntu's own WSL image (Canonical's cloud-images), checked against its SHA256SUMS.
const ubuntuWSL = "https://cloud-images.ubuntu.com/wsl/releases/noble/current/"
const ubuntuFile = "ubuntu-noble-wsl-amd64-wsl.rootfs.tar.gz"

func (m *Manager) fetchUbuntu(ctx context.Context) (string, error) {
	dir := filepath.Join(m.Dir, "builder")
	os.MkdirAll(dir, 0755)
	dst := filepath.Join(dir, ubuntuFile)
	sums, err := httpGetSmall(ctx, ubuntuWSL+"SHA256SUMS")
	if err != nil {
		return "", fmt.Errorf("can't reach cloud-images.ubuntu.com to download Ubuntu: %v", err)
	}
	want := ""
	for _, l := range strings.Split(sums, "\n") {
		if f := strings.Fields(l); len(f) == 2 && strings.TrimPrefix(f[1], "*") == ubuntuFile {
			want = f[0]
		}
	}
	if want == "" {
		return "", errors.New("Ubuntu's checksum list doesn't name the WSL image")
	}
	if sum, _, _ := sha256File(dst); sum == want {
		return dst, nil
	}
	m.emit("step", map[string]any{"label": "Downloading Ubuntu 24.04 for WSL (340 MB, resumes if interrupted)"})
	if err := m.download(ctx, ubuntuWSL+ubuntuFile, dst); err != nil {
		return "", fmt.Errorf("Ubuntu download: %v", err)
	}
	if sum, _, _ := sha256File(dst); sum != want {
		os.Remove(dst)
		return "", errors.New("the Ubuntu download is corrupt (checksum mismatch); press Set up again")
	}
	return dst, nil
}
