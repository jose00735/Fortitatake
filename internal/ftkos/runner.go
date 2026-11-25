package ftkos

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

func sha256File(p string) (string, int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), n, err
}

// extractAssets copies the embedded build tree, driver and agents to <dir>/src.
func (m *Manager) extractAssets() (string, error) {
	if m.Assets == nil {
		return "", errors.New("this copy of FortiTatake has no build files")
	}
	dst := filepath.Join(m.Dir, "src")
	os.RemoveAll(dst)
	err := fs.WalkDir(m.Assets, "ftkos", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel := strings.TrimPrefix(p, "ftkos")
		out := filepath.Join(dst, filepath.FromSlash(rel))
		if d.IsDir() {
			return os.MkdirAll(out, 0755)
		}
		b, err := fs.ReadFile(m.Assets, p)
		if err != nil {
			return err
		}
		return os.WriteFile(out, b, 0644)
	})
	return dst, err
}

// ---------------------------------------------------------------- QEMU runner

func (m *Manager) qemuPath() string {
	name := "qemu-system-" + hostArch()
	if runtime.GOOS == "windows" {
		p := filepath.Join(m.ExeDir, "qemu", name+".exe")
		if _, err := os.Stat(p); err == nil {
			return p
		}
		return ""
	}
	if runtime.GOOS == "android" {
		p := filepath.Join(m.ExeDir, "libqemu.so") // shipped in the APK's native libraries
		if _, err := os.Stat(p); err == nil {
			return p
		}
		return ""
	}
	p, _ := exec.LookPath(name)
	return p
}

func (m *Manager) runnerInfo() map[string]any {
	return map[string]any{"qemu": m.qemuPath() != "", "build": filepath.Base(m.pickBuild(hostArch()))}
}

// VM is one running FortiTatake OS.
type VM struct {
	cmd    *exec.Cmd
	conn   net.Conn
	mu     sync.Mutex
	nextID int
	wait   map[int]chan map[string]any
	Accel  string
	Start  time.Time
	exited chan struct{}
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// qemuArgs builds the command line for one boot.
func qemuArgs(arch, build, accel string, port, memMB int) []string {
	a := []string{"-nodefaults", "-nographic", "-no-reboot", "-m", fmt.Sprint(memMB), "-smp", "2",
		"-kernel", filepath.Join(build, "kernel"), "-append", cmdlineFor(arch),
		"-drive", "if=none,id=root,format=raw,readonly=on,file=" + filepath.Join(build, "rootfs.erofs"),
		"-device", "virtio-blk-pci,drive=root",
		"-device", "virtio-serial-pci",
		"-chardev", fmt.Sprintf("socket,id=agent,host=127.0.0.1,port=%d,server=on,wait=off", port),
		"-device", "virtconsole,chardev=agent",
		"-device", "virtio-rng-pci",
		"-device", "virtio-balloon-pci,free-page-reporting=on",
		"-serial", "stdio",
	}
	if arch == "aarch64" {
		a = append([]string{"-machine", "virt,gic-version=3", "-cpu", "max"}, a...)
	} else {
		a = append([]string{"-machine", "q35"}, a...)
	}
	switch accel {
	case "whpx":
		a = append(a, "-accel", "whpx,kernel-irqchip=off")
	case "kvm":
		a = append(a, "-accel", "kvm", "-cpu", "host")
	default:
		a = append(a, "-accel", "tcg")
	}
	return a
}

// Boot starts QEMU with the best accelerator that works and connects to the agent.
func (m *Manager) Boot(ctx context.Context, memMB int) (*VM, error) {
	qemu := m.qemuPath()
	if qemu == "" {
		return nil, errors.New("QEMU isn't installed with this copy of FortiTatake")
	}
	arch := hostArch()
	cands := m.bootCandidates(arch)
	if len(cands) == 0 {
		return nil, fmt.Errorf("no FortiTatake OS build for %s yet: build it first", arch)
	}
	accels := []string{"tcg"}
	switch runtime.GOOS {
	case "windows":
		accels = []string{"whpx", "tcg"}
	case "linux":
		if _, err := os.Stat("/dev/kvm"); err == nil {
			accels = []string{"kvm", "tcg"}
		}
	}
	pub, _ := os.ReadFile(filepath.Join(m.Dir, "signing.pub"))
	var last error
	for bi, build := range cands {
		if len(pub) > 0 {
			if _, err := Verify(build, pub); err != nil {
				last = fmt.Errorf("build %s failed its seal check: %v", filepath.Base(build), err)
				continue
			}
		}
		for _, acc := range accels {
			vm, err := m.bootWith(ctx, qemu, arch, build, acc, memMB)
			if err == nil {
				return vm, nil
			}
			last = err
			if ctx.Err() != nil {
				return nil, err
			}
			m.emit("vm", map[string]any{"state": "fallback", "accel": acc, "build": filepath.Base(build), "error": err.Error()})
		}
		// This build doesn't boot here at all: remember that (until it's rebuilt) and use the next one.
		if bi < len(cands)-1 {
			os.WriteFile(filepath.Join(build, "boot-failed"), []byte(last.Error()), 0644)
			m.emit("vm", map[string]any{"state": "build_failed", "build": filepath.Base(build), "error": last.Error()})
		}
	}
	return nil, last
}

// bootCandidates: the tuned build first, then the generic one; a build that failed to boot
// is skipped until it's rebuilt (its manifest is newer than the failure note).
func (m *Manager) bootCandidates(arch string) []string {
	var out []string
	variants := []string{"tuned", "generic"}
	if arch == "x86_64" {
		variants = []string{"generic"} // PC builds are generic only (older tuned builds are ignored)
	}
	for _, v := range variants {
		d := filepath.Join(m.Dir, "builds", arch+"-"+v)
		mf, err := os.Stat(filepath.Join(d, "manifest.json"))
		if err != nil {
			continue
		}
		if bad, err := os.Stat(filepath.Join(d, "boot-failed")); err == nil && !mf.ModTime().After(bad.ModTime()) {
			continue
		}
		out = append(out, d)
	}
	if len(out) == 0 { // every build failed once: try them all again
		for _, v := range variants {
			if d := filepath.Join(m.Dir, "builds", arch+"-"+v); fileExists(filepath.Join(d, "manifest.json")) {
				out = append(out, d)
			}
		}
	}
	return out
}

func (m *Manager) bootWith(ctx context.Context, qemu, arch, build, accel string, memMB int) (*VM, error) {
	port, err := freePort()
	if err != nil {
		return nil, err
	}
	args := qemuArgs(arch, build, accel, port, memMB)
	if share := filepath.Join(filepath.Dir(qemu), "share"); fileExists(share) {
		args = append(args, "-L", share) // firmware shipped next to the bundled QEMU
	}
	cmd := exec.Command(qemu, args...)
	cmd.Dir = filepath.Dir(qemu)
	hideWindow(cmd)
	logf, _ := os.Create(filepath.Join(m.Dir, "vm-console.log"))
	cmd.Stdout, cmd.Stderr = logf, logf
	vm := &VM{cmd: cmd, wait: map[int]chan map[string]any{}, Accel: accel, Start: time.Now(), exited: make(chan struct{})}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	go func() { cmd.Wait(); close(vm.exited); logf.Close() }()
	m.emit("vm", map[string]any{"state": "starting", "accel": accel, "build": filepath.Base(build)})
	deadline := time.Now().Add(90 * time.Second)
	for {
		select {
		case <-vm.exited:
			b, _ := os.ReadFile(filepath.Join(m.Dir, "vm-console.log"))
			return nil, fmt.Errorf("QEMU stopped: %s", lastLines(string(b), 4))
		case <-ctx.Done():
			vm.Stop()
			return nil, ctx.Err()
		default:
		}
		if vm.conn == nil {
			if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second); err == nil {
				vm.conn = c
				go vm.readLoop()
			}
		}
		if vm.conn != nil {
			if res, err := vm.Call(map[string]any{"op": "hello"}, 700*time.Millisecond); err == nil {
				m.emit("vm", map[string]any{"state": "ready", "accel": accel, "boot_ms": time.Since(vm.Start).Milliseconds(), "hello": res})
				return vm, nil
			}
		}
		if time.Now().After(deadline) {
			vm.Stop()
			return nil, errors.New("the agent didn't answer within 90 s")
		}
		time.Sleep(150 * time.Millisecond)
	}
}

func lastLines(s string, n int) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	if len(l) > n {
		l = l[len(l)-n:]
	}
	return strings.Join(l, " | ")
}

func (vm *VM) readLoop() {
	sc := bufio.NewScanner(vm.conn)
	sc.Buffer(make([]byte, 1<<20), 32<<20)
	for sc.Scan() {
		var d map[string]any
		if json.Unmarshal(sc.Bytes(), &d) != nil {
			continue
		}
		id, ok := d["id"].(float64)
		if !ok {
			continue
		}
		vm.mu.Lock()
		ch := vm.wait[int(id)]
		delete(vm.wait, int(id))
		vm.mu.Unlock()
		if ch != nil {
			ch <- d
		}
	}
}

// Call sends one request to the agent and waits for its reply.
func (vm *VM) Call(req map[string]any, timeout time.Duration) (map[string]any, error) {
	vm.mu.Lock()
	vm.nextID++
	id := vm.nextID
	ch := make(chan map[string]any, 1)
	vm.wait[id] = ch
	vm.mu.Unlock()
	req["id"] = id
	b, _ := json.Marshal(req)
	if _, err := vm.conn.Write(append(b, '\n')); err != nil {
		return nil, err
	}
	select {
	case d := <-ch:
		if ok, _ := d["ok"].(bool); !ok {
			e, _ := d["err"].(string)
			return d, errors.New(e)
		}
		return d, nil
	case <-time.After(timeout):
		vm.mu.Lock()
		delete(vm.wait, id)
		vm.mu.Unlock()
		return nil, errors.New("agent timeout")
	case <-vm.exited:
		return nil, errors.New("the VM stopped")
	}
}

// Stop powers the VM off.
func (vm *VM) Stop() {
	if vm.conn != nil {
		vm.conn.Close()
	}
	if vm.cmd.Process != nil {
		vm.cmd.Process.Kill()
	}
}

// RSS returns QEMU's resident memory in bytes, if the platform tells us.
func (vm *VM) RSS() int64 {
	if vm.cmd.Process == nil {
		return 0
	}
	return processRSS(vm.cmd.Process.Pid)
}

// ---------------------------------------------------------------- stage 0 test

func (m *Manager) testJob(j *job) error {
	ctx, cancel := context.WithCancel(context.Background())
	j.cancel = cancel
	defer cancel()
	m.emit("phase", map[string]any{"phase": "test", "state": "start", "label": "Booting FortiTatake OS"})
	t0 := time.Now()
	vm, err := m.Boot(ctx, 192)
	if err != nil {
		return err
	}
	defer vm.Stop()
	boot := time.Since(t0).Milliseconds()
	hello, _ := vm.Call(map[string]any{"op": "hello"}, 5*time.Second)
	m.emit("phase", map[string]any{"phase": "test", "state": "bench", "label": "Building a 10-device lab and sending traffic"})
	bench, err := vm.Call(map[string]any{"op": "bench", "devices": 10}, 120*time.Second)
	if err != nil {
		return fmt.Errorf("benchmark: %v", err)
	}
	rss := vm.RSS()
	res := map[string]any{
		"when": time.Now().Format(time.RFC3339), "device": deviceInfo(), "accel": vm.Accel, "boot_ms": boot,
		"hello": hello, "bench": bench, "qemu_rss_bytes": rss, "build": filepath.Base(m.pickBuild(hostArch())),
	}
	m.saveReport("tests."+runtime.GOOS, res)
	if runtime.GOOS == "android" { // goes to the PC on the next sync
		b, _ := json.MarshalIndent(map[string]any{"device": deviceInfo(), "app": m.Version, "test": res}, "", " ")
		os.WriteFile(filepath.Join(m.Dir, "phone-report.json"), b, 0644)
	}
	m.emit("test", res)
	m.emit("phase", map[string]any{"phase": "test", "state": "done", "label": "Stage 0 test finished"})
	return nil
}

// saveReport merges one section into report.json (the file to share for tuning).
func (m *Manager) saveReport(key string, v any) {
	p := filepath.Join(m.Dir, "report.json")
	rep := map[string]any{}
	if b, err := os.ReadFile(p); err == nil {
		json.Unmarshal(b, &rep)
	}
	rep["app"] = m.Version
	rep["updated"] = time.Now().Format(time.RFC3339)
	rep[key] = v
	rep["builds"] = m.Builds()
	b, _ := json.MarshalIndent(rep, "", " ")
	tmp := p + ".tmp"
	if os.WriteFile(tmp, b, 0644) == nil {
		os.Rename(tmp, p)
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
