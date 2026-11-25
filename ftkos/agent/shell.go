package main

// Linux shells inside a lab device: the app's console sends lines and polls output. No pty
// (the console is line-based), so full-screen programs don't work; ping, traceroute,
// nslookup, curl, ip, nft, tcpdump do. Ctrl+C interrupts whatever the shell is running.

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

type labShell struct {
	ns    string
	cmd   *exec.Cmd
	stdin io.WriteCloser
	pty   *os.File
	mu    sync.Mutex
	buf   []byte
	base  int64 // offset of buf[0] in the whole output
	done  bool
}

var (
	shMu   sync.Mutex
	shells = map[string]*labShell{}
	shSeq  int
)

const shKeep = 256 << 10

func (s *labShell) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf = append(s.buf, p...)
	if len(s.buf) > shKeep {
		cut := len(s.buf) - shKeep
		s.buf = s.buf[cut:]
		s.base += int64(cut)
	}
	return len(p), nil
}

func shellOpen(r req) (map[string]any, error) {
	ns := r.str("ns")
	if err := checkNS(ns); err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join("/run/netns", ns)); err != nil {
		return nil, fmt.Errorf("device %s is not up", ns)
	}
	s := &labShell{ns: ns}
	cmd := exec.Command("ip", "netns", "exec", ns, "sh")
	cmd.Env = append(os.Environ(), "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "TERM=dumb", "PS1=", "PS2=", "HOSTNAME="+ns)
	cmd.Dir = "/"
	// A terminal, so programs print line by line (ping, traceroute) instead of buffering.
	master, slave, err := openPty()
	if err != nil {
		return nil, fmt.Errorf("no terminal for the shell: %v", err)
	}
	// Input stays a pipe: the shell then doesn't echo or redraw lines; output is the terminal.
	makeRaw(slave) // \n stays \n
	in, err := cmd.StdinPipe()
	if err != nil {
		master.Close()
		slave.Close()
		return nil, err
	}
	cmd.Stdout, cmd.Stderr = slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 1}
	if err := cmd.Start(); err != nil {
		master.Close()
		slave.Close()
		return nil, err
	}
	slave.Close()
	s.cmd, s.stdin, s.pty = cmd, in, master
	go io.Copy(s, master)
	shMu.Lock()
	shSeq++
	id := fmt.Sprintf("sh%d", shSeq)
	shells[id] = s
	shMu.Unlock()
	go func() {
		cmd.Wait()
		s.mu.Lock()
		s.done = true
		s.mu.Unlock()
	}()
	return map[string]any{"shell": id}, nil
}

func getShell(r req) (*labShell, error) {
	shMu.Lock()
	defer shMu.Unlock()
	s := shells[r.str("shell")]
	if s == nil {
		return nil, fmt.Errorf("no such shell")
	}
	return s, nil
}

func shellWrite(r req) (map[string]any, error) {
	s, err := getShell(r)
	if err != nil {
		return map[string]any{"alive": false}, nil
	}
	if _, err := io.WriteString(s.stdin, r.str("data")); err != nil {
		return map[string]any{"alive": false}, nil
	}
	return map[string]any{"alive": true}, nil
}

func shellRead(r req) (map[string]any, error) {
	s, err := getShell(r)
	if err != nil {
		return map[string]any{"alive": false, "data": "", "next": 0}, nil
	}
	since := int64(r.num("since", 0))
	s.mu.Lock()
	defer s.mu.Unlock()
	end := s.base + int64(len(s.buf))
	if since < s.base {
		since = s.base
	}
	if since > end {
		since = end
	}
	return map[string]any{"alive": !s.done, "data": string(s.buf[since-s.base:]), "next": end}, nil
}

// shellSignal interrupts the shell's running commands (Ctrl+C), not the shell itself.
func shellSignal(r req) (map[string]any, error) {
	s, err := getShell(r)
	if err != nil {
		return map[string]any{}, nil
	}
	for _, pid := range descendants(s.cmd.Process.Pid) {
		syscall.Kill(pid, syscall.SIGINT)
	}
	return map[string]any{}, nil
}

func descendants(root int) []int {
	parent := map[int]int{}
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		st := string(b)
		i := strings.LastIndexByte(st, ')')
		if i < 0 {
			continue
		}
		f := strings.Fields(st[i+1:])
		if len(f) > 1 {
			pp, _ := strconv.Atoi(f[1])
			parent[pid] = pp
		}
	}
	var out []int
	var walk func(int)
	walk = func(p int) {
		for c, pp := range parent {
			if pp == p {
				out = append(out, c)
				walk(c)
			}
		}
	}
	walk(root)
	// skip the shell itself (ip netns exec execs into sh, so root may already be sh)
	return out
}

func shellClose(r req) (map[string]any, error) {
	shMu.Lock()
	s := shells[r.str("shell")]
	delete(shells, r.str("shell"))
	shMu.Unlock()
	if s != nil {
		syscall.Kill(-s.cmd.Process.Pid, syscall.SIGKILL)
		s.stdin.Close()
		s.pty.Close()
	}
	return map[string]any{}, nil
}

// openPty returns a new pseudo-terminal pair (mounting devpts if init didn't).
func openPty() (*os.File, *os.File, error) {
	ptmx := "/dev/pts/ptmx"
	if _, err := os.Stat(ptmx); err != nil {
		os.MkdirAll("/dev/pts", 0755)
		syscall.Mount("devpts", "/dev/pts", "devpts", 0, "mode=620,ptmxmode=666")
	}
	m, err := os.OpenFile(ptmx, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		if m, err = os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0); err != nil {
			return nil, nil, err
		}
	}
	var unlock int32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(), syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); e != 0 {
		m.Close()
		return nil, nil, e
	}
	var n uint32
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, m.Fd(), syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n))); e != 0 {
		m.Close()
		return nil, nil, e
	}
	sl, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		m.Close()
		return nil, nil, err
	}
	return m, sl, nil
}

func stopAllShells() {
	shMu.Lock()
	all := shells
	shells = map[string]*labShell{}
	shMu.Unlock()
	for _, s := range all {
		syscall.Kill(-s.cmd.Process.Pid, syscall.SIGKILL)
		s.stdin.Close()
		s.pty.Close()
	}
}
