package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Services (lighttpd, dnsmasq, dropbear, ...) are started on request, inside one device,
// with config files FortiTatake writes. Files can only land under /run/ftk.

var (
	svcMu sync.Mutex
	svcs  = map[string]*exec.Cmd{}
)

func serviceStart(r req) (map[string]any, error) {
	ns, name := r.str("ns"), r.str("name")
	if err := checkNS(ns); err != nil {
		return nil, err
	}
	if !nameRe.MatchString(name) {
		return nil, fmt.Errorf("bad service name %q", name)
	}
	dir := filepath.Join("/run/ftk/svc", ns+"-"+name)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	if files, ok := r["files"].(map[string]any); ok {
		for fn, body := range files {
			clean := filepath.Clean("/" + fn)
			if strings.Contains(fn, "..") {
				return nil, fmt.Errorf("bad file name %q", fn)
			}
			p := filepath.Join(dir, clean)
			os.MkdirAll(filepath.Dir(p), 0755)
			if err := os.WriteFile(p, []byte(fmt.Sprint(body)), 0644); err != nil {
				return nil, err
			}
		}
	}
	argv := r.strs("argv")
	if len(argv) == 0 {
		return nil, fmt.Errorf("argv is empty")
	}
	for i, a := range argv {
		argv[i] = strings.ReplaceAll(a, "{dir}", dir)
	}
	key := ns + "/" + name
	serviceStopKey(key)
	cmd := exec.Command("ip", append([]string{"netns", "exec", ns}, argv...)...)
	cmd.Dir = dir
	log, _ := os.Create(filepath.Join(dir, "service.log"))
	cmd.Stdout, cmd.Stderr = log, log
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	svcMu.Lock()
	svcs[key] = cmd
	svcMu.Unlock()
	go cmd.Wait()
	// Optional readiness: wait until the service listens on a TCP port.
	if p := int(r.num("ready_port", 0)); p > 0 {
		ip := r.str("ready_ip")
		if ip == "" {
			ip = "127.0.0.1"
		}
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			ok := false
			withNetns(ns, func() error {
				c, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, p), 200*time.Millisecond)
				if err == nil {
					c.Close()
					ok = true
				}
				return nil
			})
			if ok {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	return map[string]any{"pid": cmd.Process.Pid, "dir": dir}, nil
}

func serviceStop(r req) (map[string]any, error) {
	serviceStopKey(r.str("ns") + "/" + r.str("name"))
	return map[string]any{}, nil
}

func serviceStopKey(key string) {
	svcMu.Lock()
	cmd := svcs[key]
	delete(svcs, key)
	svcMu.Unlock()
	if cmd != nil && cmd.Process != nil {
		syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		time.Sleep(20 * time.Millisecond)
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}

func stopAllServices() {
	svcMu.Lock()
	keys := make([]string, 0, len(svcs))
	for k := range svcs {
		keys = append(keys, k)
	}
	svcMu.Unlock()
	for _, k := range keys {
		serviceStopKey(k)
	}
}
