package main

// FRR (OSPF and BGP) inside lab namespaces: FortiTatake compiles each speaker's routing config
// (a FortiGate's `router ospf` / `router bgp`, a lab router's ospf/bgp spec) into an FRR config and
// the agent runs zebra, staticd, ospfd and bgpd in that device's namespace, so routes are learned
// from real OSPF and BGP exchanges between the namespaces instead of being computed and installed.
// One FRR instance per namespace, separated by FRR's pathspace (-N).

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Debian-style builds put the daemons in /usr/lib/frr, Buildroot's in /usr/sbin
var frrBin = func() string {
	for _, d := range []string{"/usr/lib/frr", "/usr/sbin"} {
		if _, err := os.Stat(filepath.Join(d, "zebra")); err == nil {
			return d
		}
	}
	return "/usr/lib/frr"
}()

var frrDaemons = []string{"zebra", "staticd", "ospfd", "bgpd"}

func frrDir(ns string) string { return filepath.Join("/run/ftk/frr", ns) }

func frrAvailable() bool {
	_, err := os.Stat(filepath.Join(frrBin, "zebra"))
	return err == nil
}

func frrStopNS(ns string) {
	for i := len(frrDaemons) - 1; i >= 0; i-- {
		b, err := os.ReadFile(filepath.Join(frrDir(ns), frrDaemons[i]+".pid"))
		if err != nil {
			continue
		}
		if pid, _ := strconv.Atoi(strings.TrimSpace(string(b))); pid > 1 {
			syscall.Kill(pid, syscall.SIGTERM)
		}
	}
	time.Sleep(300 * time.Millisecond)
	for _, d := range frrDaemons {
		if b, err := os.ReadFile(filepath.Join(frrDir(ns), d+".pid")); err == nil {
			if pid, _ := strconv.Atoi(strings.TrimSpace(string(b))); pid > 1 {
				syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	}
	os.RemoveAll(frrDir(ns))
}

func frrStopAll() {
	ents, _ := os.ReadDir("/run/ftk/frr")
	for _, e := range ents {
		frrStopNS(e.Name())
	}
}

// frr.apply: {ns, conf, daemons}: (re)start FRR in a namespace with this config
func frrApply(r req) (map[string]any, error) {
	ns, conf := r.str("ns"), r.str("conf")
	if err := checkNS(ns); err != nil {
		return nil, err
	}
	if !frrAvailable() {
		return nil, fmt.Errorf("this FortiTatake OS image has no FRR (rebuild it)")
	}
	frrStopNS(ns)
	if conf == "" {
		return map[string]any{"running": false}, nil
	}
	dir := frrDir(ns)
	os.MkdirAll(dir, 0o755)
	cf := filepath.Join(dir, "frr.conf")
	conf = strings.Replace(conf, "log syslog warnings", "log file "+filepath.Join(dir, "frr.log")+" informational", 1) // readable from the lab
	if err := os.WriteFile(cf, []byte(conf), 0o600); err != nil {
		return nil, err
	}
	want := map[string]bool{"zebra": true, "staticd": true}
	for _, d := range r.strs("daemons") {
		want[d] = true
	}
	started := []string{}
	for _, d := range frrDaemons {
		if !want[d] {
			continue
		}
		// sockets under /run/ftk/frr/<ns>: zebra's API and every daemon's vty (the image's /var/run may be read-only)
		args := []string{"netns", "exec", ns, filepath.Join(frrBin, d), "-d", "-N", ns, "-u", "root", "-g", "root", "-f", cf, "-i", filepath.Join(dir, d+".pid"), "-P", "0",
			"-z", filepath.Join(dir, "zserv.api"), "--vty_socket", dir}
		if d == "bgpd" {
			args = append(args, "-p", "179")
		}
		_, e, code, err := run(10*time.Second, "", append([]string{"ip"}, args...)...)
		if err != nil || code != 0 {
			return map[string]any{"running": false, "started": started, "error": fmt.Sprintf("%s: %s", d, strings.TrimSpace(e))}, nil
		}
		started = append(started, d)
		if d == "zebra" {
			time.Sleep(300 * time.Millisecond) // the others connect to zebra's socket
		}
	}
	return map[string]any{"running": true, "started": started}, nil
}

// frr.show: {ns, cmd}: a read-only vtysh command (show ...) in that namespace's FRR
func frrShow(r req) (map[string]any, error) {
	ns, cmd := r.str("ns"), strings.TrimSpace(r.str("cmd"))
	if err := checkNS(ns); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(cmd, "show ") || strings.ContainsAny(cmd, ";|&`$\n") {
		return nil, fmt.Errorf("only show commands")
	}
	out, e, _, err := run(10*time.Second, "", "vtysh", "-N", ns, "--vty_socket", frrDir(ns), "-c", cmd)
	if err != nil {
		return nil, err
	}
	return map[string]any{"out": out, "err": e}, nil
}
