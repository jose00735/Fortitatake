package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Topology spec as sent by FortiTatake. Every device becomes a network namespace.
type topoSpec struct {
	Devices []struct {
		Name    string            `json:"name"`
		Kind    string            `json:"kind"`
		Forward bool              `json:"forward"`
		Sysctl  map[string]string `json:"sysctl"`
	} `json:"devices"`
	Links []struct {
		A     endpoint `json:"a"`
		B     endpoint `json:"b"`
		MTU   int      `json:"mtu"`
		Netem string   `json:"netem"`
		Down  bool     `json:"down"`
	} `json:"links"`
	Bridges []struct {
		Dev           string `json:"dev"`
		Name          string `json:"name"`
		VlanFiltering bool   `json:"vlan_filtering"`
		STP           bool   `json:"stp"`
		Ports         []struct {
			If       string `json:"if"`
			Pvid     int    `json:"pvid"`
			Untagged bool   `json:"untagged"`
			Vlans    []int  `json:"vlans"`
		} `json:"ports"`
	} `json:"bridges"`
	Addrs []struct {
		Dev  string `json:"dev"`
		If   string `json:"if"`
		CIDR string `json:"cidr"`
	} `json:"addrs"`
	Internet *inetCfg `json:"internet"` // the namespace whose exit relays DNS and ICMP to the real Internet
	Routes   []struct {
		Dev    string `json:"dev"`
		Dst    string `json:"dst"`
		Via    string `json:"via"`
		If     string `json:"if"`
		Metric int    `json:"metric"`
		Type   string `json:"type"` // "" or blackhole, local
	} `json:"routes"`
	// 802.1Q sub-interfaces (FortiGate VLAN interfaces)
	Vlans []struct {
		Dev    string `json:"dev"`
		If     string `json:"if"`
		Parent string `json:"parent"`
		ID     int    `json:"id"`
		Down   bool   `json:"down"`
	} `json:"vlans"`
	// interfaces with no cable: loopbacks, unplugged ports
	Dummies []struct {
		Dev  string `json:"dev"`
		If   string `json:"if"`
		Down bool   `json:"down"`
	} `json:"dummies"`
	// proxy ARP (VIP external IPs, IP pools)
	Proxies []struct {
		Dev string `json:"dev"`
		If  string `json:"if"`
		IP  string `json:"ip"`
	} `json:"proxies"`
}

type endpoint struct {
	Dev string `json:"dev"`
	If  string `json:"if"`
	MAC string `json:"mac"`
}

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
var ifRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,14}$`)

func checkNS(n string) error {
	if !nameRe.MatchString(n) {
		return fmt.Errorf("bad device name %q", n)
	}
	return nil
}

func checkIf(n string) error {
	if !ifRe.MatchString(n) {
		return fmt.Errorf("bad interface name %q (max 15 chars)", n)
	}
	return nil
}

// run executes a command with a timeout and returns combined stdout, stderr, exit code.
func run(timeout time.Duration, stdin string, argv ...string) (string, string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &limited{b: &o}, &limited{b: &e}
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	err := cmd.Run()
	code := 0
	if err != nil {
		if x, ok := err.(*exec.ExitError); ok {
			code = x.ExitCode()
			err = nil
		} else if ctx.Err() != nil {
			code, err = 124, nil
			e.WriteString("timed out")
		}
	}
	return o.String(), e.String(), code, err
}

type limited struct{ b *bytes.Buffer }

func (l *limited) Write(p []byte) (int, error) {
	if l.b.Len() < 1<<20 {
		l.b.Write(p)
	}
	return len(p), nil
}

// batch runs one `ip -batch` per namespace ("" = the agent's own namespace).
func ipBatch(ns string, lines []string) error {
	if len(lines) == 0 {
		return nil
	}
	argv := []string{"ip", "-force", "-batch", "-"}
	if ns != "" {
		argv = []string{"ip", "-n", ns, "-force", "-batch", "-"}
	}
	_, e, code, err := run(20*time.Second, strings.Join(lines, "\n")+"\n", argv...)
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("ip %s: %s", ns, strings.TrimSpace(e))
	}
	return nil
}

func tcBatch(ns string, lines []string) error {
	if len(lines) == 0 {
		return nil
	}
	_, e, code, err := run(10*time.Second, strings.Join(lines, "\n")+"\n", "ip", "netns", "exec", ns, "tc", "-force", "-batch", "-")
	if err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("tc %s: %s", ns, strings.TrimSpace(e))
	}
	return nil
}

// withNetns runs f on an OS thread switched into the named namespace.
func withNetns(ns string, f func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	self, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		return err
	}
	defer self.Close()
	target, err := os.Open(filepath.Join("/run/netns", ns))
	if err != nil {
		return fmt.Errorf("device %s is not up", ns)
	}
	defer target.Close()
	if err := setns(target.Fd()); err != nil {
		return err
	}
	defer setns(self.Fd())
	return f()
}

func setns(fd uintptr) error {
	_, _, e := syscall.RawSyscall(sysSetns, fd, syscall.CLONE_NEWNET, 0)
	if e != 0 {
		return e
	}
	return nil
}

func sysctlIn(ns, key, val string) error {
	return withNetns(ns, func() error {
		p := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
		return os.WriteFile(p, []byte(val), 0644)
	})
}

func listNS() []string {
	es, _ := os.ReadDir("/run/netns")
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

func topoClear() (map[string]any, error) {
	inetStop()
	stopAllShells()
	stopAllRemote()
	stopAllSenders()
	stopAllListeners()
	stopAllGens()
	stopAllIPS()
	edrStopAll()
	stopAllServices()
	stopAllCaptures()
	t := time.Now()
	for _, ns := range listNS() {
		run(10*time.Second, "", "ip", "netns", "delete", ns)
	}
	return map[string]any{"ms": time.Since(t).Milliseconds()}, nil
}

func topoApply(r req) (map[string]any, error) {
	raw, _ := json.Marshal(r["topo"])
	var t topoSpec
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("bad topo: %v", err)
	}
	start := time.Now()
	if _, err := topoClear(); err != nil {
		return nil, err
	}
	steps := map[string]int64{}
	mark := func(k string, s time.Time) { steps[k] = time.Since(s).Milliseconds() }

	s := time.Now()
	var root []string
	for _, d := range t.Devices {
		if err := checkNS(d.Name); err != nil {
			return nil, err
		}
		root = append(root, "netns add "+d.Name)
	}
	if err := ipBatch("", root); err != nil {
		return nil, err
	}
	mark("namespaces", s)

	// veth pairs: created in the agent's namespace, then moved and renamed.
	s = time.Now()
	root = nil
	per := map[string][]string{}
	tcs := map[string][]string{}
	for i, l := range t.Links {
		for _, ep := range []endpoint{l.A, l.B} {
			if err := checkNS(ep.Dev); err != nil {
				return nil, err
			}
			if err := checkIf(ep.If); err != nil {
				return nil, err
			}
		}
		a, b := fmt.Sprintf("fa%d", i), fmt.Sprintf("fb%d", i)
		root = append(root, fmt.Sprintf("link add %s type veth peer name %s", a, b))
		for _, x := range []struct {
			tmp string
			ep  endpoint
		}{{a, l.A}, {b, l.B}} {
			root = append(root, fmt.Sprintf("link set %s netns %s name %s", x.tmp, x.ep.Dev, x.ep.If))
			cmds := []string{}
			if x.ep.MAC != "" {
				cmds = append(cmds, fmt.Sprintf("link set %s address %s", x.ep.If, x.ep.MAC))
			}
			if l.MTU > 0 {
				cmds = append(cmds, fmt.Sprintf("link set %s mtu %d", x.ep.If, l.MTU))
			}
			if !l.Down {
				cmds = append(cmds, fmt.Sprintf("link set %s up", x.ep.If))
			}
			if l.Netem != "" {
				tcs[x.ep.Dev] = append(tcs[x.ep.Dev], fmt.Sprintf("qdisc replace dev %s root netem %s", x.ep.If, l.Netem))
			}
			per[x.ep.Dev] = append(per[x.ep.Dev], cmds...)
		}
	}
	if err := ipBatch("", root); err != nil {
		return nil, err
	}
	mark("links", s)

	// bridges (switches): VLAN filtering, access and trunk ports.
	s = time.Now()
	bridgeCmds := map[string][]string{}
	for _, br := range t.Bridges {
		name := br.Name
		if name == "" {
			name = "br0"
		}
		vf, stp := 0, 0
		if br.VlanFiltering {
			vf = 1
		}
		if br.STP {
			stp = 1
		}
		per[br.Dev] = append(per[br.Dev],
			fmt.Sprintf("link add %s type bridge vlan_filtering %d stp_state %d", name, vf, stp),
			fmt.Sprintf("link set %s up", name))
		for _, p := range br.Ports {
			per[br.Dev] = append(per[br.Dev], fmt.Sprintf("link set %s master %s", p.If, name))
			if br.VlanFiltering && (p.Pvid > 0 || len(p.Vlans) > 0) {
				bridgeCmds[br.Dev] = append(bridgeCmds[br.Dev], fmt.Sprintf("vlan del dev %s vid 1", p.If))
				for _, v := range p.Vlans {
					if v != p.Pvid {
						bridgeCmds[br.Dev] = append(bridgeCmds[br.Dev], fmt.Sprintf("vlan add dev %s vid %d", p.If, v))
					}
				}
				if p.Pvid > 0 {
					extra := " pvid"
					if p.Untagged {
						extra += " untagged"
					}
					bridgeCmds[br.Dev] = append(bridgeCmds[br.Dev], fmt.Sprintf("vlan add dev %s vid %d%s", p.If, p.Pvid, extra))
				}
			}
		}
	}

	for _, d := range t.Devices {
		per[d.Name] = append([]string{"link set lo up"}, per[d.Name]...)
	}
	for _, v := range t.Dummies {
		if err := checkIf(v.If); err != nil {
			return nil, err
		}
		if os.Getenv("FTK_NO_DUMMY") != "" { // test hosts without the dummy driver
			per[v.Dev] = append(per[v.Dev], fmt.Sprintf("link add %s type veth peer name %s", v.If, "x"+strings.ReplaceAll(v.If, ".", "")[:min(len(v.If), 13)]))
		} else {
			per[v.Dev] = append(per[v.Dev], fmt.Sprintf("link add %s type dummy", v.If))
		}
		if !v.Down {
			per[v.Dev] = append(per[v.Dev], fmt.Sprintf("link set %s up", v.If))
		}
	}
	for _, v := range t.Vlans {
		if err := checkIf(v.If); err != nil {
			return nil, err
		}
		if v.ID < 1 || v.ID > 4094 {
			return nil, fmt.Errorf("bad VLAN id %d on %s", v.ID, v.If)
		}
		per[v.Dev] = append(per[v.Dev], fmt.Sprintf("link add link %s name %s type vlan id %d", v.Parent, v.If, v.ID))
		if !v.Down {
			per[v.Dev] = append(per[v.Dev], fmt.Sprintf("link set %s up", v.If))
		}
	}
	for _, a := range t.Addrs {
		per[a.Dev] = append(per[a.Dev], fmt.Sprintf("addr add %s dev %s", a.CIDR, a.If))
	}
	for _, rt := range t.Routes {
		line := "route replace " + rt.Dst
		switch rt.Type {
		case "blackhole":
			per[rt.Dev] = append(per[rt.Dev], "route replace blackhole "+rt.Dst)
			continue
		case "local":
			per[rt.Dev] = append(per[rt.Dev], "route replace local "+rt.Dst+" dev lo")
			continue
		}
		if rt.Via != "" {
			line += " via " + rt.Via
		}
		if rt.If != "" {
			line += " dev " + rt.If
		}
		if rt.Metric > 0 {
			line += fmt.Sprintf(" metric %d", rt.Metric)
		}
		per[rt.Dev] = append(per[rt.Dev], line)
	}
	for _, p := range t.Proxies {
		per[p.Dev] = append(per[p.Dev], fmt.Sprintf("neigh add proxy %s dev %s", p.IP, p.If))
	}
	for _, d := range t.Devices {
		if err := ipBatch(d.Name, per[d.Name]); err != nil {
			return nil, err
		}
	}
	for dev, cmds := range tcs {
		if err := tcBatch(dev, cmds); err != nil {
			return nil, err
		}
	}
	for dev, cmds := range bridgeCmds {
		_, e, code, err := run(10*time.Second, strings.Join(cmds, "\n")+"\n", "bridge", "-n", dev, "-force", "-batch", "-")
		if err != nil || code != 0 {
			return nil, fmt.Errorf("bridge %s: %s %v", dev, strings.TrimSpace(e), err)
		}
	}
	mark("config", s)

	s = time.Now()
	for _, d := range t.Devices {
		if d.Forward {
			if err := sysctlIn(d.Name, "net.ipv4.ip_forward", "1"); err != nil {
				return nil, err
			}
		}
		for k, v := range d.Sysctl {
			if err := sysctlIn(d.Name, k, v); err != nil {
				return nil, fmt.Errorf("%s %s: %v", d.Name, k, err)
			}
		}
	}
	mark("sysctl", s)
	if err := inetStart(t.Internet); err != nil {
		return nil, fmt.Errorf("internet exit: %v", err)
	}
	return map[string]any{"ms": time.Since(start).Milliseconds(), "steps": steps, "devices": len(t.Devices), "links": len(t.Links)}, nil
}

func nsExec(r req) (map[string]any, error) {
	ns := r.str("ns")
	argv := r.strs("argv")
	if len(argv) == 0 {
		return nil, fmt.Errorf("argv is empty")
	}
	if ns != "" {
		if err := checkNS(ns); err != nil {
			return nil, err
		}
		argv = append([]string{"ip", "netns", "exec", ns}, argv...)
	}
	to := time.Duration(r.num("timeout_ms", 15000)) * time.Millisecond
	t := time.Now()
	o, e, code, err := run(to, r.str("input"), argv...)
	if err != nil {
		return nil, err
	}
	return map[string]any{"code": code, "stdout": o, "stderr": e, "ms": time.Since(t).Milliseconds()}, nil
}

func nsNft(r req) (map[string]any, error) {
	ns := r.str("ns")
	if err := checkNS(ns); err != nil {
		return nil, err
	}
	rules := "flush ruleset\n" + r.str("ruleset") + "\n"
	// a file, not stdin: the VM has no /dev/stdin
	os.MkdirAll("/run/ftk/nft", 0755)
	fn := filepath.Join("/run/ftk/nft", ns+".nft")
	if err := os.WriteFile(fn, []byte(rules), 0644); err != nil {
		return nil, err
	}
	_, e, code, err := run(15*time.Second, "", "ip", "netns", "exec", ns, "nft", "-f", fn)
	if err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, fmt.Errorf("nft: %s", strings.TrimSpace(e))
	}
	return map[string]any{}, nil
}

// raw state, returned as the tools print it; FortiTatake turns it into FortiOS output.
var stateCmds = map[string][]string{
	"addr":        {"ip", "-j", "addr", "show"},
	"link":        {"ip", "-j", "-s", "link", "show"},
	"route":       {"ip", "-j", "route", "show", "table", "all"},
	"neigh":       {"ip", "-j", "neigh", "show"},
	"rule":        {"ip", "-j", "rule", "show"},
	"nft":         {"nft", "-j", "list", "ruleset"},
	"conntrack":   {"conntrack", "-L", "-o", "extended,id"},
	"bridge-fdb":  {"bridge", "-j", "fdb", "show"},
	"bridge-vlan": {"bridge", "-j", "vlan", "show"},
	"qdisc":       {"tc", "-j", "qdisc", "show"},
}

func nsState(r req) (map[string]any, error) {
	ns := r.str("ns")
	if err := checkNS(ns); err != nil {
		return nil, err
	}
	what := r.strs("what")
	if len(what) == 0 {
		what = []string{r.str("what")}
	}
	out := map[string]any{}
	for _, w := range what {
		c, ok := stateCmds[w]
		if !ok {
			return nil, fmt.Errorf("unknown state %q", w)
		}
		o, e, code, err := run(10*time.Second, "", append([]string{"ip", "netns", "exec", ns}, c...)...)
		if err != nil {
			return nil, err
		}
		if code != 0 {
			out[w] = map[string]any{"err": strings.TrimSpace(e)}
			continue
		}
		var js any
		if json.Unmarshal([]byte(o), &js) == nil {
			out[w] = js
		} else {
			out[w] = o
		}
	}
	return map[string]any{"state": out}, nil
}

// ns.link changes one interface at run time: lab events (link down, worse quality).
func nsLink(r req) (map[string]any, error) {
	ns, ifn := r.str("ns"), r.str("if")
	if err := checkNS(ns); err != nil {
		return nil, err
	}
	if err := checkIf(ifn); err != nil {
		return nil, err
	}
	var cmds []string
	if v, ok := r["up"].(bool); ok {
		st := "down"
		if v {
			st = "up"
		}
		cmds = append(cmds, fmt.Sprintf("link set %s %s", ifn, st))
	}
	if m := int(r.num("mtu", 0)); m > 0 {
		cmds = append(cmds, fmt.Sprintf("link set %s mtu %d", ifn, m))
	}
	if err := ipBatch(ns, cmds); err != nil {
		return nil, err
	}
	if n, ok := r["netem"].(string); ok {
		tc := fmt.Sprintf("qdisc replace dev %s root netem %s", ifn, n)
		if n == "" {
			tc = fmt.Sprintf("qdisc del dev %s root", ifn)
		}
		if err := tcBatch(ns, []string{tc}); err != nil && n != "" {
			return nil, err
		}
	}
	return map[string]any{}, nil
}
