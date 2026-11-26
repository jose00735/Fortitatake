package main

// FortiEDR-style collectors. Each lab host that has a collector gets a goroutine here that
// reads real signals for that host from the kernel and ships them to its EDR manager over the
// lab network (a TCP session from the host's own namespace), so a firewall policy between the
// two decides whether the manager hears anything:
//   perf  CPU (percent of one core) and memory from the host's cgroup
//   proc  processes that started in the host's cgroup: pid, parent, name, command line, user
//   net   TCP connections the host opened (from its namespace's socket table)
//   other events the app injects for emulated steps (edr.emit): a Windows command line, a file burst
// Events are JSON lines. While the manager is unreachable they wait (up to 10 minutes, 3000
// events); after that the oldest are dropped and a gap marker is sent.
//
// Prevention actions come back as ops: edr.kill (a process in the host's cgroup) and edr.block
// (a destination, in the host's own nftables). Isolation stays in the app's compiled rules.

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type edrEvent map[string]any

type collector struct {
	ns, mgr  string
	port     int
	stop     chan struct{}
	mu       sync.Mutex
	queue    []edrEvent
	dropped  int
	seenPID  map[int]bool
	seenConn map[string]bool
	lastCPU  int64
	pidCPU   map[int]int64 // clock ticks per process at the last sample
	lastT    time.Time
	conn     net.Conn
	sent     int64
	lastOK   time.Time
	lastErr  string
	seq      int64
}

var (
	edrMu   sync.Mutex
	edrCols = map[string]*collector{}
)

const edrQueueMax = 3000

func (c *collector) push(e edrEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	e["seq"] = c.seq
	e["host"] = c.ns
	if _, ok := e["t"]; !ok {
		e["t"] = time.Now().UnixMilli()
	}
	c.queue = append(c.queue, e)
	cutoff := time.Now().Add(-10 * time.Minute).UnixMilli()
	for len(c.queue) > 0 && (len(c.queue) > edrQueueMax || toI64(c.queue[0]["t"]) < cutoff) {
		c.queue = c.queue[1:]
		c.dropped++
	}
}

func toI64(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case float64:
		return int64(x)
	case int:
		return int64(x)
	}
	return 0
}

func procInfo(pid int) (ppid int, comm, cmd, user string) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err == nil {
		s := string(b)
		if i, j := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')'); i >= 0 && j > i {
			comm = s[i+1 : j]
			f := strings.Fields(s[j+1:])
			if len(f) > 1 {
				ppid, _ = strconv.Atoi(f[1])
			}
		}
	}
	if c, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
		cmd = strings.TrimSpace(strings.ReplaceAll(string(c), "\x00", " "))
	}
	user = "root"
	if st, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid)); err == nil {
		for _, l := range strings.Split(string(st), "\n") {
			if strings.HasPrefix(l, "Uid:") {
				if f := strings.Fields(l); len(f) > 1 && f[1] != "0" {
					user = "uid " + f[1]
				}
			}
		}
	}
	return
}

// one sampling pass: cgroup counters, new processes, new connections
func (c *collector) sample() {
	d := filepath.Join(cgRoot, "ftk", c.ns)
	if cgReady {
		cpu := cgKV(d, "cpu.stat")["usage_usec"]
		now := time.Now()
		procs, _ := os.ReadFile(filepath.Join(d, "cgroup.procs"))
		// the busiest process since the last sample (utime + stime, in USER_HZ ticks)
		ticks := map[int]int64{}
		topPID, topD := 0, int64(-1)
		for _, p := range strings.Fields(string(procs)) {
			pid, _ := strconv.Atoi(p)
			if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
				s := string(b)
				if j := strings.LastIndexByte(s, ')'); j > 0 {
					if f := strings.Fields(s[j+1:]); len(f) > 13 {
						u, _ := strconv.ParseInt(f[11], 10, 64)
						st, _ := strconv.ParseInt(f[12], 10, 64)
						ticks[pid] = u + st
						if dlt := u + st - c.pidCPU[pid]; dlt > topD {
							topPID, topD = pid, dlt
						}
					}
				}
			}
		}
		c.pidCPU = ticks
		if !c.lastT.IsZero() {
			pct := float64(cpu-c.lastCPU) / float64(now.Sub(c.lastT).Microseconds()) * 100
			mem := cgReadInt(d, "memory.current")
			ev := edrEvent{"kind": "perf", "cpu": int(pct + 0.5), "mem_mb": mem >> 20, "throttled": cgKV(d, "cpu.stat")["nr_throttled"]}
			if oom := cgKV(d, "memory.events")["oom_kill"]; oom > 0 {
				ev["oom"] = oom
			}
			if topPID > 0 {
				_, comm, _, _ := procInfo(topPID)
				ev["top"] = map[string]any{"pid": topPID, "name": comm}
			}
			c.push(ev)
		}
		c.lastCPU, c.lastT = cpu, now
		alive := map[int]bool{}
		for _, p := range strings.Fields(string(procs)) {
			pid, _ := strconv.Atoi(p)
			alive[pid] = true
			if c.seenPID[pid] {
				continue
			}
			c.seenPID[pid] = true
			ppid, comm, cmd, user := procInfo(pid)
			_, pcomm, pcmd, _ := procInfo(ppid)
			c.push(edrEvent{"kind": "proc", "pid": pid, "ppid": ppid, "name": comm, "cmd": cmd, "user": user, "parent": pcomm, "parent_cmd": pcmd})
		}
		for pid := range c.seenPID {
			if !alive[pid] {
				delete(c.seenPID, pid)
			}
		}
	}
	// connections the host opened: its namespace's TCP table (states SYN_SENT and ESTABLISHED)
	var lines []string
	withNetns(c.ns, func() error {
		f, err := os.Open("/proc/thread-self/net/tcp")
		if err != nil {
			return err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			lines = append(lines, sc.Text())
		}
		return nil
	})
	listen := map[int]bool{}
	type row struct{ l, r, st, inode string }
	rows := []row{}
	for _, l := range lines[min(1, len(lines)):] {
		f := strings.Fields(l)
		if len(f) < 4 {
			continue
		}
		ino := ""
		if len(f) > 9 {
			ino = f[9]
		}
		rows = append(rows, row{f[1], f[2], f[3], ino})
		if f[3] == "0A" {
			_, p := hexAddr(f[1])
			listen[p] = true
		}
	}
	// which process owns each socket (only the host's own processes, from its cgroup)
	owner := map[string]int{}
	for pid := range c.seenPID {
		fds, _ := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
		for _, fd := range fds {
			if l, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name())); err == nil && strings.HasPrefix(l, "socket:[") {
				owner[strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]")] = pid
			}
		}
	}
	now := map[string]bool{}
	for _, r := range rows {
		if r.st != "01" && r.st != "02" { // ESTABLISHED, SYN_SENT
			continue
		}
		lip, lport := hexAddr(r.l)
		rip, rport := hexAddr(r.r)
		if listen[lport] || rip == "127.0.0.1" { // inbound to a local service, or loopback
			continue
		}
		k := fmt.Sprintf("%s:%d>%s:%d", lip, lport, rip, rport)
		now[k] = true
		c.mu.Lock()
		seen := c.seenConn[k]
		c.mu.Unlock()
		if !seen {
			ev := edrEvent{"kind": "net", "src": lip, "sport": lport, "dst": rip, "dport": rport, "state": map[string]string{"01": "established", "02": "connecting"}[r.st]}
			if pid := owner[r.inode]; pid > 0 {
				_, comm, _, _ := procInfo(pid)
				ev["pid"], ev["process"] = pid, comm
			}
			c.push(ev)
		}
	}
	c.mu.Lock()
	c.seenConn = now
	c.mu.Unlock()
}

func hexAddr(s string) (string, int) {
	a, p, ok := strings.Cut(s, ":")
	if !ok || len(a) != 8 {
		return "", 0
	}
	b, _ := hex.DecodeString(a)
	port, _ := strconv.ParseInt(p, 16, 32)
	if len(b) != 4 {
		return "", 0
	}
	return net.IPv4(b[3], b[2], b[1], b[0]).String(), int(port)
}

// flush sends what's queued to the manager; on failure everything stays queued
func (c *collector) flush() {
	c.mu.Lock()
	batch := append([]edrEvent{}, c.queue...)
	dropped := c.dropped
	c.mu.Unlock()
	if len(batch) == 0 && dropped == 0 {
		return
	}
	if c.conn == nil {
		var conn net.Conn
		err := withNetns(c.ns, func() error {
			d := net.Dialer{Timeout: 2 * time.Second}
			cc, err := d.Dial("tcp4", net.JoinHostPort(c.mgr, strconv.Itoa(c.port)))
			conn = cc
			return err
		})
		if err != nil {
			c.lastErr = err.Error()
			return
		}
		c.conn = conn
	}
	var sb strings.Builder
	if dropped > 0 {
		b, _ := json.Marshal(edrEvent{"kind": "gap", "host": c.ns, "dropped": dropped, "t": time.Now().UnixMilli()})
		sb.Write(b)
		sb.WriteByte('\n')
	}
	for _, e := range batch {
		b, _ := json.Marshal(e)
		sb.Write(b)
		sb.WriteByte('\n')
	}
	c.conn.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.conn.Write([]byte(sb.String())); err != nil {
		c.conn.Close()
		c.conn = nil
		c.lastErr = err.Error()
		return
	}
	c.mu.Lock()
	c.queue = c.queue[len(batch):]
	c.dropped -= dropped
	c.sent += int64(len(batch))
	c.lastOK = time.Now()
	c.lastErr = ""
	c.mu.Unlock()
}

func (c *collector) run() {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.stop:
			if c.conn != nil {
				c.conn.Close()
			}
			return
		case <-t.C:
			c.sample()
			c.flush()
		}
	}
}

// edr.start: {ns, manager, port (555)}
func edrStart(r req) (map[string]any, error) {
	ns, mgr := r.str("ns"), r.str("manager")
	if err := checkNS(ns); err != nil {
		return nil, err
	}
	if net.ParseIP(mgr) == nil {
		return nil, fmt.Errorf("bad manager address")
	}
	edrMu.Lock()
	defer edrMu.Unlock()
	if old := edrCols[ns]; old != nil {
		if old.mgr == mgr {
			return map[string]any{"running": true}, nil
		}
		close(old.stop)
	}
	cgDir(ns) // the host's cgroup exists before anything runs in it
	c := &collector{ns: ns, mgr: mgr, port: int(r.num("port", 555)), stop: make(chan struct{}), seenPID: map[int]bool{}, seenConn: map[string]bool{}}
	c.push(edrEvent{"kind": "register", "os": "Linux", "version": agentVersion})
	edrCols[ns] = c
	kmsgOnce.Do(func() {
		os.WriteFile("/proc/sys/net/netfilter/nf_log_all_netns", []byte("1"), 0o644) // logs from lab namespaces reach the kernel log
		go edrKmsg()
	})
	go c.run()
	return map[string]any{"running": true, "cgroups": cgReady}, nil
}

func edrStopAll() {
	edrMu.Lock()
	defer edrMu.Unlock()
	for k, c := range edrCols {
		close(c.stop)
		delete(edrCols, k)
	}
}

// edr.emit: {ns, events: [{kind, ...}]}: emulated steps (Windows hosts have no real processes here)
func edrEmit(r req) (map[string]any, error) {
	edrMu.Lock()
	c := edrCols[r.str("ns")]
	edrMu.Unlock()
	if c == nil {
		return nil, fmt.Errorf("no collector on %s", r.str("ns"))
	}
	evs, _ := r["events"].([]any)
	for _, e := range evs {
		if m, ok := e.(map[string]any); ok {
			m["emulated"] = true
			c.push(edrEvent(m))
		}
	}
	return map[string]any{"queued": len(evs)}, nil
}

// edr.status: per collector, what it sent and whether the manager answers
func edrStatus(r req) (map[string]any, error) {
	edrMu.Lock()
	defer edrMu.Unlock()
	out := map[string]any{}
	for k, c := range edrCols {
		c.mu.Lock()
		out[k] = map[string]any{"manager": c.mgr, "sent": c.sent, "queued": len(c.queue), "dropped": c.dropped, "last_ok_ms": c.lastOK.UnixMilli(), "error": c.lastErr}
		c.mu.Unlock()
	}
	return map[string]any{"collectors": out}, nil
}

// edr.kill: {ns, pid}: only a process in that host's cgroup
func edrKill(r req) (map[string]any, error) {
	ns, pid := r.str("ns"), int(r.num("pid", 0))
	if err := checkNS(ns); err != nil {
		return nil, err
	}
	procs, _ := os.ReadFile(filepath.Join(cgRoot, "ftk", ns, "cgroup.procs"))
	for _, p := range strings.Fields(string(procs)) {
		if p == strconv.Itoa(pid) && pid > 1 {
			return map[string]any{"killed": syscall.Kill(pid, syscall.SIGKILL) == nil}, nil
		}
	}
	return map[string]any{"killed": false, "error": "no such process on this host"}, nil
}

// edr.block: {ns, ip}: drop traffic to a destination in the host's own firewall
func edrBlock(r req) (map[string]any, error) {
	ns, ip := r.str("ns"), r.str("ip")
	if err := checkNS(ns); err != nil {
		return nil, err
	}
	if net.ParseIP(ip) == nil {
		return nil, fmt.Errorf("bad address")
	}
	_, e, code, err := run(5*time.Second, "", "ip", "netns", "exec", ns, "sh", "-c",
		fmt.Sprintf("nft list table ip ftkedr >/dev/null 2>&1 || nft 'add table ip ftkedr; add chain ip ftkedr out { type filter hook output priority -5; policy accept; }'; nft add rule ip ftkedr out ip daddr %s drop", ip))
	if err != nil || code != 0 {
		return map[string]any{"blocked": false, "error": strings.TrimSpace(e)}, nil
	}
	return map[string]any{"blocked": true}, nil
}

// ---- new connections, as they happen: the host's nftables logs each new outbound flow to the
// kernel log with the prefix "FTKE <host> " (compiled by the app), read here from /dev/kmsg.
var kmsgOnce sync.Once

func edrKmsg() {
	f, err := os.Open("/dev/kmsg")
	if err != nil {
		return
	}
	f.Seek(0, 2) // only what happens from now on
	buf := make([]byte, 8192)
	for {
		n, err := f.Read(buf)
		if err != nil {
			if err == syscall.EPIPE { // overwritten while we read: carry on
				continue
			}
			time.Sleep(time.Second)
			continue
		}
		line := string(buf[:n])
		i := strings.Index(line, "FTKE ")
		if i < 0 {
			continue
		}
		rest := line[i+5:]
		ns, kv, _ := strings.Cut(rest, " ")
		edrMu.Lock()
		c := edrCols[ns]
		edrMu.Unlock()
		if c == nil {
			continue
		}
		fields := map[string]string{}
		for _, w := range strings.Fields(kv) {
			if k, v, ok := strings.Cut(w, "="); ok {
				fields[k] = v
			}
		}
		dport, _ := strconv.Atoi(fields["DPT"])
		sport, _ := strconv.Atoi(fields["SPT"])
		proto := strings.ToLower(fields["PROTO"])
		if fields["DST"] == "" || fields["DST"] == "127.0.0.1" {
			continue
		}
		ev := edrEvent{"kind": "net", "proto": proto, "src": fields["SRC"], "sport": sport, "dst": fields["DST"], "dport": dport, "state": "new"}
		if pid := c.ownerOf(proto, sport); pid > 0 {
			ppid, comm, cmd, user := procInfo(pid)
			_, pcomm, _, _ := procInfo(ppid)
			ev["pid"], ev["process"], ev["cmd"], ev["parent"], ev["ppid"], ev["user"] = pid, comm, cmd, pcomm, ppid, user
		}
		c.mu.Lock()
		if c.seenConn != nil {
			c.seenConn[fmt.Sprintf("%s:%d>%s:%d", fields["SRC"], sport, fields["DST"], dport)] = true
		}
		c.mu.Unlock()
		c.push(ev)
	}
}

// ownerOf finds the host process that owns a local port right now (its socket's inode)
func (c *collector) ownerOf(proto string, sport int) int {
	file := "/proc/thread-self/net/tcp"
	if proto == "udp" {
		file = "/proc/thread-self/net/udp"
	}
	inode := ""
	withNetns(c.ns, func() error {
		b, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		for _, l := range strings.Split(string(b), "\n")[1:] {
			f := strings.Fields(l)
			if len(f) > 9 {
				if _, p := hexAddr(f[1]); p == sport {
					inode = f[9]
				}
			}
		}
		return nil
	})
	if inode == "" || !cgReady {
		return 0
	}
	procs, _ := os.ReadFile(filepath.Join(cgRoot, "ftk", c.ns, "cgroup.procs"))
	for _, p := range strings.Fields(string(procs)) {
		fds, _ := os.ReadDir("/proc/" + p + "/fd")
		for _, fd := range fds {
			if l, err := os.Readlink("/proc/" + p + "/fd/" + fd.Name()); err == nil && l == "socket:["+inode+"]" {
				pid, _ := strconv.Atoi(p)
				return pid
			}
		}
	}
	return 0
}
