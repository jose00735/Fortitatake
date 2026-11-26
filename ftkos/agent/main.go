// ftk-agent: the lab agent inside FortiTatake OS.
//
// It is deliberately thin. FortiTatake (the app) compiles configs and formats output;
// the agent only builds the lab topology out of network namespaces, applies what it is
// given, runs commands inside a device, sends probes and returns raw state.
//
// Protocol: one JSON object per line, both ways, over the virtio console (/dev/hvc0)
// or stdin/stdout (--stdio, for tests). Requests carry "id" and "op"; every reply
// echoes the id with "ok" and either results or "err".
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

const agentVersion = "0.10.2"

var started = time.Now()

var opLock sync.RWMutex

var mutating = map[string]bool{
	"topo.apply": true, "topo.clear": true, "ns.nft": true, "ns.link": true,
	"service.start": true, "service.stop": true, "bench": true, "listen.start": true,
}

type req map[string]any

func (r req) str(k string) string {
	if v, ok := r[k].(string); ok {
		return v
	}
	return ""
}

func (r req) num(k string, def float64) float64 {
	if v, ok := r[k].(float64); ok {
		return v
	}
	return def
}

func (r req) strs(k string) []string {
	var out []string
	if a, ok := r[k].([]any); ok {
		for _, x := range a {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

type writer struct {
	mu sync.Mutex
	w  io.Writer
}

func (w *writer) send(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		b, _ = json.Marshal(map[string]any{"ok": false, "err": err.Error()})
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.w.Write(append(b, '\n'))
}

func main() {
	port := flag.String("port", "", "serial device to talk on, e.g. /dev/hvc0")
	stdio := flag.Bool("stdio", false, "talk on stdin/stdout (tests)")
	flag.Parse()
	runtime.GOMAXPROCS(1) // tiny VM: one CPU for the agent is plenty
	var in io.Reader
	var out io.Writer
	switch {
	case *stdio:
		in, out = os.Stdin, os.Stdout
	case *port != "":
		f, err := os.OpenFile(*port, os.O_RDWR, 0)
		if err != nil {
			log.Fatalf("open %s: %v", *port, err)
		}
		makeRaw(f)
		in, out = f, f
	default:
		log.Fatal("give --port or --stdio")
	}
	w := &writer{w: out}
	w.send(map[string]any{"ev": "ready", "ver": agentVersion, "uptime_ms": uptimeMS()})
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r req
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			w.send(map[string]any{"ok": false, "err": "bad json: " + err.Error()})
			continue
		}
		// Changes run one at a time and in order; reads and probes may overlap them only
		// after every earlier change has finished.
		if op := r.str("op"); op == "relay.wait" || op == "relay.answer" {
			go handle(w, r) // the Internet relay never waits for, or holds up, topology changes
		} else if mutating[op] {
			opLock.Lock()
			go func(r req) { defer opLock.Unlock(); handle(w, r) }(r)
		} else {
			opLock.RLock()
			go func(r req) { defer opLock.RUnlock(); handle(w, r) }(r)
		}
	}
}

func handle(w *writer, r req) {
	id := r["id"]
	defer func() {
		if p := recover(); p != nil {
			w.send(map[string]any{"id": id, "ok": false, "err": fmt.Sprint("panic: ", p)})
		}
	}()
	res, err := dispatch(r)
	if err != nil {
		w.send(map[string]any{"id": id, "ok": false, "err": err.Error()})
		return
	}
	if res == nil {
		res = map[string]any{}
	}
	res["id"] = id
	res["ok"] = true
	w.send(res)
}

func dispatch(r req) (map[string]any, error) {
	switch r.str("op") {
	case "hello":
		return hello(), nil
	case "topo.apply":
		return topoApply(r)
	case "topo.clear":
		return topoClear()
	case "ns.exec":
		return nsExec(r)
	case "ns.nft":
		return nsNft(r)
	case "ns.state":
		return nsState(r)
	case "ns.link":
		return nsLink(r)
	case "probe":
		return probe(r)
	case "capture.start":
		return captureStart(r)
	case "capture.stop":
		return captureStop(r)
	case "service.start":
		return serviceStart(r)
	case "service.stop":
		return serviceStop(r)
	case "listen.start":
		return listenStart(r)
	case "listen.log":
		return listenLog(r)
	case "send":
		return sendLines(r)
	case "shell.open":
		return shellOpen(r)
	case "shell.write":
		return shellWrite(r)
	case "shell.read":
		return shellRead(r)
	case "shell.signal":
		return shellSignal(r)
	case "shell.close":
		return shellClose(r)
	case "dns.query":
		return dnsQuery(r)
	case "relay.wait":
		return relayWait(r)
	case "relay.answer":
		return relayAnswer(r)
	case "console.poll":
		return consolePoll(r)
	case "console.reply":
		return consoleReply(r)
	case "remote.open":
		return remoteOpen(r)
	case "remote.send":
		return remoteSend(r)
	case "remote.read":
		return remoteRead(r)
	case "remote.close":
		return remoteClose(r)
	case "bench":
		return bench(r)
	case "mem":
		return map[string]any{"mem": meminfo()}, nil
	}
	return nil, fmt.Errorf("unknown op %q", r.str("op"))
}

func hello() map[string]any {
	b, _ := os.ReadFile("/etc/ftkos-build")
	k, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	return map[string]any{
		"ver":       agentVersion,
		"relay":     relayStats(),
		"build":     strings.TrimSpace(string(b)),
		"kernel":    strings.TrimSpace(string(k)),
		"arch":      runtime.GOARCH,
		"cpus":      runtime.NumCPU(),
		"uptime_ms": uptimeMS(),
		"mem":       meminfo(),
	}
}

func uptimeMS() int64 {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return time.Since(started).Milliseconds()
	}
	var s float64
	fmt.Sscanf(string(b), "%f", &s)
	return int64(s * 1000)
}

func meminfo() map[string]int64 {
	b, _ := os.ReadFile("/proc/meminfo")
	out := map[string]int64{}
	for _, l := range strings.Split(string(b), "\n") {
		var k string
		var v int64
		if n, _ := fmt.Sscanf(strings.Replace(l, ":", " ", 1), "%s %d", &k, &v); n == 2 {
			switch k {
			case "MemTotal", "MemFree", "MemAvailable", "Buffers", "Cached", "Shmem", "Slab":
				out[k+"_kb"] = v
			}
		}
	}
	return out
}
