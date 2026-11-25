package ftkos

// The lab VM: one warm FortiTatake OS that runs the lab on screen. The app compiles the lab
// (web/js/labs/compile.js) and drives the agent through engine/lab/call; the VM boots on the
// first call and powers off after ten idle minutes.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
)

const labIdle = 10 * time.Minute

var labOps = map[string]time.Duration{
	"hello": 5 * time.Second, "mem": 5 * time.Second, "topo.apply": 60 * time.Second, "topo.clear": 20 * time.Second,
	"ns.nft": 20 * time.Second, "ns.state": 10 * time.Second, "ns.exec": 20 * time.Second, "ns.link": 10 * time.Second,
	"listen.start": 10 * time.Second, "listen.log": 5 * time.Second, "probe": 15 * time.Second,
	"capture.start": 10 * time.Second, "capture.stop": 20 * time.Second,
	"shell.open": 10 * time.Second, "shell.write": 5 * time.Second, "shell.read": 5 * time.Second,
	"shell.signal": 5 * time.Second, "shell.close": 5 * time.Second,
}

func (m *Manager) labVM() (*VM, error) {
	m.labMu.Lock()
	defer m.labMu.Unlock()
	if m.lab != nil {
		select {
		case <-m.lab.exited:
			m.lab = nil
		default:
		}
	}
	if m.lab == nil {
		m.emit("vm", map[string]any{"state": "booting", "for": "lab"})
		vm, err := m.Boot(context.Background(), 256)
		if err != nil {
			return nil, err
		}
		m.lab = vm
		m.emit("vm", map[string]any{"state": "running", "for": "lab", "accel": vm.Accel, "boot_ms": time.Since(vm.Start).Milliseconds()})
		go m.labReaper(vm)
	}
	m.labUsed = time.Now()
	return m.lab, nil
}

func (m *Manager) labReaper(vm *VM) {
	for {
		select {
		case <-vm.exited:
			return
		case <-time.After(30 * time.Second):
		}
		m.labMu.Lock()
		idle := m.lab == vm && time.Since(m.labUsed) > labIdle
		if idle {
			m.lab = nil
		}
		m.labMu.Unlock()
		if idle {
			vm.Stop()
			m.emit("vm", map[string]any{"state": "stopped", "for": "lab", "why": "idle"})
			return
		}
	}
}

func (m *Manager) labStop() {
	m.labMu.Lock()
	vm := m.lab
	m.lab = nil
	m.labMu.Unlock()
	if vm != nil {
		vm.Stop()
		m.emit("vm", map[string]any{"state": "stopped", "for": "lab"})
	}
}

func (m *Manager) labInfo() map[string]any {
	m.labMu.Lock()
	defer m.labMu.Unlock()
	if m.lab == nil {
		return map[string]any{"running": false}
	}
	return map[string]any{"running": true, "accel": m.lab.Accel, "rss": m.lab.RSS(), "up_s": int(time.Since(m.lab.Start).Seconds())}
}

// labCall handles POST engine/lab/call: one agent request, passed through.
func (m *Manager) labCall(w http.ResponseWriter, r *http.Request) {
	var req map[string]any
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<20)).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"ok": false, "err": "bad request"})
		return
	}
	op, _ := req["op"].(string)
	to, ok := labOps[op]
	if !ok {
		writeJSON(w, 400, map[string]any{"ok": false, "err": "op not allowed: " + op})
		return
	}
	vm, err := m.labVM()
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "err": err.Error(), "boot": true})
		return
	}
	res, err := vm.Call(req, to)
	if err != nil && res == nil {
		if errors.Is(err, errVMStopped) || err.Error() == "the VM stopped" {
			m.labMu.Lock()
			if m.lab == vm {
				m.lab = nil
			}
			m.labMu.Unlock()
		}
		writeJSON(w, 200, map[string]any{"ok": false, "err": err.Error()})
		return
	}
	writeJSON(w, 200, res)
}

var errVMStopped = errors.New("the VM stopped")
