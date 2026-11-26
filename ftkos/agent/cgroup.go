package main

// Per-device cgroups (cgroup v2). Every process the agent starts inside a lab device's
// namespace (lab shells, services) is placed in /sys/fs/cgroup/ftk/<device>, so its CPU and
// memory are capped and measured by the kernel. The caps keep a runaway command from
// freezing the phone or the PC; the counters are what the EDR collectors read later.
//
// The kernel needs CONFIG_CGROUPS, CONFIG_MEMCG and CONFIG_CFS_BANDWIDTH (FortiTatake OS 0.11+).
// On an older image cgReady stays false and processes simply run uncapped.

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

const cgRoot = "/sys/fs/cgroup"

var (
	cgOnce  sync.Once
	cgReady bool
	cgErr   string
	cgMu    sync.Mutex
	cgCaps  = map[string][2]int{} // device -> {cpu percent of one core, memory MB}
)

// default caps per device: half a core and 96 MB; the whole lab: 60% of the VM's memory
const cgDefCPU, cgDefMem = 50, 96

func cgInit() bool {
	cgOnce.Do(func() {
		if _, err := os.Stat(filepath.Join(cgRoot, "cgroup.controllers")); err != nil {
			os.MkdirAll(cgRoot, 0o755)
			if err := syscall.Mount("cgroup2", cgRoot, "cgroup2", 0, ""); err != nil {
				cgErr = "this FortiTatake OS image has no cgroups (rebuild it): " + err.Error()
				return
			}
		}
		ctl, _ := os.ReadFile(filepath.Join(cgRoot, "cgroup.controllers"))
		for _, c := range []string{"cpu", "memory", "pids"} {
			if !strings.Contains(" "+string(ctl)+" ", " "+c+" ") && !strings.Contains(string(ctl), c) {
				cgErr = "the kernel lacks the " + c + " controller"
				return
			}
		}
		if err := os.WriteFile(filepath.Join(cgRoot, "cgroup.subtree_control"), []byte("+cpu +memory +pids"), 0o644); err != nil {
			cgErr = "cannot enable cgroup controllers: " + err.Error()
			return
		}
		ftk := filepath.Join(cgRoot, "ftk")
		os.MkdirAll(ftk, 0o755)
		if err := os.WriteFile(filepath.Join(ftk, "cgroup.subtree_control"), []byte("+cpu +memory +pids"), 0o644); err != nil {
			cgErr = "cannot enable controllers for the lab: " + err.Error()
			return
		}
		if total := memTotalKB(); total > 0 {
			os.WriteFile(filepath.Join(ftk, "memory.max"), []byte(strconv.Itoa(total*1024*6/10)), 0o644)
		}
		cgReady = true
	})
	return cgReady
}

func memTotalKB() int {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Fields(l); len(f) >= 2 && f[0] == "MemTotal:" {
			n, _ := strconv.Atoi(f[1])
			return n
		}
	}
	return 0
}

// cgDir creates (once) and returns the device's cgroup directory, with its caps applied.
func cgDir(ns string) (string, error) {
	if !cgInit() {
		return "", fmt.Errorf("%s", cgErr)
	}
	d := filepath.Join(cgRoot, "ftk", ns)
	if _, err := os.Stat(d); err != nil {
		if err := os.Mkdir(d, 0o755); err != nil && !os.IsExist(err) {
			return "", err
		}
		cgMu.Lock()
		c, ok := cgCaps[ns]
		cgMu.Unlock()
		if !ok {
			c = [2]int{cgDefCPU, cgDefMem}
		}
		cgApply(d, c)
	}
	return d, nil
}

func cgApply(d string, c [2]int) {
	os.WriteFile(filepath.Join(d, "cpu.max"), []byte(fmt.Sprintf("%d 100000", c[0]*1000)), 0o644)
	os.WriteFile(filepath.Join(d, "memory.max"), []byte(strconv.Itoa(c[1]<<20)), 0o644)
	os.WriteFile(filepath.Join(d, "memory.swap.max"), []byte("0"), 0o644)
	os.WriteFile(filepath.Join(d, "pids.max"), []byte("256"), 0o644)
}

// cgAttr returns process attributes that start the child directly inside the device's
// cgroup (clone3 with CLONE_INTO_CGROUP), so nothing it forks escapes the cap.
// The caller closes the returned file after Start.
func cgAttr(ns string, base *syscall.SysProcAttr) (*syscall.SysProcAttr, *os.File) {
	if base == nil {
		base = &syscall.SysProcAttr{}
	}
	d, err := cgDir(ns)
	if err != nil {
		return base, nil
	}
	f, err := os.Open(d)
	if err != nil {
		return base, nil
	}
	base.UseCgroupFD = true
	base.CgroupFD = int(f.Fd())
	return base, f
}

func cgReadInt(d, name string) int64 {
	b, err := os.ReadFile(filepath.Join(d, name))
	if err != nil {
		return -1
	}
	n, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	return n
}

func cgKV(d, name string) map[string]int64 {
	out := map[string]int64{}
	b, err := os.ReadFile(filepath.Join(d, name))
	if err != nil {
		return out
	}
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Fields(l); len(f) == 2 {
			n, _ := strconv.ParseInt(f[1], 10, 64)
			out[f[0]] = n
		}
	}
	return out
}

// cg.stat: the kernel's counters for one device or all of them
func cgStat(r req) (map[string]any, error) {
	if !cgInit() {
		return map[string]any{"ready": false, "error": cgErr}, nil
	}
	want := r.str("ns")
	ents, _ := os.ReadDir(filepath.Join(cgRoot, "ftk"))
	devs := map[string]any{}
	for _, e := range ents {
		if !e.IsDir() || (want != "" && e.Name() != want) {
			continue
		}
		d := filepath.Join(cgRoot, "ftk", e.Name())
		cpu := cgKV(d, "cpu.stat")
		procs, _ := os.ReadFile(filepath.Join(d, "cgroup.procs"))
		pids := []int{}
		for _, p := range strings.Fields(string(procs)) {
			n, _ := strconv.Atoi(p)
			pids = append(pids, n)
		}
		devs[e.Name()] = map[string]any{
			"cpu_usec": cpu["usage_usec"], "throttled_usec": cpu["throttled_usec"], "nr_throttled": cpu["nr_throttled"],
			"mem": cgReadInt(d, "memory.current"), "mem_peak": cgReadInt(d, "memory.peak"), "mem_max": cgReadInt(d, "memory.max"),
			"oom_kill": cgKV(d, "memory.events")["oom_kill"], "pids": pids,
		}
	}
	return map[string]any{"ready": true, "devices": devs}, nil
}

// cg.set: change one device's caps (CPU percent of one core, memory MB)
func cgSet(r req) (map[string]any, error) {
	ns := r.str("ns")
	if err := checkNS(ns); err != nil {
		return nil, err
	}
	c := [2]int{int(r.num("cpu_pct", cgDefCPU)), int(r.num("mem_mb", cgDefMem))}
	if c[0] < 5 || c[0] > 100 || c[1] < 16 || c[1] > 512 {
		return nil, fmt.Errorf("caps out of range (cpu 5-100 %%, memory 16-512 MB)")
	}
	cgMu.Lock()
	cgCaps[ns] = c
	cgMu.Unlock()
	d, err := cgDir(ns)
	if err != nil {
		return map[string]any{"ready": false, "error": err.Error()}, nil
	}
	cgApply(d, c)
	return map[string]any{"ready": true}, nil
}

// a device that goes away takes its cgroup with it (only possible once its processes ended)
func cgRemove(ns string) {
	if cgReady {
		os.Remove(filepath.Join(cgRoot, "ftk", ns))
	}
}
