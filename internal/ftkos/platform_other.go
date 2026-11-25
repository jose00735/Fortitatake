//go:build !windows

package ftkos

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

func hideWindow(*exec.Cmd) {}

func processRSS(pid int) int64 {
	b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	for _, l := range strings.Split(string(b), "\n") {
		var kb int64
		if n, _ := fmt.Sscanf(l, "VmRSS: %d kB", &kb); n == 1 {
			return kb * 1024
		}
	}
	return 0
}

// deviceInfo describes this machine; on a phone the CPU parts identify its cores,
// which the PC uses to tune the ARM64 build.
func deviceInfo() map[string]any {
	info := map[string]any{"os": runtime.GOOS, "arch": runtime.GOARCH, "logical_cpus": runtime.NumCPU()}
	b, _ := os.ReadFile("/proc/cpuinfo")
	parts := map[string]int{}
	for _, l := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "model name", "Hardware":
			info["cpu"] = v
		case "CPU part":
			parts[v]++
		case "Features":
			info["features"] = v
		}
	}
	if len(parts) > 0 {
		info["cpu_parts"] = parts
	}
	m, _ := os.ReadFile("/proc/meminfo")
	var kb int64
	fmt.Sscanf(strings.SplitN(string(m), "\n", 2)[0], "MemTotal: %d kB", &kb)
	info["ram_bytes"] = kb * 1024
	return info
}
