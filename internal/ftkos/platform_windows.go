//go:build windows

package ftkos

import (
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

func hideWindow(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
}

func powershell(cmd string) string {
	c := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", cmd)
	hideWindow(c)
	out, _ := c.Output()
	return strings.TrimSpace(string(out))
}

func processRSS(pid int) int64 {
	n, _ := strconv.ParseInt(powershell("(Get-Process -Id "+strconv.Itoa(pid)+").WorkingSet64"), 10, 64)
	return n
}

func deviceInfo() map[string]any {
	ram, _ := strconv.ParseInt(powershell("(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory"), 10, 64)
	return map[string]any{
		"os": "windows", "arch": runtime.GOARCH, "logical_cpus": runtime.NumCPU(),
		"cpu": powershell("(Get-CimInstance Win32_Processor | Select-Object -First 1).Name"),
		"ram_bytes": ram,
		"hypervisor_platform": powershell("(Get-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -ErrorAction SilentlyContinue).State"),
	}
}
