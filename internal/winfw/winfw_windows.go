//go:build windows

package winfw

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

const createNoWindow = 0x08000000

func hidden(name string, args ...string) *exec.Cmd {
	c := exec.Command(name, args...)
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
	return c
}

// Check reads the network categories and whether our rules exist. No admin rights needed.
func Check(port int) Status {
	st := Status{Supported: true, Port: port}
	out, err := hidden("powershell", "-NoProfile", "-NonInteractive", "-Command",
		"(Get-NetConnectionProfile | ForEach-Object { $_.NetworkCategory }) -join ','").Output()
	if err != nil {
		st.Error = "couldn't read the network profile"
	} else {
		for _, p := range strings.Split(strings.TrimSpace(string(out)), ",") {
			if p = strings.TrimSpace(p); p != "" {
				st.Profiles = append(st.Profiles, p)
			}
		}
	}
	tcp := hidden("netsh", "advfirewall", "firewall", "show", "rule", "name="+RuleName+" (TCP)")
	if out, err := tcp.Output(); err == nil && strings.Contains(string(out), fmt.Sprint(port)) {
		st.RuleOK = true
	}
	return st
}

// Fix asks Windows (UAC prompt) to add inbound rules for this exe: TCP <port> for sync
// and UDP 5353 for discovery, only from the local subnet. It returns once the prompt
// has been shown; the caller re-checks the status afterwards.
func Fix(port int) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	rule := func(proto, ports string) string {
		n := RuleName + " (" + proto + ")"
		return fmt.Sprintf(`netsh advfirewall firewall delete rule name="%s" >nul 2>&1 & netsh advfirewall firewall add rule name="%s" dir=in action=allow program="%s" protocol=%s localport=%s remoteip=localsubnet profile=any`,
			n, n, exe, proto, ports)
	}
	args := "/c " + rule("TCP", fmt.Sprint(port)) + " & " + rule("UDP", "5353")
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString("cmd.exe")
	a, _ := windows.UTF16PtrFromString(args)
	if err := windows.ShellExecute(0, verb, file, a, nil, windows.SW_HIDE); err != nil {
		return fmt.Errorf("Windows didn't run the firewall change (was the prompt cancelled?): %v", err)
	}
	return nil
}
