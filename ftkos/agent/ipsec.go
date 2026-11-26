package main

// IKE inside lab namespaces (stage 6): FortiTatake compiles each FortiGate's phase1-interface and
// phase2-interface entries (and a lab router's ipsec spec) into a swanctl configuration, and the
// agent runs one strongSwan charon per namespace, so tunnels come up from a real IKEv1/IKEv2
// exchange: proposals, DH groups, the pre-shared key, IDs and traffic selectors all have to agree.
// charon keeps its pid file and vici socket in /var/run, so each instance gets a private mount
// namespace (ip netns exec makes one) with its own directory bound over /var/run.

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var charonBin = func() string {
	for _, p := range []string{"/usr/lib/ipsec/charon", "/usr/libexec/ipsec/charon", "/usr/lib/strongswan/charon"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}()

func ipsecAvailable() bool {
	if charonBin == "" {
		return false
	}
	_, err := os.Stat("/usr/sbin/swanctl")
	return err == nil
}

func ipsecDir(ns string) string { return filepath.Join("/run/ftk/ipsec", ns) }

// what charon loads; plugins missing from a build are skipped
const strongswanConf = `swanctl {
  load = pem pkcs1 x509 pubkey openssl random nonce
}
charon {
  load_modular = no
  load = random nonce openssl aes des sha1 sha2 md5 hmac gcm xcbc kdf drbg pem pkcs1 pkcs8 x509 pubkey kernel-netlink socket-default vici updown
  install_routes = no
  install_virtual_ip = no
  retransmit_tries = 3
  retransmit_timeout = 1.0
  retransmit_base = 1.4
  i_dont_care_about_security_and_use_aggressive_mode_psk = yes
  plugins {
    vici { socket = unix:///var/run/charon.vici }
  }
  syslog { daemon { default = -1 } }
  filelog {
    ftk {
      path = /var/run/charon.log
      time_format = %b %e %T
      flush_line = yes
      default = 1
      ike = 1
      cfg = 1
      knl = 0
      net = 0
      enc = 0
    }
  }
}
`

func ipsecStopNS(ns string) {
	dir := ipsecDir(ns)
	if b, err := os.ReadFile(filepath.Join(dir, "charon.pid")); err == nil {
		if pid, _ := strconv.Atoi(strings.TrimSpace(string(b))); pid > 1 {
			syscall.Kill(pid, syscall.SIGTERM)
			for i := 0; i < 20 && syscall.Kill(pid, 0) == nil; i++ {
				time.Sleep(50 * time.Millisecond)
			}
			syscall.Kill(pid, syscall.SIGKILL)
		}
	}
	os.RemoveAll(dir)
}

func ipsecStopAll() {
	ents, _ := os.ReadDir("/run/ftk/ipsec")
	for _, e := range ents {
		ipsecStopNS(e.Name())
	}
}

func swanctl(ns string, timeout time.Duration, args ...string) (string, string, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/sbin/swanctl", append(args, "--uri", "unix://"+filepath.Join(ipsecDir(ns), "charon.vici"))...)
	cmd.Env = append(os.Environ(), "STRONGSWAN_CONF="+filepath.Join(ipsecDir(ns), "strongswan.conf"))
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &limited{b: &o}, &limited{b: &e}
	err := cmd.Run()
	code := 0
	if err != nil {
		if x, ok := err.(*exec.ExitError); ok {
			code, err = x.ExitCode(), nil
			if code < 0 {
				e.WriteString(x.String())
			}
		}
	}
	return o.String(), e.String(), code, err
}

// ipsec.apply: {ns, conf}: (re)start charon in a namespace and load this swanctl.conf
// (connections and secrets); an empty conf stops it
func ipsecApply(r req) (map[string]any, error) {
	ns, conf := r.str("ns"), r.str("conf")
	if err := checkNS(ns); err != nil {
		return nil, err
	}
	if !ipsecAvailable() {
		return nil, fmt.Errorf("this FortiTatake OS image has no strongSwan (rebuild it)")
	}
	ipsecStopNS(ns)
	if conf == "" {
		return map[string]any{"running": false}, nil
	}
	dir := ipsecDir(ns)
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "strongswan.conf"), []byte(strongswanConf), 0o644)
	if err := os.WriteFile(filepath.Join(dir, "swanctl.conf"), []byte(conf), 0o600); err != nil {
		return nil, err
	}
	// daemonize through the shell: the private mount stays with charon
	sh := fmt.Sprintf("mount -o bind %s /var/run && STRONGSWAN_CONF=/var/run/strongswan.conf exec %s </dev/null >/dev/null 2>&1 &", dir, charonBin)
	if _, e, code, err := run(5*time.Second, "", "ip", "netns", "exec", ns, "sh", "-c", sh); err != nil || code != 0 {
		return map[string]any{"running": false, "error": "charon: " + strings.TrimSpace(e)}, nil
	}
	sock := filepath.Join(dir, "charon.vici")
	for i := 0; i < 60; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	var o, e string
	var code int
	var err error
	for try := 0; try < 3; try++ { // the vici socket can appear a moment before charon accepts on it
		if o, e, code, err = swanctl(ns, 10*time.Second, "--load-all", "--noprompt", "--file", filepath.Join(dir, "swanctl.conf")); err == nil && code == 0 {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if err != nil || code != 0 {
		msg := strings.TrimSpace(e + " " + o)
		if err != nil {
			msg += " " + err.Error()
		}
		return map[string]any{"running": true, "error": fmt.Sprintf("swanctl (%d): %s", code, msg)}, nil
	}
	return map[string]any{"running": true}, nil
}

var (
	reIKE   = regexp.MustCompile(`^([\w.-]+): #(\d+), (\w+), (IKEv\d)`)
	reChild = regexp.MustCompile(`^\s+([\w.-]+): #\d+, reqid \d+, (\w+), \w+, (\S+)`)
)

// ipsec.show: {ns, lines}: the SAs charon holds now ({conn: {state, version, children: {name: state}}})
// and the last lines of its log
func ipsecShow(r req) (map[string]any, error) {
	ns := r.str("ns")
	if err := checkNS(ns); err != nil {
		return nil, err
	}
	dir := ipsecDir(ns)
	if _, err := os.Stat(filepath.Join(dir, "charon.vici")); err != nil {
		return map[string]any{"running": false, "sas": map[string]any{}}, nil
	}
	out, _, _, _ := swanctl(ns, 8*time.Second, "--list-sas", "--noblock")
	sas := map[string]any{}
	var cur map[string]any
	for _, l := range strings.Split(out, "\n") {
		if m := reIKE.FindStringSubmatch(l); m != nil {
			c, _ := sas[m[1]].(map[string]any)
			if c == nil || m[3] == "ESTABLISHED" {
				c = map[string]any{"state": m[3], "version": m[4], "children": map[string]any{}}
				sas[m[1]] = c
			}
			cur = c
			continue
		}
		if m := reChild.FindStringSubmatch(l); m != nil && cur != nil {
			ch := cur["children"].(map[string]any)
			if ch[m[1]] != "INSTALLED" {
				ch[m[1]] = m[2]
			}
			cur["proposal_"+m[1]] = m[3]
		}
	}
	res := map[string]any{"running": true, "sas": sas, "raw": out}
	if n := int(r.num("lines", 0)); n > 0 {
		b, _ := os.ReadFile(filepath.Join(dir, "charon.log"))
		ls := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
		if len(ls) > n {
			ls = ls[len(ls)-n:]
		}
		res["log"] = ls
	}
	return res, nil
}
