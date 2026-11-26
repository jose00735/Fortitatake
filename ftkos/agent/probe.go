package main

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// probe sends one real piece of traffic from inside a device and reports what happened.
// The grader and the device consoles use it; FortiTatake explains the result.
func probe(r req) (map[string]any, error) {
	ns := r.str("ns")
	if err := checkNS(ns); err != nil {
		return nil, err
	}
	proto := r.str("proto")
	dst := r.str("dst")
	port := int(r.num("port", 0))
	to := time.Duration(r.num("timeout_ms", 3000)) * time.Millisecond
	if proto == "icmp" {
		return pingProbe(ns, dst, int(r.num("count", 1)), int(r.num("ttl", 0)), to)
	}
	var res map[string]any
	err := withNetns(ns, func() error {
		t := time.Now()
		switch proto {
		case "tcp":
			c, err := net.DialTimeout("tcp", net.JoinHostPort(dst, strconv.Itoa(port)), to)
			res = result(t, err)
			if c != nil {
				res["local"] = c.LocalAddr().String()
				c.Close()
			}
		case "http", "https":
			res = httpProbe(proto, dst, port, r.str("host"), r.str("path"), to, time.Duration(r.num("hold_ms", 0))*time.Millisecond)
		case "dns":
			res = dnsProbe(dst, r.str("name"), to)
		case "udp":
			c, err := net.DialTimeout("udp", net.JoinHostPort(dst, strconv.Itoa(port)), to)
			if err == nil {
				_, err = c.Write([]byte(r.str("payload")))
				c.Close()
			}
			res = result(t, err)
		default:
			return fmt.Errorf("unknown proto %q", proto)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func result(t time.Time, err error) map[string]any {
	m := map[string]any{"ok": err == nil, "ms": float64(time.Since(t).Microseconds()) / 1000}
	if err != nil {
		m["ok"] = true // the request itself worked; the probe failed
		m["pass"] = false
		m["error"] = classify(err)
		m["detail"] = err.Error()
	} else {
		m["pass"] = true
	}
	return m
}

func classify(err error) string {
	s := err.Error()
	switch {
	case strings.Contains(s, "refused"):
		return "refused"
	case strings.Contains(s, "timeout"), strings.Contains(s, "deadline"):
		return "timeout"
	case strings.Contains(s, "unreachable"):
		return "unreachable"
	case strings.Contains(s, "reset"):
		return "reset"
	}
	return "error"
}

func httpProbe(proto, dst string, port int, host, path string, to, hold time.Duration) map[string]any {
	t := time.Now()
	if port == 0 {
		port = 80
		if proto == "https" {
			port = 443
		}
	}
	if path == "" {
		path = "/"
	}
	if host == "" {
		host = dst
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort(dst, strconv.Itoa(port)), to)
	if err != nil {
		return result(t, err)
	}
	held := false
	defer func() {
		if !held {
			c.Close()
		}
	}()
	c.SetDeadline(time.Now().Add(to))
	var conn net.Conn = c
	m := map[string]any{}
	if proto == "https" {
		tc := tls.Client(c, &tls.Config{ServerName: host, InsecureSkipVerify: true})
		if err := tc.Handshake(); err != nil {
			r := result(t, err)
			r["error"] = "tls"
			return r
		}
		st := tc.ConnectionState()
		m["tls_version"] = tls.VersionName(st.Version)
		m["tls_suite"] = tls.CipherSuiteName(st.CipherSuite)
		conn = tc
	}
	cn := "close"
	if hold > 0 {
		cn = "keep-alive"
	}
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: curl/8\r\nConnection: %s\r\n\r\n", path, host, cn)
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return result(t, err)
	}
	r := result(t, nil)
	for k, v := range m {
		r[k] = v
	}
	r["status"] = strings.TrimSpace(line)
	body := make([]byte, 4096)
	n, _ := br.Read(body)
	r["head"] = string(body[:n])
	if hold > 0 { // keep the connection open, idle, like a browser's keep-alive
		held = true
		go func() {
			conn.SetDeadline(time.Now().Add(hold))
			io.Copy(io.Discard, conn)
			conn.Close()
		}()
	}
	return r
}

// dnsProbe sends one A query and returns the answers.
func dnsProbe(server, name string, to time.Duration) map[string]any {
	t := time.Now()
	c, err := net.DialTimeout("udp", net.JoinHostPort(server, "53"), to)
	if err != nil {
		return result(t, err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(to))
	id := uint16(rand.Intn(65535))
	q := make([]byte, 12)
	binary.BigEndian.PutUint16(q[0:], id)
	binary.BigEndian.PutUint16(q[2:], 0x0100) // recursion desired
	binary.BigEndian.PutUint16(q[4:], 1)
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0, 0, 1, 0, 1)
	if _, err := c.Write(q); err != nil {
		return result(t, err)
	}
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	if err != nil {
		return result(t, err)
	}
	r := result(t, nil)
	if n < 12 {
		r["pass"], r["error"] = false, "short reply"
		return r
	}
	rcode := buf[3] & 0x0f
	r["rcode"] = map[byte]string{0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}[rcode]
	r["answers"] = parseA(buf[:n])
	if rcode != 0 {
		r["pass"] = false
	}
	return r
}

func parseA(b []byte) []string {
	qd := int(binary.BigEndian.Uint16(b[4:]))
	an := int(binary.BigEndian.Uint16(b[6:]))
	i := 12
	skipName := func() {
		for i < len(b) {
			l := int(b[i])
			if l == 0 {
				i++
				return
			}
			if l&0xc0 == 0xc0 {
				i += 2
				return
			}
			i += l + 1
		}
	}
	for q := 0; q < qd; q++ {
		skipName()
		i += 4
	}
	var out []string
	for a := 0; a < an && i < len(b); a++ {
		skipName()
		if i+10 > len(b) {
			break
		}
		typ := binary.BigEndian.Uint16(b[i:])
		rdl := int(binary.BigEndian.Uint16(b[i+8:]))
		i += 10
		if typ == 1 && rdl == 4 && i+4 <= len(b) {
			out = append(out, net.IP(b[i:i+4]).String())
		}
		i += rdl
	}
	return out
}

var rttRe = regexp.MustCompile(`time=([0-9.]+) ?ms`)

func pingProbe(ns, dst string, count, ttl int, to time.Duration) (map[string]any, error) {
	if count < 1 {
		count = 1
	}
	argv := []string{"ip", "netns", "exec", ns, "ping", "-c", strconv.Itoa(count), "-W", strconv.Itoa(int(to.Seconds()) + 1)}
	if ttl > 0 {
		argv = append(argv, "-t", strconv.Itoa(ttl))
	}
	argv = append(argv, dst)
	o, e, code, err := run(to*time.Duration(count)+5*time.Second, "", argv...)
	if err != nil {
		return nil, err
	}
	var rtts []float64
	for _, m := range rttRe.FindAllStringSubmatch(o, -1) {
		v, _ := strconv.ParseFloat(m[1], 64)
		rtts = append(rtts, v)
	}
	return map[string]any{"ok": true, "pass": code == 0 && len(rtts) > 0, "replies": len(rtts), "sent": count, "rtt_ms": rtts, "output": o + e}, nil
}
