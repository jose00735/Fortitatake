package main

// attack.run: send a threat pack's requests from a lab device, the way its generator would,
// and report what came back for each (an answer, a reset, a timeout). The requests come from
// content/threats (checked at build time to aim only at the lab target); the targets are lab
// stand-ins, so nothing here works against a real system.

import (
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

func remarshal(r req, out any) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

func attackRun(r req) (map[string]any, error) {
	ns, dst, src, sni := r.str("ns"), r.str("dst"), r.str("src"), r.str("sni")
	port := int(r.num("port", 80))
	useTLS, _ := r["tls"].(bool)
	to := time.Duration(r.num("timeout_ms", 3000)) * time.Millisecond
	if err := checkNS(ns); err != nil {
		return nil, err
	}
	if net.ParseIP(dst) == nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("bad target")
	}
	results := []map[string]any{}
	reqs := r.strs("requests")
	for _, h := range r.strs("requests_hex") { // binary protocols
		b, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("bad hex request")
		}
		reqs = append(reqs, string(b))
	}
	for _, raw := range reqs {
		res := map[string]any{}
		var c net.Conn
		err := withNetns(ns, func() error {
			d := net.Dialer{Timeout: to}
			if src != "" {
				d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(src)}
			}
			cc, err := d.Dial("tcp4", net.JoinHostPort(dst, strconv.Itoa(port)))
			c = cc
			return err
		})
		if err != nil {
			res["error"], res["kind"] = err.Error(), classify(err)
			results = append(results, res)
			continue
		}
		res["local"] = c.LocalAddr().String()
		conn := c
		if useTLS {
			tc := tls.Client(c, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
			tc.SetDeadline(time.Now().Add(to))
			if err := tc.Handshake(); err != nil {
				c.Close()
				res["error"], res["kind"] = err.Error(), classify(err)
				results = append(results, res)
				continue
			}
			conn = tc
			oracleAdd(c.LocalAddr(), raw) // what a deep-inspecting FortiGate would decrypt
		}
		conn.SetDeadline(time.Now().Add(to))
		_, err = io.WriteString(conn, raw)
		if err == nil {
			buf := make([]byte, 4096)
			var n int
			n, err = conn.Read(buf)
			if n > 0 {
				if line, _, ok := strings.Cut(string(buf[:n]), "\n"); ok && strings.HasPrefix(line, "HTTP/") {
					res["status"] = strings.TrimSpace(line)
				} else {
					res["status"] = fmt.Sprintf("%d bytes", n)
				}
				err = nil
			}
		}
		if err != nil {
			res["error"], res["kind"] = err.Error(), classify(err)
		}
		conn.Close()
		results = append(results, res)
	}
	return map[string]any{"results": results}, nil
}
