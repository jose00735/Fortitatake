package main

// attack.run: send a threat pack's requests from a lab device, the way its generator would,
// and report what came back for each (an answer, a reset, a timeout). The requests come from
// content/threats (checked at build time to aim only at the lab target); the targets are lab
// stand-ins, so nothing here works against a real system.

import (
	"bufio"
	"crypto/tls"
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
	for _, raw := range r.strs("requests") {
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
			var status string
			status, err = bufio.NewReader(conn).ReadString('\n')
			res["status"] = strings.TrimSpace(status)
		}
		if err != nil {
			res["error"], res["kind"] = err.Error(), classify(err)
		}
		conn.Close()
		results = append(results, res)
	}
	return map[string]any{"results": results}, nil
}
