package ftkos

// The lab's Internet relay, FortiTatake's half. The agent queues DNS questions and ICMP echo
// requests for real Internet addresses; this loop answers them from the PC or phone the app
// runs on: DNS through a public resolver (or the system resolver if UDP 53 is blocked), pings
// with the system's own ICMP. Only these two kinds of request exist; nothing else leaves the lab.

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

var relayCount atomic.Int64

func (m *Manager) labRelay(vm *VM) {
	for {
		select {
		case <-vm.exited:
			return
		default:
		}
		res, err := vm.Call(map[string]any{"op": "relay.wait", "timeout_ms": 15000}, 20*time.Second)
		if err != nil {
			if strings.Contains(err.Error(), "unknown op") || strings.Contains(err.Error(), "stopped") {
				return // an OS build from before v0.9.0, or the VM is gone
			}
			time.Sleep(2 * time.Second)
			continue
		}
		reqs, _ := res["reqs"].([]any)
		for _, x := range reqs {
			q, _ := x.(map[string]any)
			go m.relayOne(vm, q)
		}
	}
}

func (m *Manager) relayOne(vm *VM, q map[string]any) {
	kind, _ := q["kind"].(string)
	ans := map[string]any{"op": "relay.answer", "rid": q["rid"], "ok": false}
	switch kind {
	case "dns":
		raw, _ := q["data"].(string)
		query, err := base64.StdEncoding.DecodeString(raw)
		if err == nil {
			if resp, err := relayDNS(query); err == nil {
				ans["ok"], ans["data"] = true, base64.StdEncoding.EncodeToString(resp)
			}
		}
	case "ping":
		dst, _ := q["dst"].(string)
		size, _ := q["size"].(float64)
		if ip := net.ParseIP(dst).To4(); ip != nil {
			if rtt, ttl, err := realPing(ip, int(size), 2*time.Second); err == nil {
				ans["ok"], ans["rtt_ms"], ans["ttl"] = true, rtt, ttl
			}
		}
	}
	relayCount.Add(1)
	vm.Call(ans, 5*time.Second)
}

// relayDNS forwards the lab's question unchanged to a public resolver; if UDP 53 is blocked
// where the app runs, the system resolver answers and the reply is built from its addresses.
func relayDNS(q []byte) ([]byte, error) {
	if len(q) < 12 {
		return nil, errors.New("short query")
	}
	for _, up := range []string{"1.1.1.1:53", "8.8.8.8:53"} {
		c, err := net.DialTimeout("udp4", up, time.Second)
		if err != nil {
			continue
		}
		c.SetDeadline(time.Now().Add(1500 * time.Millisecond))
		if _, err := c.Write(q); err == nil {
			buf := make([]byte, 4096)
			if n, err := c.Read(buf); err == nil && n >= 12 && buf[0] == q[0] && buf[1] == q[1] {
				c.Close()
				return buf[:n], nil
			}
		}
		c.Close()
	}
	name, qtype, qend := dnsQuestion(q)
	if name == "" {
		return nil, errors.New("bad question")
	}
	out := append([]byte{}, q[:qend]...)
	out[2] = 0x81 | (q[2] & 0x01)
	out[3] = 0x80
	binary.BigEndian.PutUint16(out[6:], 0)
	binary.BigEndian.PutUint16(out[8:], 0)
	binary.BigEndian.PutUint16(out[10:], 0)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", name)
	if err != nil {
		var de *net.DNSError
		if errors.As(err, &de) && de.IsNotFound {
			out[3] |= 3 // NXDOMAIN
			return out, nil
		}
		return nil, err
	}
	if qtype != 1 {
		return out, nil
	}
	n := 0
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
			out = append(out, v4...)
			n++
		}
	}
	binary.BigEndian.PutUint16(out[6:], uint16(n))
	return out, nil
}

func dnsQuestion(q []byte) (string, uint16, int) {
	i := 12
	var labels []string
	for i < len(q) && q[i] != 0 {
		l := int(q[i])
		if l > 63 || i+1+l > len(q) {
			return "", 0, 0
		}
		labels = append(labels, string(q[i+1:i+1+l]))
		i += 1 + l
	}
	i++
	if i+4 > len(q) {
		return "", 0, 0
	}
	return strings.Join(labels, "."), binary.BigEndian.Uint16(q[i:]), i + 4
}
