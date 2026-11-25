package main

// dns.query: a real DNS lookup from inside a device's namespace, to the DNS server that device
// is configured with. The packets cross the lab like any other (FortiGate policies, NAT, logs,
// sniffer), so name resolution is visible instead of happening inside the app.

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

func dnsBuildQuery(name string, qtype uint16) ([]byte, error) {
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if name == "" || len(name) > 253 {
		return nil, fmt.Errorf("bad name")
	}
	q := make([]byte, 12)
	rand.Read(q[0:2])
	q[2] = 0x01 // recursion desired
	binary.BigEndian.PutUint16(q[4:], 1)
	for _, l := range strings.Split(name, ".") {
		if l == "" || len(l) > 63 {
			return nil, fmt.Errorf("bad name")
		}
		q = append(q, byte(len(l)))
		q = append(q, l...)
	}
	q = append(q, 0, byte(qtype>>8), byte(qtype), 0, 1)
	return q, nil
}

// dnsSkipName returns the offset after a (possibly compressed) name.
func dnsSkipName(m []byte, i int) int {
	for i < len(m) {
		l := int(m[i])
		if l == 0 {
			return i + 1
		}
		if l&0xc0 == 0xc0 {
			return i + 2
		}
		i += 1 + l
	}
	return len(m)
}

// dnsParse returns the response code and the A records of a response.
func dnsParse(m []byte) (rcode int, addrs []string, cname string, ttl int, err error) {
	if len(m) < 12 {
		return 0, nil, "", 0, fmt.Errorf("short answer")
	}
	rcode = int(m[3] & 0x0f)
	qd := int(binary.BigEndian.Uint16(m[4:]))
	an := int(binary.BigEndian.Uint16(m[6:]))
	i := 12
	for k := 0; k < qd; k++ {
		i = dnsSkipName(m, i) + 4
	}
	for k := 0; k < an && i+10 <= len(m); k++ {
		i = dnsSkipName(m, i)
		if i+10 > len(m) {
			break
		}
		t := binary.BigEndian.Uint16(m[i:])
		rttl := int(binary.BigEndian.Uint32(m[i+4:]))
		l := int(binary.BigEndian.Uint16(m[i+8:]))
		i += 10
		if i+l > len(m) {
			break
		}
		if t == 1 && l == 4 {
			addrs = append(addrs, net.IP(m[i:i+4]).String())
			if ttl == 0 {
				ttl = rttl
			}
		} else if t == 5 && cname == "" {
			cname = "(alias)"
		}
		i += l
	}
	return rcode, addrs, cname, ttl, nil
}

func dnsQuery(r req) (map[string]any, error) {
	ns, server, name := r.str("ns"), r.str("server"), r.str("name")
	if err := checkNS(ns); err != nil {
		return nil, err
	}
	if net.ParseIP(server).To4() == nil {
		return nil, fmt.Errorf("bad server")
	}
	q, err := dnsBuildQuery(name, 1)
	if err != nil {
		return nil, err
	}
	to := time.Duration(r.num("timeout_ms", 2500)) * time.Millisecond
	var resp []byte
	var ms float64
	err = withNetns(ns, func() error {
		c, err := net.Dial("udp4", net.JoinHostPort(server, "53"))
		if err != nil {
			return err
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(to))
		t := time.Now()
		if _, err := c.Write(q); err != nil {
			return err
		}
		buf := make([]byte, 4096)
		for {
			k, err := c.Read(buf)
			if err != nil {
				return err
			}
			if k >= 12 && buf[0] == q[0] && buf[1] == q[1] {
				resp = append([]byte{}, buf[:k]...)
				ms = float64(time.Since(t).Microseconds()) / 1000
				return nil
			}
		}
	})
	if err != nil {
		e := err.Error()
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			e = "timeout"
		} else if strings.Contains(e, "refused") {
			e = "refused"
		} else if strings.Contains(e, "unreachable") {
			e = "unreachable"
		}
		return map[string]any{"error": e}, nil
	}
	rcode, addrs, cname, ttl, _ := dnsParse(resp)
	if addrs == nil {
		addrs = []string{}
	}
	return map[string]any{"rcode": rcode, "addrs": addrs, "alias": cname != "", "ttl": ttl, "ms": ms}, nil
}
