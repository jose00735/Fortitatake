package main

// Lab servers without daemons: the agent opens the sockets itself inside a device's
// namespace (a socket keeps the namespace it was created in), answers like a small web,
// TLS, DNS or plain TCP server, and logs who connected so FortiTatake can check NAT
// (which source the server saw, which address the client reached).

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type hit struct {
	Proto string `json:"proto"`
	Port  int    `json:"port"`
	Src   string `json:"src"`
	Dst   string `json:"dst"`
	T     int64  `json:"t"`
	Seq   int64  `json:"seq"`
	Data  string `json:"data,omitempty"` // kept for log collectors (syslog, OFTP stand-in)
}

var hitSeq int64 // guarded by lsMu

type nsListen struct {
	mu      sync.Mutex
	closers []io.Closer
	log     []hit
	names   map[string]string
}

var (
	lsMu   sync.Mutex
	lsByNS = map[string]*nsListen{}
	tlsCfg *tls.Config
	tlsMu  sync.Mutex
)

func (n *nsListen) add(h hit) {
	lsMu.Lock()
	hitSeq++
	h.Seq = hitSeq
	lsMu.Unlock()
	n.mu.Lock()
	defer n.mu.Unlock()
	h.T = time.Now().UnixMilli()
	n.log = append(n.log, h)
	if len(n.log) > 4000 {
		n.log = n.log[len(n.log)-4000:]
	}
}

func labTLS() *tls.Config {
	tlsMu.Lock()
	defer tlsMu.Unlock()
	if tlsCfg != nil {
		return tlsCfg
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "FortiTatake lab server"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	tlsCfg = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	return tlsCfg
}

func listenStart(r req) (map[string]any, error) {
	ns := r.str("ns")
	if err := checkNS(ns); err != nil {
		return nil, err
	}
	lsMu.Lock()
	n := lsByNS[ns]
	if n == nil {
		n = &nsListen{names: map[string]string{}}
		lsByNS[ns] = n
	}
	lsMu.Unlock()
	if m, ok := r["names"].(map[string]any); ok {
		n.mu.Lock()
		for k, v := range m {
			n.names[strings.ToLower(strings.TrimSuffix(k, "."))] = fmt.Sprint(v)
		}
		n.mu.Unlock()
	}
	binds, _ := r["binds"].([]any)
	opened, failed := 0, []string{}
	for _, b := range binds {
		m, _ := b.(map[string]any)
		ip, _ := m["ip"].(string)
		proto, _ := m["proto"].(string)
		pf, _ := m["port"].(float64)
		port := int(pf)
		keep, _ := m["keep"].(bool)
		if ip == "" {
			ip = "0.0.0.0"
		}
		if net.ParseIP(ip) == nil || port < 1 || port > 65535 {
			continue
		}
		addr := net.JoinHostPort(ip, strconv.Itoa(port))
		err := withNetns(ns, func() error {
			switch proto {
			case "tcp":
				l, err := net.Listen("tcp4", addr)
				if err != nil {
					return err
				}
				n.mu.Lock()
				n.closers = append(n.closers, l)
				n.mu.Unlock()
				go serveTCP(n, l, port, keep)
			case "udp":
				c, err := net.ListenPacket("udp4", addr)
				if err != nil {
					return err
				}
				n.mu.Lock()
				n.closers = append(n.closers, c)
				n.mu.Unlock()
				go serveUDP(n, c, port, keep)
			default:
				return fmt.Errorf("bad proto %q", proto)
			}
			return nil
		})
		if err != nil {
			failed = append(failed, proto+"/"+addr+": "+err.Error())
		} else {
			opened++
		}
	}
	return map[string]any{"opened": opened, "failed": failed}, nil
}

func serveTCP(n *nsListen, l net.Listener, port int, keep bool) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			src, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			dst, _, _ := net.SplitHostPort(c.LocalAddr().String())
			n.add(hit{Proto: "tcp", Port: port, Src: src, Dst: dst})
			if keep { // a log collector: one hit per line, for as long as the sender stays connected
				sc := bufio.NewScanner(c)
				sc.Buffer(make([]byte, 64<<10), 64<<10)
				for sc.Scan() {
					if line := strings.TrimSpace(sc.Text()); line != "" {
						n.add(hit{Proto: "tcp", Port: port, Src: src, Dst: dst, Data: line})
					}
				}
				return
			}
			c.SetDeadline(time.Now().Add(5 * time.Second))
			switch port {
			case 443, 8443, 10443:
				tc := tls.Server(c, labTLS())
				if tc.Handshake() == nil {
					httpReply(tc, dst)
				}
			case 80, 8080:
				httpReply(c, dst)
			case 22:
				c.Write([]byte("SSH-2.0-FortiTatake\r\n"))
				io.Copy(io.Discard, io.LimitReader(c, 4096))
			default:
				io.Copy(io.Discard, io.LimitReader(c, 4096))
			}
		}(c)
	}
}

func httpReply(c net.Conn, dst string) {
	buf := make([]byte, 4096)
	c.Read(buf)
	body := "FortiTatake lab server at " + dst + "\n"
	fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
}

func serveUDP(n *nsListen, c net.PacketConn, port int, keep bool) {
	buf := make([]byte, 1500)
	local, _, _ := net.SplitHostPort(c.LocalAddr().String())
	for {
		k, from, err := c.ReadFrom(buf)
		if err != nil {
			return
		}
		src, _, _ := net.SplitHostPort(from.String())
		h := hit{Proto: "udp", Port: port, Src: src, Dst: local}
		if keep {
			h.Data = strings.TrimSpace(string(buf[:k]))
		}
		n.add(h)
		if port == 53 {
			if resp := dnsAnswer(n, buf[:k]); resp != nil {
				c.WriteTo(resp, from)
			}
		}
	}
}

// dnsAnswer answers one A query from the lab's names (NXDOMAIN otherwise).
func dnsAnswer(n *nsListen, q []byte) []byte {
	if len(q) < 17 {
		return nil
	}
	i := 12
	var labels []string
	for i < len(q) && q[i] != 0 {
		l := int(q[i])
		if l > 63 || i+1+l > len(q) {
			return nil
		}
		labels = append(labels, string(q[i+1:i+1+l]))
		i += 1 + l
	}
	i++ // zero label
	if i+4 > len(q) {
		return nil
	}
	qend := i + 4
	qtype := binary.BigEndian.Uint16(q[i:])
	name := strings.ToLower(strings.Join(labels, "."))
	n.mu.Lock()
	ip := n.names[name]
	n.mu.Unlock()
	out := append([]byte{}, q[:qend]...)
	out[2] = 0x81 | (q[2] & 0x01) // response, recursion desired echoed
	out[3] = 0x80                // recursion available
	binary.BigEndian.PutUint16(out[6:], 0)
	binary.BigEndian.PutUint16(out[8:], 0)
	binary.BigEndian.PutUint16(out[10:], 0)
	v4 := net.ParseIP(ip).To4()
	if v4 == nil {
		if ip == "" {
			out[3] |= 3 // NXDOMAIN
		}
		return out
	}
	if qtype != 1 {
		return out
	}
	binary.BigEndian.PutUint16(out[6:], 1)
	out = append(out, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
	return append(out, v4...)
}

func listenLog(r req) (map[string]any, error) {
	// since_seq: only hits after that point (the VM's clock isn't the app's clock)
	ns := r.str("ns")
	lsMu.Lock()
	n := lsByNS[ns]
	seq := hitSeq
	lsMu.Unlock()
	out := []hit{}
	if n == nil {
		return map[string]any{"hits": out, "seq": seq}, nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	since := int64(r.num("since_seq", 0))
	for _, h := range n.log {
		if h.Seq > since {
			out = append(out, h)
		}
	}
	return map[string]any{"hits": out, "seq": seq}, nil
}

func stopAllListeners() {
	lsMu.Lock()
	all := lsByNS
	lsByNS = map[string]*nsListen{}
	lsMu.Unlock()
	for _, n := range all {
		n.mu.Lock()
		for _, c := range n.closers {
			c.Close()
		}
		n.mu.Unlock()
	}
}

// ---------------------------------------------------------------- senders
// A device sending log lines: FortiGate → FortiAnalyzer (TCP, kept open like OFTP) and
// FortiGate → syslog (UDP, one datagram per line). The socket is opened inside the device's
// namespace from the configured source address, so routing and policies apply for real.
var (
	sndMu   sync.Mutex
	senders = map[string]net.Conn{}
)

func sendLines(r req) (map[string]any, error) {
	ns, proto, dst, src := r.str("ns"), r.str("proto"), r.str("dst"), r.str("src")
	port := int(r.num("port", 514))
	if err := checkNS(ns); err != nil {
		return nil, err
	}
	if net.ParseIP(dst) == nil || (proto != "tcp" && proto != "udp") {
		return nil, fmt.Errorf("bad destination")
	}
	key := fmt.Sprintf("%s|%s|%s|%s:%d", ns, proto, src, dst, port)
	sndMu.Lock()
	c := senders[key]
	sndMu.Unlock()
	if c == nil {
		err := withNetns(ns, func() error {
			d := net.Dialer{Timeout: time.Duration(r.num("timeout_ms", 2500)) * time.Millisecond}
			if src != "" {
				if proto == "tcp" {
					d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(src)}
				} else {
					d.LocalAddr = &net.UDPAddr{IP: net.ParseIP(src)}
				}
			}
			cc, err := d.Dial(proto+"4", net.JoinHostPort(dst, strconv.Itoa(port)))
			c = cc
			return err
		})
		if err != nil {
			return map[string]any{"sent": 0, "error": err.Error()}, nil
		}
		sndMu.Lock()
		senders[key] = c
		sndMu.Unlock()
	}
	sent := 0
	for _, l := range r.strs("lines") {
		c.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write([]byte(l + "\n")); err != nil {
			c.Close()
			sndMu.Lock()
			delete(senders, key)
			sndMu.Unlock()
			return map[string]any{"sent": sent, "error": err.Error()}, nil
		}
		sent++
	}
	return map[string]any{"sent": sent}, nil
}

func stopAllSenders() {
	sndMu.Lock()
	defer sndMu.Unlock()
	for k, c := range senders {
		c.Close()
		delete(senders, k)
	}
}
