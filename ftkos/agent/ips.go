package main

// The FortiGate IPS on the real network. FortiTatake compiles each policy's IPS sensor into a
// list of threat-pack signatures and an nftables rule that queues the first packets of that
// policy's sessions (to the ports the signatures name) to an NFQUEUE in the FortiGate's
// namespace. The agent reads the queue, looks at the request each packet carries and gives the
// verdict before the packet moves on: accept, drop (block) or a TCP reset. Only an inline
// verdict can stop the packet that carries the attack.
//
// Matching mirrors tools/build_threats.py and web/js/labs/ips.js: the HTTP buffers method,
// uri (percent-decoded once, dot segments kept), header, body and raw; literals and regexes.
//
// HTTPS: a FortiGate needs deep inspection to see inside TLS. FortiTatake doesn't re-sign
// certificates; instead the lab's own clients (the attack generator) register the plaintext of
// each TLS request here, and the IPS reads it only when the policy's SSL profile is
// deep-inspection. With certificate inspection the IPS sees only ciphertext, as a real one does.

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

type ipsCond struct {
	Buf      string `json:"buf"`
	Contains string `json:"contains"`
	Regex    string `json:"regex"`
	Nocase   bool   `json:"nocase"`
	re       *regexp.Regexp
}

type ipsSig struct {
	ID    int       `json:"id"`
	Ports []int     `json:"ports"`
	Match []ipsCond `json:"match"`
}

type ipsRuleSig struct {
	ID     int    `json:"id"`
	Action string `json:"action"` // pass | block | reset
}

type ipsRule struct {
	Queue  int          `json:"queue"`
	Policy int          `json:"policy"`
	Deep   bool         `json:"deep"`
	Sigs   []ipsRuleSig `json:"sigs"`
}

type ipsHit struct {
	Seq    int64  `json:"seq"`
	T      int64  `json:"t"`
	NS     string `json:"ns"`
	Policy int    `json:"policy"`
	Sig    int    `json:"sig"`
	Action string `json:"action"`
	Src    string `json:"src"`
	Sport  int    `json:"sport"`
	Dst    string `json:"dst"`
	Dport  int    `json:"dport"`
	TLS    bool   `json:"tls"`
	URI    string `json:"uri"`
}

type ipsEngine struct {
	bmu     sync.Mutex
	blocked map[string]time.Time // flows the IPS blocked: every later packet goes too (retransmits included)
	ns      string
	sigs    map[int]*ipsSig
	rules   []*ipsRule
	qs      []*nfq
	stop    chan struct{}
}

var (
	ipsMu      sync.Mutex
	ipsEngines = map[string]*ipsEngine{}
	ipsLog     []ipsHit
	ipsSeq     int64
	oracleMu   sync.Mutex
	oracle     = map[string]oracleEntry{} // "ip:port" of a lab TLS client -> its plaintext request
)

type oracleEntry struct {
	plain string
	t     time.Time
}

const ipsResetMark = 0x7f1c0000

func oracleAdd(local net.Addr, plain string) {
	oracleMu.Lock()
	defer oracleMu.Unlock()
	for k, e := range oracle {
		if time.Since(e.t) > 30*time.Second {
			delete(oracle, k)
		}
	}
	oracle[local.String()] = oracleEntry{plain, time.Now()}
}

func oracleTake(key string) (string, bool) {
	oracleMu.Lock()
	defer oracleMu.Unlock()
	e, ok := oracle[key]
	if ok {
		delete(oracle, key)
	}
	return e.plain, ok
}

var httpMethods = []string{"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH "}

func httpBufs(p string) map[string]string {
	head, body, _ := strings.Cut(p, "\r\n\r\n")
	lines := strings.Split(head, "\r\n")
	f := strings.SplitN(lines[0], " ", 3)
	m := map[string]string{"raw": p, "body": body, "header": strings.Join(lines[1:], "\r\n")}
	if len(f) > 0 {
		m["method"] = f[0]
	}
	if len(f) > 1 {
		u, err := url.PathUnescape(f[1])
		if err != nil {
			u = f[1]
		}
		m["uri"] = u
	}
	return m
}

func (c *ipsCond) ok(b map[string]string) bool {
	s := b[c.Buf]
	if c.re != nil {
		return c.re.MatchString(s)
	}
	if c.Nocase {
		return strings.Contains(strings.ToLower(s), strings.ToLower(c.Contains))
	}
	return strings.Contains(s, c.Contains)
}

func (s *ipsSig) matches(b map[string]string, port int) bool {
	if len(s.Ports) > 0 {
		in := false
		for _, p := range s.Ports {
			if p == port {
				in = true
			}
		}
		if !in {
			return false
		}
	}
	for i := range s.Match {
		if !s.Match[i].ok(b) {
			return false
		}
	}
	return true
}

func (e *ipsEngine) run(r *ipsRule, q *nfq) {
	buf := make([]byte, 70000)
	for {
		select {
		case <-e.stop:
			q.close()
			return
		default:
		}
		id, pkt, err := q.next(buf)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				continue // the receive timeout: check for stop
			}
			q.close()
			return
		}
		v, mark := e.inspect(r, pkt)
		q.verdict(id, v, mark)
	}
}

// inspect decides one packet: an IPv4 TCP segment with a request in it, or anything else (accepted)
func (e *ipsEngine) inspect(r *ipsRule, pkt []byte) (uint32, uint32) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 || pkt[9] != 6 {
		return nfAccept, 0
	}
	ihl := int(pkt[0]&15) * 4
	if len(pkt) < ihl+20 {
		return nfAccept, 0
	}
	tcp := pkt[ihl:]
	doff := int(tcp[12]>>4) * 4
	if len(tcp) < doff {
		return nfAccept, 0
	}
	data := tcp[doff:]
	if len(data) == 0 {
		return nfAccept, 0
	}
	src, dst := net.IP(pkt[12:16]).String(), net.IP(pkt[16:20]).String()
	sport, dport := int(binary.BigEndian.Uint16(tcp[0:])), int(binary.BigEndian.Uint16(tcp[2:]))
	flow := fmt.Sprintf("%s:%d>%s:%d", src, sport, dst, dport)
	e.bmu.Lock()
	until, isBlocked := e.blocked[flow]
	e.bmu.Unlock()
	if isBlocked && time.Now().Before(until) {
		return nfDrop, 0
	}
	payload, tlsSeen := "", false
	s := string(data)
	for _, m := range httpMethods {
		if strings.HasPrefix(s, m) {
			payload = s
		}
	}
	if payload == "" && (data[0] == 0x17) { // TLS application data
		tlsSeen = true
		if !r.Deep {
			return nfAccept, 0
		}
		p, ok := oracleTake(fmt.Sprintf("%s:%d", src, sport))
		if !ok {
			return nfAccept, 0
		}
		payload = p
	}
	if payload == "" {
		return nfAccept, 0
	}
	b := httpBufs(payload)
	for _, rs := range r.Sigs {
		sig := e.sigs[rs.ID]
		if sig == nil || !sig.matches(b, dport) {
			continue
		}
		h := ipsHit{T: time.Now().UnixMilli(), NS: e.ns, Policy: r.Policy, Sig: rs.ID, Action: rs.Action, Src: src, Sport: sport, Dst: dst, Dport: dport, TLS: tlsSeen, URI: b["uri"]}
		ipsMu.Lock()
		ipsSeq++
		h.Seq = ipsSeq
		ipsLog = append(ipsLog, h)
		if len(ipsLog) > 2000 {
			ipsLog = ipsLog[len(ipsLog)-2000:]
		}
		ipsMu.Unlock()
		switch rs.Action {
		case "block", "reset":
			e.bmu.Lock()
			if e.blocked == nil {
				e.blocked = map[string]time.Time{}
			}
			for k, t := range e.blocked {
				if time.Now().After(t) {
					delete(e.blocked, k)
				}
			}
			e.blocked[flow] = time.Now().Add(2 * time.Minute)
			e.bmu.Unlock()
			// the rest of the session goes too, both ways
			go run(5*time.Second, "", "ip", "netns", "exec", e.ns, "nft", fmt.Sprintf("add element ip ftkips blk { %s . %d . %s . %d timeout 120s, %s . %d . %s . %d timeout 120s }", src, sport, dst, dport, dst, dport, src, sport))
			if rs.Action == "reset" {
				return nfRepeat, ipsResetMark
			}
			return nfDrop, 0
		}
		return nfAccept, 0
	}
	return nfAccept, 0
}

func ipsStopNS(ns string) {
	ipsMu.Lock()
	e := ipsEngines[ns]
	delete(ipsEngines, ns)
	ipsMu.Unlock()
	if e != nil {
		for _, q := range e.qs {
			q.unbind()
		}
		close(e.stop)
	}
}

func stopAllIPS() {
	ipsMu.Lock()
	ns := []string{}
	for k := range ipsEngines {
		ns = append(ns, k)
	}
	ipsMu.Unlock()
	for _, n := range ns {
		ipsStopNS(n)
	}
}

// ips.load: {ns, sigs: [...], rules: [{queue, policy, deep, sigs: [{id, action}]}]}
func ipsLoad(r req) (map[string]any, error) {
	ns := r.str("ns")
	if err := checkNS(ns); err != nil {
		return nil, err
	}
	var in struct {
		Sigs  []*ipsSig  `json:"sigs"`
		Rules []*ipsRule `json:"rules"`
	}
	if err := remarshal(r, &in); err != nil {
		return nil, err
	}
	ipsStopNS(ns)
	if len(in.Rules) == 0 {
		return map[string]any{"queues": 0}, nil
	}
	e := &ipsEngine{ns: ns, sigs: map[int]*ipsSig{}, rules: in.Rules, stop: make(chan struct{})}
	for _, s := range in.Sigs {
		for i := range s.Match {
			c := &s.Match[i]
			if c.Regex != "" {
				pat := c.Regex
				if c.Nocase {
					pat = "(?i)" + pat
				}
				re, err := regexp.Compile(pat)
				if err != nil {
					return nil, fmt.Errorf("signature %d: %v", s.ID, err)
				}
				c.re = re
			}
		}
		e.sigs[s.ID] = s
	}
	for _, ru := range e.rules {
		sort.SliceStable(ru.Sigs, func(i, j int) bool { return ru.Sigs[i].ID < ru.Sigs[j].ID })
		var q *nfq
		err := withNetns(ns, func() error {
			var err error
			q, err = nfqOpen(uint16(ru.Queue))
			return err
		})
		if err != nil {
			close(e.stop)
			for _, x := range e.qs {
				x.close()
			}
			return nil, err
		}
		tv := syscall.NsecToTimeval(int64(time.Second))
		syscall.SetsockoptTimeval(q.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
		e.qs = append(e.qs, q)
	}
	for i, ru := range e.rules {
		go e.run(ru, e.qs[i])
	}
	ipsMu.Lock()
	ipsEngines[ns] = e
	ipsMu.Unlock()
	return map[string]any{"queues": len(e.qs)}, nil
}

// ips.log: hits since a sequence number
func ipsLogs(r req) (map[string]any, error) {
	since := int64(r.num("since", 0))
	ipsMu.Lock()
	defer ipsMu.Unlock()
	out := []ipsHit{}
	for _, h := range ipsLog {
		if h.Seq > since {
			out = append(out, h)
		}
	}
	return map[string]any{"hits": out, "next": ipsSeq}, nil
}
