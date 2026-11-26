package main

// Office traffic generators. Each one runs as goroutines inside a lab client's network
// namespace and talks to the stand-in servers in listen.go, so every flow is a real
// connection: it crosses the FortiGate policies, gets NAT and shows in the session list,
// the sniffer and the logs. Random choices come from a seed, so a run repeats.
//
//   web    DNS lookup, then HTTP/HTTPS pages of 1-6 objects with browser headers (keep-alive)
//   dns    A and AAAA lookups, about 3% for names that don't exist, NTP every 15 minutes
//   smb    SMB2 negotiate, session setup, tree connect, then reads and writes of 4 KB-2 MB
//   mail   SMTP submission on 587 with STARTTLS, IMAPS polls on 993, HTTPS calls to a SaaS API
//   voice  SIP REGISTER and INVITE on UDP 5060, then RTP at 50 packets/s for the call
//
// The FortiTatake app picks the targets (lab servers, or the Internet stand-ins) and the rate.

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type genEv struct {
	T     int64  `json:"t"`
	Gen   string `json:"gen"`
	NS    string `json:"ns"`
	Kind  string `json:"kind"`
	What  string `json:"what"`
	Dst   string `json:"dst"`
	Port  int    `json:"port"`
	Proto string `json:"proto"`
	Bytes int64  `json:"bytes"`
	OK    bool   `json:"ok"`
	Err   string `json:"err,omitempty"`
	Seq   int64  `json:"seq"`
}

type genTarget struct {
	Name  string
	IP    string
	Port  int
	TLS   bool
	Paths []string
}

type generator struct {
	id, ns, kind, src, resolver string
	rate                        float64
	rnd                         *rand.Rand
	rmu                         sync.Mutex
	targets                     []genTarget
	names                       []string
	stop                        chan struct{}
	flows, bytes, errs          int64
	started                     time.Time
}

var (
	genMu  sync.Mutex
	gens   = map[string]*generator{}
	genLog []genEv
	genSeq int64
)

const genLogMax = 3000

func (g *generator) intn(n int) int {
	g.rmu.Lock()
	defer g.rmu.Unlock()
	if n <= 0 {
		return 0
	}
	return g.rnd.Intn(n)
}

// wait sleeps a random time in [lo, hi) seconds divided by the rate; false when stopped
func (g *generator) wait(lo, hi float64) bool {
	s := lo + float64(g.intn(1000))/1000*(hi-lo)
	d := time.Duration(s / g.rate * float64(time.Second))
	if d < 50*time.Millisecond {
		d = 50 * time.Millisecond
	}
	select {
	case <-g.stop:
		return false
	case <-time.After(d):
		return true
	}
}

func (g *generator) stopped() bool {
	select {
	case <-g.stop:
		return true
	default:
		return false
	}
}

func (g *generator) record(e genEv) {
	e.T, e.Gen, e.NS, e.Kind = time.Now().UnixMilli(), g.id, g.ns, g.kind
	genMu.Lock()
	genSeq++
	e.Seq = genSeq
	g.flows++
	g.bytes += e.Bytes
	if !e.OK {
		g.errs++
	}
	genLog = append(genLog, e)
	if len(genLog) > genLogMax {
		genLog = genLog[len(genLog)-genLogMax:]
	}
	genMu.Unlock()
}

// dial opens a connection from the generator's namespace (the socket stays in it)
func (g *generator) dial(proto, ip string, port int, to time.Duration) (net.Conn, error) {
	var c net.Conn
	err := withNetns(g.ns, func() error {
		d := net.Dialer{Timeout: to}
		if g.src != "" {
			if proto == "udp" {
				d.LocalAddr = &net.UDPAddr{IP: net.ParseIP(g.src)}
			} else {
				d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(g.src)}
			}
		}
		cc, err := d.Dial(proto+"4", net.JoinHostPort(ip, strconv.Itoa(port)))
		c = cc
		return err
	})
	return c, err
}

// resolve asks the client's DNS server, as the client would before connecting
func (g *generator) resolve(name string, qtype uint16) (string, int, error) {
	if g.resolver == "" || net.ParseIP(name) != nil {
		return name, 0, nil
	}
	q, err := dnsBuildQuery(name, qtype)
	if err != nil {
		return "", 0, err
	}
	c, err := g.dial("udp", g.resolver, 53, 2*time.Second)
	if err != nil {
		return "", 0, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write(q); err != nil {
		return "", 0, err
	}
	buf := make([]byte, 1500)
	k, err := c.Read(buf)
	if err != nil {
		return "", len(q), err
	}
	rc, addrs, _, _, err := dnsParse(buf[:k])
	if err != nil {
		return "", len(q) + k, err
	}
	if rc == 3 {
		return "", len(q) + k, fmt.Errorf("NXDOMAIN")
	}
	if len(addrs) == 0 {
		return "", len(q) + k, fmt.Errorf("no address")
	}
	return addrs[0], len(q) + k, nil
}

func (g *generator) pick() genTarget {
	return g.targets[g.intn(len(g.targets))]
}

var browserUA = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
}

var webObjects = []string{"/", "/index.html", "/css/site.css", "/js/app.js", "/img/logo.png", "/favicon.ico", "/api/v1/news", "/fonts/main.woff2"}

func (g *generator) runWeb() {
	for g.wait(20, 90) {
		t := g.pick()
		ip, nb, err := g.resolve(t.Name, 1)
		if t.IP != "" && (err != nil || ip == t.Name) {
			ip, err = t.IP, nil
		}
		g.record(genEv{What: "dns " + t.Name, Dst: g.resolver, Port: 53, Proto: "udp", Bytes: int64(nb), OK: err == nil, Err: errStr(err)})
		if err != nil {
			continue
		}
		port := t.Port
		if port == 0 {
			port = map[bool]int{true: 443, false: 80}[t.TLS]
		}
		c, err := g.dial("tcp", ip, port, 4*time.Second)
		if err != nil {
			g.record(genEv{What: "page " + t.Name, Dst: ip, Port: port, Proto: "tcp", Err: errStr(err)})
			continue
		}
		if t.TLS {
			tc := tls.Client(c, &tls.Config{ServerName: t.Name, InsecureSkipVerify: true})
			c.SetDeadline(time.Now().Add(4 * time.Second))
			if err := tc.Handshake(); err != nil {
				c.Close()
				g.record(genEv{What: "tls " + t.Name, Dst: ip, Port: port, Proto: "tcp", Err: errStr(err)})
				continue
			}
			c = tc
		}
		objs := 1 + g.intn(6)
		paths := t.Paths
		if len(paths) == 0 {
			paths = webObjects
		}
		ua := browserUA[g.intn(len(browserUA))]
		var total int64
		ok := true
		rd := bufio.NewReader(c)
		for i := 0; i < objs && !g.stopped(); i++ {
			path := paths[0]
			if i > 0 {
				path = paths[g.intn(len(paths))]
			}
			c.SetDeadline(time.Now().Add(4 * time.Second))
			reqs := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: text/html,application/xhtml+xml,*/*;q=0.8\r\nAccept-Language: es-CO,es;q=0.9,en;q=0.8\r\nAccept-Encoding: identity\r\nConnection: keep-alive\r\n\r\n", path, t.Name, ua)
			if _, err := io.WriteString(c, reqs); err != nil {
				ok = false
				break
			}
			n, err := readHTTP(rd)
			total += int64(len(reqs)) + n
			if err != nil {
				ok = false
				break
			}
			time.Sleep(time.Duration(30+g.intn(200)) * time.Millisecond)
		}
		c.Close()
		g.record(genEv{What: fmt.Sprintf("page %s (%d objects)", t.Name, objs), Dst: ip, Port: port, Proto: "tcp", Bytes: total, OK: ok})
	}
}

// readHTTP reads one response (status, headers, Content-Length body) and returns its size
func readHTTP(rd *bufio.Reader) (int64, error) {
	var n int64
	cl := 0
	for {
		l, err := rd.ReadString('\n')
		n += int64(len(l))
		if err != nil {
			return n, err
		}
		if lw := strings.ToLower(l); strings.HasPrefix(lw, "content-length:") {
			cl, _ = strconv.Atoi(strings.TrimSpace(l[15:]))
		}
		if l == "\r\n" || l == "\n" {
			break
		}
	}
	if cl > 0 {
		k, err := io.CopyN(io.Discard, rd, int64(cl))
		n += k
		return n, err
	}
	return n, nil
}

func (g *generator) runDNS() {
	lastNTP := time.Time{}
	for g.wait(4, 15) {
		if len(g.names) > 0 {
			name := g.names[g.intn(len(g.names))]
			if g.intn(100) < 3 { // a typo or a stale bookmark
				name = fmt.Sprintf("x%d.%s", g.intn(99999), name)
			}
			qt := uint16(1)
			if g.intn(3) == 0 {
				qt = 28
			}
			_, nb, err := g.resolve(name, qt)
			if err != nil && err.Error() == "no address" && qt == 28 {
				err = nil // a name without IPv6 is normal
			}
			g.record(genEv{What: map[uint16]string{1: "A ", 28: "AAAA "}[qt] + name, Dst: g.resolver, Port: 53, Proto: "udp", Bytes: int64(nb), OK: err == nil, Err: errStr(err)})
		}
		if len(g.targets) > 0 && time.Since(lastNTP) > time.Duration(float64(15*time.Minute)/g.rate) {
			lastNTP = time.Now()
			t := g.pick()
			g.record(g.ntp(t.IP))
		}
	}
}

func (g *generator) ntp(ip string) genEv {
	ev := genEv{What: "ntp", Dst: ip, Port: 123, Proto: "udp"}
	c, err := g.dial("udp", ip, 123, 2*time.Second)
	if err != nil {
		ev.Err = errStr(err)
		return ev
	}
	defer c.Close()
	p := make([]byte, 48)
	p[0] = 0x23 // NTPv4, client
	c.SetDeadline(time.Now().Add(2 * time.Second))
	c.Write(p)
	k, err := c.Read(make([]byte, 128))
	ev.Bytes, ev.OK, ev.Err = int64(48+k), err == nil, errStr(err)
	return ev
}

// ----- SMB2 client: enough of the protocol that a capture and the stand-in see real commands -----

func smb2(cmd uint16, msgID uint64, body []byte) []byte {
	h := make([]byte, 64)
	copy(h, "\xfeSMB")
	binary.LittleEndian.PutUint16(h[4:], 64)
	binary.LittleEndian.PutUint16(h[12:], cmd)
	binary.LittleEndian.PutUint16(h[14:], 1) // credits
	binary.LittleEndian.PutUint64(h[24:], msgID)
	m := append(h, body...)
	nb := make([]byte, 4)
	binary.BigEndian.PutUint32(nb, uint32(len(m)))
	return append(nb, m...)
}

func readSMB(c net.Conn) ([]byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr) & 0xffffff
	if n > 4<<20 {
		return nil, fmt.Errorf("frame too big")
	}
	b := make([]byte, n)
	_, err := io.ReadFull(c, b)
	return b, err
}

var smbFiles = []string{`Facturas\2026-11.xlsx`, `RRHH\turnos.docx`, `Citas\agenda.pdf`, `Contabilidad\balance.xlsx`, `Escaneos\scan0042.pdf`}

func (g *generator) runSMB() {
	burst := 3 // the start of the day: everyone opens the share at once
	for {
		if burst > 0 {
			burst--
			if !g.wait(1, 4) {
				return
			}
		} else if !g.wait(300, 900) {
			return
		}
		t := g.pick()
		ev := genEv{Dst: t.IP, Port: 445, Proto: "tcp"}
		c, err := g.dial("tcp", t.IP, 445, 4*time.Second)
		if err != nil {
			ev.What, ev.Err = "smb connect", errStr(err)
			g.record(ev)
			continue
		}
		var total int64
		step := func(cmd uint16, id uint64, body []byte) error {
			f := smb2(cmd, id, body)
			c.SetDeadline(time.Now().Add(5 * time.Second))
			if _, err := c.Write(f); err != nil {
				return err
			}
			r, err := readSMB(c)
			total += int64(len(f) + len(r) + 4)
			return err
		}
		file := smbFiles[g.intn(len(smbFiles))]
		write := g.intn(3) == 0
		size := 4096 << g.intn(10) // 4 KB .. 2 MB
		if size > 2<<20 {
			size = 2 << 20
		}
		if g.rate > 10 && size > 256<<10 { // a compressed day keeps the bytes of a real one per minute, not per hour
			size = 256 << 10
		}
		err = step(0, 0, []byte{36, 0, 2, 0, 1, 0, 0, 0, 0x7f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x02, 0x10, 0x02}) // NEGOTIATE 2.0.2, 2.1
		if err == nil {
			err = step(1, 1, []byte("NTLMSSP\x00"+g.ns)) // SESSION_SETUP (shape only)
		}
		if err == nil {
			err = step(3, 2, []byte(`\\`+t.Name+`\compartido`)) // TREE_CONNECT
		}
		if err == nil {
			err = step(5, 3, []byte(file)) // CREATE
		}
		if err == nil {
			chunk := make([]byte, 64<<10)
			for left, id := size, uint64(4); left > 0 && err == nil && !g.stopped(); id++ {
				k := len(chunk)
				if left < k {
					k = left
				}
				if write {
					err = step(9, id, append([]byte(file+"\x00"), chunk[:k]...)) // WRITE
				} else {
					err = step(8, id, []byte(fmt.Sprintf("%s\x00%d", file, k))) // READ
				}
				left -= k
			}
		}
		if err == nil {
			step(6, 99, []byte(file)) // CLOSE
		}
		c.Close()
		ev.What = fmt.Sprintf("smb %s %s (%d KB)", map[bool]string{true: "write", false: "read"}[write], file, size>>10)
		ev.Bytes, ev.OK, ev.Err = total, err == nil, errStr(err)
		g.record(ev)
	}
}

// ----- mail and SaaS -----

func (g *generator) runMail() {
	var mailT, imapT, saasT []genTarget
	for _, t := range g.targets {
		switch t.Port {
		case 587, 25:
			mailT = append(mailT, t)
		case 993:
			imapT = append(imapT, t)
		default:
			saasT = append(saasT, t)
		}
	}
	nextSend := time.Now().Add(time.Duration(float64(time.Duration(60+g.intn(240))*time.Second) / g.rate))
	for g.wait(100, 140) { // IMAP poll about every 2 minutes
		if len(imapT) > 0 {
			g.record(g.imapPoll(imapT[g.intn(len(imapT))]))
		}
		if len(saasT) > 0 && g.intn(2) == 0 {
			t := saasT[g.intn(len(saasT))]
			g.record(g.saasCall(t))
		}
		if len(mailT) > 0 && time.Now().After(nextSend) {
			nextSend = time.Now().Add(time.Duration(float64(time.Duration(600+g.intn(1200))*time.Second) / g.rate))
			g.record(g.smtpSend(mailT[g.intn(len(mailT))]))
		}
	}
}

func (g *generator) host(t genTarget) string {
	if t.Name == "" {
		return t.IP
	}
	if ip, _, err := g.resolve(t.Name, 1); err == nil && ip != t.Name {
		return ip
	}
	if t.IP != "" {
		return t.IP
	}
	return t.Name
}

func (g *generator) smtpSend(t genTarget) genEv {
	ip := g.host(t)
	ev := genEv{What: "smtp submit " + t.Name, Dst: ip, Port: t.Port, Proto: "tcp"}
	c, err := g.dial("tcp", ip, t.Port, 4*time.Second)
	if err != nil {
		ev.Err = errStr(err)
		return ev
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(8 * time.Second))
	var total int64
	rd := bufio.NewReader(c)
	expect := func(code string) error {
		for {
			l, err := rd.ReadString('\n')
			total += int64(len(l))
			if err != nil {
				return err
			}
			if !strings.HasPrefix(l, code) {
				return fmt.Errorf("server said %q", strings.TrimSpace(l))
			}
			if len(l) < 4 || l[3] != '-' {
				return nil
			}
		}
	}
	say := func(s string) { total += int64(len(s)); io.WriteString(c, s) }
	err = expect("220")
	if err == nil {
		say("EHLO " + strings.ToLower(g.ns) + ".lab\r\n")
		err = expect("250")
	}
	if err == nil {
		say("STARTTLS\r\n")
		err = expect("220")
	}
	if err == nil {
		tc := tls.Client(c, &tls.Config{ServerName: t.Name, InsecureSkipVerify: true})
		if err = tc.Handshake(); err == nil {
			c = tc
			rd = bufio.NewReader(tc)
			say("EHLO " + strings.ToLower(g.ns) + ".lab\r\n")
			err = expect("250")
			for _, cmd := range []string{"MAIL FROM:<" + strings.ToLower(g.ns) + "@clinica.lab>\r\n", "RCPT TO:<contabilidad@clinica.lab>\r\n"} {
				if err == nil {
					say(cmd)
					err = expect("250")
				}
			}
			if err == nil {
				say("DATA\r\n")
				err = expect("354")
			}
			if err == nil {
				body := fmt.Sprintf("Subject: Reporte %d\r\n\r\n%s\r\n.\r\n", g.intn(1000), strings.Repeat("Buen dia, adjunto el reporte. ", 20+g.intn(200)))
				say(body)
				err = expect("250")
			}
			say("QUIT\r\n")
		}
	}
	ev.Bytes, ev.OK, ev.Err = total, err == nil, errStr(err)
	return ev
}

func (g *generator) imapPoll(t genTarget) genEv {
	ip := g.host(t)
	ev := genEv{What: "imaps poll " + t.Name, Dst: ip, Port: t.Port, Proto: "tcp"}
	c, err := g.dial("tcp", ip, t.Port, 4*time.Second)
	if err != nil {
		ev.Err = errStr(err)
		return ev
	}
	defer c.Close()
	tc := tls.Client(c, &tls.Config{ServerName: t.Name, InsecureSkipVerify: true})
	tc.SetDeadline(time.Now().Add(6 * time.Second))
	var total int64
	rd := bufio.NewReader(tc)
	tagged := func(tag string) error {
		for {
			l, err := rd.ReadString('\n')
			total += int64(len(l))
			if err != nil {
				return err
			}
			if strings.HasPrefix(l, tag+" ") {
				if !strings.HasPrefix(l, tag+" OK") {
					return fmt.Errorf("server said %q", strings.TrimSpace(l))
				}
				return nil
			}
		}
	}
	err = tc.Handshake()
	if err == nil {
		_, err = rd.ReadString('\n') // greeting
	}
	for i, cmd := range []string{"LOGIN " + strings.ToLower(g.ns) + " ********", "SELECT INBOX", "FETCH 1:* (FLAGS)", "LOGOUT"} {
		if err != nil {
			break
		}
		tag := fmt.Sprintf("a%d", i+1)
		io.WriteString(tc, tag+" "+cmd+"\r\n")
		err = tagged(tag)
	}
	ev.Bytes, ev.OK, ev.Err = total, err == nil, errStr(err)
	return ev
}

var saasPaths = []string{"/api/v1/me", "/api/v1/calendar/events?days=7", "/api/v1/files?recent=1", "/api/v1/chat/messages?since=300"}

func (g *generator) saasCall(t genTarget) genEv {
	ip := g.host(t)
	port := t.Port
	if port == 0 {
		port = 443
	}
	ev := genEv{What: "saas " + t.Name, Dst: ip, Port: port, Proto: "tcp"}
	c, err := g.dial("tcp", ip, port, 4*time.Second)
	if err != nil {
		ev.Err = errStr(err)
		return ev
	}
	defer c.Close()
	tc := tls.Client(c, &tls.Config{ServerName: t.Name, InsecureSkipVerify: true})
	tc.SetDeadline(time.Now().Add(5 * time.Second))
	if err = tc.Handshake(); err == nil {
		p := saasPaths[g.intn(len(saasPaths))]
		r := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: OfficeSync/4.2\r\nAuthorization: Bearer lab-token\r\nAccept: application/json\r\nConnection: close\r\n\r\n", p, t.Name)
		io.WriteString(tc, r)
		var n int64
		n, err = readHTTP(bufio.NewReader(tc))
		ev.Bytes = int64(len(r)) + n
		ev.What += " " + p
	}
	ev.OK, ev.Err = err == nil, errStr(err)
	return ev
}

// ----- voice: SIP signalling and an RTP stream -----

func (g *generator) runVoice() {
	t := g.pick()
	if !g.sip(t, "REGISTER", "") {
		// keep trying: the PBX may be behind a policy the student hasn't written yet
	}
	reg := time.Now()
	for g.wait(2400, 4800) { // about one call an hour
		if time.Since(reg) > time.Duration(float64(30*time.Minute)/g.rate) {
			g.sip(t, "REGISTER", "")
			reg = time.Now()
		}
		ext := fmt.Sprintf("%d", 200+g.intn(40))
		if !g.sip(t, "INVITE", ext) {
			continue
		}
		secs := 60 + g.intn(180)
		dur := time.Duration(float64(time.Duration(secs)*time.Second) / g.rate)
		if dur < 3*time.Second {
			dur = 3 * time.Second
		}
		g.record(g.rtp(t, dur))
		g.sip(t, "BYE", ext)
	}
}

func (g *generator) sip(t genTarget, method, ext string) bool {
	port := t.Port
	if port == 0 {
		port = 5060
	}
	ev := genEv{What: "sip " + method, Dst: t.IP, Port: port, Proto: "udp"}
	c, err := g.dial("udp", t.IP, port, 2*time.Second)
	if err != nil {
		ev.Err = errStr(err)
		g.record(ev)
		return false
	}
	defer c.Close()
	me, _, _ := net.SplitHostPort(c.LocalAddr().String())
	user := strings.ToLower(g.ns)
	uri := "sip:" + t.IP
	if ext != "" {
		uri = "sip:" + ext + "@" + t.IP
		ev.What += " " + ext
	}
	msg := fmt.Sprintf("%s %s SIP/2.0\r\nVia: SIP/2.0/UDP %s:5060;branch=z9hG4bK%d\r\nMax-Forwards: 70\r\nFrom: <sip:%s@%s>;tag=%d\r\nTo: <%s>\r\nCall-ID: %d@%s\r\nCSeq: 1 %s\r\nContact: <sip:%s@%s:5060>\r\nUser-Agent: LabPhone 1.0\r\nContent-Length: 0\r\n\r\n",
		method, uri, me, g.intn(1<<30), user, t.IP, g.intn(1<<30), uri, g.intn(1<<30), me, method, user, me)
	c.SetDeadline(time.Now().Add(2 * time.Second))
	c.Write([]byte(msg))
	buf := make([]byte, 1500)
	k, err := c.Read(buf)
	ev.Bytes = int64(len(msg) + k)
	ev.OK = err == nil && strings.HasPrefix(string(buf[:k]), "SIP/2.0 200")
	ev.Err = errStr(err)
	g.record(ev)
	return ev.OK
}

func (g *generator) rtp(t genTarget, dur time.Duration) genEv {
	ev := genEv{What: fmt.Sprintf("rtp call %ds", int(dur.Seconds())), Dst: t.IP, Port: 16384, Proto: "udp"}
	c, err := g.dial("udp", t.IP, 16384, 2*time.Second)
	if err != nil {
		ev.Err = errStr(err)
		return ev
	}
	defer c.Close()
	pkt := make([]byte, 172) // 12-byte RTP header + 160 bytes of G.711 (20 ms)
	pkt[0], pkt[1] = 0x80, 0x00
	ssrc := uint32(g.intn(1 << 30))
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	end := time.Now().Add(dur)
	var seq uint16
	var ts uint32
	for time.Now().Before(end) {
		select {
		case <-g.stop:
			end = time.Now()
		case <-tick.C:
			seq++
			ts += 160
			binary.BigEndian.PutUint16(pkt[2:], seq)
			binary.BigEndian.PutUint32(pkt[4:], ts)
			binary.BigEndian.PutUint32(pkt[8:], ssrc)
			if _, err := c.Write(pkt); err == nil {
				ev.Bytes += int64(len(pkt))
			}
		}
	}
	ev.OK = ev.Bytes > 0
	return ev
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return classify(err) + ": " + err.Error()
}

// ----- ops -----

func genStart(r req) (map[string]any, error) {
	id, ns, kind := r.str("id"), r.str("ns"), r.str("kind")
	if err := checkNS(ns); err != nil {
		return nil, err
	}
	if id == "" {
		id = ns + "/" + kind
	}
	g := &generator{id: id, ns: ns, kind: kind, src: r.str("src"), resolver: r.str("resolver"), rate: r.num("rate", 1),
		rnd: rand.New(rand.NewSource(int64(r.num("seed", 1)))), stop: make(chan struct{}), started: time.Now()}
	if g.rate <= 0 || g.rate > 500 {
		return nil, fmt.Errorf("rate out of range (0-500)")
	}
	if g.resolver != "" && net.ParseIP(g.resolver) == nil {
		return nil, fmt.Errorf("bad resolver")
	}
	ts, _ := r["targets"].([]any)
	for _, x := range ts {
		m, _ := x.(map[string]any)
		t := genTarget{Name: fmt.Sprint(m["name"]), IP: fmt.Sprint(m["ip"])}
		if m["name"] == nil {
			t.Name = ""
		}
		if m["ip"] == nil {
			t.IP = ""
		}
		if p, ok := m["port"].(float64); ok {
			t.Port = int(p)
		}
		t.TLS, _ = m["tls"].(bool)
		if ps, ok := m["paths"].([]any); ok {
			for _, p := range ps {
				t.Paths = append(t.Paths, fmt.Sprint(p))
			}
		}
		if t.IP != "" && net.ParseIP(t.IP) == nil {
			return nil, fmt.Errorf("bad target address %q", t.IP)
		}
		g.targets = append(g.targets, t)
	}
	g.names = r.strs("names")
	var run func()
	switch kind {
	case "web":
		run = g.runWeb
	case "dns":
		run = g.runDNS
	case "smb":
		run = g.runSMB
	case "mail":
		run = g.runMail
	case "voice":
		run = g.runVoice
	default:
		return nil, fmt.Errorf("unknown generator %q", kind)
	}
	if len(g.targets) == 0 && kind != "dns" {
		return nil, fmt.Errorf("generator %s needs targets", kind)
	}
	genMu.Lock()
	if old := gens[id]; old != nil {
		close(old.stop)
	}
	gens[id] = g
	genMu.Unlock()
	go run()
	return map[string]any{"id": id}, nil
}

func genStop(r req) (map[string]any, error) {
	id := r.str("id")
	genMu.Lock()
	defer genMu.Unlock()
	n := 0
	for k, g := range gens {
		if id == "" || k == id || g.ns == id {
			close(g.stop)
			delete(gens, k)
			n++
		}
	}
	return map[string]any{"stopped": n}, nil
}

func stopAllGens() { genStop(req{}) }

// gen.stats: running generators and the flow events since a sequence number
func genStats(r req) (map[string]any, error) {
	since := int64(r.num("since", 0))
	genMu.Lock()
	defer genMu.Unlock()
	run := []map[string]any{}
	for _, g := range gens {
		run = append(run, map[string]any{"id": g.id, "ns": g.ns, "kind": g.kind, "rate": g.rate, "flows": g.flows, "bytes": g.bytes, "errors": g.errs, "up_ms": time.Since(g.started).Milliseconds()})
	}
	evs := []genEv{}
	for _, e := range genLog {
		if e.Seq > since {
			evs = append(evs, e)
		}
	}
	if len(evs) > 500 {
		evs = evs[len(evs)-500:]
	}
	return map[string]any{"running": run, "events": evs, "next": genSeq}, nil
}
