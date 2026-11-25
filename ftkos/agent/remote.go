package main

// SSH and Telnet between lab devices. The bytes on the wire are real: TCP from the client's
// namespace to the server's, an SSH version exchange and KEXINIT that offer modern algorithms
// (curve25519-sha256, ssh-ed25519, chacha20-poly1305@openssh.com, aes256-gcm@openssh.com),
// an ECDH-style key exchange and NEWKEYS, then encrypted packets. What protects them is
// deliberately weak: the session key comes from the two public values sent in the clear and
// the cipher is a keyed XOR stream. Cheap on a phone, and anyone with the pcap can decrypt it.
// Telnet is plain text. The device's CLI is answered by FortiTatake (console.poll/reply).

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

var labAlgos = [][]string{
	{"curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "diffie-hellman-group16-sha512"},
	{"ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256"},
	{"chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com", "aes256-ctr"},
	{"chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com", "aes256-ctr"},
	{"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com"},
	{"hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com"},
	{"none", "zlib@openssh.com"},
	{"none", "zlib@openssh.com"},
	{}, {},
}

// ---------- SSH binary packets ----------
func sshString(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out
}

func writePacket(w io.Writer, payload []byte) error {
	pad := 8 - (5+len(payload))%8
	if pad < 4 {
		pad += 8
	}
	p := make([]byte, 5+len(payload)+pad)
	binary.BigEndian.PutUint32(p, uint32(1+len(payload)+pad))
	p[4] = byte(pad)
	copy(p[5:], payload)
	rand.Read(p[5+len(payload):])
	_, err := w.Write(p)
	return err
}

func readPacket(r *bufio.Reader) ([]byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:4])
	if n < 1 || n > 1<<16 {
		return nil, errors.New("bad packet")
	}
	rest := make([]byte, n-1)
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, err
	}
	pad := int(hdr[4])
	if pad > len(rest) {
		return nil, errors.New("bad padding")
	}
	return rest[:len(rest)-pad], nil
}

func kexinit() []byte {
	p := []byte{20}
	cookie := make([]byte, 16)
	rand.Read(cookie)
	p = append(p, cookie...)
	for _, l := range labAlgos {
		p = append(p, sshString([]byte(strings.Join(l, ",")))...)
	}
	return append(p, 0, 0, 0, 0, 0)
}

// the "lab cipher": XOR with a SHA-256 counter stream keyed by the visible exchange values
type labStream struct {
	key   [32]byte
	ctr   uint64
	block []byte
}

func newStream(seed []byte, dir string) *labStream {
	s := &labStream{key: sha256.Sum256(append(append([]byte{}, seed...), dir...))}
	return s
}
func (s *labStream) xor(b []byte) {
	for i := range b {
		if len(s.block) == 0 {
			var c [8]byte
			binary.BigEndian.PutUint64(c[:], s.ctr)
			s.ctr++
			h := sha256.Sum256(append(s.key[:], c[:]...))
			s.block = h[:]
		}
		b[i] ^= s.block[0]
		s.block = s.block[1:]
	}
}

// encrypted records after NEWKEYS: 4-byte length in clear (like -etm MACs), then the XORed bytes
func writeRec(w io.Writer, s *labStream, data []byte) error {
	b := append([]byte{}, data...)
	s.xor(b)
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	_, err := w.Write(append(l[:], b...))
	return err
}
func readRec(r *bufio.Reader, s *labStream) ([]byte, error) {
	var l [4]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(l[:])
	if n > 1<<20 {
		return nil, errors.New("record too large")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	s.xor(b)
	return b, nil
}

// ---------- server side: sessions bridged to FortiTatake ----------
type conEvent struct {
	Sid  string `json:"sid"`
	NS   string `json:"ns"`
	Kind string `json:"kind"` // open, line, close
	Line string `json:"line,omitempty"`
	User string `json:"user,omitempty"`
	From string `json:"from,omitempty"`
	Prot string `json:"proto,omitempty"`
}
type conSession struct {
	send func(string) error
	c    net.Conn
}

var (
	conMu   sync.Mutex
	conQ    []conEvent
	conSess = map[string]*conSession{}
	conSeq  int
)

func conPush(e conEvent) {
	conMu.Lock()
	conQ = append(conQ, e)
	if len(conQ) > 2000 {
		conQ = conQ[len(conQ)-2000:]
	}
	conMu.Unlock()
}

// serveRemote handles one SSH or Telnet connection on a lab device
func serveRemote(n *nsListen, ns string, c net.Conn, port int, mode, banner string) {
	defer c.Close()
	src, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	dst, _, _ := net.SplitHostPort(c.LocalAddr().String())
	n.add(hit{Proto: "tcp", Port: port, Src: src, Dst: dst})
	r := bufio.NewReader(c)
	conMu.Lock()
	conSeq++
	sid := fmt.Sprintf("in%d", conSeq)
	conMu.Unlock()
	var send func(string) error
	var recv func() (string, error)
	user := ""
	if mode == "ssh" {
		c.SetDeadline(time.Now().Add(20 * time.Second))
		if banner == "" {
			banner = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"
		}
		fmt.Fprintf(c, "%s\r\n", banner)
		if _, err := r.ReadString('\n'); err != nil {
			return
		}
		writePacket(c, kexinit())
		if p, err := readPacket(r); err != nil || len(p) == 0 || p[0] != 20 {
			return
		}
		ci, err := readPacket(r) // KEX_ECDH_INIT: the client's public value
		if err != nil || len(ci) < 5 || ci[0] != 30 {
			return
		}
		qc := ci[5:]
		qs := make([]byte, 32)
		rand.Read(qs)
		hostkey := append(sshString([]byte("ssh-ed25519")), sshString(qs)...)
		sig := sha256.Sum256(append(append([]byte{}, qc...), qs...))
		reply := append([]byte{31}, sshString(hostkey)...)
		reply = append(reply, sshString(qs)...)
		reply = append(reply, sshString(append(sshString([]byte("ssh-ed25519")), sshString(append(sig[:], sig[:]...))...))...)
		writePacket(c, reply)
		writePacket(c, []byte{21}) // NEWKEYS
		if p, err := readPacket(r); err != nil || len(p) == 0 || p[0] != 21 {
			return
		}
		seed := append(append([]byte{}, qc...), qs...)
		in, out := newStream(seed, "c2s"), newStream(seed, "s2c")
		send = func(s string) error { return writeRec(c, out, []byte(s)) }
		recv = func() (string, error) { b, err := readRec(r, in); return string(b), err }
		c.SetDeadline(time.Now().Add(3 * time.Minute)) // the person types the password
		auth, err := recv()                            // "user\x00password"
		if err != nil {
			return
		}
		user = strings.SplitN(auth, "\x00", 2)[0]
		c.SetDeadline(time.Time{})
	} else {
		send = func(s string) error { _, err := io.WriteString(c, strings.ReplaceAll(s, "\n", "\r\n")); return err }
		recv = func() (string, error) {
			l, err := r.ReadString('\n')
			// drop Telnet option negotiation (IAC sequences)
			var b strings.Builder
			for i := 0; i < len(l); i++ {
				if l[i] == 255 && i+2 < len(l) {
					i += 2
					continue
				}
				b.WriteByte(l[i])
			}
			return strings.TrimRight(b.String(), "\r\n"), err
		}
	}
	conMu.Lock()
	conSess[sid] = &conSession{send: send, c: c}
	conMu.Unlock()
	conPush(conEvent{Sid: sid, NS: ns, Kind: "open", User: user, From: src, Prot: mode})
	defer func() {
		conMu.Lock()
		delete(conSess, sid)
		conMu.Unlock()
		conPush(conEvent{Sid: sid, NS: ns, Kind: "close"})
	}()
	for {
		line, err := recv()
		if line != "" || err == nil {
			conPush(conEvent{Sid: sid, NS: ns, Kind: "line", Line: line})
		}
		if err != nil {
			return
		}
	}
}

func consolePoll(r req) (map[string]any, error) {
	conMu.Lock()
	defer conMu.Unlock()
	out := conQ
	conQ = nil
	if out == nil {
		out = []conEvent{}
	}
	return map[string]any{"events": out}, nil
}

func consoleReply(r req) (map[string]any, error) {
	conMu.Lock()
	s := conSess[r.str("sid")]
	conMu.Unlock()
	if s == nil {
		return map[string]any{"alive": false}, nil
	}
	if r.str("close") == "1" {
		s.c.Close()
		return map[string]any{"alive": false}, nil
	}
	if err := s.send(r.str("text")); err != nil {
		return map[string]any{"alive": false}, nil
	}
	return map[string]any{"alive": true}, nil
}

// ---------- client side ----------
type remoteClient struct {
	mu    sync.Mutex
	buf   []byte
	next  int64
	alive bool
	send  func(string) error
	c     net.Conn
	info  map[string]any
}

var (
	rcMu sync.Mutex
	rcs  = map[string]*remoteClient{}
	rcN  int
)

func (rc *remoteClient) push(s string) {
	rc.mu.Lock()
	rc.buf = append(rc.buf, s...)
	rc.mu.Unlock()
}

func remoteOpen(r req) (map[string]any, error) {
	ns, dst, proto, user, pass := r.str("ns"), r.str("dst"), r.str("proto"), r.str("user"), r.str("password")
	port := int(r.num("port", 22))
	if err := checkNS(ns); err != nil {
		return nil, err
	}
	var c net.Conn
	err := withNetns(ns, func() error {
		d := net.Dialer{Timeout: 4 * time.Second}
		cc, err := d.Dial("tcp4", net.JoinHostPort(dst, strconv.Itoa(port)))
		c = cc
		return err
	})
	if err != nil {
		return map[string]any{"error": err.Error()}, nil
	}
	rc := &remoteClient{alive: true, c: c, info: map[string]any{}}
	br := bufio.NewReader(c)
	var recv func() (string, error)
	if proto == "ssh" {
		c.SetDeadline(time.Now().Add(10 * time.Second))
		sb, err := br.ReadString('\n')
		if err != nil || !strings.HasPrefix(sb, "SSH-") {
			c.Close()
			return map[string]any{"error": "kex_exchange_identification: Connection closed by remote host"}, nil
		}
		rc.info["server"] = strings.TrimSpace(sb)
		fmt.Fprintf(c, "SSH-2.0-OpenSSH_for_Windows_9.5\r\n")
		writePacket(c, kexinit())
		if p, err := readPacket(br); err != nil || len(p) == 0 || p[0] != 20 {
			c.Close()
			return map[string]any{"error": "no KEXINIT from the server"}, nil
		}
		qc := make([]byte, 32)
		rand.Read(qc)
		writePacket(c, append([]byte{30}, sshString(qc)...))
		rep, err := readPacket(br)
		if err != nil || len(rep) < 1 || rep[0] != 31 {
			c.Close()
			return map[string]any{"error": "key exchange failed"}, nil
		}
		// K_S, Q_S
		ks := binary.BigEndian.Uint32(rep[1:5])
		off := 5 + int(ks)
		if off+4 > len(rep) {
			c.Close()
			return map[string]any{"error": "key exchange failed"}, nil
		}
		ql := int(binary.BigEndian.Uint32(rep[off : off+4]))
		qs := rep[off+4 : off+4+ql]
		if p, err := readPacket(br); err != nil || len(p) == 0 || p[0] != 21 {
			c.Close()
			return map[string]any{"error": "key exchange failed"}, nil
		}
		writePacket(c, []byte{21})
		fp := sha256.Sum256(qs)
		rc.info["kex"], rc.info["hostkey"], rc.info["cipher"], rc.info["mac"] = "curve25519-sha256", "ssh-ed25519", "chacha20-poly1305@openssh.com", "<implicit>"
		rc.info["fingerprint"] = "SHA256:" + strings.TrimRight(b64(fp[:]), "=")
		seed := append(append([]byte{}, qc...), qs...)
		out, in := newStream(seed, "c2s"), newStream(seed, "s2c")
		rc.send = func(s string) error { return writeRec(c, out, []byte(s)) }
		recv = func() (string, error) { b, err := readRec(br, in); return string(b), err }
		// without a password the first line sent is the password (the console asks for it after the key exchange)
		raw := rc.send
		if _, given := r["password"]; given {
			if err := raw(user + "\x00" + pass); err != nil {
				c.Close()
				return map[string]any{"error": err.Error()}, nil
			}
		} else {
			authed := false
			var mu sync.Mutex
			rc.send = func(s string) error {
				mu.Lock()
				defer mu.Unlock()
				if !authed {
					authed = true
					return raw(user + "\x00" + s)
				}
				return raw(s)
			}
		}
		c.SetDeadline(time.Time{})
	} else {
		rc.send = func(s string) error { _, err := io.WriteString(c, s+"\r\n"); return err }
		recv = func() (string, error) {
			b := make([]byte, 4096)
			k, err := br.Read(b)
			return strings.ReplaceAll(string(b[:k]), "\r\n", "\n"), err
		}
	}
	go func() {
		for {
			s, err := recv()
			if s != "" {
				rc.push(s)
			}
			if err != nil {
				rc.mu.Lock()
				rc.alive = false
				rc.mu.Unlock()
				return
			}
		}
	}()
	rcMu.Lock()
	rcN++
	id := fmt.Sprintf("rc%d", rcN)
	rcs[id] = rc
	rcMu.Unlock()
	return map[string]any{"session": id, "info": rc.info}, nil
}

func getRC(r req) *remoteClient { rcMu.Lock(); defer rcMu.Unlock(); return rcs[r.str("session")] }

func remoteSend(r req) (map[string]any, error) {
	rc := getRC(r)
	if rc == nil || rc.send(r.str("line")) != nil {
		return map[string]any{"alive": false}, nil
	}
	return map[string]any{"alive": true}, nil
}

func remoteRead(r req) (map[string]any, error) {
	rc := getRC(r)
	if rc == nil {
		return map[string]any{"alive": false, "data": ""}, nil
	}
	rc.mu.Lock()
	defer rc.mu.Unlock()
	d := string(rc.buf)
	rc.buf = nil
	return map[string]any{"alive": rc.alive, "data": d}, nil
}

func remoteClose(r req) (map[string]any, error) {
	rcMu.Lock()
	rc := rcs[r.str("session")]
	delete(rcs, r.str("session"))
	rcMu.Unlock()
	if rc != nil {
		rc.c.Close()
	}
	return map[string]any{}, nil
}

func stopAllRemote() {
	rcMu.Lock()
	for k, rc := range rcs {
		rc.c.Close()
		delete(rcs, k)
	}
	rcMu.Unlock()
	conMu.Lock()
	for _, s := range conSess {
		s.c.Close()
	}
	conQ = nil
	conMu.Unlock()
}

func b64(b []byte) string {
	const t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var s strings.Builder
	for i := 0; i < len(b); i += 3 {
		var n uint32
		k := 0
		for j := 0; j < 3; j++ {
			n <<= 8
			if i+j < len(b) {
				n |= uint32(b[i+j])
				k++
			}
		}
		for j := 0; j < 4; j++ {
			if j <= k {
				s.WriteByte(t[(n>>(18-6*j))&63])
			} else {
				s.WriteByte('=')
			}
		}
	}
	return s.String()
}
