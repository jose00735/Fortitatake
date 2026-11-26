package main

// Stand-in office servers for the traffic generators (gen.go): a NAS that speaks enough
// SMB2 to answer each command, a mail server (SMTP submission with STARTTLS, IMAPS), a PBX
// (SIP over UDP, an RTP sink) and NTP. Each command is logged as a hit, so labs can see
// what really reached the server through the FortiGate.

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const rtpPort = 16384

var (
	rtpMu   sync.Mutex
	rtpLast = map[string]time.Time{}
)

func rtpSeen(src string) bool {
	rtpMu.Lock()
	defer rtpMu.Unlock()
	if t, ok := rtpLast[src]; ok && time.Since(t) < 10*time.Second {
		return true
	}
	rtpLast[src] = time.Now()
	return false
}

// officeUDP answers SIP and NTP; nil for any other port
func officeUDP(port int, p []byte) []byte {
	switch port {
	case 5060:
		s := string(p)
		first := strings.SplitN(s, "\r\n", 2)[0]
		if !strings.Contains(first, "SIP/2.0") || strings.HasPrefix(first, "SIP/2.0") {
			return nil
		}
		var hdr []string
		for _, l := range strings.Split(s, "\r\n") {
			ll := strings.ToLower(l)
			for _, k := range []string{"via:", "from:", "to:", "call-id:", "cseq:"} {
				if strings.HasPrefix(ll, k) {
					if k == "to:" && !strings.Contains(ll, "tag=") {
						l += ";tag=ftkpbx"
					}
					hdr = append(hdr, l)
				}
			}
		}
		return []byte("SIP/2.0 200 OK\r\n" + strings.Join(hdr, "\r\n") + "\r\nServer: FortiTatake lab PBX\r\nContent-Length: 0\r\n\r\n")
	case 123:
		if len(p) < 48 {
			return nil
		}
		r := make([]byte, 48)
		r[0], r[1] = 0x24, 2 // NTPv4 server, stratum 2
		sec := uint32(time.Now().Unix() + 2208988800)
		for _, off := range []int{32, 40} {
			binary.BigEndian.PutUint32(r[off:], sec)
		}
		copy(r[24:32], p[40:48])
		return r
	}
	return nil
}

// officeTCP serves SMB, SMTP and IMAPS; false for any other port
func officeTCP(n *nsListen, c net.Conn, port int, src, dst string) bool {
	log := func(what string) { n.add(hit{Proto: "tcp", Port: port, Src: src, Dst: dst, Data: what}) }
	switch port {
	case 445:
		smbServe(c, log)
	case 25, 587:
		smtpServe(c, log)
	case 993:
		c.SetDeadline(time.Now().Add(30 * time.Second))
		tc := tls.Server(c, labTLS())
		if tc.Handshake() == nil {
			imapServe(tc, log)
		}
	default:
		return false
	}
	return true
}

var smbCmd = map[uint16]string{0: "NEGOTIATE", 1: "SESSION_SETUP", 2: "LOGOFF", 3: "TREE_CONNECT", 5: "CREATE", 6: "CLOSE", 8: "READ", 9: "WRITE"}

func smbServe(c net.Conn, log func(string)) {
	var reads, writes, rb, wb int
	file := ""
	defer func() {
		if reads+writes > 0 {
			log(fmt.Sprintf("SMB2 %s: %d reads (%d KB), %d writes (%d KB)", file, reads, rb>>10, writes, wb>>10))
		}
	}()
	for {
		c.SetDeadline(time.Now().Add(30 * time.Second))
		m, err := readSMB(c)
		if err == nil && len(m) >= 32 && string(m[:4]) == "\xffSMB" { // SMBv1: this NAS has it off
			log(fmt.Sprintf("SMB1 command 0x%02x refused (SMBv1 disabled)", m[4]))
			r := make([]byte, 35)
			copy(r, m[:32])
			binary.LittleEndian.PutUint32(r[5:], 0xc0000022) // STATUS_ACCESS_DENIED
			r[9] |= 0x80                                     // reply
			nb := []byte{0, 0, 0, byte(len(r))}
			c.Write(append(nb, r...))
			return
		}
		if err != nil || len(m) < 64 || string(m[:4]) != "\xfeSMB" {
			return
		}
		cmd := binary.LittleEndian.Uint16(m[12:])
		body := m[64:]
		var out []byte
		switch cmd {
		case 8: // READ: "<file>\x00<bytes>"
			k := 0
			if i := strings.IndexByte(string(body), 0); i >= 0 {
				fmt.Sscan(string(body[i+1:]), &k)
			}
			if k > 1<<20 {
				k = 1 << 20
			}
			out = make([]byte, 16+k)
			reads++
			rb += k
		case 9:
			writes++
			wb += len(body)
			out = make([]byte, 16)
		default:
			if cmd == 5 || cmd == 3 || cmd == 1 {
				log("SMB2 " + smbCmd[cmd] + " " + strings.TrimRight(string(body), "\x00"))
				if cmd == 5 {
					file = strings.TrimRight(string(body), "\x00")
				}
			} else if cmd == 0 {
				log("SMB2 NEGOTIATE (dialect 2.1)")
			}
			out = make([]byte, 16)
		}
		h := make([]byte, 64)
		copy(h, m[:64])
		binary.LittleEndian.PutUint16(h[12:], cmd)
		h[16] = 1 // server-to-client flag
		frame := append(h, out...)
		nb := make([]byte, 4)
		binary.BigEndian.PutUint32(nb, uint32(len(frame)))
		if _, err := c.Write(append(nb, frame...)); err != nil {
			return
		}
	}
}

func smtpServe(c net.Conn, log func(string)) {
	c.SetDeadline(time.Now().Add(30 * time.Second))
	var rw io.ReadWriter = c
	rd := bufio.NewReader(rw)
	say := func(s string) { io.WriteString(rw, s+"\r\n") }
	say("220 mail.lab ESMTP FortiTatake")
	tlsOn := false
	from, rcpt := "", ""
	for {
		l, err := rd.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(l))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			if tlsOn {
				say("250-mail.lab\r\n250-SIZE 35882577\r\n250 AUTH PLAIN LOGIN")
			} else {
				say("250-mail.lab\r\n250-SIZE 35882577\r\n250 STARTTLS")
			}
		case cmd == "STARTTLS":
			say("220 Ready to start TLS")
			tc := tls.Server(c, labTLS())
			if tc.Handshake() != nil {
				return
			}
			rw, rd, tlsOn = tc, bufio.NewReader(tc), true
		case strings.HasPrefix(cmd, "MAIL FROM"):
			from = strings.TrimSpace(l[10:])
			say("250 OK")
		case strings.HasPrefix(cmd, "RCPT TO"):
			rcpt = strings.TrimSpace(l[8:])
			say("250 OK")
		case cmd == "DATA":
			say("354 End data with <CR><LF>.<CR><LF>")
			size := 0
			subj := ""
			for {
				d, err := rd.ReadString('\n')
				if err != nil {
					return
				}
				if d == ".\r\n" || d == ".\n" {
					break
				}
				size += len(d)
				if subj == "" && strings.HasPrefix(strings.ToLower(d), "subject:") {
					subj = strings.TrimSpace(d[8:])
				}
			}
			log(fmt.Sprintf("SMTP %s -> %s %q %d bytes (TLS %v)", from, rcpt, subj, size, tlsOn))
			say("250 OK queued")
		case cmd == "QUIT":
			say("221 Bye")
			return
		default:
			say("250 OK")
		}
	}
}

func imapServe(c net.Conn, log func(string)) {
	rd := bufio.NewReader(c)
	io.WriteString(c, "* OK FortiTatake lab IMAP ready\r\n")
	user := ""
	for {
		l, err := rd.ReadString('\n')
		if err != nil {
			return
		}
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		tag, cmd := f[0], strings.ToUpper(f[1])
		switch cmd {
		case "LOGIN":
			if len(f) > 2 {
				user = f[2]
			}
			io.WriteString(c, tag+" OK LOGIN completed\r\n")
		case "SELECT":
			io.WriteString(c, "* 3 EXISTS\r\n* 1 RECENT\r\n"+tag+" OK [READ-WRITE] SELECT completed\r\n")
		case "FETCH":
			io.WriteString(c, "* 1 FETCH (FLAGS (\\Seen))\r\n* 2 FETCH (FLAGS (\\Seen))\r\n* 3 FETCH (FLAGS ())\r\n"+tag+" OK FETCH completed\r\n")
		case "LOGOUT":
			io.WriteString(c, "* BYE\r\n"+tag+" OK LOGOUT completed\r\n")
			log("IMAPS session for " + user)
			return
		default:
			io.WriteString(c, tag+" OK\r\n")
		}
	}
}
