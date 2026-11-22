package ftsp

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"sync"
	"time"
)

// A deliberately small mDNS / DNS-SD responder: it answers queries for
// _fortitatake._tcp.local so phones can find the hub with Android's NsdManager.
// The QR code and manual entry still work when multicast is blocked on a network.

var mdnsGroup = &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}

const (
	typeA   = 1
	typePTR = 12
	typeTXT = 16
	typeSRV = 33
	typeANY = 255
)

type mdnsResponder struct {
	instance string // "FortiTatake on DESKTOP-1"
	host     string // "ft-01jd3x0q.local"
	port     int
	txt      []string
	conns    []*net.UDPConn
	mu       sync.Mutex
	recent   map[string]time.Time
	stop     chan struct{}
}

func newMDNS(name, hubID string, port int, txt []string) *mdnsResponder {
	short := strings.ToLower(hubID)
	if len(short) > 8 {
		short = short[:8]
	}
	return &mdnsResponder{
		instance: "FortiTatake on " + sanitizeLabel(name),
		host:     "ft-" + short + ".local",
		port:     port,
		txt:      txt,
		recent:   map[string]time.Time{},
		stop:     make(chan struct{}),
	}
}

func sanitizeLabel(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '.' {
			return '-'
		}
		return r
	}, s)
	if len(s) > 40 {
		s = s[:40]
	}
	return s
}

func (m *mdnsResponder) start() error {
	ifs, _ := net.Interfaces()
	for i := range ifs {
		ifc := ifs[i]
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagMulticast == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(ifaceIPv4(&ifc)) == 0 {
			continue
		}
		c, err := net.ListenMulticastUDP("udp4", &ifc, mdnsGroup)
		if err != nil {
			continue
		}
		m.conns = append(m.conns, c)
		go m.serve(c)
	}
	if len(m.conns) == 0 {
		return errors.New("mDNS unavailable on this network; phones can still pair with the QR code or the PC's address")
	}
	go func() { // announce twice, as RFC 6762 suggests
		for i := 0; i < 2; i++ {
			for _, ip := range LANAddrs() {
				m.send(m.conns[0], mdnsGroup, m.answer(net.ParseIP(ip), 0))
			}
			select {
			case <-m.stop:
				return
			case <-time.After(time.Second):
			}
		}
	}()
	return nil
}

func (m *mdnsResponder) close() {
	select {
	case <-m.stop:
	default:
		close(m.stop)
	}
	for _, c := range m.conns {
		c.Close()
	}
}

func ifaceIPv4(ifc *net.Interface) []net.IP {
	var out []net.IP
	addrs, _ := ifc.Addrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil {
			out = append(out, ipn.IP.To4())
		}
	}
	return out
}

// localIPFor picks this machine's IPv4 on the same subnet as the asker.
func localIPFor(src net.IP) net.IP {
	ifs, _ := net.Interfaces()
	for i := range ifs {
		addrs, _ := ifs[i].Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && ipn.Contains(src) {
				return ipn.IP.To4()
			}
		}
	}
	return nil
}

func (m *mdnsResponder) serve(c *net.UDPConn) {
	buf := make([]byte, 9000)
	for {
		n, src, err := c.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if !m.wanted(buf[:n]) {
			continue
		}
		ip := localIPFor(src.IP)
		if ip == nil {
			continue
		}
		key := src.String() + "|" + ip.String()
		m.mu.Lock()
		if t, ok := m.recent[key]; ok && time.Since(t) < 800*time.Millisecond {
			m.mu.Unlock()
			continue // the same query arrived on several sockets
		}
		m.recent[key] = time.Now()
		for k, t := range m.recent {
			if time.Since(t) > 10*time.Second {
				delete(m.recent, k)
			}
		}
		m.mu.Unlock()
		id := binary.BigEndian.Uint16(buf[:2])
		if src.Port != 5353 { // legacy one-shot query: unicast reply echoing the id
			m.send(c, src, m.answer(ip, id))
			continue
		}
		m.send(c, mdnsGroup, m.answer(ip, 0))
		m.send(c, src, m.answer(ip, 0)) // also unicast, in case multicast leaves by another adapter
	}
}

func (m *mdnsResponder) send(c *net.UDPConn, to *net.UDPAddr, msg []byte) {
	_ = c.SetWriteDeadline(time.Now().Add(time.Second))
	_, _ = c.WriteToUDP(msg, to)
}

// wanted reports whether a query asks about our service, instance or host.
func (m *mdnsResponder) wanted(p []byte) bool {
	if len(p) < 12 || p[2]&0x80 != 0 { // too short, or a response
		return false
	}
	qd := int(binary.BigEndian.Uint16(p[4:6]))
	off := 12
	svc := ServiceType + ".local"
	for i := 0; i < qd; i++ {
		name, next, ok := readName(p, off)
		if !ok || next+4 > len(p) {
			return false
		}
		qt := binary.BigEndian.Uint16(p[next : next+2])
		off = next + 4
		name = strings.ToLower(strings.TrimSuffix(name, "."))
		switch {
		case name == svc && (qt == typePTR || qt == typeANY):
			return true
		case name == strings.ToLower(m.instance+"."+svc) && (qt == typeSRV || qt == typeTXT || qt == typeANY):
			return true
		case name == m.host && (qt == typeA || qt == typeANY):
			return true
		case name == "_services._dns-sd._udp.local" && (qt == typePTR || qt == typeANY):
			return true
		}
	}
	return false
}

func readName(p []byte, off int) (string, int, bool) {
	var labels []string
	end, jumps := -1, 0
	for {
		if off >= len(p) {
			return "", 0, false
		}
		l := int(p[off])
		switch {
		case l == 0:
			if end < 0 {
				end = off + 1
			}
			return strings.Join(labels, "."), end, true
		case l&0xC0 == 0xC0:
			if off+1 >= len(p) || jumps > 10 {
				return "", 0, false
			}
			if end < 0 {
				end = off + 2
			}
			off = int(binary.BigEndian.Uint16(p[off:off+2]) & 0x3FFF)
			jumps++
		default:
			if off+1+l > len(p) {
				return "", 0, false
			}
			labels = append(labels, string(p[off+1:off+1+l]))
			off += 1 + l
		}
	}
}

func putName(b []byte, name string) []byte {
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if l == "" {
			continue
		}
		if len(l) > 63 {
			l = l[:63]
		}
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0)
}

func putRR(b []byte, name string, typ uint16, flush bool, ttl uint32, rdata []byte) []byte {
	b = putName(b, name)
	class := uint16(1)
	if flush {
		class |= 0x8000
	}
	b = binary.BigEndian.AppendUint16(b, typ)
	b = binary.BigEndian.AppendUint16(b, class)
	b = binary.BigEndian.AppendUint32(b, ttl)
	b = binary.BigEndian.AppendUint16(b, uint16(len(rdata)))
	return append(b, rdata...)
}

// instance names may contain spaces and capitals; the first label is the whole instance.
func instanceRDATA(instance, svc string) []byte {
	var b []byte
	l := instance
	if len(l) > 63 {
		l = l[:63]
	}
	b = append(b, byte(len(l)))
	b = append(b, l...)
	return putName(b, svc)
}

func putInstanceName(b []byte, instance, svc string) []byte {
	return append(b, instanceRDATA(instance, svc)...)
}

func (m *mdnsResponder) answer(ip net.IP, id uint16) []byte {
	svc := ServiceType + ".local"
	b := make([]byte, 12, 512)
	binary.BigEndian.PutUint16(b[0:], id)
	binary.BigEndian.PutUint16(b[2:], 0x8400) // response, authoritative
	binary.BigEndian.PutUint16(b[6:], 1)      // answers
	binary.BigEndian.PutUint16(b[10:], 3)     // additional: SRV, TXT, A

	// PTR svc -> instance
	b = putRR(b, svc, typePTR, false, 4500, instanceRDATA(m.instance, svc))

	// SRV instance -> host:port
	srv := []byte{0, 0, 0, 0}
	srv = binary.BigEndian.AppendUint16(srv, uint16(m.port))
	srv = putName(srv, m.host)
	b = putInstanceName(b, m.instance, svc)
	b = binary.BigEndian.AppendUint16(b, typeSRV)
	b = binary.BigEndian.AppendUint16(b, 0x8001)
	b = binary.BigEndian.AppendUint32(b, 120)
	b = binary.BigEndian.AppendUint16(b, uint16(len(srv)))
	b = append(b, srv...)

	// TXT
	var txt []byte
	for _, kv := range m.txt {
		if len(kv) > 255 {
			kv = kv[:255]
		}
		txt = append(txt, byte(len(kv)))
		txt = append(txt, kv...)
	}
	b = putInstanceName(b, m.instance, svc)
	b = binary.BigEndian.AppendUint16(b, typeTXT)
	b = binary.BigEndian.AppendUint16(b, 0x8001)
	b = binary.BigEndian.AppendUint32(b, 4500)
	b = binary.BigEndian.AppendUint16(b, uint16(len(txt)))
	b = append(b, txt...)

	// A host -> ip
	b = putRR(b, m.host, typeA, true, 120, ip.To4())
	return b
}
