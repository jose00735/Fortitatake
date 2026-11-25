package main

// The Internet namespace's exit. Packets for real Internet addresses that no lab device owns
// would hit the namespace's blackhole default route; this watcher sees them first (AF_PACKET),
// relays ICMP echo and DNS questions through FortiTatake, and writes the answers back with the
// real destination as their source (a raw socket), so the lab sees real replies with real RTTs.
// The namespace's kernel ignores echo requests (icmp_echo_ignore_all), so the agent also
// answers pings for the lab's own Internet hosts that have no real counterpart.

import (
	"encoding/binary"
	"net"
	"sync"
	"syscall"
	"time"
)

type inetCfg struct {
	NS    string   `json:"ns"`
	Hosts []string `json:"hosts"` // the lab's Internet hosts (addresses local to the namespace)
}

var (
	inetMu  sync.Mutex
	inetGen int
	inetFDs []int
)

func inetStop() {
	inetMu.Lock()
	inetGen++
	for _, fd := range inetFDs {
		syscall.Close(fd)
	}
	inetFDs = nil
	inetMu.Unlock()
}

func inetStart(c *inetCfg) error {
	inetStop()
	if c == nil || c.NS == "" {
		return nil
	}
	local := map[[4]byte]bool{}
	for _, h := range c.Hosts {
		if ip := net.ParseIP(h).To4(); ip != nil {
			local[[4]byte(ip)] = true
		}
	}
	var pfd, rfd int
	err := withNetns(c.NS, func() error {
		var err error
		if pfd, err = syscall.Socket(syscall.AF_PACKET, syscall.SOCK_DGRAM, int(htons(syscall.ETH_P_IP))); err != nil {
			return err
		}
		if rfd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW); err != nil {
			syscall.Close(pfd)
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	tv := syscall.Timeval{Sec: 1}
	syscall.SetsockoptTimeval(pfd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	inetMu.Lock()
	gen := inetGen
	inetFDs = []int{pfd, rfd}
	inetMu.Unlock()
	send := func(pkt []byte, dst [4]byte) {
		syscall.Sendto(rfd, pkt, 0, &syscall.SockaddrInet4{Addr: dst})
	}
	go func() {
		buf := make([]byte, 65536)
		for {
			inetMu.Lock()
			alive := gen == inetGen
			inetMu.Unlock()
			if !alive {
				return
			}
			n, from, err := syscall.Recvfrom(pfd, buf, 0)
			if err != nil {
				if err == syscall.EAGAIN || err == syscall.EINTR {
					continue
				}
				return
			}
			if ll, ok := from.(*syscall.SockaddrLinklayer); ok && ll.Pkttype == 4 { // PACKET_OUTGOING: our own replies
				continue
			}
			inetPacket(append([]byte{}, buf[:n]...), local, send)
		}
	}()
	return nil
}

// inetPacket handles one IPv4 packet seen in the Internet namespace.
func inetPacket(p []byte, local map[[4]byte]bool, send func([]byte, [4]byte)) {
	if len(p) < 20 || p[0]>>4 != 4 {
		return
	}
	ihl := int(p[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(p[2:4]))
	if ihl < 20 || total > len(p) || total < ihl+8 {
		return
	}
	p = p[:total]
	var src, dst [4]byte
	copy(src[:], p[12:16])
	copy(dst[:], p[16:20])
	body := p[ihl:]
	switch p[9] {
	case 1: // ICMP
		if body[0] != 8 { // echo request only
			return
		}
		reply := func(ttl int) {
			r := append([]byte{}, body...)
			r[0], r[2], r[3] = 0, 0, 0
			binary.BigEndian.PutUint16(r[2:], csum(r))
			send(ipv4(dst, src, 1, ttl, r), src)
		}
		// the lab's own Internet hosts answer from the lab, except the famous public resolvers,
		// which the lab often defines as its DNS servers: those are pinged for real
		if realInternet(net.IP(dst[:])) && (!local[dst] || famous[dst]) {
			go func() {
				if a, ok := relayAsk("ping", net.IP(dst[:]).String(), nil, len(body)-8, 4*time.Second); ok {
					ttl := a.TTL
					if ttl <= 0 || ttl > 255 {
						ttl = 54
					}
					reply(ttl)
				} else if local[dst] { // no way out: the lab's own host answers
					reply(64)
				}
			}()
		} else if local[dst] {
			reply(64)
		}
	case 17: // UDP
		if len(body) < 8 || binary.BigEndian.Uint16(body[2:4]) != 53 || local[dst] || !realInternet(net.IP(dst[:])) {
			return // lab DNS servers answer through their own listeners
		}
		sport := binary.BigEndian.Uint16(body[0:2])
		q := append([]byte{}, body[8:]...)
		go func() {
			a, ok := relayAsk("dns", "", q, 0, 4*time.Second)
			if !ok || len(a.Data) < 12 {
				return
			}
			u := make([]byte, 8+len(a.Data))
			binary.BigEndian.PutUint16(u[0:], 53)
			binary.BigEndian.PutUint16(u[2:], sport)
			binary.BigEndian.PutUint16(u[4:], uint16(len(u)))
			copy(u[8:], a.Data) // UDP checksum 0: optional on IPv4
			send(ipv4(dst, src, 17, 54, u), src)
		}()
	}
}

var famous = map[[4]byte]bool{{8, 8, 8, 8}: true, {8, 8, 4, 4}: true, {1, 1, 1, 1}: true, {1, 0, 0, 1}: true, {9, 9, 9, 9}: true, {208, 67, 222, 222}: true}

func ipv4(src, dst [4]byte, proto byte, ttl int, payload []byte) []byte {
	h := make([]byte, 20+len(payload))
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:], uint16(len(h)))
	h[8] = byte(ttl)
	h[9] = proto
	copy(h[12:16], src[:])
	copy(h[16:20], dst[:])
	binary.BigEndian.PutUint16(h[10:], csum(h[:20]))
	copy(h[20:], payload)
	return h
}

func csum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}
