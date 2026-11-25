package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
)

// Packet capture on any wire: an AF_PACKET socket inside the device, written as pcap.
// One goroutine per capture, no tcpdump process; capped so a forgotten capture stays small.

type capture struct {
	fd      int
	buf     bytes.Buffer
	max     int
	packets int
	stop    chan struct{}
	done    chan struct{}
	mu      sync.Mutex
}

var (
	capMu  sync.Mutex
	caps   = map[string]*capture{}
	capSeq int
)

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func captureStart(r req) (map[string]any, error) {
	ns, ifn := r.str("ns"), r.str("if")
	if err := checkNS(ns); err != nil {
		return nil, err
	}
	max := int(r.num("max_bytes", 1<<20))
	if max > 8<<20 {
		max = 8 << 20
	}
	c := &capture{max: max, stop: make(chan struct{}), done: make(chan struct{})}
	err := withNetns(ns, func() error {
		ifi, err := net.InterfaceByName(ifn)
		if err != nil {
			return fmt.Errorf("%s has no interface %s", ns, ifn)
		}
		fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
		if err != nil {
			return err
		}
		if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ALL), Ifindex: ifi.Index}); err != nil {
			syscall.Close(fd)
			return err
		}
		tv := syscall.Timeval{Usec: 200000}
		syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
		c.fd = fd
		return nil
	})
	if err != nil {
		return nil, err
	}
	// pcap global header: magic, v2.4, snaplen 65535, linktype Ethernet
	h := make([]byte, 24)
	binary.LittleEndian.PutUint32(h[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(h[4:], 2)
	binary.LittleEndian.PutUint16(h[6:], 4)
	binary.LittleEndian.PutUint32(h[16:], 65535)
	binary.LittleEndian.PutUint32(h[20:], 1)
	c.buf.Write(h)
	capMu.Lock()
	capSeq++
	id := fmt.Sprintf("cap%d", capSeq)
	caps[id] = c
	capMu.Unlock()
	go c.loop()
	return map[string]any{"capture": id}, nil
}

func (c *capture) loop() {
	defer close(c.done)
	defer syscall.Close(c.fd)
	pkt := make([]byte, 65536)
	for {
		select {
		case <-c.stop:
			return
		default:
		}
		n, _, err := syscall.Recvfrom(c.fd, pkt, 0)
		if err != nil || n <= 0 {
			continue
		}
		now := time.Now()
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec[0:], uint32(now.Unix()))
		binary.LittleEndian.PutUint32(rec[4:], uint32(now.Nanosecond()/1000))
		binary.LittleEndian.PutUint32(rec[8:], uint32(n))
		binary.LittleEndian.PutUint32(rec[12:], uint32(n))
		c.mu.Lock()
		if c.buf.Len()+16+n <= c.max {
			c.buf.Write(rec)
			c.buf.Write(pkt[:n])
			c.packets++
		}
		c.mu.Unlock()
	}
}

func captureStop(r req) (map[string]any, error) {
	id := r.str("capture")
	capMu.Lock()
	c := caps[id]
	delete(caps, id)
	capMu.Unlock()
	if c == nil {
		return nil, fmt.Errorf("no capture %s", id)
	}
	close(c.stop)
	<-c.done
	c.mu.Lock()
	defer c.mu.Unlock()
	return map[string]any{"packets": c.packets, "bytes": c.buf.Len(), "pcap_b64": base64.StdEncoding.EncodeToString(c.buf.Bytes())}, nil
}

func stopAllCaptures() {
	capMu.Lock()
	all := caps
	caps = map[string]*capture{}
	capMu.Unlock()
	for _, c := range all {
		close(c.stop)
		<-c.done
	}
}
