//go:build windows

package ftkos

import (
	"encoding/binary"
	"errors"
	"net"
	"syscall"
	"time"
	"unsafe"
)

// realPing sends one ICMP echo with the Windows ICMP API (no administrator rights needed).
var (
	iphlp      = syscall.NewLazyDLL("iphlpapi.dll")
	icmpCreate = iphlp.NewProc("IcmpCreateFile")
	icmpSend   = iphlp.NewProc("IcmpSendEcho")
	icmpClose  = iphlp.NewProc("IcmpCloseHandle")
)

func realPing(dst net.IP, size int, timeout time.Duration) (float64, int, error) {
	if size <= 0 || size > 1400 {
		size = 32
	}
	h, _, _ := icmpCreate.Call()
	if h == 0 || h == ^uintptr(0) {
		return 0, 0, errors.New("IcmpCreateFile failed")
	}
	defer icmpClose.Call(h)
	data := make([]byte, size)
	for i := range data {
		data[i] = byte('a' + i%23)
	}
	reply := make([]byte, 64+size+8)
	addr := binary.LittleEndian.Uint32(dst.To4())
	t := time.Now()
	n, _, _ := icmpSend.Call(h, uintptr(addr), uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), 0,
		uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(timeout.Milliseconds()))
	if n == 0 {
		return 0, 0, errors.New("timeout")
	}
	if binary.LittleEndian.Uint32(reply[4:8]) != 0 { // IP_SUCCESS
		return 0, 0, errors.New("unreachable")
	}
	rtt := float64(binary.LittleEndian.Uint32(reply[8:12]))
	if rtt == 0 {
		rtt = float64(time.Since(t).Microseconds()) / 1000
	}
	ttl := int(reply[8+8+unsafe.Sizeof(uintptr(0))]) // ICMP_ECHO_REPLY.Options.Ttl
	return rtt, ttl, nil
}
