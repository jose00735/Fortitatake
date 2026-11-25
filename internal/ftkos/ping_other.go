//go:build !windows

package ftkos

import (
	"encoding/binary"
	"errors"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"syscall"
	"time"
)

// realPing sends one ICMP echo: an unprivileged ICMP socket where the system allows it
// (Android, most Linux), otherwise the system's ping command.
func realPing(dst net.IP, size int, timeout time.Duration) (float64, int, error) {
	if size <= 0 || size > 1400 {
		size = 56
	}
	if fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_ICMP); err == nil {
		defer syscall.Close(fd)
		tv := syscall.NsecToTimeval(timeout.Nanoseconds())
		syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
		syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_RECVTTL, 1)
		pkt := make([]byte, 8+size)
		pkt[0] = 8
		binary.BigEndian.PutUint16(pkt[6:], 1)
		var sa syscall.SockaddrInet4
		copy(sa.Addr[:], dst.To4())
		t := time.Now()
		if err := syscall.Sendto(fd, pkt, 0, &sa); err == nil {
			buf := make([]byte, 2048)
			oob := make([]byte, 64)
			for time.Since(t) < timeout {
				n, oobn, _, _, err := syscall.Recvmsg(fd, buf, oob, 0)
				if err != nil {
					return 0, 0, errors.New("timeout")
				}
				if n >= 8 && buf[0] == 0 {
					ttl := 0
					if msgs, err := syscall.ParseSocketControlMessage(oob[:oobn]); err == nil {
						for _, m := range msgs {
							if m.Header.Level == syscall.IPPROTO_IP && m.Header.Type == syscall.IP_TTL && len(m.Data) > 0 {
								ttl = int(m.Data[0])
							}
						}
					}
					return float64(time.Since(t).Microseconds()) / 1000, ttl, nil
				}
			}
			return 0, 0, errors.New("timeout")
		}
	}
	out, err := exec.Command("ping", "-c", "1", "-W", strconv.Itoa(int(timeout.Seconds()+0.5)), "-s", strconv.Itoa(size), dst.String()).Output()
	if err != nil {
		return 0, 0, errors.New("timeout")
	}
	m := regexp.MustCompile(`ttl=(\d+).*time=([\d.]+)`).FindSubmatch(out)
	if m == nil {
		return 0, 0, errors.New("no reply")
	}
	ttl, _ := strconv.Atoi(string(m[1]))
	rtt, _ := strconv.ParseFloat(string(m[2]), 64)
	return rtt, ttl, nil
}
