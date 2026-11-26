package main

// A minimal nfnetlink_queue client (no cgo, no libnetfilter_queue): bind a queue inside a
// network namespace, receive each queued packet with its id and payload, and give a verdict.
// Wire format from include/uapi/linux/netfilter/nfnetlink_queue.h.

import (
	"encoding/binary"
	"fmt"
	"syscall"
)

const (
	nfnlSubsysQueue  = 3
	nfqnlMsgPacket   = 0
	nfqnlMsgVerdict  = 1
	nfqnlMsgConfig   = 2
	nfqaPacketHdr    = 1
	nfqaVerdictHdr   = 2
	nfqaMark         = 3
	nfqaPayload      = 10
	nfqaCfgCmd       = 1
	nfqaCfgParams    = 2
	nfqnlCfgCmdBind  = 1
	nfqnlCopyPacket  = 2
	nlmFRequest      = 1
	nlmFAck          = 4
	netlinkNetfilter = 12
	nfDrop           = 0
	nfAccept         = 1
	nfRepeat         = 4
)

type nfq struct {
	fd    int
	queue uint16
	seq   uint32
}

func nlAttr(typ uint16, data []byte) []byte {
	l := 4 + len(data)
	b := make([]byte, (l+3)&^3)
	binary.LittleEndian.PutUint16(b[0:], uint16(l))
	binary.LittleEndian.PutUint16(b[2:], typ)
	copy(b[4:], data)
	return b
}

func (q *nfq) msg(typ uint16, flags uint16, attrs ...[]byte) []byte {
	body := []byte{syscall.AF_UNSPEC, 0, 0, 0} // nfgenmsg: family, version, res_id (big endian)
	binary.BigEndian.PutUint16(body[2:], q.queue)
	for _, a := range attrs {
		body = append(body, a...)
	}
	h := make([]byte, 16)
	q.seq++
	binary.LittleEndian.PutUint32(h[0:], uint32(16+len(body)))
	binary.LittleEndian.PutUint16(h[4:], nfnlSubsysQueue<<8|typ)
	binary.LittleEndian.PutUint16(h[6:], nlmFRequest|flags)
	binary.LittleEndian.PutUint32(h[8:], q.seq)
	return append(h, body...)
}

func (q *nfq) send(b []byte) error {
	return syscall.Sendto(q.fd, b, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
}

// ack waits for the kernel's answer to a request sent with NLM_F_ACK
func (q *nfq) ack() error {
	buf := make([]byte, 8192)
	n, _, err := syscall.Recvfrom(q.fd, buf, 0)
	if err != nil {
		return err
	}
	if n >= 20 && binary.LittleEndian.Uint16(buf[4:]) == syscall.NLMSG_ERROR {
		if e := int32(binary.LittleEndian.Uint32(buf[16:])); e != 0 {
			return syscall.Errno(-e)
		}
	}
	return nil
}

// nfqOpen binds a queue; call it inside the namespace (the socket keeps it).
func nfqOpen(queue uint16) (*nfq, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, netlinkNetfilter)
	if err != nil {
		return nil, fmt.Errorf("netlink: %v", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 1<<20)
	q := &nfq{fd: fd, queue: queue}
	cmd := []byte{nfqnlCfgCmdBind, 0, 0, syscall.AF_INET}
	if err := q.send(q.msg(nfqnlMsgConfig, nlmFAck, nlAttr(nfqaCfgCmd, cmd))); err != nil {
		q.close()
		return nil, err
	}
	if err := q.ack(); err != nil {
		q.close()
		return nil, fmt.Errorf("bind queue %d: %v (kernel without NFQUEUE? rebuild FortiTatake OS)", queue, err)
	}
	params := make([]byte, 5)
	binary.BigEndian.PutUint32(params, 0xffff)
	params[4] = nfqnlCopyPacket
	if err := q.send(q.msg(nfqnlMsgConfig, nlmFAck, nlAttr(nfqaCfgParams, params))); err != nil {
		q.close()
		return nil, err
	}
	if err := q.ack(); err != nil {
		q.close()
		return nil, err
	}
	return q, nil
}

func (q *nfq) close() { syscall.Close(q.fd) }

// unbind releases the queue at once, so a new socket can bind it while this one's reader winds down
func (q *nfq) unbind() {
	cmd := []byte{2 /* NFQNL_CFG_CMD_UNBIND */, 0, 0, syscall.AF_INET}
	q.send(q.msg(nfqnlMsgConfig, 0, nlAttr(nfqaCfgCmd, cmd)))
}

// next blocks for the next queued packet: its id and the IP packet
func (q *nfq) next(buf []byte) (uint32, []byte, error) {
	for {
		n, _, err := syscall.Recvfrom(q.fd, buf, 0)
		if err != nil {
			if err == syscall.ENOBUFS || err == syscall.EINTR {
				continue // the kernel dropped some under load (fail-open lets them through)
			}
			return 0, nil, err
		}
		for off := 0; off+16 <= n; {
			l := int(binary.LittleEndian.Uint32(buf[off:]))
			typ := binary.LittleEndian.Uint16(buf[off+4:])
			if l < 16 || off+l > n {
				break
			}
			if typ == nfnlSubsysQueue<<8|nfqnlMsgPacket {
				var id uint32
				var payload []byte
				for a := off + 20; a+4 <= off+l; {
					al := int(binary.LittleEndian.Uint16(buf[a:]))
					at := binary.LittleEndian.Uint16(buf[a+2:]) & 0x3fff
					if al < 4 || a+al > off+l {
						break
					}
					switch at {
					case nfqaPacketHdr:
						id = binary.BigEndian.Uint32(buf[a+4:])
					case nfqaPayload:
						payload = append([]byte{}, buf[a+4:a+al]...)
					}
					a += (al + 3) &^ 3
				}
				return id, payload, nil
			}
			off += (l + 3) &^ 3
		}
	}
}

func (q *nfq) verdict(id uint32, v uint32, mark uint32) error {
	vh := make([]byte, 8)
	binary.BigEndian.PutUint32(vh[0:], v)
	binary.BigEndian.PutUint32(vh[4:], id)
	attrs := [][]byte{nlAttr(nfqaVerdictHdr, vh)}
	if mark != 0 {
		m := make([]byte, 4)
		binary.BigEndian.PutUint32(m, mark)
		attrs = append(attrs, nlAttr(nfqaMark, m))
	}
	return q.send(q.msg(nfqnlMsgVerdict, 0, attrs...))
}
