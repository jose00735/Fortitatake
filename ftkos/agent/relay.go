package main

// The lab's only door to the real Internet: DNS questions and ICMP echo. The agent has no
// network of its own, so it queues each request for FortiTatake (relay.wait, a long poll) and
// FortiTatake answers from the host it runs on (relay.answer). Nothing else leaves the lab.

import (
	"encoding/base64"
	"net"
	"sync"
	"time"
)

type relayReq struct {
	ID   int64  `json:"rid"`
	Kind string `json:"kind"` // "dns" or "ping"
	Dst  string `json:"dst,omitempty"`
	Data string `json:"data,omitempty"` // base64 DNS query
	Size int    `json:"size,omitempty"`
}

type relayAns struct {
	OK   bool
	Data []byte
	RTT  float64
	TTL  int
}

var (
	relayMu   sync.Mutex
	relayQ    []relayReq
	relayKick = make(chan struct{}, 1)
	relayPend = map[int64]chan relayAns{}
	relayN    int64
	relaySeen time.Time // last time FortiTatake was waiting for requests
	relayHits struct{ DNS, Ping, Fail int }
)

// relayOnline: FortiTatake is polling, so a request will be picked up.
func relayOnline() bool {
	relayMu.Lock()
	defer relayMu.Unlock()
	return !relaySeen.IsZero() && time.Since(relaySeen) < 30*time.Second
}

// relayAsk queues one request and waits for the answer.
func relayAsk(kind, dst string, data []byte, size int, wait time.Duration) (relayAns, bool) {
	if !relayOnline() {
		return relayAns{}, false
	}
	ch := make(chan relayAns, 1)
	relayMu.Lock()
	relayN++
	id := relayN
	relayPend[id] = ch
	r := relayReq{ID: id, Kind: kind, Dst: dst, Size: size}
	if data != nil {
		r.Data = base64.StdEncoding.EncodeToString(data)
	}
	relayQ = append(relayQ, r)
	relayMu.Unlock()
	select {
	case relayKick <- struct{}{}:
	default:
	}
	select {
	case a := <-ch:
		relayMu.Lock()
		if !a.OK {
			relayHits.Fail++
		} else if kind == "dns" {
			relayHits.DNS++
		} else {
			relayHits.Ping++
		}
		relayMu.Unlock()
		return a, a.OK
	case <-time.After(wait):
		relayMu.Lock()
		delete(relayPend, id)
		relayHits.Fail++
		relayMu.Unlock()
		return relayAns{}, false
	}
}

// relay.wait: FortiTatake's long poll. Not under opLock, so it never blocks topology changes.
func relayWait(r req) (map[string]any, error) {
	t := time.NewTimer(time.Duration(r.num("timeout_ms", 20000)) * time.Millisecond)
	defer t.Stop()
	for {
		relayMu.Lock()
		relaySeen = time.Now()
		if len(relayQ) > 0 {
			out := relayQ
			relayQ = nil
			relayMu.Unlock()
			return map[string]any{"reqs": out}, nil
		}
		relayMu.Unlock()
		select {
		case <-relayKick:
		case <-t.C:
			relayMu.Lock()
			relaySeen = time.Now()
			relayMu.Unlock()
			return map[string]any{"reqs": []relayReq{}}, nil
		}
	}
}

func relayAnswer(r req) (map[string]any, error) {
	id := int64(r.num("rid", 0)) // "id" is the request's own id on the agent channel
	relayMu.Lock()
	ch := relayPend[id]
	delete(relayPend, id)
	relayMu.Unlock()
	if ch != nil {
		a := relayAns{OK: r["ok"] == true, RTT: r.num("rtt_ms", 0), TTL: int(r.num("ttl", 0))}
		if d := r.str("data"); d != "" {
			a.Data, _ = base64.StdEncoding.DecodeString(d)
		}
		ch <- a
	}
	return map[string]any{}, nil
}

func relayStats() map[string]any {
	relayMu.Lock()
	defer relayMu.Unlock()
	return map[string]any{"online": !relaySeen.IsZero() && time.Since(relaySeen) < 30*time.Second, "dns": relayHits.DNS, "ping": relayHits.Ping, "failed": relayHits.Fail}
}

// realInternet: addresses that mean something on the real Internet. Private, shared, loopback,
// link-local, documentation (TEST-NET), benchmarking, multicast and reserved space stay in the lab.
var notInternet = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3"} {
		_, n, _ := net.ParseCIDR(c)
		out = append(out, n)
	}
	return out
}()

func realInternet(ip net.IP) bool {
	ip = ip.To4()
	if ip == nil {
		return false
	}
	for _, n := range notInternet {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}
