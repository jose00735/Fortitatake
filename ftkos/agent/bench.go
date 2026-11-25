package main

import (
	"fmt"
	"net"
	"time"
)

// bench is the stage 0 measurement: build a chain of N devices, send traffic end to end,
// and report how long each part took and how much memory it used.
func bench(r req) (map[string]any, error) {
	n := int(r.num("devices", 10))
	if n < 2 {
		n = 2
	}
	if n > 40 {
		n = 40
	}
	memBefore := meminfo()
	spec := map[string]any{}
	var devs, links, addrs, routes []map[string]any
	for i := 0; i < n; i++ {
		devs = append(devs, map[string]any{"name": fmt.Sprintf("bench%d", i), "kind": "router", "forward": true})
	}
	for i := 0; i+1 < n; i++ {
		a, b := fmt.Sprintf("bench%d", i), fmt.Sprintf("bench%d", i+1)
		links = append(links, map[string]any{"a": map[string]any{"dev": a, "if": "right"}, "b": map[string]any{"dev": b, "if": "left"}})
		addrs = append(addrs,
			map[string]any{"dev": a, "if": "right", "cidr": fmt.Sprintf("10.99.%d.1/30", i)},
			map[string]any{"dev": b, "if": "left", "cidr": fmt.Sprintf("10.99.%d.2/30", i)})
	}
	last := fmt.Sprintf("10.99.%d.2", n-2)
	for i := 0; i < n; i++ {
		d := fmt.Sprintf("bench%d", i)
		if i+1 < n {
			routes = append(routes, map[string]any{"dev": d, "dst": "default", "via": fmt.Sprintf("10.99.%d.2", i)})
		}
		if i > 1 {
			// the way back to the first device
			routes = append(routes, map[string]any{"dev": d, "dst": "10.99.0.0/30", "via": fmt.Sprintf("10.99.%d.1", i-1)})
		}
	}
	spec["devices"], spec["links"], spec["addrs"], spec["routes"] = devs, links, addrs, routes
	topo, err := topoApply(req{"topo": spec})
	if err != nil {
		return nil, err
	}
	defer topoClear()

	// a listener on the last device, then a TCP connect from the first
	var ln net.Listener
	if err := withNetns(fmt.Sprintf("bench%d", n-1), func() error {
		var e error
		ln, e = net.Listen("tcp", last+":7")
		return e
	}); err != nil {
		return nil, err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	defer ln.Close()
	var tcp []float64
	for i := 0; i < 5; i++ {
		res, err := probe(req{"ns": "bench0", "proto": "tcp", "dst": last, "port": float64(7), "timeout_ms": float64(3000)})
		if err != nil {
			return nil, err
		}
		if pass, _ := res["pass"].(bool); !pass {
			return nil, fmt.Errorf("bench probe failed: %v", res["detail"])
		}
		tcp = append(tcp, res["ms"].(float64))
	}
	t := time.Now()
	ping, _ := probe(req{"ns": "bench0", "proto": "icmp", "dst": last, "count": float64(3)})
	pingMS := time.Since(t).Milliseconds()
	return map[string]any{
		"devices":    n,
		"topo":       topo,
		"tcp_ms":     tcp,
		"ping":       ping,
		"ping_wall":  pingMS,
		"mem_before": memBefore,
		"mem_during": meminfo(),
		"uptime_ms":  uptimeMS(),
	}, nil
}
