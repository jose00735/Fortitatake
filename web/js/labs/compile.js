// FortiOS → Linux compiler for FortiTatake OS. Turns a running lab (its devices, cabling and the
// FortiGates' current configuration) into what the engine builds inside the VM: one network namespace
// per device, a switching fabric of Linux bridges, addresses and routes, an nftables ruleset per
// FortiGate (policies, VIPs, NAT, allowaccess) and the servers each device runs.
// The simulator still explains what happened (policy ids, trace lines); the kernel decides whether
// packets get through.
import { FortiGate } from "./fgt.js";
import { ipToInt, intToIp, parsePrefix, prefixStr, network, isPrivate } from "./net.js";

export const FABRIC = "FTK-FABRIC";
const NSOK = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;
const IFOK = /^[A-Za-z0-9][A-Za-z0-9._-]{0,14}$/;
const PRIVATE = "{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 }";
const ADMIN = { https: ["tcp", 443], http: ["tcp", 80], ssh: ["tcp", 22], telnet: ["tcp", 23], fgfm: ["tcp", 541], snmp: ["udp", 161] };
const adminPorts = (fg) => {
  const g = fg.obj("system global");
  return { ...ADMIN, https: ["tcp", Number(fg.one("system global", g, "admin-sport") || 443)], ssh: ["tcp", Number(fg.one("system global", g, "admin-ssh-port") || 22)] };
};

// What the compiler can't build yet: the lab then stays on the simulator.
export function unsupported(lab) {
  const why = [];
  for (const d of lab.devices.values()) {
    if (!NSOK.test(d.id)) why.push(`device name ${d.id}`);
    if (d instanceof FortiGate) {
      if (d.kind !== "fortigate") why.push(`${d.kind} ${d.id}`);
      if (d.parent || (d.allVdoms && d.allVdoms().length > 1)) why.push(`VDOMs on ${d.id}`);
      if (d.entries("vpn ipsec phase1-interface").length) why.push(`IPsec on ${d.id}`);
      try { if (d.one("system sdwan", d.obj("system sdwan"), "status") === "enable") why.push(`SD-WAN on ${d.id}`); } catch { /* no SD-WAN */ }
      try { const m = d.one("system ha", d.obj("system ha"), "mode"); if (m && m !== "standalone") why.push(`HA on ${d.id}`); } catch { /* no HA */ }
    } else if (d.kind === "fortiswitch") { /* cabled through: switchSegments() already gives the broadcast domains */ }
  }
  return why;
}

export function compile(lab) {
  const topo = { devices: [], links: [], bridges: [], addrs: [], routes: [], vlans: [], dummies: [], proxies: [] };
  const nft = {};
  const listen = [];
  const where = {}; // ip -> device id (who owns an address)
  const segs = lab.segments.filter((s) => !s.cable && !s.vlink);
  const devs = [...lab.devices.values()].filter((d) => d.kind !== "fortiswitch");
  const kindOf = (d) => (d instanceof FortiGate ? "fortigate" : d.kind);

  for (const d of devs) topo.devices.push({ name: d.id, kind: kindOf(d), forward: d instanceof FortiGate || d.kind === "router" || d.kind === "cloud", sysctl: {} });
  topo.devices.push({ name: FABRIC, kind: "fabric", forward: false, sysctl: {} });

  // ----- physical attachments: one cable per (device, port), carrying one or more segments -----
  const cloudPort = new Map(); // seg id -> port name on the cloud
  let cloudN = 0;
  const portName = (m) => {
    const d = lab.dev(m.dev);
    if (!d) return null;
    if (d.kind === "cloud") { const s = segs.find((x) => x.members.includes(m)); if (!cloudPort.has(s.id)) cloudPort.set(s.id, "net" + cloudN++); return cloudPort.get(s.id); }
    if (d.kind === "host" || d.kind === "server") return m.port || d.port || "eth0";
    return m.port;
  };
  const att = new Map(); // "dev|port" -> {dev, port, segs: [{seg, vlan}]}
  for (const s of segs) for (const m of s.members) {
    const d = lab.dev(m.dev);
    if (!d || d.kind === "fortiswitch") continue;
    const port = portName(m);
    if (!port || !IFOK.test(port)) continue;
    const k = m.dev + "|" + port;
    if (!att.has(k)) att.set(k, { dev: m.dev, port, down: false, segs: [] });
    const a = att.get(k);
    a.segs.push({ seg: s, vlan: m.vlan || 0 });
    if (m.down) a.down = true;
  }
  // bridges: segments that share a cable must share a bridge
  const parent = new Map(segs.map((s) => [s.id, s.id]));
  const find = (x) => { while (parent.get(x) !== x) x = parent.get(x); return x; };
  for (const a of att.values()) for (let i = 1; i < a.segs.length; i++) parent.set(find(a.segs[i].seg.id), find(a.segs[0].seg.id));
  const comp = new Map();
  for (const s of segs) { const r = find(s.id); if (!comp.has(r)) comp.set(r, { name: "br" + comp.size, segs: [], ports: [] }); comp.get(r).segs.push(s); }
  // VLAN ids on the fabric: a segment carried tagged uses its tag, an access-only one gets its own id
  const vid = new Map();
  segs.forEach((s, i) => { const t = s.members.find((m) => m.vlan); vid.set(s.id, t ? t.vlan : 3000 + i); });
  let pn = 0;
  for (const a of att.values()) {
    const fp = "p" + pn++;
    topo.links.push({ a: { dev: a.dev, if: a.port }, b: { dev: FABRIC, if: fp }, down: a.down || a.segs.every((x) => x.seg.down) });
    const live = a.segs.filter((x) => !x.seg.down);
    const access = live.find((x) => !x.vlan);
    const c = comp.get(find(a.segs[0].seg.id));
    c.ports.push({ if: fp, pvid: access ? vid.get(access.seg.id) : 0, untagged: !!access, vlans: live.filter((x) => x.vlan).map((x) => vid.get(x.seg.id)) });
  }
  for (const c of comp.values()) if (c.ports.length) topo.bridges.push({ dev: FABRIC, name: c.name, vlan_filtering: true, stp: false, ports: c.ports });
  const attached = (dev, port) => att.has(dev + "|" + port);

  // ----- hosts and servers -----
  for (const h of devs.filter((d) => d.kind === "host" || d.kind === "server")) {
    const port = h.port || "eth0";
    if (!attached(h.id, port)) topo.dummies.push({ dev: h.id, if: port, down: true });
    const p = h.addr();
    if (p) { topo.addrs.push({ dev: h.id, if: port, cidr: `${intToIp(p.ip)}/${p.len}` }); where[p.ip] = h.id; }
    const gw = h.gateway();
    if (p && gw) topo.routes.push({ dev: h.id, dst: "default", via: intToIp(gw) });
    const binds = [];
    for (const s of h.services) { const m = s.match(/^(tcp|udp)\/(\d+)$/); if (m) binds.push({ proto: m[1], port: Number(m[2]) }); }
    listen.push({ ns: h.id, binds });
    if (!h.services.has("icmp")) nft[h.id] = "table ip ftk {\n chain ftk_in { type filter hook input priority 0; policy accept;\n  icmp type echo-request drop\n }\n}";
  }

  // ----- the Internet -----
  const clouds = devs.filter((d) => d.kind === "cloud");
  const cloudIp = new Map(); // seg id -> ip the cloud uses on it
  for (const c of clouds) {
    for (const s of segs.filter((x) => x.members.some((m) => m.dev === c.id))) {
      const port = cloudPort.get(s.id);
      const others = s.members.map((m) => lab.dev(m.dev)).filter((d) => d && d.kind === "router");
      const ifs = others.flatMap((r) => r.ifaces.filter((i) => i.prefix && s.members.some((m) => m.dev === r.id && m.port === i.name)));
      if (!ifs.length) continue;
      const pre = ifs[0].prefix;
      const used = new Set(ifs.map((i) => i.prefix.ip));
      let ip = network(pre) + 1;
      while (used.has(ip)) ip++;
      cloudIp.set(s.id, ip);
      topo.addrs.push({ dev: c.id, if: port, cidr: `${intToIp(ip)}/${pre.len}` });
      // the cloud routes each ISP's public space back to that ISP
      for (const r of others) {
        const rif = ifs.find((i) => s.members.some((m) => m.dev === r.id && m.port === i.name));
        if (!rif) continue;
        const pubs = [...r.ifaces.filter((i) => i !== rif && i.prefix).map((i) => i.prefix), ...(r.spec.announce || []).map((a) => parsePrefix(a)), ...r.routes.filter((x) => x.dst && x.dst.len > 0).map((x) => x.dst)];
        for (const p of pubs) if (p && !isPrivate(p.ip)) topo.routes.push({ dev: c.id, dst: prefixStr(p), via: intToIp(rif.prefix.ip) });
      }
    }
    const binds = [];
    for (const h of c.hosts) {
      topo.addrs.push({ dev: c.id, if: "lo", cidr: intToIp(h.ip) + "/32" });
      where[h.ip] = c.id;
      for (const s of h.services) { const m = s.match(/^(tcp|udp)\/(\d+)$/); if (m) binds.push({ ip: intToIp(h.ip), proto: m[1], port: Number(m[2]) }); }
    }
    const names = {};
    for (const [n, ip] of lab.names) names[n] = intToIp(ip);
    listen.push({ ns: c.id, binds, names });
  }

  // ----- ISP routers -----
  for (const r of devs.filter((d) => d.kind === "router")) {
    for (const i of r.ifaces) {
      if (!IFOK.test(i.name)) continue;
      if (!attached(r.id, i.name)) topo.dummies.push({ dev: r.id, if: i.name, down: true });
      if (i.prefix) { topo.addrs.push({ dev: r.id, if: i.name, cidr: `${intToIp(i.prefix.ip)}/${i.prefix.len}` }); where[i.prefix.ip] = r.id; }
    }
    const up = segs.find((s) => s.members.some((m) => m.dev === r.id) && s.members.some((m) => (lab.dev(m.dev) || {}).kind === "cloud"));
    const upIf = up && up.members.find((m) => m.dev === r.id).port;
    for (const rt of r.routes) {
      const dst = rt.dst.len === 0 ? "default" : prefixStr(rt.dst);
      if (rt.dev === "internet" || rt.via === null) { if (up && cloudIp.has(up.id)) topo.routes.push({ dev: r.id, dst, via: intToIp(cloudIp.get(up.id)) }); }
      else topo.routes.push({ dev: r.id, dst, via: intToIp(rt.via) });
    }
    // routes the simulator's OSPF/BGP gave this router (FRR takes over in a later stage)
    for (const x of lab.routerDynamic(r) || []) {
      const dst = x.dst.len === 0 ? "default" : prefixStr(x.dst);
      if (x.gw && !r.routes.some((y) => y.dst && prefixStr(y.dst) === prefixStr(x.dst))) topo.routes.push({ dev: r.id, dst, via: intToIp(x.gw) });
    }
    // ISPs don't carry private addresses across the Internet
    if (r.dropPrivate && upIf) nft[r.id] = `table ip ftk {\n chain ftk_fwd { type filter hook forward priority 0; policy accept;\n  oifname "${upIf}" ip saddr ${PRIVATE} drop\n  oifname "${upIf}" ip daddr ${PRIVATE} drop\n }\n}`;
  }

  // ----- FortiGates -----
  const notes = [];
  for (const fg of devs.filter((d) => d instanceof FortiGate)) {
    const dev = topo.devices.find((x) => x.name === fg.id);
    dev.sysctl = { "net.ipv4.conf.all.arp_ignore": "1", "net.ipv4.conf.all.rp_filter": "0", "net.ipv4.conf.default.rp_filter": "0",
      // session list: byte/packet counters and FortiOS-like timers
      "net.netfilter.nf_conntrack_acct": "1", "net.netfilter.nf_conntrack_tcp_timeout_established": "3600", "net.netfilter.nf_conntrack_udp_timeout_stream": "180" };
    const intfs = lab.fgtIntfs(fg);
    for (const i of intfs) {
      if (!IFOK.test(i.name)) { notes.push(`${fg.id}: interface name ${i.name} is too long for Linux`); continue; }
      if (i.type === "vlan") topo.vlans.push({ dev: fg.id, if: i.name, parent: i.parent, id: i.vlan, down: !i.admin });
      else if (i.type === "loopback") topo.dummies.push({ dev: fg.id, if: i.name, down: !i.admin });
      else if (i.type === "tunnel" || i.type === "vdom-link") continue;
      else if (!attached(fg.id, i.name)) topo.dummies.push({ dev: fg.id, if: i.name, down: true });
      else if (!i.admin) { const l = topo.links.find((x) => x.a.dev === fg.id && x.a.if === i.name); if (l) l.down = true; }
      if (i.prefix) { topo.addrs.push({ dev: fg.id, if: i.name, cidr: `${intToIp(i.prefix.ip)}/${i.prefix.len}` }); where[i.prefix.ip] = fg.id; }
      if (i.srcCheck) dev.sysctl[`net.ipv4.conf.${i.name}.rp_filter`] = "0"; // FortiOS's RPF is looser than Linux strict mode
    }
    const { active } = lab.fgtRoutes(fg);
    const seen = new Set();
    for (const r of active) {
      if (r.type === "C" || r.inactive) continue;
      const dst = r.dst.len === 0 ? "default" : prefixStr(r.dst);
      if (seen.has(dst)) continue; // ECMP: Linux gets the first path
      seen.add(dst);
      if (r.blackhole) topo.routes.push({ dev: fg.id, dst, type: "blackhole" });
      else if (r.gw) topo.routes.push({ dev: fg.id, dst, via: intToIp(r.gw), if: r.dev });
      else topo.routes.push({ dev: fg.id, dst, if: r.dev });
    }
    const out = fgtRules(lab, fg, intfs, notes);
    nft[fg.id] = out.rules;
    // VIP and IP-pool addresses the FortiGate answers ARP for: extra /32s on the interface
    for (const p of out.proxies) if (!topo.addrs.some((a) => a.dev === p.dev && a.cidr === p.cidr)) topo.addrs.push({ dev: p.dev, if: p.if, cidr: p.cidr });
    const ap = adminPorts(fg);
    listen.push({ ns: fg.id, binds: [...new Set([ap.https[1], 80, ap.ssh[1], 23])].map((port) => ({ proto: "tcp", port })).concat(out.dns ? [{ proto: "udp", port: 53 }] : []), names: out.dns ? Object.fromEntries([...lab.names].map(([n, ip]) => [n, intToIp(ip)])) : undefined });
  }
  return { topo, nft, listen, where, notes, ver: lab.ver };
}

// ---------------------------------------------------------------- FortiGate → nftables

function fgtRules(lab, fg, intfs, notes) {
  const q = (s) => `"${String(s).replace(/"/g, "")}"`;
  const set = (xs) => (xs.length === 1 ? xs[0] : `{ ${xs.join(", ")} }`);
  const zoneMembers = (name) => { const z = fg.entry("system zone", name); return z ? fg.val("system zone", z, "interface") : [name]; };
  const ifMatch = (dir, names) => (names.includes("any") || !names.length ? "" : `${dir} ${set([...new Set(names.flatMap(zoneMembers))].map(q))} `);
  const proxies = [];

  // addresses → list of nft address terms ("10.0.0.0/24", "10.0.0.5-10.0.0.9"); null = any
  const addr = (name, depth = 0) => {
    if (depth > 8 || name === "none") return [];
    if (name === "all") return null;
    const a = fg.entry("firewall address", name);
    if (a) {
      const t = fg.one("firewall address", a, "type");
      if (t === "iprange") return [`${fg.one("firewall address", a, "start-ip")}-${fg.one("firewall address", a, "end-ip")}`];
      if (t === "fqdn") { const ip = lab.lookupName(fg.one("firewall address", a, "fqdn")); return ip ? [intToIp(ip)] : []; }
      if (t === "interface-subnet") { const i = intfs.find((x) => x.name === fg.one("firewall address", a, "interface")); return i && i.prefix ? [prefixStr(i.prefix)] : []; }
      if (t === "geography" || t === "mac" || t === "dynamic") { notes.push(`${fg.id}: address ${name} (${t}) isn't compiled`); return []; }
      const p = parsePrefix(fg.one("firewall address", a, "subnet"));
      return p ? [p.len === 0 ? null : prefixStr(p)].filter((x) => x !== undefined) : [];
    }
    const g = fg.entry("firewall addrgrp", name);
    if (g) {
      const parts = fg.val("firewall addrgrp", g, "member").map((m) => addr(m, depth + 1));
      if (parts.some((p) => p === null)) return null;
      if (fg.one("firewall addrgrp", g, "exclude") === "enable") notes.push(`${fg.id}: exclude-member in ${name} isn't compiled`);
      return parts.flat().filter(Boolean);
    }
    return [];
  };
  const addrs = (names) => { const parts = names.filter((n) => !fg.entry("firewall vip", n) && !fg.entry("firewall vipgrp", n)).map((n) => addr(n)); return parts.some((p) => p === null || (Array.isArray(p) && p.includes(null))) ? null : [...new Set(parts.flat())]; };

  // services → list of terms: {proto: "tcp"|"udp"|"icmp"|number|null, ports: ["80", "1000-2000"], icmp: type}
  const svc = (name, depth = 0) => {
    if (depth > 8) return [];
    const s = fg.entry("firewall service custom", name);
    if (s) {
      const proto = fg.one("firewall service custom", s, "protocol") || "TCP/UDP/SCTP";
      if (proto === "IP") { const n = Number(fg.one("firewall service custom", s, "protocol-number") || 0); return [{ proto: n || null }]; }
      if (proto === "ICMP") { const t = (s.attrs.get("icmptype") || [])[0]; return [{ proto: "icmp", icmp: t !== undefined ? Number(t) : null }]; }
      const out = [];
      for (const [key, p] of [["tcp-portrange", "tcp"], ["udp-portrange", "udp"]]) {
        const ports = (s.attrs.get(key) || []).join(" ").split(/\s+/).filter(Boolean).map((r) => r.split(":")[0]);
        if (ports.length) out.push({ proto: p, ports });
      }
      return out;
    }
    const g = fg.entry("firewall service group", name);
    if (g) return fg.val("firewall service group", g, "member").flatMap((m) => svc(m, depth + 1));
    return [];
  };
  const svcTerm = (t) => {
    if (t.proto === null) return "";
    if (typeof t.proto === "number") return `ip protocol ${t.proto} `;
    if (t.proto === "icmp") return t.icmp === null ? "ip protocol icmp " : `icmp type ${t.icmp} `;
    return `${t.proto} dport ${set(t.ports)} `;
  };

  // VIPs: DNAT in prerouting, marked so policies know the session came through a VIP
  const vips = fg.entries("firewall vip");
  const vipIdx = new Map(vips.map((v, i) => [v.key, i + 1]));
  const policies = fg.entries("firewall policy").filter((p) => fg.one("firewall policy", p, "status") !== "disable");
  const vipOf = (names, depth = 0) => names.flatMap((n) => { if (vipIdx.has(n)) return [n]; const g = fg.entry("firewall vipgrp", n); return g && depth < 6 ? vipOf(fg.val("firewall vipgrp", g, "member"), depth + 1) : []; });
  const usedVips = new Set(policies.filter((p) => fg.one("firewall policy", p, "action") === "accept").flatMap((p) => vipOf(fg.val("firewall policy", p, "dstaddr"))));
  const pre = [];
  for (const v of vips) {
    if (!usedVips.has(v.key)) continue; // FortiOS doesn't translate until a policy uses the VIP
    const ext = String(fg.one("firewall vip", v, "extip") || "").split("-")[0];
    const mapped = String(fg.val("firewall vip", v, "mappedip")[0] || "").split("-")[0];
    if (!ipToInt(ext) || !ipToInt(mapped)) continue;
    const ei = fg.one("firewall vip", v, "extintf") || "any";
    const pf = fg.one("firewall vip", v, "portforward") === "enable";
    let m = `${ei === "any" ? "" : `iifname ${q(ei)} `}ip daddr ${ext} `;
    let to = mapped;
    if (pf) {
      const proto = (fg.one("firewall vip", v, "protocol") || "tcp").toLowerCase();
      const [lo, hi] = String(fg.one("firewall vip", v, "extport") || "0").split("-").map(Number);
      const mp = Number(String(fg.one("firewall vip", v, "mappedport") || lo).split("-")[0]);
      m += `${proto} dport ${hi ? `${lo}-${hi}` : lo} `;
      to = hi && hi > lo ? `${mapped}:${mp}-${mp + (hi - lo)}` : `${mapped}:${mp}`;
    }
    pre.push(`  ${m}meta mark set ${vipIdx.get(v.key)} dnat ip to ${to}`);
    if (fg.one("firewall vip", v, "arp-reply") !== "disable" && !intfs.some((i) => i.prefix && intToIp(i.prefix.ip) === ext))
      for (const i of intfs.filter((x) => (ei === "any" || x.name === ei) && x.prefix && (x.prefix.ip ^ ipToInt(ext)) >>> (32 - x.prefix.len) === 0)) proxies.push({ dev: fg.id, if: i.name, cidr: ext + "/32" });
  }

  // policies, in FortiOS order: first match wins
  const fwd = [], post = [];
  let auto = 900000;
  for (const p of policies) {
    const v = (a) => fg.val("firewall policy", p, a);
    const id = /^\d+$/.test(p.key) ? Number(p.key) : auto++;
    if (!lab.schedMatch(fg, fg.one("firewall policy", p, "schedule"))) continue; // the lab clock decides schedules
    if (v("groups").length || v("users").length) { notes.push(`${fg.id}: identity policy ${p.key} isn't compiled`); continue; }
    const action = fg.one("firewall policy", p, "action") === "accept" ? "accept" : "drop";
    const head = ifMatch("iifname", v("srcintf")) + ifMatch("oifname", v("dstintf"));
    const sneg = fg.one("firewall policy", p, "srcaddr-negate") === "enable" ? "!= " : "";
    const dneg = fg.one("firewall policy", p, "dstaddr-negate") === "enable" ? "!= " : "";
    const src = addrs(v("srcaddr"));
    if (src && !src.length && !sneg) continue;
    const sm = src === null ? "" : src.length ? `ip saddr ${sneg}${set(src)} ` : "";
    // destination: through a VIP the policy must name the VIP (it then sees the mapped address)
    const pv = vipOf(v("dstaddr"));
    const dsts = [];
    if (pv.length) dsts.push(`meta mark ${set(pv.map((n) => vipIdx.get(n)))} `);
    const dst = addrs(v("dstaddr"));
    if (dst === null) dsts.push("meta mark 0 ");
    else if (dst.length) dsts.push(`meta mark 0 ip daddr ${dneg}${set(dst)} `);
    const terms = v("service").flatMap((s) => svc(s));
    for (const dm of dsts) for (const t of terms.length ? terms : []) fwd.push(`  ${head}${sm}${dm}${svcTerm(t)}ct mark set ${id} ${action}`);
    if (action === "accept" && fg.one("firewall policy", p, "nat") === "enable") {
      const outIfs = ifMatch("oifname", v("dstintf"));
      const poolName = fg.one("firewall policy", p, "ippool") === "enable" ? v("poolname")[0] : null;
      const pool = poolName && fg.entry("firewall ippool", poolName);
      if (pool) {
        const lo = fg.one("firewall ippool", pool, "startip"), hi = fg.one("firewall ippool", pool, "endip");
        post.push(`  ct mark ${id} ${outIfs}snat ip to ${lo === hi ? lo : `${lo}-${hi}`}`);
        if (fg.one("firewall ippool", pool, "arp-reply") !== "disable") {
          for (let n = ipToInt(lo); n <= ipToInt(hi) && n - ipToInt(lo) < 64; n++)
            for (const i of intfs.filter((x) => x.prefix && !intfs.some((y) => y.prefix && y.prefix.ip === n) && (x.prefix.ip ^ n) >>> (32 - x.prefix.len) === 0)) proxies.push({ dev: fg.id, if: i.name, cidr: intToIp(n) + "/32" });
        }
      } else post.push(`  ct mark ${id} ${outIfs}masquerade`);
    }
  }

  // local-in: allowaccess on the interface the packet arrives on, trusted hosts for admin logins
  const trust = [];
  for (const a of fg.entries("system admin")) for (let i = 1; i <= 10; i++) { const t = a.attrs.get("trusthost" + i); if (t) { const p = parsePrefix(t[0]); if (p) trust.push(p.len === 0 ? null : prefixStr(p)); } }
  const own = intfs.filter((i) => i.prefix).map((i) => intToIp(i.prefix.ip));
  const ownM = own.length ? `ip daddr ${set(own)} ` : "";
  const trustM = !trust.length || trust.includes(null) ? "" : `ip saddr ${set([...new Set(trust)])} `;
  const inp = [];
  let dns = false;
  for (const i of intfs) {
    if (!IFOK.test(i.name)) continue;
    for (const a of i.allow || []) {
      if (a === "ping") inp.push(`  iifname ${q(i.name)} ${ownM}icmp type echo-request accept`);
      const svcDef = adminPorts(fg)[a];
      if (svcDef) inp.push(`  iifname ${q(i.name)} ${ownM}${["https", "http", "ssh", "telnet"].includes(a) ? trustM : ""}${svcDef[0]} dport ${svcDef[1]} accept`);
    }
  }
  for (const e of fg.entries("system dns-server")) { dns = true; inp.push(`  iifname ${q(e.key)} udp dport 53 accept`); }
  for (const s of fg.entries("system dhcp server")) { const i = fg.one("system dhcp server", s, "interface"); if (i) inp.push(`  iifname ${q(i)} udp dport 67 accept`); }

  const rules = `table ip ftk {
 chain ftk_pre { type nat hook prerouting priority dstnat; policy accept;
${pre.join("\n")}
 }
 chain ftk_fwd { type filter hook forward priority filter; policy drop;
  ct state established,related accept
  ct state invalid drop
${fwd.join("\n")}
 }
 chain ftk_post { type nat hook postrouting priority srcnat; policy accept;
${post.join("\n")}
 }
 chain ftk_in { type filter hook input priority filter; policy drop;
  ct state established,related accept
  iif "lo" accept
${inp.join("\n")}
 }
}`;
  return { rules, proxies, dns };
}
