// Network simulator for FortiTatake labs: topology, hosts, routers, the Internet, and the FortiGate packet path.
// It answers "what would this packet do" from the devices' current config, and feeds debug flow and the sniffer.
import { FortiGate } from "./fgt.js";
import { ipToInt, intToIp, parsePrefix, inPrefix, isPrivate, prefixStr, hex, rng, lenToMask, network } from "./net.js";

const ICMP = 1, TCP = 6, UDP = 17;
export const PROTO = { icmp: ICMP, tcp: TCP, udp: UDP };
const PNAME = { 1: "icmp", 6: "tcp", 17: "udp" };

// ---------- simple devices ----------
class Host {
  constructor(spec, lab) {
    this.id = spec.id;
    this.kind = spec.kind; // host | server
    this.os = spec.os || (spec.kind === "server" ? "linux" : "windows");
    this.lab = lab;
    const nic = spec.nic || {};
    this.dhcp = nic.ip === "dhcp";
    this.static = this.dhcp ? null : parsePrefix(nic.ip, 24);
    this.gw = nic.gw || null;
    this.dns = nic.dns || [];
    this.port = nic.port || "eth0";
    this.services = new Set((spec.services || []).map((s) => String(s).toLowerCase()));
    if (spec.icmp !== false) this.services.add("icmp");
    this.lease = null;
    this.history = [];
    this.hostname = spec.hostname || spec.id;
    this.vpnSpec = spec.vpn || null;
    this.vpn = null;
  }
  addr() { return this.dhcp ? (this.lease && this.lease.prefix) : this.static; }
  ip() { const a = this.addr(); return a ? a.ip : null; }
  gateway() { return this.dhcp ? (this.lease && this.lease.gw) : (this.gw ? ipToInt(this.gw) : null); }
  dnsServers() { return this.dhcp ? (this.lease ? this.lease.dns : []) : this.dns.map(ipToInt); }
  listens(proto, port) {
    if (proto === ICMP) return this.services.has("icmp");
    return this.services.has(`${PNAME[proto]}/${port}`);
  }
}

class Router {
  constructor(spec) {
    this.id = spec.id;
    this.kind = "router";
    this.ifaces = (spec.ifaces || []).map((i) => ({ name: i.name, prefix: parsePrefix(i.ip, 24), up: i.up !== false }));
    this.routes = (spec.routes || []).map((r) => ({ dst: parsePrefix(r.dst, 32), via: r.via ? ipToInt(r.via) : null, dev: r.dev || null }));
    this.history = [];
    this.label = spec.label || "ISP router";
    this.dropPrivate = spec.drop_private !== false; // ISPs don't route RFC 1918 sources back
    this.mtu = spec.mtu || 1500;
    this.quality = spec.quality || null;
  }
}

class Cloud {
  constructor(spec) {
    this.id = spec.id;
    this.kind = "cloud";
    this.hosts = (spec.hosts || []).map((h) => ({ name: h.name, ip: ipToInt(h.ip), services: new Set([...(h.services || []).map((s) => String(s).toLowerCase()), "icmp"]), dns: !!h.dns, files: h.files || {}, pinned: !!h.pinned }));
    this.history = [];
  }
}

// ---------- the lab network ----------
export class Lab {
  constructor(def, schemas) {
    this.def = def;
    this.devices = new Map();
    this.order = [];
    this.clock = def.clock ? Date.parse(def.clock) : Date.parse("2026-11-24T10:00:00-05:00");
    this.rand = rng(7);
    this.sessSeq = 0x1a2b00;
    this.names = new Map(); // DNS name -> ip
    for (const d of def.devices || []) {
      let dev;
      if (d.kind === "fortigate" || d.kind === "fortianalyzer" || d.kind === "fortimanager") {
        const sch = d.kind === "fortigate" ? schemas.fortios : schemas[d.kind];
        dev = new FortiGate(d, sch, {
          onCommit: (fg, path, key) => { this.onCommit(fg, path, key); if (this.ready) this.dirty(fg); },
          onDelete: (fg, path, key) => { this.onDelete(fg, path, key); if (this.ready) this.dirty(fg); },
        });
        dev.diag = (fg, toks, line) => this.diagnose(fg, toks, line);
        dev.kind = d.kind;
        if (d.kind !== "fortigate") this.mgmtInit(dev);
        dev.sessions = new Map();
        dev.dbg = { enabled: false, flowFilter: {}, flowCount: 0, traceId: 0, sniffer: null, pingSrc: null };
        dev.async = [];
      } else if (d.kind === "router") dev = new Router(d);
      else if (d.kind === "cloud") dev = new Cloud(d);
      else dev = new Host(d, this);
      dev.spec = d;
      this.devices.set(d.id, dev);
      this.order.push(d.id);
    }
    for (const d of def.devices || []) if (d.kind === "cloud") for (const h of d.hosts || []) if (h.name) this.names.set(h.name.toLowerCase(), ipToInt(h.ip));
    for (const [n, ip] of Object.entries(def.dns || {})) this.names.set(n.toLowerCase(), ipToInt(ip));
    // segments: [{id, members: ["DEV:port" | {at:"DEV:port", vlan:N}], down?}]
    this.segments = (def.segments || []).map((s, i) => ({
      id: s.id || "seg" + i, down: !!s.down, label: s.label || "",
      members: (s.members || []).map((m) => {
        const at = typeof m === "string" ? m : m.at;
        const [dev, port] = at.split(":");
        return { dev, port: port || null, vlan: (typeof m === "object" && m.vlan) || 0 };
      }),
    }));
    this.ver = 1;
    this.haSyncAll();
    this.renewAll();
    this.ready = true;
  }

  dirty(fg) { this.ver = (this.ver || 0) + 1; this.haSync(fg); this.renewAll(); this.ver++; }
  dev(id) { return this.devices.get(id); }
  now() { this.clock += 37 + Math.floor(this.rand() * 40); return this.clock; }

  // ----- segments and addressing -----
  segOf(devId, port, vlan = 0) {
    return this.segments.find((s) => s.members.some((m) => !m.down && m.dev === devId && (m.port === port || (!m.port && !port) || (!m.port && port === "eth0")) && (m.vlan || 0) === vlan));
  }
  // logical FortiGate interfaces derived from config
  fgtIntfs(fg) {
    return fg.entries("system interface").map((e) => {
      const type = fg.one("system interface", e, "type");
      const ipv = fg.one("system interface", e, "ip") || "0.0.0.0 0.0.0.0";
      const p = parsePrefix(ipv);
      const parent = type === "vlan" ? fg.one("system interface", e, "interface") : null;
      const vlan = type === "vlan" ? Number(fg.one("system interface", e, "vlanid") || 0) : 0;
      const st = fg.one("system interface", e, "status");
      const admin = st !== "down" && st !== "disable";
      const seg = type === "loopback" || type === "tunnel" ? null : this.segOf(fg.id, parent || e.key, vlan);
      let parentUp = true;
      if (parent) { const pe = fg.entry("system interface", parent); parentUp = !pe || fg.one("system interface", pe, "status") !== "down"; }
      const up = type === "tunnel" ? admin && this.tunnelUp(fg, e.key) : admin && parentUp && (type === "loopback" || (!!seg && !seg.down));
      return {
        name: e.key, type, prefix: p && p.ip ? p : null, up, admin, seg, parent, vlan,
        allow: fg.val("system interface", e, "allowaccess"), role: fg.one("system interface", e, "role"),
        srcCheck: fg.one("system interface", e, "src-check") !== "disable", mtu: Number(fg.one("system interface", e, "mtu") || 1500),
        mode: fg.one("system interface", e, "mode"),
      };
    });
  }
  // who answers ARP for ip on a segment: returns {dev, port}
  arp(seg, ip) {
    if (!seg || seg.down) return null;
    for (const m of seg.members) {
      const d = this.dev(m.dev);
      if (!d || m.down) continue;
      if (d instanceof Host && d.ip() === ip) return { dev: d, port: d.port };
      if (d instanceof Router) { const i = d.ifaces.find((x) => x.name === m.port && x.up && x.prefix && x.prefix.ip === ip); if (i) return { dev: d, port: i.name }; }
      if (d instanceof Cloud) { if (d.hosts.some((h) => h.ip === ip) || this.cloudGw(d, seg) === ip) return { dev: d, port: "net" }; }
      if (d instanceof FortiGate) {
        if (this.haRole(d) === "secondary") continue;
        for (const i of this.fgtIntfs(d)) {
          if (!i.up || i.seg !== seg) continue;
          if (i.prefix && i.prefix.ip === ip) return { dev: d, port: i.name };
          // proxy ARP for VIPs and IP pools (arp-reply enable)
          for (const v of d.entries("firewall vip")) if (d.one("firewall vip", v, "extip") === intToIp(ip) && d.one("firewall vip", v, "arp-reply") !== "disable") return { dev: d, port: i.name };
          for (const p of d.entries("firewall ippool")) {
            const lo = ipToInt(d.one("firewall ippool", p, "startip")), hi = ipToInt(d.one("firewall ippool", p, "endip"));
            if (ip >= lo && ip <= hi && d.one("firewall ippool", p, "arp-reply") !== "disable") return { dev: d, port: i.name };
          }
        }
      }
    }
    return null;
  }
  cloudGw(cloud, seg) { return null; }

  // ----- DHCP -----
  renewAll() { for (const d of this.devices.values()) if (d instanceof Host && d.dhcp) this.renew(d); }
  renew(h) {
    h.lease = null;
    const seg = this.segOf(h.id, h.port) || this.segOf(h.id, null);
    if (!seg || seg.down) return false;
    for (const m of seg.members) {
      const fg = this.dev(m.dev);
      if (!(fg instanceof FortiGate)) continue;
      const intf = this.fgtIntfs(fg).find((i) => i.seg === seg && i.up && i.prefix);
      if (!intf) continue;
      for (const srv of fg.entries("system dhcp server")) {
        if (fg.one("system dhcp server", srv, "interface") !== intf.name) continue;
        if (fg.one("system dhcp server", srv, "status") === "disable") continue;
        const ranges = srv.children.get("ip-range");
        const r = ranges && ranges.list()[0];
        if (!r) continue;
        const lo = ipToInt(fg.val("system dhcp server", r, "start-ip", ["ip-range"])[0]);
        const hi = ipToInt(fg.val("system dhcp server", r, "end-ip", ["ip-range"])[0]);
        if (!lo || !hi || !inPrefix(lo, intf.prefix)) continue;
        const idx = seg.members.filter((x) => this.dev(x.dev) instanceof Host && this.dev(x.dev).dhcp).findIndex((x) => x.dev === h.id);
        const ip = lo + idx;
        if (ip > hi) continue;
        const gwS = fg.one("system dhcp server", srv, "default-gateway");
        const mask = fg.one("system dhcp server", srv, "netmask");
        const len = mask && mask !== "0.0.0.0" ? maskLen(mask) : intf.prefix.len;
        const svc = fg.one("system dhcp server", srv, "dns-service");
        let dns = [];
        if (svc === "local") dns = [intf.prefix.ip];
        else if (svc === "default") dns = this.fgtDns(fg);
        else dns = ["dns-server1", "dns-server2"].map((k) => fg.one("system dhcp server", srv, k)).filter((x) => x && x !== "0.0.0.0").map(ipToInt);
        h.lease = { prefix: { ip, len }, gw: gwS && gwS !== "0.0.0.0" ? ipToInt(gwS) : null, dns, server: intf.prefix.ip, fgt: fg.id, intf: intf.name };
        return true;
      }
    }
    return false;
  }
  fgtDns(fg) {
    const o = fg.obj("system dns");
    return ["primary", "secondary"].map((k) => fg.one("system dns", o, k)).filter((x) => x && x !== "0.0.0.0").map(ipToInt);
  }

  // ----- FortiGate routing -----
  fgtRoutes(fg) {
    const intfs = this.fgtIntfs(fg);
    const routes = [];
    for (const i of intfs) if (i.up && i.prefix) routes.push({ type: "C", dst: { ip: network(i.prefix), len: i.prefix.len }, dev: i.name, distance: 0, priority: 0 });
    for (const r of fg.entries("router static")) {
      if (fg.one("router static", r, "status") === "disable") continue;
      const dst = parsePrefix(fg.one("router static", r, "dst"));
      const zone = fg.one("router static", r, "sdwan-zone");
      if (zone) {
        for (const m of this.sdwanMembers(fg, zone)) if (m.alive) routes.push({ type: "S", id: r.key, dst: { ip: network(dst), len: dst.len }, gw: m.gw, dev: m.intf, distance: Number(fg.one("router static", r, "distance")), priority: Number(m.priority || 1), sdwan: true });
        continue;
      }
      const devName = fg.one("router static", r, "device");
      const bh = fg.one("router static", r, "blackhole") === "enable";
      const i = intfs.find((x) => x.name === devName);
      if (!bh && (!i || !i.up)) continue;
      const gw = ipToInt(fg.one("router static", r, "gateway") || "0.0.0.0");
      routes.push({ type: "S", id: r.key, dst: { ip: network(dst), len: dst.len }, gw, dev: bh ? "Null" : devName, distance: Number(fg.one("router static", r, "distance")), priority: Number(fg.one("router static", r, "priority")), blackhole: bh });
    }
    for (const r of fg.product !== "fortios" ? fg.entries("system route") : []) {
      const dst = parsePrefix(fg.one("system route", r, "dst") || "0.0.0.0 0.0.0.0");
      const i = intfs.find((x) => x.name === fg.one("system route", r, "device"));
      if (dst && i && i.up) routes.push({ type: "S", id: r.key, dst: { ip: network(dst), len: dst.len }, gw: ipToInt(fg.one("system route", r, "gateway") || "0.0.0.0"), dev: i.name, distance: 10, priority: 0 });
    }
    routes.push(...this.extraRoutes(fg, intfs));
    // RIB: for each prefix keep the lowest distance; FIB = those
    const best = new Map();
    for (const r of routes) {
      const k = prefixStr(r.dst);
      const cur = best.get(k);
      if (!cur || r.distance < cur[0].distance) best.set(k, [r]);
      else if (r.distance === cur[0].distance) cur.push(r);
    }
    return { all: routes, active: [...best.values()].flat() };
  }
  fgtLookup(fg, dst, onlyIntf) {
    const { active } = this.fgtRoutes(fg);
    let cands = active.filter((r) => inPrefix(dst, r.dst));
    if (onlyIntf) cands = cands.filter((r) => r.dev === onlyIntf);
    if (!cands.length) return null;
    const maxLen = Math.max(...cands.map((r) => r.dst.len));
    cands = cands.filter((r) => r.dst.len === maxLen).sort((a, b) => a.priority - b.priority);
    return cands[0];
  }
  isLocal(fg, ip) { return this.fgtIntfs(fg).some((i) => i.prefix && i.prefix.ip === ip && i.admin); }

  // ----- address, service, schedule matching -----
  addrMatch(fg, name, ip, depth = 0) {
    if (depth > 8) return false;
    if (name === "all") return true;
    if (name === "none") return false;
    const a = fg.entry("firewall address", name);
    if (a) {
      const t = fg.one("firewall address", a, "type");
      if (t === "iprange") return ip >= ipToInt(fg.one("firewall address", a, "start-ip")) && ip <= ipToInt(fg.one("firewall address", a, "end-ip"));
      if (t === "fqdn") { const r = this.lookupName(fg.one("firewall address", a, "fqdn")); return r === ip; }
      if (t === "interface-subnet") { const i = this.fgtIntfs(fg).find((x) => x.name === fg.one("firewall address", a, "interface")); return !!(i && i.prefix && inPrefix(ip, i.prefix)); }
      return inPrefix(ip, parsePrefix(fg.one("firewall address", a, "subnet")));
    }
    const g = fg.entry("firewall addrgrp", name);
    if (g) {
      const hit = fg.val("firewall addrgrp", g, "member").some((m) => this.addrMatch(fg, m, ip, depth + 1));
      return fg.one("firewall addrgrp", g, "exclude") === "enable" ? hit && !fg.val("firewall addrgrp", g, "exclude-member").some((m) => this.addrMatch(fg, m, ip, depth + 1)) : hit;
    }
    return false;
  }
  svcMatch(fg, name, pkt, depth = 0) {
    if (depth > 8) return false;
    const s = fg.entry("firewall service custom", name);
    if (s) {
      const proto = fg.one("firewall service custom", s, "protocol");
      if (proto === "IP") { const n = Number(fg.one("firewall service custom", s, "protocol-number") || 0); return n === 0 || n === pkt.proto; }
      if (proto === "ICMP") { const t = s.attrs.get("icmptype"); return pkt.proto === ICMP && (!t || Number(t[0]) === pkt.icmpType); }
      const key = pkt.proto === TCP ? "tcp-portrange" : pkt.proto === UDP ? "udp-portrange" : null;
      if (!key) return false;
      const ranges = (s.attrs.get(key) || []).join(" ").split(/\s+/).filter(Boolean);
      return ranges.some((r) => { const dst = r.split(":")[0]; const [lo, hi] = dst.split("-").map(Number); return pkt.dport >= lo && pkt.dport <= (hi || lo); });
    }
    const g = fg.entry("firewall service group", name);
    if (g) return fg.val("firewall service group", g, "member").some((m) => this.svcMatch(fg, m, pkt, depth + 1));
    return false;
  }
  schedMatch(fg, name) {
    if (name === "always") return true;
    const r = fg.entry("firewall schedule recurring", name);
    if (!r) return true;
    const d = new Date(this.clock - 5 * 3600000); // lab clock is in Colombia time
    const days = ["sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"];
    const on = fg.val("firewall schedule recurring", r, "day");
    if (!on.includes(days[d.getUTCDay()])) return false;
    const mins = d.getUTCHours() * 60 + d.getUTCMinutes();
    const hm = (s) => { const [h, m] = String(s || "00:00").split(":").map(Number); return h * 60 + (m || 0); };
    const st = hm(fg.one("firewall schedule recurring", r, "start")), en = hm(fg.one("firewall schedule recurring", r, "end"));
    return st === en ? true : st < en ? mins >= st && mins < en : mins >= st || mins < en;
  }
  zoneOf(fg, intf) {
    for (const z of fg.entries("system zone")) if (fg.val("system zone", z, "interface").includes(intf)) return z;
    return null;
  }
  intfMatch(fg, names, intf) {
    if (names.includes("any")) return true;
    if (names.includes(intf)) return true;
    const z = this.zoneOf(fg, intf);
    return !!(z && names.includes(z.key));
  }
  vipFor(fg, pkt, inIntf) {
    for (const v of fg.entries("firewall vip")) {
      const ext = fg.one("firewall vip", v, "extip");
      if (!ext || ipToInt(String(ext).split("-")[0]) !== pkt.dst) continue;
      const ei = fg.one("firewall vip", v, "extintf") || "any";
      if (ei !== "any" && ei !== inIntf) continue;
      const pf = fg.one("firewall vip", v, "portforward") === "enable";
      let dport = pkt.dport;
      if (pf) {
        const proto = PROTO[fg.one("firewall vip", v, "protocol") || "tcp"];
        if (proto !== pkt.proto) continue;
        const [lo, hi] = String(fg.one("firewall vip", v, "extport") || "0").split("-").map(Number);
        if (pkt.dport < lo || pkt.dport > (hi || lo)) continue;
        const mp = String(fg.one("firewall vip", v, "mappedport") || lo).split("-").map(Number)[0];
        dport = mp + (pkt.dport - lo);
      }
      const mapped = ipToInt(String(fg.val("firewall vip", v, "mappedip")[0] || "").split("-")[0]);
      if (mapped === null) continue;
      return { name: v.key, dst: mapped, dport, pf };
    }
    return null;
  }
  vipRefs(fg, names, vipName, depth = 0) {
    if (depth > 6) return false;
    for (const n of names) {
      if (n === vipName) return true;
      const g = fg.entry("firewall vipgrp", n);
      if (g && this.vipRefs(fg, fg.val("firewall vipgrp", g, "member"), vipName, depth + 1)) return true;
    }
    return false;
  }
  // first matching policy (FortiOS order); returns {policy, action} or null (implicit deny)
  policyLookup(fg, pkt, inIntf, outIntf, vip) {
    for (const p of fg.entries("firewall policy")) {
      const v = (a) => fg.val("firewall policy", p, a);
      if (fg.one("firewall policy", p, "status") === "disable") continue;
      if (!this.intfMatch(fg, v("srcintf"), inIntf)) continue;
      if (!this.intfMatch(fg, v("dstintf"), outIntf)) continue;
      const sneg = fg.one("firewall policy", p, "srcaddr-negate") === "enable";
      const dneg = fg.one("firewall policy", p, "dstaddr-negate") === "enable";
      const sm = v("srcaddr").some((a) => this.addrMatch(fg, a, pkt.src));
      if (sm === sneg) continue;
      let dm;
      if (vip) dm = this.vipRefs(fg, v("dstaddr"), vip.name);
      else dm = v("dstaddr").some((a) => !fg.entry("firewall vip", a) && this.addrMatch(fg, a, pkt.dst));
      if (dm === dneg) continue;
      const svcNames = v("service");
      const probe = vip ? { ...pkt, dport: vip.dport } : pkt;
      if (!svcNames.some((s) => this.svcMatch(fg, s, probe))) continue;
      if (!this.schedMatch(fg, fg.one("firewall policy", p, "schedule"))) continue;
      return { policy: p, id: p.key, action: fg.one("firewall policy", p, "action"), nat: fg.one("firewall policy", p, "nat") === "enable", name: fg.one("firewall policy", p, "name") };
    }
    return null;
  }

  // ----- tracing helpers -----
  trace(fg, pkt, lines) {
    if (this.quiet) return;
    const d = fg.dbg;
    if (!d.enabled || d.flowCount <= 0) return;
    const f = d.flowFilter;
    if (f.addr && pkt.src !== f.addr && pkt.dst !== f.addr && pkt.origDst !== f.addr) return;
    if (f.saddr && pkt.src !== f.saddr) return;
    if (f.daddr && pkt.dst !== f.daddr && pkt.origDst !== f.daddr) return;
    if (f.proto && f.proto !== pkt.proto) return;
    if (f.port && pkt.dport !== f.port && pkt.sport !== f.port) return;
    d.flowCount--;
    d.traceId++;
    const id = 20000 + (d.traceId * 7) % 9000;
    for (const [fn, ln, msg] of lines) fg.async.push(`id=${id} trace_id=${d.traceId} func=${fn} line=${ln} msg="${msg}"`);
  }
  sniff(fg, intf, dir, pkt) {
    if (this.quiet) return;
    const s = fg.dbg.sniffer;
    if (!s || s.left <= 0) return;
    if (s.intf !== "any" && s.intf !== intf) return;
    if (!bpf(s.filter, pkt)) return;
    s.left--;
    const t = ((this.clock - s.start) / 1000).toFixed(6);
    const head = s.verbose >= 4 ? `${t} ${intf} ${dir} ` : `${t} `;
    fg.async.push(head + describePkt(pkt));
    if (s.left === 0) fg.async.push(`\n${s.total} packets received by filter\n0 packets dropped by kernel`);
  }

  // ----- the packet walk -----
  // send pkt from device `from`; returns {delivered, reply, path, drop}
  send(fromId, pkt, opts = {}) {
    const res = { path: [], fgt: [], drop: null, delivered: null };
    let at = this.dev(fromId);
    let port = null;
    let p = { ttl: 64, ...pkt };
    for (let hop = 0; hop < 24 && at; hop++) {
      const step = this.process(at, port, p, res, hop === 0);
      if (!step) return res;
      if (step.delivered) { res.delivered = { dev: at.id, pkt: step.pkt }; return res; }
      ({ dev: at, port, pkt: p } = step);
    }
    if (!res.drop) res.drop = { dev: at && at.id, reason: "loop" };
    return res;
  }

  // returns null (dropped), {delivered, pkt} or {dev, port, pkt} for the next hop
  process(dev, inPort, pkt, res, origin) {
    res.path.push(dev.id);
    if (dev instanceof Host) return this.hostProcess(dev, inPort, pkt, res, origin);
    if (dev instanceof Router) return this.routerProcess(dev, inPort, pkt, res);
    if (dev instanceof Cloud) return this.cloudProcess(dev, inPort, pkt, res);
    if (dev instanceof FortiGate) return this.fgtProcess(dev, inPort, pkt, res, origin);
    return null;
  }
  forwardOnSeg(seg, nh, pkt, res, devId, why) {
    const a = this.arp(seg, nh);
    if (!a) { res.drop = { dev: devId, reason: why || `no ARP reply from ${intToIp(nh)}` }; return null; }
    return { dev: a.dev, port: a.port, pkt };
  }
  hostProcess(h, inPort, pkt, res, origin) {
    const me = h.addr();
    if (origin) {
      if (!me) { res.drop = { dev: h.id, reason: "no IP address (DHCP failed)" }; return null; }
      if (h.vpn && h.vpn.up && pkt.src === h.vpn.ip) { const t = this.clientTunnel(h, pkt, res); if (t) return t; }
      const seg = this.segOf(h.id, h.port) || this.segOf(h.id, null);
      const nh = inPrefix(pkt.dst, me) ? pkt.dst : h.gateway();
      if (!nh) { res.drop = { dev: h.id, reason: "no default gateway" }; return null; }
      return this.forwardOnSeg(seg, nh, pkt, res, h.id, nh === pkt.dst ? `no ARP reply from ${intToIp(nh)}` : `gateway ${intToIp(nh)} does not answer ARP`);
    }
    if ((me && pkt.dst === me.ip) || (h.vpn && h.vpn.up && pkt.dst === h.vpn.ip)) return { delivered: true, pkt };
    res.drop = { dev: h.id, reason: "not for this host" };
    return null;
  }
  routerProcess(r, inPort, pkt, res) {
    if (r.quality) { res.q = res.q || { latency: 0, jitter: 0, loss: 0 }; res.q.latency += r.quality.latency || 0; res.q.jitter += r.quality.jitter || 0; res.q.loss = Math.max(res.q.loss, r.quality.loss || 0); }
    if (r.quality && (r.quality.loss || 0) >= 100) { res.drop = { dev: r.id, reason: "link down at the ISP (100% loss)" }; return null; }
    if (r.ifaces.some((i) => i.prefix && i.prefix.ip === pkt.dst)) return { delivered: true, pkt };
    pkt = { ...pkt, ttl: pkt.ttl - 1 };
    if (pkt.ttl <= 0) { res.drop = { dev: r.id, reason: "ttl exceeded", ttl: true }; return null; }
    if (pkt.size && pkt.df && pkt.size > r.mtu) { res.drop = { dev: r.id, reason: `packet of ${pkt.size} bytes with DF set exceeds MTU ${r.mtu}`, mtu: r.mtu }; return null; }
    // connected
    for (const i of r.ifaces) {
      if (i.up && i.prefix && inPrefix(pkt.dst, i.prefix)) {
        return this.forwardOnSeg(this.segOf(r.id, i.name), pkt.dst, pkt, res, r.id);
      }
    }
    const cands = r.routes.filter((x) => inPrefix(pkt.dst, x.dst)).sort((a, b) => b.dst.len - a.dst.len);
    const rt = cands[0];
    if (!rt || (r.dropPrivate && isPrivate(pkt.dst) && rt.dst.len === 0)) { res.drop = { dev: r.id, reason: `no route to ${intToIp(pkt.dst)}` }; return null; }
    if (rt.dev === "internet" || rt.via === null) {
      const seg = this.segments.find((s) => s.members.some((m) => m.dev === r.id) && s.members.some((m) => this.dev(m.dev) instanceof Cloud));
      if (!seg) { res.drop = { dev: r.id, reason: "no uplink" }; return null; }
      const cm = seg.members.find((m) => this.dev(m.dev) instanceof Cloud);
      if (isPrivate(pkt.src) && r.dropPrivate) { res.drop = { dev: r.id, reason: `private source ${intToIp(pkt.src)} is not routable on the Internet`, privateSrc: true }; return null; }
      return { dev: this.dev(cm.dev), port: "net", pkt };
    }
    const outI = r.ifaces.find((i) => i.up && i.prefix && inPrefix(rt.via, i.prefix));
    if (!outI) { res.drop = { dev: r.id, reason: "next hop unreachable" }; return null; }
    return this.forwardOnSeg(this.segOf(r.id, outI.name), rt.via, pkt, res, r.id);
  }
  cloudProcess(c, inPort, pkt, res) {
    if (c.hosts.some((h) => h.ip === pkt.dst)) return { delivered: true, pkt };
    // route to the router that owns the destination prefix
    for (const seg of this.segments) {
      if (!seg.members.some((m) => m.dev === c.id)) continue;
      for (const m of seg.members) {
        const r = this.dev(m.dev);
        if (!(r instanceof Router)) continue;
        const owns = r.ifaces.some((i) => i.up && i.prefix && inPrefix(pkt.dst, i.prefix)) || (r.spec.announce || []).some((a) => inPrefix(pkt.dst, parsePrefix(a)));
        if (owns && !isPrivate(pkt.dst)) return { dev: r, port: m.port, pkt: { ...pkt, ttl: pkt.ttl - 1 } };
      }
    }
    // any other public address is "somewhere on the Internet" (clients, vendors)
    if (!isPrivate(pkt.dst)) return { delivered: true, pkt };
    res.drop = { dev: c.id, reason: `no Internet route to ${intToIp(pkt.dst)}` };
    return null;
  }

  fgtProcess(fg, inIntfName, pkt, res, origin) {
    const intfs = this.fgtIntfs(fg);
    const ev = { dev: fg.id, in: inIntfName, src: pkt.src, dst: pkt.dst, proto: pkt.proto };
    res.fgt.push(ev);
    const now = this.now();
    const sport = pkt.proto === ICMP ? pkt.icmpId || 1 : pkt.sport;
    const dportShown = pkt.proto === ICMP ? (pkt.icmpType || 0) * 256 : pkt.dport;
    const tl = [];
    const recv = (from) => ["print_pkt_detail", 5939, `vd-root:0 received a packet(proto=${pkt.proto}, ${intToIp(pkt.src)}:${sport}->${intToIp(pkt.dst)}:${dportShown}) tun_id=0.0.0.0 from ${from}.${pkt.proto === ICMP ? ` type=${pkt.icmpType || 0}, code=0, id=${sport}, seq=${pkt.seq || 1}.` : pkt.proto === TCP ? ` flag [${pkt.flags || "S"}], seq ${pkt.tcpSeq || 3459283734}, ack ${pkt.tcpAck || 0}, win 64240` : ""}`];
    const done = () => { this.trace(fg, { ...pkt, origDst: ev.origDst }, tl); };

    // local-out (packets the FortiGate itself sends: ping, DNS, etc.)
    if (origin) {
      const rt = pkt.via ? { type: pkt.via.gw ? "S" : "C", dev: pkt.via.intf, gw: pkt.via.gw } : this.fgtLookup(fg, pkt.dst);
      if (!rt || rt.blackhole) { res.drop = { dev: fg.id, reason: "no route", noroute: true }; ev.drop = "noroute"; return null; }
      const outI = intfs.find((i) => i.name === rt.dev);
      this.sniff(fg, outI.name, "out", pkt);
      const nh = rt.type === "C" ? pkt.dst : rt.gw;
      ev.out = outI.name;
      const key = sessKey(pkt.proto, pkt.dst, pkt.proto === ICMP ? sport : pkt.dport, pkt.src, pkt.proto === ICMP ? sport : pkt.sport);
      fg.sessions.set(key, { local: true, id: ++this.sessSeq, proto: pkt.proto, reply: true, in: outI.name, out: outI.name, origin: pkt });
      if (outI.type === "tunnel") return this.tunnelForward(fg, outI, pkt, res, [], () => {}, ev);
      return this.forwardOnSeg(outI.seg, nh, pkt, res, fg.id);
    }

    const inI = intfs.find((i) => i.name === inIntfName) || intfs.find((i) => i.seg && i.seg === this.segOf(fg.id, inIntfName));
    if (!inI || !inI.up) { res.drop = { dev: fg.id, reason: `interface ${inIntfName} is down` }; ev.drop = "down"; return null; }
    this.sniff(fg, inI.name, "in", pkt);
    tl.push(recv(inI.name));

    // existing session (reply direction)
    const rkey = sessKey(pkt.proto, pkt.src, pkt.proto === ICMP ? sport : pkt.sport, pkt.dst, pkt.proto === ICMP ? sport : pkt.dport);
    const s = fg.sessions.get(rkey);
    if (s) {
      tl.push(["resolve_ip_tuple_fast", 5800, `Find an existing session, id-${hex(s.id)}, reply direction`]);
      ev.session = s.id; ev.reply = true;
      if (s.local) { done(); return { delivered: true, pkt }; }
      let out = { ...pkt };
      if (s.snat) { out.dst = s.orig.src; if (pkt.proto !== ICMP) out.dport = s.orig.sport; tl.push(["__ip_session_run_tuple", 3500, `DNAT ${intToIp(pkt.dst)}:${pkt.proto === ICMP ? sport : pkt.dport}->${intToIp(out.dst)}:${pkt.proto === ICMP ? sport : out.dport}`]); }
      if (s.dnat) { out.src = s.orig.dst; if (pkt.proto !== ICMP) out.sport = s.orig.dport; tl.push(["__ip_session_run_tuple", 3500, `SNAT ${intToIp(pkt.src)}->${intToIp(out.src)}:${out.sport || sport}`]); }
      const back = intfs.find((i) => i.name === s.in);
      if (back && back.type === "tunnel" && back.up) return this.tunnelForward(fg, back, out, res, tl, done, ev);
      tl.push(["__vf_ip_route_input_rcu", 1988, `find a route: flag=00000000 gw-${intToIp(out.dst)} via ${s.in}`]);
      done();
      this.sniff(fg, s.in, "out", out);
      if (!back || !back.up) { res.drop = { dev: fg.id, reason: "return interface down" }; return null; }
      const rtb = this.fgtLookup(fg, out.dst, s.in);
      const nh = !rtb || rtb.type === "C" ? out.dst : rtb.gw;
      return this.forwardOnSeg(back.seg, nh, out, res, fg.id);
    }

    const sid = ++this.sessSeq;
    tl.push(["init_ip_session_common", 6120, `allocate a new session-${hex(sid)}, tun_id=0.0.0.0`]);

    // DNAT (VIP)
    let vip = this.vipFor(fg, pkt, inI.name);
    tl.push(["iprope_dnat_check", 5480, `in-[${inI.name}], out-[]`]);
    let dst = pkt.dst, dport = pkt.dport;
    let vipPolicy = null;
    if (vip) {
      const rtv = this.fgtLookup(fg, vip.dst);
      if (rtv && !rtv.blackhole) {
        vipPolicy = this.policyLookup(fg, pkt, inI.name, rtv.dev, vip);
        if (!vipPolicy || vipPolicy.action !== "accept") vip = null;
      } else vip = null;
    }
    if (vip) {
      tl.push(["iprope_dnat_check", 5505, `result: skb_flags-02000000, vid-0, ret-matched, act-accept, flag-00000000`]);
      tl.push(["get_new_addr", 1219, `find DNAT: IP-${intToIp(vip.dst)}, port-${pkt.proto === ICMP ? sport : vip.dport}(fixed port)`]);
      dst = vip.dst; dport = vip.dport; ev.dnat = vip.dst; ev.vip = vip.name; ev.origDst = pkt.dst;
    } else {
      tl.push(["iprope_dnat_check", 5505, `result: skb_flags-02000000, vid-0, ret-no-match, act-accept, flag-00000000`]);
    }

    if (fg.product !== "fortios" && !this.isLocal(fg, dst)) { done(); res.drop = { dev: fg.id, reason: `${fg.id} doesn't route traffic` }; return null; }
    // local-in (traffic to the FortiGate itself)
    if (!vip && this.isLocal(fg, dst)) {
      tl.push(["__vf_ip_route_input_rcu", 1988, `find a route: flag=84000000 gw-${intToIp(dst)} via root`]);
      const svc = localSvc(pkt, fg);
      const allowed = svc === "ike" ? this.ikeAccepted(fg, inI.name, pkt.src) : (svc === "oftp" || svc === "fgfm") && fg.product !== "fortios" ? true : svc && inI.allow.includes(svc) && this.trusted(fg, pkt.src, svc);
      ev.local = true; ev.localSvc = svc;
      if (!allowed) {
        tl.push(["iprope_in_check", 1029, `iprope_in_check() check failed on policy 0, drop`]);
        done();
        ev.drop = "local-in";
        res.drop = { dev: fg.id, reason: svc ? `${svc.toUpperCase()} is not in allowaccess on ${inI.name}${svc && inI.allow.includes(svc) ? " (trusted hosts)" : ""}` : "not a FortiGate service", localIn: true };
        return null;
      }
      done();
      res.localAnswer = { fgt: fg.id, svc };
      const replyKey = sessKey(pkt.proto, dst, pkt.proto === ICMP ? sport : dport, pkt.src, pkt.proto === ICMP ? sport : pkt.sport);
      fg.sessions.set(replyKey, { local: true, id: sid, in: inI.name });
      return { delivered: true, pkt, fgt: fg };
    }

    // route to destination
    const rt = this.sdwanSelect(fg, { ...pkt, dst, dport }, inI.name, tl) || this.fgtLookup(fg, dst);
    if (!rt) {
      tl.push(["__vf_ip_route_input_rcu", 1988, `find a route: flag=00000000 gw-0.0.0.0 via root`]);
      tl.push(["ip_route_input_slowpath", 2210, `no route to destination ${intToIp(dst)}, drop`]);
      done(); ev.drop = "noroute";
      res.drop = { dev: fg.id, reason: `no route to ${intToIp(dst)}`, noroute: true };
      return null;
    }
    if (rt.blackhole) {
      tl.push(["__vf_ip_route_input_rcu", 1988, `find a route: flag=00000000 gw-0.0.0.0 via Null`]);
      done(); ev.drop = "blackhole";
      res.drop = { dev: fg.id, reason: `blackhole route ${prefixStr(rt.dst)}` };
      return null;
    }
    const outI = intfs.find((i) => i.name === rt.dev);
    const gw = rt.type === "C" ? dst : rt.gw;
    tl.push(["__vf_ip_route_input_rcu", 1988, `find a route: flag=04000000 gw-${intToIp(gw)} via ${outI.name}`]);
    ev.out = outI.name;

    // reverse path check (loose: any route back to the source through the ingress interface)
    const strict = fg.one("system settings", fg.obj("system settings"), "strict-src-check") === "enable";
    if (inI.srcCheck) {
      const back = strict ? this.fgtLookup(fg, pkt.src) : this.fgtLookup(fg, pkt.src, inI.name);
      if (!back || back.dev !== inI.name) {
        tl.push(["ip_route_input_slowpath", 2210, `reverse path check fail, drop`]);
        done(); ev.drop = "rpf";
        res.drop = { dev: fg.id, reason: `reverse path check failed: no route back to ${intToIp(pkt.src)} via ${inI.name}`, rpf: true };
        return null;
      }
    }

    // intra-zone traffic
    const zin = this.zoneOf(fg, inI.name), zout = this.zoneOf(fg, outI.name);
    let pol;
    if (zin && zout && zin.key === zout.key && inI.name !== outI.name && fg.one("system zone", zin, "intrazone") === "allow") pol = { id: "0", action: "accept", nat: false, intrazone: true };
    else pol = vip ? vipPolicy : this.policyLookup(fg, pkt, inI.name, outI.name, null);
    tl.push(["__iprope_fwd_check", 810, `in-[${inI.name}], out-[${outI.name}], skb_flags-02000000, vid-0, app_id: 0, url_cat_id: 0`]);
    if (!pol || pol.action !== "accept") {
      const id = pol ? pol.id : "0";
      tl.push(["__iprope_tree_check", 524, `gnum-100004, use addr/intf hash, len=2`]);
      tl.push(["fw_forward_handler", 930, `Denied by forward policy check (policy ${id})`]);
      done(); ev.drop = "policy"; ev.policy = id;
      if (!this.quiet) this.logTraffic(fg, pol ? pol.policy : null, { ...pkt, inIntf: inI.name, outIntf: outI.name, action: "deny", policyid: id });
      res.drop = { dev: fg.id, reason: pol ? `denied by policy ${id}${pol.name ? ` (${pol.name})` : ""}` : "no policy matches: implicit deny (policy 0)", policy: id };
      return null;
    }
    ev.policy = pol.id;
    // SNAT
    let out = { ...pkt, dst, dport };
    let snat = null;
    if (pol.nat) {
      const p = pol.policy;
      let ip = outI.prefix ? outI.prefix.ip : null;
      if (fg.one("firewall policy", p, "ippool") === "enable") {
        const pn = fg.val("firewall policy", p, "poolname")[0];
        const pe = pn && fg.entry("firewall ippool", pn);
        if (pe) ip = ipToInt(fg.one("firewall ippool", pe, "startip"));
      }
      const nport = pkt.proto === ICMP ? sport : 60000 + Math.floor(this.rand() * 5000);
      snat = { ip, port: nport };
      out.src = ip;
      if (pkt.proto !== ICMP) out.sport = nport;
      tl.push(["fw_forward_handler", 930, `Allowed by Policy-${pol.id}: SNAT`]);
      tl.push(["__ip_session_run_tuple", 3500, `SNAT ${intToIp(pkt.src)}->${intToIp(ip)}:${nport}`]);
      ev.snat = ip;
    } else {
      tl.push(["fw_forward_handler", 930, pol.intrazone ? `Allowed by intra-zone traffic` : `Allowed by Policy-${pol.id}:`]);
    }
    if (vip) tl.push(["__ip_session_run_tuple", 3500, `DNAT ${intToIp(pkt.dst)}:${pkt.proto === ICMP ? sport : pkt.dport}->${intToIp(dst)}:${pkt.proto === ICMP ? sport : dport}`]);
    if ((pkt.ttl || 64) <= 1) {
      done(); ev.drop = "ttl";
      res.drop = { dev: fg.id, reason: "ttl exceeded", ttl: true, hopIp: inI.prefix ? inI.prefix.ip : null };
      return null;
    }
    out.ttl = (pkt.ttl || 64) - 1;
    // MTU on egress (DF)
    if (out.size && out.df && out.size > outI.mtu) {
      done(); ev.drop = "mtu";
      res.drop = { dev: fg.id, reason: `packet of ${out.size} bytes with DF set exceeds MTU ${outI.mtu} on ${outI.name}`, mtu: outI.mtu };
      return null;
    }
    if (!this.quiet && pol.policy) this.logTraffic(fg, pol.policy, { ...pkt, inIntf: inI.name, outIntf: outI.name, action: "accept", policyid: pol.id, transip: snat ? snat.ip : undefined, dnat: vip ? dst : undefined });
    const isTunnel = outI.type === "tunnel";
    if (!isTunnel) done();
    // create the session and remember the reply tuple
    const sess = { id: sid, proto: pkt.proto, in: inI.name, out: outI.name, policy: pol.id, orig: { src: pkt.src, sport: pkt.proto === ICMP ? sport : pkt.sport, dst: pkt.dst, dport: pkt.proto === ICMP ? sport : pkt.dport },
      snat, dnat: vip ? { ip: dst, port: dport } : null, gw, prevHop: res.prevHop || null, start: now, bytes: 0 };
    const replyKey = sessKey(pkt.proto, dst, pkt.proto === ICMP ? sport : dport, out.src, pkt.proto === ICMP ? sport : out.sport);
    fg.sessions.set(replyKey, sess);
    sess.key = replyKey;
    fg.sessList = fg.sessList || [];
    fg.sessList.push(sess);
    if (fg.sessList.length > 200) fg.sessList.shift();
    if (isTunnel) return this.tunnelForward(fg, outI, out, res, tl, done, ev);
    this.sniff(fg, outI.name, "out", out);
    return this.forwardOnSeg(outI.seg, gw, out, res, fg.id, rt.type === "C" ? `no ARP reply from ${intToIp(gw)} on ${outI.name}` : `gateway ${intToIp(gw)} does not answer ARP on ${outI.name}`);
  }
  trusted(fg, src, svc) {
    if (svc !== "https" && svc !== "ssh" && svc !== "http" && svc !== "telnet") return true;
    const admins = fg.entries("system admin");
    const hosts = [];
    for (const a of admins) for (let i = 1; i <= 10; i++) { const t = a.attrs.get("trusthost" + i); if (t) hosts.push(parsePrefix(t[0])); }
    if (!hosts.length) return true;
    return hosts.some((p) => (p.len === 0 && p.ip === 0) || inPrefix(src, p));
  }

  // DNS answer for a name, as the public Internet would give it: known lab names first (with or without www),
  // then any other public-looking domain gets a stable address on a generic web server; internal names don't exist.
  lookupName(name) {
    const n = String(name || "").toLowerCase().replace(/\.$/, "");
    const hit = this.names.get(n) ?? this.names.get(n.replace(/^www\./, "")) ?? this.names.get("www." + n);
    if (hit !== undefined) return hit;
    if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(n) || /\.(local|lan|internal|corp|home|localdomain|invalid|test)$/.test(n) || /^\d+(\.\d+)+$/.test(n)) return null;
    const cloud = [...this.devices.values()].find((d) => d instanceof Cloud);
    if (!cloud) return null;
    let h = 2166136261;
    for (const ch of n) { h ^= ch.charCodeAt(0); h = Math.imul(h, 16777619) >>> 0; }
    let ip = ((151 << 24) | (101 << 16) | (h & 0xffff)) >>> 0; // 151.101.x.y, public CDN-like space
    while (cloud.hosts.some((x) => x.ip === ip)) ip = (ip + 1) >>> 0;
    cloud.hosts.push({ name: n, ip, services: new Set(["tcp/80", "tcp/443", "icmp"]), dns: false, files: {}, pinned: false });
    this.names.set(n, ip);
    return ip;
  }

  // ---------- end-to-end probes (used by hosts, FortiGate ping, and the grader) ----------
  // Send a request from device `fromId` and simulate the reply. Returns a rich result.
  probe(fromId, req) {
    const src = this.dev(fromId);
    let srcIp = req.src;
    if (srcIp === undefined) {
      if (src instanceof Host) srcIp = src.vpn && src.vpn.up && (!src.vpn.split || src.vpn.split.some((p) => inPrefix(req.dst, p))) ? src.vpn.ip : src.ip();
      else if (src instanceof FortiGate) {
        const rt = this.fgtLookup(src, req.dst);
        const i = rt && this.fgtIntfs(src).find((x) => x.name === rt.dev);
        srcIp = src.dbg.pingSrc || (i && i.prefix ? i.prefix.ip : null);
      }
    }
    const proto = req.proto || ICMP;
    const pkt = { via: req.via, src: srcIp, dst: req.dst, proto, sport: req.sport || 49152 + Math.floor(this.rand() * 10000), dport: req.dport || 0, icmpType: proto === ICMP ? 8 : undefined, icmpId: req.icmpId || 1, seq: req.seq || 1, flags: "S", size: req.size, df: req.df, ttl: req.ttl || 64 };
    if (srcIp === null || srcIp === undefined) return { ok: false, drop: { dev: fromId, reason: src instanceof Host ? "no IP address (DHCP failed)" : "no source address" }, fwd: { fgt: [] } };
    const fwd = this.send(fromId, pkt);
    const out = { ok: false, fwd, req: pkt };
    if (!fwd.delivered) { out.drop = fwd.drop; return out; }
    const target = this.dev(fwd.delivered.dev);
    const got = fwd.delivered.pkt;
    // does the target answer?
    let answers = false;
    if (fwd.localAnswer) answers = true;
    else if (target instanceof Host) answers = target.listens(got.proto, got.dport);
    else if (target instanceof Cloud) { const h = target.hosts.find((x) => x.ip === got.dst); answers = !!h && (got.proto === ICMP ? h.services.has("icmp") : h.services.has(`${PNAME[got.proto]}/${got.dport}`)); }
    else if (target instanceof Router) answers = got.proto === ICMP;
    out.reached = target.id;
    out.seenSrc = got.src;
    out.seenDst = got.dst;
    if (!answers) { out.drop = { dev: target.id, reason: got.proto === TCP ? `${target.id} refused the connection (port ${got.dport} closed)` : `${target.id} did not answer`, refused: got.proto === TCP }; return out; }
    // reply packet
    const rp = { src: got.dst, dst: got.src, proto: got.proto, sport: got.dport, dport: got.sport, icmpType: got.proto === ICMP ? 0 : undefined, icmpId: got.icmpId, seq: got.seq, flags: "SA", tcpAck: 3459283735, ttl: 64 };
    let rev;
    if (fwd.localAnswer) {
      const fg = this.dev(fwd.localAnswer.fgt);
      // FortiGate answers from its own IP: route back out
      rev = this.sendFromFgt(fg, rp);
    } else rev = this.send(target.id, rp);
    out.rev = rev;
    if (!rev.delivered || rev.delivered.dev !== fromId) { out.drop = rev.drop || { dev: target.id, reason: "reply lost" }; out.replyLost = true; return out; }
    out.ok = true;
    out.replySrc = rev.delivered.pkt.src;
    return out;
  }
  sendFromFgt(fg, rp) {
    const res = { path: [], fgt: [], drop: null, delivered: null };
    const rt = this.fgtLookup(fg, rp.dst);
    if (!rt || rt.blackhole) { res.drop = { dev: fg.id, reason: "no route back" }; return res; }
    const outI = this.fgtIntfs(fg).find((i) => i.name === rt.dev);
    const nh = rt.type === "C" ? rp.dst : rt.gw;
    this.sniff(fg, outI.name, "out", rp);
    const step = this.forwardOnSeg(outI.seg, nh, rp, res, fg.id);
    if (!step) return res;
    let at = step.dev, port = step.port, p = step.pkt;
    for (let hop = 0; hop < 24 && at; hop++) {
      const st = this.process(at, port, p, res, false);
      if (!st) return res;
      if (st.delivered) { res.delivered = { dev: at.id, pkt: st.pkt }; return res; }
      ({ dev: at, port, pkt: p } = st);
    }
    return res;
  }
  resolve(fromId, name) {
    if (/^\d+\.\d+\.\d+\.\d+$/.test(name)) return { ip: ipToInt(name) };
    const h = this.dev(fromId);
    const servers = h instanceof Host ? h.dnsServers() : h instanceof FortiGate ? this.fgtDns(h) : [];
    if (!servers.length) return { err: "no DNS server configured" };
    for (const s of servers) {
      const r = this.probe(fromId, { dst: s, proto: UDP, dport: 53 });
      if (r.ok) {
        const ip = this.lookupName(name);
        return ip ? { ip, server: s } : { err: `can't find ${name}: Non-existent domain`, server: s };
      }
    }
    return { err: "DNS request timed out", server: servers[0] };
  }
}

// Defaults, replaced by vpn.js / sdwan.js / ha.js
Lab.prototype.tunnelUp = function () { return false; };
Lab.prototype.extraRoutes = function () { return []; };
Lab.prototype.sdwanMembers = function () { return []; };
Lab.prototype.sdwanSelect = function () { return null; };
Lab.prototype.tunnelForward = function (fg, outI, out, res, tl, done) { done(); res.drop = { dev: fg.id, reason: "tunnel not simulated" }; return null; };
Lab.prototype.ikeAccepted = function () { return false; };
Lab.prototype.haRole = function () { return "standalone"; };
Lab.prototype.haSync = function () {};
Lab.prototype.haSyncAll = function () {};
Lab.prototype.mgmtInit = function () {};
Lab.prototype.mgmtExec = function () { return null; };
Lab.prototype.mgmtPrompt = function () { return null; };
Lab.prototype.logTraffic = function () {};
Lab.prototype.onCommit = function () {};
Lab.prototype.postLoad = function () {};
Lab.prototype.onDelete = function () {};
Lab.prototype.clientTunnel = function (h, pkt, res) { res.drop = { dev: h.id, reason: "VPN not simulated" }; return null; };

function maskLen(m) { const n = ipToInt(m); let l = 0; for (let i = 31; i >= 0; i--) if ((n >>> i) & 1) l++; return l; }
export function sessKey(proto, a, ap, b, bp) { return `${proto}|${a}|${ap}|${b}|${bp}`; }
function localSvc(pkt, fg) {
  if (pkt.proto === ICMP) return "ping";
  const g = fg.obj("system global");
  const https = Number(fg.one("system global", g, "admin-sport") || 443), ssh = Number(fg.one("system global", g, "admin-ssh-port") || 22);
  if (pkt.proto === TCP) {
    if (pkt.dport === https) return "https";
    if (pkt.dport === ssh) return "ssh";
    if (pkt.dport === 80) return "http";
    if (pkt.dport === 23) return "telnet";
    if (pkt.dport === 541) return "fgfm";
    if (pkt.dport === 514) return "oftp";
  }
  if (pkt.proto === UDP && (pkt.dport === 500 || pkt.dport === 4500)) return "ike";
  if (pkt.proto === UDP && pkt.dport === 161) return "snmp";
  if (pkt.proto === UDP && pkt.dport === 53) return "dns";
  return null;
}
export function describePkt(p) {
  const s = intToIp(p.src), d = intToIp(p.dst);
  if (p.proto === ICMP) return `${s} -> ${d}: icmp: ${p.icmpType === 0 ? "echo reply" : p.icmpType === 8 ? "echo request" : "type " + p.icmpType}`;
  if (p.proto === TCP) return `${s}.${p.sport} -> ${d}.${p.dport}: ${p.flags === "SA" ? "syn " + 2214851107 + " ack " + 3459283735 : "syn " + 3459283734}`;
  if (p.proto === UDP) return `${s}.${p.sport} -> ${d}.${p.dport}: udp ${p.size || 40}`;
  return `${s} -> ${d}: ip-proto-${p.proto}`;
}
// a small subset of BPF: host/src/dst host, net, port, icmp/tcp/udp, and/or/not, parentheses ignored
export function bpf(expr, p) {
  const t = String(expr || "").replace(/[()]/g, " ").trim().split(/\s+/).filter(Boolean);
  if (!t.length || t[0] === "none") return true;
  let i = 0;
  const atom = () => {
    const w = t[i++];
    if (w === "not") return !atom();
    if (w === "icmp") return p.proto === ICMP;
    if (w === "tcp") return p.proto === TCP;
    if (w === "udp") return p.proto === UDP;
    if (w === "host") { const ip = ipToInt(t[i++]); return p.src === ip || p.dst === ip; }
    if (w === "src" || w === "dst") {
      let k = t[i++]; if (k === "host") k = t[i++];
      if (k === "port") { const n = Number(t[i++]); return w === "src" ? p.sport === n : p.dport === n; }
      const ip = ipToInt(k); return w === "src" ? p.src === ip : p.dst === ip;
    }
    if (w === "net") { const pr = parsePrefix(t[i++]); return inPrefix(p.src, pr) || inPrefix(p.dst, pr); }
    if (w === "port") { const n = Number(t[i++]); return p.sport === n || p.dport === n; }
    const ip = ipToInt(w);
    if (ip !== null) return p.src === ip || p.dst === ip;
    return true;
  };
  let v = atom();
  while (i < t.length) {
    const op = t[i++];
    const r = atom();
    v = op === "or" ? v || r : v && r;
  }
  return v;
}
