// SD-WAN for the lab simulator: members, zones, health checks fed by ISP link quality, and service rules.
import { Lab } from "./sim.js";
import { ipToInt, intToIp, parsePrefix, inPrefix } from "./net.js";

const SD = "system sdwan";

Lab.prototype.sdwanCfg = function (fg) {
  const root = fg.obj(SD);
  if (!root) return { on: false, members: [], hcs: [], services: [] };
  const on = fg.one(SD, root, "status") === "enable";
  const kid = (n) => { const t = root.children.get(n); return t ? t.list() : []; };
  const val = (e, a, c) => fg.val(SD, e, a, [c]);
  const one = (e, a, c) => val(e, a, c)[0];
  const members = kid("members").map((e) => ({ seq: e.key, intf: one(e, "interface", "members"), gw: ipToInt(one(e, "gateway", "members") || "0.0.0.0"), zone: one(e, "zone", "members") || "virtual-wan-link", priority: Number(one(e, "priority", "members") || 1), cost: Number(one(e, "cost", "members") || 0), status: one(e, "status", "members") !== "disable", source: ipToInt(one(e, "source", "members") || "0.0.0.0") || 0 }));
  const hcs = kid("health-check").map((e) => {
    const slat = e.children.get("sla");
    return { name: e.key, server: (val(e, "server", "health-check")[0] || "").split(/\s+/)[0], protocol: one(e, "protocol", "health-check") || "ping", members: val(e, "members", "health-check"), updateRoute: one(e, "update-static-route", "health-check") !== "disable",
      slas: slat ? slat.list().map((x) => ({ id: x.key, lat: Number(fg.val(SD, x, "latency-threshold", ["health-check", "sla"])[0] || 5000), jit: Number(fg.val(SD, x, "jitter-threshold", ["health-check", "sla"])[0] || 5000), loss: Number(fg.val(SD, x, "packetloss-threshold", ["health-check", "sla"])[0] || 100) })) : [] };
  });
  const services = kid("service").map((e) => {
    const slat = e.children.get("sla");
    return { id: e.key, name: one(e, "name", "service") || "", mode: one(e, "mode", "service") || "manual", dst: val(e, "dst", "service"), src: val(e, "src", "service"), proto: Number(one(e, "protocol", "service") || 0),
      sp: Number(one(e, "start-port", "service") || 1), ep: Number(one(e, "end-port", "service") || 65535), prio: val(e, "priority-members", "service"), hc: val(e, "health-check", "service"), lcf: one(e, "link-cost-factor", "service") || "latency",
      input: val(e, "input-device", "service"), status: one(e, "status", "service") !== "disable",
      slas: slat ? slat.list().map((x) => ({ hc: fg.val(SD, x, "health-check", ["service", "sla"])[0] || x.key, id: (x.attrs.get("id") || ["1"])[0] })) : [] };
  });
  return { on, members, hcs, services };
};

// health of one member against one health check: probe the server through that member
Lab.prototype.memberHealth = function (fg, m, hc) {
  const k = `${fg.id}|${m.seq}|${hc.name}`;
  if (!this._hc || this._hcVer !== this.ver) { this._hc = new Map(); this._hcVer = this.ver; }
  if (this._hc.has(k)) return this._hc.get(k);
  // probing through a member can ask SD-WAN about that member again: assume alive while measuring
  this._hcBusy = this._hcBusy || new Set();
  if (this._hcBusy.has(k)) return { alive: true, latency: 0, jitter: 0, loss: 0, why: "", sla: hc.slas.map(() => true) };
  this._hcBusy.add(k);
  try { return this.memberHealthInner(fg, m, hc, k); } finally { this._hcBusy.delete(k); }
};
Lab.prototype.memberHealthInner = function (fg, m, hc, k) {
  const intf = this.fgtIntfs(fg).find((i) => i.name === m.intf);
  let r = { alive: false, latency: 0, jitter: 0, loss: 100, why: "" };
  const dst = ipToInt(hc.server);
  const src = m.source || (intf && intf.prefix ? intf.prefix.ip : 0);
  if (!intf || !intf.up) r.why = `${m.intf} is down`;
  else if (dst === null) r.why = "no health-check server";
  else if (!src) r.why = `no source address: ${m.intf} has no IP, so set the member's source`;
  else {
    const proto = hc.protocol === "http" || hc.protocol === "tcp-connect" || hc.protocol === "https" ? 6 : hc.protocol === "dns" ? 17 : 1;
    const dport = hc.protocol === "http" ? 80 : hc.protocol === "https" ? 443 : hc.protocol === "dns" ? 53 : 0;
    this.quiet = (this.quiet || 0) + 1;
    let p;
    try { p = this.probe(fg.id, { dst, proto, dport, src, via: { intf: m.intf, gw: m.gw } }); } finally { this.quiet--; }
    const q = (p.fwd && p.fwd.q) || { latency: 0, jitter: 0, loss: 0 };
    if (p.ok) r = { alive: q.loss < 100, latency: 2 + q.latency, jitter: q.jitter, loss: q.loss, why: "" };
    else r.why = p.drop ? p.drop.reason : "no reply";
  }
  r.sla = hc.slas.map((s) => r.alive && r.latency <= s.lat && r.jitter <= s.jit && r.loss <= s.loss);
  this._hc.set(k, r);
  return r;
};
Lab.prototype.memberAlive = function (fg, cfg, m) {
  if (!m.status) return false;
  const intf = this.fgtIntfs(fg).find((i) => i.name === m.intf);
  if (!intf || !intf.up) return false;
  for (const hc of cfg.hcs) if (hc.updateRoute && hc.members.includes(m.seq) && !this.memberHealth(fg, m, hc).alive) return false;
  return true;
};
Lab.prototype.sdwanMembers = function (fg, zone) {
  const cfg = this.sdwanCfg(fg);
  if (!cfg.on) return [];
  return cfg.members.filter((m) => m.zone === zone).map((m) => ({ ...m, alive: this.memberAlive(fg, cfg, m) }));
};

// SD-WAN service rules are checked before the routing table
Lab.prototype.sdwanSelect = function (fg, pkt, inIntf, tl) {
  const cfg = this.sdwanCfg(fg);
  if (!cfg.on || !cfg.services.length) return null;
  for (const s of cfg.services) {
    if (!s.status) continue;
    if (s.input.length && !s.input.includes(inIntf)) continue;
    if (s.dst.length && !s.dst.some((a) => this.addrMatch(fg, a, pkt.dst))) continue;
    if (s.src.length && !s.src.some((a) => this.addrMatch(fg, a, pkt.src))) continue;
    if (s.proto && s.proto !== pkt.proto) continue;
    if (pkt.proto !== 1 && (pkt.dport < s.sp || pkt.dport > s.ep)) continue;
    const order = s.prio.map((q) => cfg.members.find((m) => m.seq === q)).filter(Boolean);
    const alive = order.filter((m) => this.memberAlive(fg, cfg, m));
    if (!alive.length) continue;
    let pick = alive[0];
    const hc = cfg.hcs.find((h) => h.name === (s.hc[0] || (s.slas[0] && s.slas[0].hc)));
    if (s.mode === "priority" && hc) {
      const metric = (m) => { const r = this.memberHealth(fg, m, hc); return s.lcf === "jitter" ? r.jitter : s.lcf === "packet-loss" ? r.loss : r.latency; };
      pick = [...alive].sort((a, b) => metric(a) - metric(b))[0];
    } else if (s.mode === "sla" && s.slas.length) {
      const meets = (m) => s.slas.every((sl) => { const h = cfg.hcs.find((x) => x.name === sl.hc); if (!h) return false; const i = h.slas.findIndex((x) => String(x.id) === String(sl.id)); return i >= 0 && this.memberHealth(fg, m, h).sla[i]; });
      pick = alive.find(meets) || alive[0];
    }
    const rid = 2133196800 + Number(s.id);
    if (tl) tl.push(["vf_ip_route_input_common", 2605, `Match policy routing id=${rid}: to ${intToIp(pkt.dst)} via ifindex-${3 + Number(pick.seq)}`]);
    return { type: "S", dev: pick.intf, gw: pick.gw, dst: { ip: 0, len: 0 }, distance: 1, priority: 1, sdwanRule: s.id };
  }
  return null;
};

// policies may name an SD-WAN zone instead of interfaces
const baseIntfMatch = Lab.prototype.intfMatch;
Lab.prototype.intfMatch = function (fg, names, intf) {
  if (baseIntfMatch.call(this, fg, names, intf)) return true;
  const cfg = this.sdwanCfg(fg);
  return cfg.members.some((m) => m.intf === intf && names.includes(m.zone));
};

Lab.prototype.sdwanDiag = function (fg, words) {
  const w = words.join(" ");
  const cfg = this.sdwanCfg(fg);
  if (/^sys sdwan health-check/.test(w)) {
    if (!cfg.hcs.length) return "Health Check: no health check configured.";
    return cfg.hcs.map((hc) => [`Health Check(${hc.name}):`, ...hc.members.map((seq) => {
      const m = cfg.members.find((x) => x.seq === seq);
      if (!m) return "";
      const r = this.memberHealth(fg, m, hc);
      const map = r.sla.reduce((a, ok, i) => a | (ok ? 1 << i : 0), 0);
      return r.alive ? `Seq(${seq} ${m.intf}): state(alive), packet-loss(${r.loss.toFixed(3)}%) latency(${r.latency.toFixed(3)}), jitter(${r.jitter.toFixed(3)}), mos(${(4.4 - r.latency / 400 - r.jitter / 100 - r.loss / 20).toFixed(3)}), bandwidth-up(999999), bandwidth-dw(999999), bandwidth-bi(1999998) sla_map=0x${map.toString(16)}`
        : `Seq(${seq} ${m.intf}): state(dead), packet-loss(100.000%) sla_map=0x0`;
    })].filter(Boolean).join("\n")).join("\n");
  }
  if (/^sys sdwan member/.test(w)) return cfg.members.map((m) => `Member(${m.seq}): interface: ${m.intf}, flags=0x0 , gateway: ${intToIp(m.gw)}, peer: 0.0.0.0, source ${intToIp(0)}, priority: ${m.priority} 1024, weight: 0\n` + `  status: ${this.memberAlive(fg, cfg, m) ? "alive" : "dead"}, zone: ${m.zone}`).join("\n") || "No SD-WAN members.";
  if (/^sys sdwan service/.test(w)) {
    return cfg.services.map((s) => {
      const hc = cfg.hcs.find((h) => h.name === (s.hc[0] || (s.slas[0] && s.slas[0].hc)));
      const order = s.prio.map((q) => cfg.members.find((m) => m.seq === q)).filter(Boolean);
      return [`Service(${s.id}): Address Mode(IPV4) flags=0x200 use-shortcut-sla use-shortcut`, `  Tie break: cfg`, `  Gen(1), TOS(0x0/0x0), Protocol(${s.proto}: ${s.sp}->${s.ep}), Mode(${s.mode})`, `  Members(${order.length}):`,
        ...order.map((m, i) => { const alive = this.memberAlive(fg, cfg, m); const r = hc ? this.memberHealth(fg, m, hc) : null; const map = r ? r.sla.reduce((a, ok, j) => a | (ok ? 1 << j : 0), 0) : 0; return `    ${i + 1}: Seq_num(${m.seq} ${m.intf}), ${alive ? "alive" : "dead"}, sla(0x${map.toString(16)}), gid(0), cfg_order(${i}), local cost(${m.cost}), ${alive ? "selected" : ""}`; }),
        `  Dst address(${s.dst.length}):`, ...s.dst.map((d) => `        ${d}`)].join("\n");
    }).join("\n") || "No SD-WAN service rules.";
  }
  return null;
};
