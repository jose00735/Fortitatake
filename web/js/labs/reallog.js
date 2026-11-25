// SecOps on the real network. With a lab live on FortiTatake OS:
// - FortiGate traffic logs come from the kernel: conntrack DESTROY events in the FortiGate's namespace
//   (accept policies with logtraffic all) and nftables `log` lines for denies (kernel log, /dev/kmsg);
// - logs travel over the lab network the way FortiGates send them: OFTP to FortiAnalyzer (a TCP 514
//   stream of key=value lines here, without OFTP's TLS framing) and syslog over UDP to FortiSIEM;
// - FortiAnalyzer and FortiSIEM show what actually arrived (the agent's collectors keep each line);
// - device registration, Windows agents and FortiEDR collectors are "connected" only if the real
//   TCP connection works.
// Scripted story logs (IPS, Windows, EDR) keep their content but go over the same real transport.
import { FortiGate } from "./fgt.js";
import { ipToInt, intToIp } from "./net.js";
import { fmtLog } from "./utm.js";
import { parseConntrack, routeHelpers } from "./realdiag.js";

const SVC = { 1: () => "PING", 6: (p) => ({ 80: "HTTP", 443: "HTTPS", 22: "SSH", 3389: "RDP", 445: "SMB", 1433: "MS-SQL", 53: "DNS" }[p] || `tcp/${p}`), 17: (p) => ({ 53: "DNS", 123: "NTP", 5060: "SIP", 500: "IKE", 514: "SYSLOG" }[p] || `udp/${p}`) };
const svcName = (proto, port) => (SVC[proto] ? SVC[proto](port) : `proto/${proto}`);
const stamp = (lab) => { const d = new Date(lab.clock - 5 * 3600000); return { date: d.toISOString().slice(0, 10), time: d.toISOString().slice(11, 19) }; };

// key=value log line back into a record
export function parseKv(line) {
  const rec = {};
  for (const m of line.replace(/^<\d+>/, "").matchAll(/(\w+)=("([^"]*)"|\S+)/g)) rec[m[1]] = m[3] !== undefined ? m[3] : /^\d+$/.test(m[2]) ? Number(m[2]) : m[2];
  return rec;
}

export class RealLogs {
  constructor(lab, call) {
    this.lab = lab; this.call = call;
    this.streams = new Map(); // key -> {id, next, partial, kind, dev, target}
    this.queue = new Map(); // fgId -> [{line, ev}] waiting for FortiAnalyzer
    this.sys = new Map(); // fgId -> [line] waiting for the syslog sender
    this.seenFaz = new Set(); this.seenSiem = new Set();
    this.collect = new Map(); // ns -> last seq read
    this.kmsgSeq = -1; this.ev = Date.now() * 1000;
    this.reach = new Map(); this.lastReach = 0;
    this.c = null;
  }

  // ---------- producers ----------
  fgts() { return [...this.lab.devices.values()].filter((d) => d instanceof FortiGate && d.kind === "fortigate" && !d.parent); }
  policyLogs(fg, id) { const p = fg.entry("firewall policy", String(id)); return p ? fg.one("firewall policy", p, "logtraffic") : null; }

  fromConntrack(fg, line) {
    const ev = /^\s*\[(\w+)\]\s*(.*)$/.exec(line);
    if (!ev || ev[1] !== "DESTROY") return;
    const s = parseConntrack(ev[2])[0];
    if (!s || !s.mark || this.policyLogs(fg, s.mark) !== "all") return;
    const h = routeHelpers(this.c, fg.id);
    const o = s.org, r = s.rep;
    const icmp = s.proto === 1;
    const rec = { ...stamp(this.lab), eventtime: ++this.ev, logid: "0000000013", type: "traffic", subtype: "forward", level: "notice", devname: fg.hostname(), devid: fg.serial, vd: "root",
      srcip: o.src, srcport: icmp ? 0 : Number(o.sport), srcintf: h.ifFor(o.src) || "", dstip: o.dst, dstport: icmp ? 0 : Number(o.dport), dstintf: h.ifFor(r.src) || "",
      sessionid: s.id || 0, proto: s.proto, action: s.proto === 6 ? "close" : "accept", policyid: s.mark, service: svcName(s.proto, Number(o.dport)),
      sentbyte: Number(o.bytes || 0), rcvdbyte: Number(r.bytes || 0), sentpkt: Number(o.packets || 0), rcvdpkt: Number(r.packets || 0) };
    if (r.dst !== o.src) Object.assign(rec, { trandisp: "snat", transip: r.dst, transport: icmp ? 0 : Number(r.dport) });
    else if (r.src !== o.dst) Object.assign(rec, { trandisp: "dnat", tranip: r.src, tranport: icmp ? 0 : Number(r.sport) });
    else rec.trandisp = "noop";
    this.lab.storeLog(fg, rec);
  }

  // "FTKD <fgt> <policy> IN=internal OUT=wan1 ... SRC=… DST=… PROTO=TCP SPT=… DPT=…"
  fromKmsg(line) {
    const m = /^(\d+),(\d+),[^;]*;FTKD (\S+) (\d+) (.*)$/.exec(line.trim());
    if (!m) return;
    const seq = Number(m[2]);
    if (seq <= this.kmsgSeq) return;
    this.kmsgSeq = seq;
    const fg = this.lab.dev(m[3]);
    if (!fg) return;
    const f = Object.fromEntries([...m[5].matchAll(/(\w+)=(\S*)/g)].map((x) => [x[1], x[2]]));
    const proto = { TCP: 6, UDP: 17, ICMP: 1 }[f.PROTO] || Number(f.PROTO) || 0;
    const rec = { ...stamp(this.lab), eventtime: ++this.ev, logid: "0000000013", type: "traffic", subtype: "forward", level: "warning", devname: fg.hostname(), devid: fg.serial, vd: "root",
      srcip: f.SRC, srcport: Number(f.SPT || 0), srcintf: f.IN || "", dstip: f.DST, dstport: Number(f.DPT || 0), dstintf: f.OUT || "", proto, action: "deny", policyid: Number(m[4]),
      service: svcName(proto, Number(f.DPT || 0)), sentbyte: 0, rcvdbyte: 0, msg: Number(m[4]) ? "" : "Denied by forward policy check (policy 0)" };
    if (!rec.msg) delete rec.msg;
    this.lab.storeLog(fg, rec);
  }

  // ---------- the FortiGate's log settings ----------
  fazTarget(fg) {
    const s = fg.obj("log fortianalyzer setting");
    if (!s || fg.one("log fortianalyzer setting", s, "status") !== "enable") return null;
    const ip = String(fg.one("log fortianalyzer setting", s, "server") || "");
    const src = String(fg.one("log fortianalyzer setting", s, "source-ip") || "");
    return ipToInt(ip) ? { ip, port: 514, src: src && src !== "0.0.0.0" ? src : "" } : null;
  }
  sysTarget(fg) {
    const s = fg.cfg.get("log syslogd setting");
    if (!s || fg.one("log syslogd setting", s, "status") !== "enable") return null;
    const ip = String(fg.one("log syslogd setting", s, "server") || "");
    return ipToInt(ip) ? { ip, port: Number(fg.one("log syslogd setting", s, "port") || 514) } : null;
  }

  // called by Lab.storeLog in live mode
  ship(fg, rec) {
    if (!(fg instanceof FortiGate) || fg.kind !== "fortigate") return;
    if (rec.eventtime === undefined) rec.eventtime = ++this.ev;
    const line = fmtLog(rec);
    if (this.fazTarget(fg)) { const q = this.queue.get(fg.id) || []; q.push({ line, ev: rec.eventtime, sent: 0 }); if (q.length > 3000) q.shift(); this.queue.set(fg.id, q); }
    if (this.sysTarget(fg)) { const q = this.sys.get(fg.id) || []; q.push(`<189>${line}`); this.sys.set(fg.id, q); }
  }

  // ---------- the loop (called from the lab's live tick) ----------
  async tick(c, generation) {
    this.c = c;
    const call = this.call;
    // a rebuilt lab network has new namespaces: streams opened in the old ones would stay silent
    if (generation !== undefined && generation !== this.gen) {
      if (this.gen !== undefined) { for (const st of this.streams.values()) call({ op: "shell.close", shell: st.id }).catch(() => {}); this.streams.clear(); this.collect.clear(); }
      this.gen = generation;
    }
    // and after a FortiGate's nftables reload, its session event stream is reopened
    for (const ns of (this.reloaded || []).splice(0)) { const st = this.streams.get(`ct:${ns}`); if (st) { call({ op: "shell.close", shell: st.id }).catch(() => {}); this.streams.delete(`ct:${ns}`); } }
    if (!this.started) {
      this.started = true;
      // kernel log lines from every namespace (deny logs)
      await call({ op: "ns.exec", ns: "", argv: ["sh", "-c", "echo 1 > /proc/sys/net/netfilter/nf_log_all_netns"] }).catch(() => {});
    }
    const fgs = this.fgts();
    // producers: one conntrack event stream per FortiGate, one kernel log reader
    for (const fg of fgs) await this.ensure(`ct:${fg.id}`, fg.id, `exec conntrack -E -e DESTROY -o id 2>/dev/null`, (l) => this.fromConntrack(fg, l));
    // Linux reaps expired sessions lazily (up to a minute later); listing the table reaps them now,
    // so a closed session is logged within a couple of seconds, as on a FortiGate
    for (const fg of fgs) await call({ op: "ns.exec", ns: fg.id, argv: ["conntrack", "-L"] }).catch(() => {});
    if (fgs.length) await this.ensure("kmsg", fgs[0].id, `exec cat /dev/kmsg`, (l) => this.fromKmsg(l));
    // senders
    for (const fg of fgs) {
      const faz = this.fazTarget(fg);
      const q = this.queue.get(fg.id) || [];
      if (faz && q.some((x) => !x.sent || Date.now() - x.sent > 8000)) {
        const out = q.filter((x) => !x.sent || Date.now() - x.sent > 8000).slice(0, 200);
        const r = await call({ op: "send", ns: fg.id, proto: "tcp", dst: faz.ip, port: 514, src: faz.src, lines: out.map((x) => x.line) }).catch(() => null);
        if (r) for (const x of out.slice(0, r.sent || 0)) x.sent = Date.now();
        this.fazErr = this.fazErr || {}; this.fazErr[fg.id] = r && r.error;
      }
      const sys = this.sysTarget(fg);
      const sq = this.sys.get(fg.id) || [];
      if (sys) {
        // a FortiGate sending syslog also sends its own periodic event logs
        if (!this.hb || Date.now() - (this.hb[fg.id] || 0) > 60000) {
          this.hb = this.hb || {}; this.hb[fg.id] = Date.now();
          sq.push(`<189>${fmtLog({ ...stamp(this.lab), eventtime: ++this.ev, logid: "0100040704", type: "event", subtype: "system", level: "notice", devname: fg.hostname(), devid: fg.serial, vd: "root", logdesc: "System performance statistics", action: "perf-stats" })}`);
          this.sys.set(fg.id, sq);
        }
        if (sq.length) await call({ op: "send", ns: fg.id, proto: "udp", dst: sys.ip, port: sys.port, lines: sq.splice(0, 200) }).catch(() => {});
      }
    }
    await this.receive(fgs);
    if (Date.now() - this.lastReach > 4000) { this.lastReach = Date.now(); await this.refreshReach(fgs); }
  }

  // keep one long-running command in a namespace; onLine gets each output line
  async ensure(key, ns, cmd, onLine) {
    let st = this.streams.get(key);
    if (st && !st.alive) { this.streams.delete(key); this.call({ op: "shell.close", shell: st.id }).catch(() => {}); st = null; }
    if (st && st.retryAt && Date.now() < st.retryAt) return null;
    if (!st) {
      const r = await this.call({ op: "shell.open", ns }).catch(() => null);
      if (!r) return null;
      st = { id: r.shell, next: 0, partial: "", alive: true, onLine };
      this.streams.set(key, st);
      await this.call({ op: "shell.write", shell: st.id, data: cmd + "\n" }).catch(() => {});
    }
    const r = await this.call({ op: "shell.read", shell: st.id, since: st.next }).catch(() => null);
    if (r) {
      st.next = r.next;
      const lines = (st.partial + (r.data || "")).split("\n");
      st.partial = lines.pop();
      if (st.onLine) for (const l of lines) st.onLine(l);
      if (!r.alive) { st.alive = false; return null; }
    }
    return st;
  }

  // ---------- receivers: what reached FortiAnalyzer and FortiSIEM ----------
  owner(ip) {
    for (const fg of this.fgts()) if (this.lab.fgtIntfs(fg).some((i) => i.prefix && intToIp(i.prefix.ip) === ip)) return fg;
    for (const fg of this.fgts()) { const t = this.fazTarget(fg); if (t && t.src === ip) return fg; }
    return null;
  }
  async receive() {
    for (const d of this.lab.devices.values()) {
      if (d.kind !== "fortianalyzer" && d.kind !== "fortisiem") continue;
      const since = this.collect.get(d.id) || 0;
      const r = await this.call({ op: "listen.log", ns: d.id, since_seq: since }).catch(() => null);
      if (!r) continue;
      this.collect.set(d.id, r.seq || since);
      for (const h of r.hits || []) {
        const fg = this.owner(h.src);
        if (d.kind === "fortianalyzer" && h.proto === "tcp" && h.port === 514) {
          if (!fg) continue;
          let m = d.managed.get(fg.id);
          if (!m) { m = { authorized: false, adom: "root", logs: [], db: null, synced: null, revisions: [] }; d.managed.set(fg.id, m); }
          m.lastSeen = Date.now();
          if (!h.data) continue;
          const rec = parseKv(h.data);
          const k = `${fg.id}:${rec.eventtime}`;
          const q = this.queue.get(fg.id);
          if (q) { const i = q.findIndex((x) => x.ev === rec.eventtime); if (i >= 0) q.splice(i, 1); } // delivered
          if (!m.authorized || this.seenFaz.has(k)) continue; // an unauthorized device's logs are dropped
          this.seenFaz.add(k);
          m.logs.push(rec);
          if (m.logs.length > 3000) m.logs.shift();
        }
        if (d.kind === "fortisiem" && h.proto === "udp" && h.data) {
          const rec = parseKv(h.data);
          const k = `${h.src}:${rec.eventtime}`;
          if (this.seenSiem.has(k)) continue;
          this.seenSiem.add(k);
          d.siem = d.siem || { events: [], inc: new Map(), rules: null };
          d.siem.events.push(this.lab.siemFromFgt(fg || { hostname: () => rec.devname || h.src }, rec, h.src));
        }
      }
    }
  }

  // ---------- connectivity the consoles report (registration, agents, collectors) ----------
  async refreshReach(fgs) {
    const want = [];
    const ipOf = (d) => (d.ip ? intToIp(d.ip() || 0) : ((this.lab.fgtIntfs(d).find((i) => i.prefix) || {}).prefix ? intToIp(this.lab.fgtIntfs(d).find((i) => i.prefix).prefix.ip) : null));
    for (const fg of fgs) {
      const faz = this.fazTarget(fg); if (faz) want.push([fg.id, faz.ip, 514]);
      const cm = fg.obj("system central-management");
      const fmg = cm && String(fg.one("system central-management", cm, "fmg") || "").replace(/"/g, "");
      if (fmg && ipToInt(fmg)) want.push([fg.id, fmg, 541]);
    }
    for (const h of this.lab.devices.values()) {
      if (!h.spec) continue;
      if (h.spec.siem_agent) { const s = this.lab.dev(h.spec.siem_agent); if (s && ipOf(s)) want.push([h.id, ipOf(s), 443]); }
      if (h.spec.edr) { const e = this.lab.dev(h.spec.edr.manager); if (e && ipOf(e)) want.push([h.id, ipOf(e), 8081]); }
    }
    for (const [from, ip, port] of want) {
      const r = await this.call({ op: "probe", ns: from, dst: ip, proto: "tcp", port, timeout_ms: 1200 }).catch(() => null);
      this.reach.set(`${from}>${ip}:${port}`, { ok: !!(r && r.pass), t: Date.now() });
    }
    this.lab.realReach = this.reach;
  }

  stop() {
    for (const st of this.streams.values()) this.call({ op: "shell.close", shell: st.id }).catch(() => {});
    this.streams.clear();
    this.lab.realReach = null;
  }
}
