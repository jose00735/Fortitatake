// A running lab: the simulated network, one console per device, the current part, hints, timing and score.
import { Lab } from "./sim.js";
import "./diag.js";
import "./vpn.js";
import "./sdwan.js";
import "./ha.js";
import "./utm.js";
import "./mgmt.js";
import "./auth.js";
import { hostRun, routerRun } from "./diag.js";
import { runChecks } from "./grader.js";
import { FortiGate } from "./fgt.js";
import { ipToInt } from "./net.js";

export class LabRun {
  constructor(def, schemas, saved) {
    this.def = def;
    this.schemas = schemas;
    this.parts = def.parts;
    this.lab = new Lab(def.topology, schemas);
    this.part = 0;
    this.passed = new Set();       // part ids completed
    this.hints = {};               // part id -> hints shown
    this.revealed = {};            // part id -> solution revealed
    this.answers = {};             // check id -> typed answer
    this.results = {};             // part id -> last check results
    this.log = [];                 // [{dev, line}] replayable
    this.started = Date.now();
    this.elapsed = 0;
    this.checksRun = 0;
    this.verified = 0;             // diagnostics run before pressing Check
    this.applyEvents(this.parts[0]);
    if (saved) this.restore(saved);
  }
  // part events change the world when a part starts: a link fails, an ISP degrades, a unit dies
  applyEvents(part) {
    let changed = false;
    for (const ev of (part && part.events) || []) {
      if (ev.segment) { const s = this.lab.segments.find((x) => x.id === ev.segment); if (s) { s.down = !!ev.down; changed = true; } }
      if (ev.link) {
        const [dev, port] = ev.link.split(":");
        for (const sg of this.lab.segments) for (const m of sg.members) if (m.dev === dev && (m.port === port || (!m.port && !port))) { m.down = !!ev.down; changed = true; }
      }
      if (ev.router) { const r = this.lab.dev(ev.router); if (r) { if (ev.quality) r.quality = ev.quality; if (ev.mtu) r.mtu = ev.mtu; changed = true; } }
      if (ev.cli) { const d = this.lab.dev(ev.cli.dev); if (d && d.load) { d.load(ev.cli.lines); changed = true; } }
      if (ev.traffic) {
        if (changed) { this.lab.dirty(); changed = false; }
        for (const t of ev.traffic) for (let i = 0; i < (t.count || 1); i++) this.lab.probe(t.from, { dst: ipToInt(t.to), proto: { icmp: 1, tcp: 6, udp: 17 }[t.proto || "tcp"], dport: t.port || 0 });
        for (const d of this.lab.devices.values()) if (d.async) d.async.length = 0;
      }
      if (ev.directory) {
        const d = this.lab.dev(ev.directory.dev), D = d && d.spec.directory;
        if (D) {
          for (const k of ["ldap", "radius", "fsso"]) if (ev.directory[k]) D[k] = { ...(D[k] || {}), ...ev.directory[k] };
          if (ev.directory.users) for (const u of ev.directory.users) { const x = (D.users || []).find((y) => y.sam === u.sam); if (x) Object.assign(x, u); else (D.users = D.users || []).push(u); }
          D._norm = null; changed = true;
        }
      }
      if (ev.dns) { for (const [n, ip] of Object.entries(ev.dns)) this.lab.names.set(n.toLowerCase(), ipToInt(ip)); changed = true; }
    }
    if (changed) this.lab.dirty();
  }
  goto(i) { while (this.part < i) { this.part++; this.applyEvents(this.parts[this.part]); } }
  // start at part i as if the earlier parts were done with their reference solutions (sortie and review runs)
  jumpTo(i) {
    while (this.part < i) { this.applySolution(this.current); this.passed.add(this.current.id); this.goto(this.part + 1); }
    this.lab.dirty();
  }
  get current() { return this.parts[this.part]; }
  device(id) { return this.lab.dev(id); }
  consoleDevices() { return this.lab.order.map((id) => this.lab.dev(id)).filter((d) => d.kind !== "cloud"); }

  // run a line on a device console; returns the text to print (async debug output appended)
  exec(devId, line, record = true) {
    const d = this.lab.dev(devId);
    let out;
    if (d instanceof FortiGate) {
      const m = this.lab.mgmtExec(d, line);
      out = m !== null && m !== undefined ? m : d.run(line);
      if (/^\s*(diag|exec|get)/i.test(line)) this.verified++;
    } else if (d.kind === "router") out = routerRun(this.lab, d, line);
    else { out = hostRun(this.lab, d, line); if (/^(ping|curl|tracert|traceroute|nslookup|tnc|nc)/i.test(line.trim())) this.verified++; }
    if (record) this.log.push({ dev: devId, line });
    return out;
  }
  prompt(devId) {
    const d = this.lab.dev(devId);
    if (d instanceof FortiGate) return this.lab.mgmtPrompt(d) || d.prompt();
    if (d.kind === "router") return `${d.id}> `;
    return d.os === "windows" ? `C:\\Users\\${d.hostname.toLowerCase()}> ` : `${d.hostname.toLowerCase()}@lab:~$ `;
  }
  // async output (debug flow, sniffer) collected per FortiGate since last call
  drain() {
    const out = {};
    for (const d of this.lab.devices.values()) if (d instanceof FortiGate && d.async.length) out[d.id] = d.async.splice(0);
    return out;
  }
  stopCapture(devId) {
    const d = this.lab.dev(devId);
    if (d instanceof FortiGate && d.dbg.sniffer) { const s = d.dbg.sniffer; d.dbg.sniffer = null; return `\n${s.total - s.left} packets received by filter\n0 packets dropped by kernel`; }
    return "";
  }

  check() {
    const p = this.current;
    this.checksRun++;
    const res = runChecks(this.lab, p.checks || [], this.answers);
    this.results[p.id] = res;
    if (res.length && res.every((r) => r.pass)) this.passed.add(p.id);
    return res;
  }
  advance() { if (this.passed.has(this.current.id) && this.part < this.parts.length - 1) { this.goto(this.part + 1); return true; } return false; }
  finished() { return this.parts.every((p) => this.passed.has(p.id)); }
  hint(partId) { const n = (this.hints[partId] || 0) + 1; this.hints[partId] = Math.min(n, (this.current.hints || []).length); return this.hints[partId]; }

  // apply a part's reference solution (used by tests and "show me" after reveal)
  applySolution(part) {
    for (const [dev, script] of Object.entries(part.solution || {})) {
      for (const line of String(script).split("\n")) if (line.trim()) this.exec(dev, line.trim());
    }
  }

  score() {
    let pts = 0;
    const par = (this.def.par || 30) * 60000;
    for (const p of this.parts) {
      if (!this.passed.has(p.id)) continue;
      let s = 100;
      s -= 10 * (this.hints[p.id] || 0);
      if (this.revealed[p.id]) s = Math.min(s, 20);
      pts += Math.max(10, s);
    }
    const avg = pts / this.parts.length;
    const overPar = Math.max(0, this.elapsed - par);
    const timePenalty = Math.min(20, Math.floor(overPar / 60000));
    return Math.max(0, Math.round(avg - timePenalty + (this.verified >= 3 ? 5 : 0)));
  }

  save() {
    return { v: 1, id: this.def.id, part: this.part, passed: [...this.passed], hints: this.hints, revealed: this.revealed, answers: this.answers, log: this.log, elapsed: this.elapsed };
  }
  restore(s) {
    if (!s || s.id !== this.def.id) return;
    for (const { dev, line } of s.log || []) { try { this.exec(dev, line, true); } catch (e) { /* skip */ } }
    for (const d of this.lab.devices.values()) if (d instanceof FortiGate) d.async.length = 0;
    this.goto(Math.min(s.part || 0, this.parts.length - 1));
    this.passed = new Set(s.passed || []);
    this.hints = s.hints || {};
    this.revealed = s.revealed || {};
    this.answers = s.answers || {};
    this.elapsed = s.elapsed || 0;
  }
}
