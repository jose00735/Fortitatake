// Attack sequences (content/sequences): timed chains of attacker steps run against the lab, each
// of which a control can stop. The simulator runs them on the lab model with nominal telemetry
// (also what grading uses); the live runner in view.js runs the same steps on the real network.
// A run stops at the first step a control stopped and names the control.
import { Lab } from "./sim.js";
import { ipToInt, intToIp } from "./net.js";
import { ATTACKER_IP, attackSource } from "./ips.js";
import { SINKHOLE_WEB } from "./intel.js";

// "c2:2", "url:0", "phish:1", a lab name, a device id or an IP -> {ip, host}
export function seqTarget(lab, to) {
  const m = /^(c2|url|phish):(\d+)$/.exec(String(to));
  if (m && lab.intel) {
    const list = { c2: lab.intel.c2, url: lab.intel.urls, phish: lab.intel.phish }[m[1]];
    const x = list[Number(m[2]) % Math.max(1, list.length)];
    if (!x) return null;
    return m[1] === "c2" ? { ip: x.ip, host: x.ip, label: `${x.ip} (${x.family || "C2"}, ${x.source})` } : { ip: SINKHOLE_WEB, host: x.host, label: `${x.host} (${m[1] === "url" ? "malware URL" : "phishing"}, ${x.source})` };
  }
  if (/^\d+\.\d+\.\d+\.\d+$/.test(to)) return { ip: to, host: to, label: to };
  const n = lab.names.get(String(to).toLowerCase());
  if (n !== undefined) return { ip: intToIp(n), host: to, label: to };
  const d = lab.dev(to);
  if (d && d.kind === "fortigate") { const i = lab.fgtIntfs(d).find((x) => x.prefix && /wan|port1/.test(x.name)) || lab.fgtIntfs(d)[0]; return i ? { ip: intToIp(i.prefix.ip), host: d.id, label: `${d.id} (${intToIp(i.prefix.ip)})` } : null; }
  if (d && d.ip && d.ip()) return { ip: intToIp(d.ip()), host: d.hostname || d.id, label: `${d.id} (${intToIp(d.ip())})` };
  return null;
}

// fill {{c2:N}} / {{url:N}} in a command line with the lab's picks
export function seqText(lab, s) {
  return String(s || "").replace(/\{\{(c2|url|phish):(\d+)\}\}/g, (_, k, n) => { const t = seqTarget(lab, `${k}:${n}`); return t ? t.host : "?"; });
}

export const seqById = (lab, id) => (lab.sequences || []).find((s) => s.id === id);

const mgrOf = (lab, h) => h && h.spec && h.spec.edr && lab.dev(h.spec.edr.manager);

// what FortiEDR did about a host since an event id: stopped (Prevention), detected, or nothing
export function edrVerdict(lab, hostId, sinceId) {
  const h = lab.dev(hostId), mgr = mgrOf(lab, h);
  if (!mgr) return null;
  const evs = lab.edrEvents(mgr).filter((e) => e.host === hostId && e.id > sinceId);
  if (!evs.length) return null;
  const stop = evs.find((e) => e.action === "Blocked");
  if (stop) return { stopped: true, by: `FortiEDR ${stop.policy} (${stop.rule}, event ${stop.id})` };
  return { stopped: false, detected: evs.map((e) => `FortiEDR ${e.rule} (Simulation, event ${e.id})`) };
}

const isolated = (lab, hostId) => { const h = lab.dev(hostId), mgr = mgrOf(lab, h); return !!(mgr && mgr.edr && mgr.edr.isolated.has(hostId)); };

// a step's telemetry for the simulator (live: the collector sends the real thing)
function feed(lab, hostId, evs) {
  const h = lab.dev(hostId), mgr = mgrOf(lab, h);
  if (!mgr) return false;
  lab.quiet = (lab.quiet || 0) + 1;
  let ok;
  try { ok = lab.probe(hostId, { dst: mgr.ip(), proto: 6, dport: 555 }).ok; } finally { lab.quiet--; }
  if (!ok) return false; // the collector can't deliver
  for (const e of evs) lab.edrIngest(mgr, { host: hostId, ...e });
  lab.edrActions = [];
  return true;
}

// FortiGate event logs for failed logins (FortiSIEM's "VPN - Failed Logins" rule reads them)
function loginLogs(lab, src, dstDev, user, n) {
  const fg = lab.dev(dstDev);
  if (!fg || fg.kind !== "fortigate" || lab.quiet) return;
  for (let i = 0; i < n; i++) lab.storeLog(fg, { ...lab.ipsStamp(), devname: fg.hostname(), devid: fg.serial, vd: "root", logid: "0101039426", type: "event", subtype: "vpn", level: "alert", action: i === n - 1 ? "ssl-login-success" : "ssl-login-fail", remip: src, user: i === n - 1 ? user : `${user}${i % 3 ? "" : i}`, reason: i === n - 1 ? "" : "sslvpn_login_permission_denied", msg: i === n - 1 ? "SSL user login success" : "SSL user failed to logged in", seq: Date.now() + i });
}

Lab.prototype.seqLoginLogs = function (src, dst, user, n) { loginLogs(this, src, dst, user, n); };

// one step on the simulator: {status: done|stopped|failed, by, detail, detected}
Lab.prototype.seqStepSim = function (st, base) {
  const [kind, a] = Object.entries(st.do)[0];
  const on = a.from || a.host;
  if (on && on !== "@attacker" && isolated(this, on)) return { status: "stopped", by: `FortiEDR isolation of ${on}` };
  const since = this._edrId || 1000;
  const pid0 = 6000 + Math.floor(Math.random() * 20000); // fresh process ids per step
  const t = (dt) => base + dt;
  const proc = (p) => ({ kind: "proc", pid: p.pid || pid0, ppid: 4999, name: p.name, cmd: seqText(this, p.cmd), parent: p.parent, path: p.path, user: p.user || "ANDES\\jgomez" });
  if (kind === "attack") {
    const r = this.attackSim(a.from || "@attacker", a.to, a.pack, a.port);
    if (r.error) return { status: "failed", detail: r.error };
    const stop = r.results.find((x) => ["blocked", "reset"].includes(x.outcome));
    if (stop) return { status: "stopped", by: `FortiGate IPS (${stop.detail})` };
    const reached = r.results.find((x) => x.outcome === "reached");
    if (!reached) return { status: "stopped", by: `FortiGate (${r.results[0].detail})` };
    return { status: "done", detail: `${r.results.length} requests reached ${reached.detail.split(" ")[0]}`, detected: r.results.filter((x) => x.sig).map((x) => `FortiGate IPS logged signature ${x.sig}`) };
  }
  if (kind === "connect" || kind === "logins") {
    const tg = seqTarget(this, a.to);
    if (!tg) return { status: "failed", detail: `no target ${a.to}` };
    const src = a.from === "@attacker" ? attackSource(this, "@attacker") : { id: a.from, ip: intToIp(this.dev(a.from).ip()) };
    const res = this.probe(src.id, { dst: ipToInt(tg.ip), proto: 6, dport: a.port, src: ipToInt(src.ip) });
    if (!res.ok) return { status: "stopped", by: `the network (${res.drop ? res.drop.reason : "no answer"})`, detail: tg.label };
    if (kind === "logins") { loginLogs(this, src.ip, a.to, a.user || "admin", a.attempts || 20); return { status: "done", detail: `${a.attempts || 20} attempts on ${tg.label}:${a.port}, the last one succeeded` }; }
    const n = a.times || 1, every = (a.every || 0) * 1000;
    const evs = [];
    for (let i = 0; i < n; i++) evs.push({ kind: "net", t: t(i * every), pid: pid0 + 1 + i, process: a.process || "unknown", cmd: a.process, src: src.ip, sport: 40000 + i, dst: tg.ip, dport: a.port });
    feed(this, a.from, evs);
    const v = edrVerdict(this, a.from, since);
    if (v && v.stopped) return { status: "stopped", by: v.by, detail: tg.label };
    return { status: "done", detail: `${n} connection${n > 1 ? "s" : ""} to ${tg.label}:${a.port}`, detected: v && v.detected };
  }
  if (kind === "proc") {
    feed(this, a.host, [{ ...proc(a), t: t(0) }]);
    const v = edrVerdict(this, a.host, since);
    if (v && v.stopped) return { status: "stopped", by: v.by };
    return { status: "done", detail: `${a.name} on ${a.host}`, detected: v && v.detected };
  }
  if (kind === "cpu") {
    const evs = [{ kind: "proc", t: t(0), pid: 7777, ppid: 1, name: "kswapd0", cmd: "/tmp/.x/kswapd0 -o pool:3333", parent: "cron", user: "www-data" }];
    for (let s = 0; s <= 96; s += 2) evs.push({ kind: "perf", t: t(s * 1000), cpu: 50, mem_mb: 40, top: { pid: 7777, name: "kswapd0" } });
    feed(this, a.host, evs);
    const v = edrVerdict(this, a.host, since);
    if (v && v.stopped) return { status: "stopped", by: v.by };
    return { status: "done", detail: `CPU at the host's cap for 96 s`, detected: v && v.detected };
  }
  if (kind === "files") {
    const evs = [];
    for (let i = 0; i < Math.ceil((a.count || 300) / 50); i++) evs.push({ kind: "file", t: t(i * 2000), count: 50, op: "renamed", ext: a.ext, process: a.process, target: `C:\\Users\\Public\\Shares\\Finanzas\\*${a.ext || ""}` });
    feed(this, a.host, evs);
    const v = edrVerdict(this, a.host, since);
    if (v && v.stopped) return { status: "stopped", by: v.by };
    return { status: "done", detail: `${a.count} files renamed to *${a.ext}`, detected: v && v.detected };
  }
  return { status: "failed", detail: `unknown step kind ${kind}` };
};

// a whole sequence on the simulator
Lab.prototype.sequenceSim = function (id, fromStep) {
  const seq = seqById(this, id);
  if (!seq) return { error: `no sequence ${id}` };
  this.clock += 15 * 60000; // a new run is a new time window (FortiEDR de-duplicates within minutes)
  let base = this.clock;
  const steps = [];
  let stoppedAt = null;
  const start = fromStep ? Math.max(0, seq.steps.findIndex((s) => s.id === fromStep)) : 0;
  for (const st of seq.steps.slice(start)) {
    const r = this.seqStepSim(st, base);
    base += 120000;
    steps.push({ id: st.id, title: st.title, tactic: st.tactic, attack: st.attack, ...r });
    if (r.status !== "done") { stoppedAt = st.id; break; }
  }
  this.ver++;
  const out = { id, name: seq.name, steps, stoppedAt, complete: !stoppedAt };
  if (!this.quiet) this._lastSeq = out;
  return out;
};

// grading: run on the simulator without leaving events, logs or telemetry behind
Lab.prototype.sequenceDry = function (id, fromStep) {
  const saved = { clock: this.clock, edrId: this._edrId, devs: [] };
  for (const d of this.devices.values()) saved.devs.push([d, d.edrlog ? d.edrlog.length : null, d.logs ? d.logs.length : null, d.siem ? d.siem.events.length : null, d.tel || null]);
  for (const d of this.devices.values()) if (d.tel) d.tel = structuredClone(d.tel);
  this.quiet = (this.quiet || 0) + 1;
  try { return this.sequenceSim(id, fromStep); } finally {
    this.quiet--;
    this.clock = saved.clock; this._edrId = saved.edrId;
    for (const [d, e, l, s, tel] of saved.devs) {
      if (e !== null) d.edrlog.length = e; else if (d.edrlog) delete d.edrlog;
      if (l !== null && d.logs) d.logs.length = l;
      if (s !== null && d.siem) d.siem.events.length = s;
      if (tel) d.tel = tel; else if (d.tel) delete d.tel;
    }
  }
};

export function seqReport(r) {
  if (r.error) return r.error;
  const icon = { done: "\u2713", stopped: "\u26d4", failed: "!" };
  const lines = r.steps.map((s, i) => `${String(i + 1).padStart(2)}. ${icon[s.status]} ${s.title}  [${s.tactic} \u00b7 ${s.attack}]${s.status === "stopped" ? `\n      stopped by ${s.by}` : ""}${s.detail ? `\n      ${s.detail}` : ""}${s.detected && s.detected.length ? `\n      seen by: ${s.detected.join("; ")}` : ""}`);
  return `${r.id} ${r.name}\n${lines.join("\n")}\n${r.complete ? "\u26a0 The attack got all the way through." : `Stopped at step ${r.steps.length} (${r.stoppedAt}).`}`;
}
