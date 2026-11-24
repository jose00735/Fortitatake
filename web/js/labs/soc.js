// SecOps for the lab simulator: a scripted log generator ("story"), FortiGate syslog to FortiSIEM, a FortiSIEM
// console (CMDB, analytics, rules, incidents), a FortiEDR console (collectors, policies, events, forensics,
// exceptions, isolation) and FortiAnalyzer event handlers, alerts and incidents.
//
// Story items (topology `story:` or a part's `events: [{story: [...]}]`):
//   { at: "08:41:12", fgt: FGT-BOG, log: { type: utm, subtype: ips, attack: "...", severity: critical, srcip, dstip, action } }
//   { at: "08:42:00", host: DC-01, win: { id: 4625, user: jperez, src: 10.20.10.66, ws: KALI } }
//   { at: "08:44:10", host: FIN-PC, edr: { process: invoice.exe, path, parent, cmd, hash, rule, policy, classification, dst } }
import { Lab, PROTO } from "./sim.js";
import { FortiGate } from "./fgt.js";
import { ipToInt, intToIp } from "./net.js";
import { fmtLog } from "./utm.js";

const day = (lab) => new Date(lab.clock - 5 * 3600000).toISOString().slice(0, 10);
const pad = (s, n) => (String(s).length >= n ? String(s) + " " : String(s) + " ".repeat(n - String(s).length));
const WIN = { 4624: "An account was successfully logged on", 4625: "An account failed to log on", 4688: "A new process has been created", 4720: "A user account was created", 4728: "A member was added to a security-enabled global group", 4740: "A user account was locked out", 7045: "A service was installed in the system", 1102: "The audit log was cleared" };
let seq = 50000;

// ---------- the story ----------
Lab.prototype.playStory = function (items) {
  for (const it of items || []) {
    const time = it.at || "09:00:00";
    if (it.fgt) {
      const fg = this.dev(it.fgt);
      if (!fg) continue;
      const l = it.log || {};
      const rec = { date: day(this), time, logid: l.logid || (l.subtype === "ips" ? "0419016384" : l.type === "event" ? "0101037128" : "0000000013"), type: l.type || "traffic", subtype: l.subtype || "forward", level: l.level || (l.severity === "critical" ? "alert" : "notice"), devname: fg.hostname(), devid: fg.serial, vd: "root", ...l, seq: ++seq };
      this.storeLog(fg, rec);
    }
    if (it.host) {
      const h = this.dev(it.host);
      if (!h) continue;
      if (it.win) { h.winlog = h.winlog || []; h.winlog.push({ time, date: day(this), computer: h.hostname, seq: ++seq, ...it.win }); }
      if (it.edr) {
        // the policy mode at the time of the event decides whether it was blocked
        const mgr = h.spec.edr && this.dev(h.spec.edr.manager);
        const mode = mgr && it.edr.policy ? edrState(this, mgr).modes[it.edr.policy] : undefined;
        this._edrId = (this._edrId || 1000) + 1;
        h.edrlog = h.edrlog || []; h.edrlog.push({ time, date: day(this), seq: ++seq, mode, id: this._edrId, ...it.edr });
      }
    }
  }
  this.ver++;
};

// ---------- FortiGate syslog → FortiSIEM ----------
const baseStore = Lab.prototype.storeLog;
Lab.prototype.storeLog = function (fg, rec) {
  baseStore.call(this, fg, rec);
  if (!(fg instanceof FortiGate) || fg.product !== "fortios") return;
  const set = fg.cfg.get("log syslogd setting");
  if (!set || fg.one("log syslogd setting", set, "status") !== "enable") return;
  const server = ipToInt(fg.one("log syslogd setting", set, "server") || "");
  const port = Number(fg.one("log syslogd setting", set, "port") || 514);
  const siem = [...this.devices.values()].find((d) => d.kind === "fortisiem" && d.ip && d.ip() === server);
  if (!siem) return;
  const k = `sys>${fg.id}>${server}:${port}`;
  if (!this._sysr || this._sysrVer !== this.ver) { this._sysr = new Map(); this._sysrVer = this.ver; }
  if (!this._sysr.has(k)) { this.quiet = (this.quiet || 0) + 1; try { this._sysr.set(k, this.probe(fg.id, { dst: server, proto: 17, dport: port }).ok); } finally { this.quiet--; } }
  if (!this._sysr.get(k)) return;
  siem.siem = siem.siem || { events: [], inc: new Map(), rules: null };
  siem.siem.events.push(siemFromFgt(fg, rec));
};
function siemFromFgt(fg, r) {
  const et = r.type === "utm" ? `FortiGate-${r.subtype}-${r.subtype === "ips" ? r.severity || "info" : r.action || "log"}` : r.type === "event" ? `FortiGate-event-${r.subtype || "system"}` : `FortiGate-traffic-${r.action || "accept"}`;
  return { eventType: et, time: r.time, date: r.date, reptDevName: fg.hostname(), reptDevIp: "", srcIpAddr: r.srcip, destIpAddr: r.dstip, destIpPort: r.dstport, ipsSignature: r.attack, severity: r.severity, user: r.user, action: r.action, raw: fmtLog(r), seq: r.seq };
}

// Windows hosts with a FortiSIEM agent ship their security log when they can reach the collector (TCP 443)
function winEvents(lab, siem) {
  const out = [];
  for (const h of lab.devices.values()) {
    if (!h.spec || h.spec.siem_agent !== siem.id || !h.winlog) continue;
    lab.quiet = (lab.quiet || 0) + 1;
    let ok;
    try { ok = lab.probe(h.id, { dst: siem.ip(), proto: 6, dport: 443 }).ok; } finally { lab.quiet--; }
    if (!ok) continue;
    for (const w of h.winlog) out.push({ eventType: `Win-Security-${w.id}`, time: w.time, date: w.date, reptDevName: h.hostname, reptDevIp: intToIp(h.ip() || 0), srcIpAddr: w.src, user: w.user, hostName: w.ws, logonType: w.logon_type, procName: w.process, svcName: w.service, msg: WIN[w.id] || "", raw: `<13>${w.date}T${w.time} ${h.hostname} Microsoft-Windows-Security-Auditing EventID=${w.id} ${WIN[w.id] || ""} TargetUserName=${w.user || "-"} IpAddress=${w.src || "-"} WorkstationName=${w.ws || "-"}${w.process ? " NewProcessName=" + w.process : ""}${w.service ? " ServiceName=" + w.service : ""}`, seq: w.seq });
  }
  return out;
}
// a FortiGate with working syslog keeps sending its own event logs (performance, admin), so it shows up in the CMDB
function heartbeats(lab, siem) {
  const out = [];
  for (const fg of lab.devices.values()) {
    if (!(fg instanceof FortiGate) || fg.product !== "fortios" || fg.parent) continue;
    const set = fg.cfg.get("log syslogd setting");
    if (!set || fg.one("log syslogd setting", set, "status") !== "enable") continue;
    if (ipToInt(fg.one("log syslogd setting", set, "server") || "") !== siem.ip()) continue;
    lab.quiet = (lab.quiet || 0) + 1;
    let ok;
    try { ok = lab.probe(fg.id, { dst: siem.ip(), proto: 17, dport: Number(fg.one("log syslogd setting", set, "port") || 514) }).ok; } finally { lab.quiet--; }
    if (ok) out.push({ eventType: "FortiGate-event-system-perf", time: "08:00:00", date: day(lab), reptDevName: fg.hostname(), raw: `date=${day(lab)} time=08:00:00 devname="${fg.hostname()}" type="event" subtype="system" logdesc="System performance statistics"`, seq: 1 });
  }
  return out;
}
Lab.prototype.siemEvents = function (siem) {
  siem.siem = siem.siem || { events: [], inc: new Map(), rules: null };
  return [...heartbeats(this, siem), ...siem.siem.events, ...winEvents(this, siem)].sort((a, b) => (a.date + a.time).localeCompare(b.date + b.time) || a.seq - b.seq);
};

// ---------- FortiSIEM rules ----------
const tsec = (e) => { const [h, m, s] = String(e.time).split(":").map(Number); return h * 3600 + m * 60 + (s || 0); };
function defaultRules(spec) {
  const R = [
    { name: "Excessive Windows Logon Failures", sev: 7, on: true, threshold: 5, window: 600, desc: "≥N failed logons (4625) from one source to one host in 10 minutes" },
    { name: "Successful Logon After Multiple Failures", sev: 9, on: true, threshold: 5, window: 900, desc: "N failed logons then a success (4624) for the same user and source" },
    { name: "Windows Service Installed", sev: 5, on: false, desc: "A new service installed (7045)" },
    { name: "Windows Audit Log Cleared", sev: 9, on: true, desc: "Security log cleared (1102)" },
    { name: "FortiGate IPS Critical Attack Detected", sev: 9, on: true, desc: "FortiGate IPS event with critical severity" },
    { name: "Outbound Traffic To Malicious IP", sev: 9, on: true, desc: "Allowed traffic to an IP in the threat feed" },
    { name: "Port Scan From Single Source", sev: 7, on: true, threshold: 15, window: 300, desc: "≥N denied connections to distinct ports from one source in 5 minutes" },
  ];
  for (const o of (spec && spec.rules) || []) { const r = R.find((x) => x.name === o.name); if (r) Object.assign(r, o); }
  return R;
}
function rulesOf(siem) { siem.siem = siem.siem || { events: [], inc: new Map(), rules: null }; if (!siem.siem.rules) siem.siem.rules = defaultRules(siem.spec.fortisiem); return siem.siem.rules; }
const excepted = (r, e) => (r.exceptions || []).some((x) => Object.entries(x).every(([k, v]) => String(e[k] ?? "") === String(v)));

Lab.prototype.siemIncidents = function (siem) {
  const ev = this.siemEvents(siem);
  const feed = new Set(((siem.spec.fortisiem && siem.spec.fortisiem.threat_feed) || []).map(String));
  const out = [];
  const push = (rule, key, evs, attrs) => {
    const id = 7000 + Math.abs([...`${rule.name}|${key}`].reduce((a, c) => (a * 31 + c.charCodeAt(0)) | 0, 7)) % 2000;
    const st = siem.siem.inc.get(id) || {};
    out.push({ id, rule: rule.name, sev: rule.sev, key, first: evs[0].time, last: evs[evs.length - 1].time, count: evs.length, events: evs, attrs, status: st.status || "Active", owner: st.owner || "", note: st.note || "" });
  };
  for (const r of rulesOf(siem)) {
    if (!r.on) continue;
    const E = ev.filter((e) => !excepted(r, e));
    if (r.name === "Excessive Windows Logon Failures") {
      const g = new Map();
      for (const e of E.filter((x) => x.eventType === "Win-Security-4625")) { const k = `${e.srcIpAddr}>${e.reptDevName}`; if (!g.has(k)) g.set(k, []); g.get(k).push(e); }
      for (const [k, list] of g) for (let i = 0; i < list.length; i++) { const win = list.filter((x) => tsec(x) >= tsec(list[i]) && tsec(x) - tsec(list[i]) <= r.window); if (win.length >= r.threshold) { push(r, k, win, { srcIpAddr: list[0].srcIpAddr, destHost: list[0].reptDevName }); break; } }
    }
    if (r.name === "Successful Logon After Multiple Failures") {
      for (const s of E.filter((x) => x.eventType === "Win-Security-4624")) {
        const fails = E.filter((x) => x.eventType === "Win-Security-4625" && x.srcIpAddr === s.srcIpAddr && x.user === s.user && tsec(s) - tsec(x) >= 0 && tsec(s) - tsec(x) <= r.window);
        if (fails.length >= r.threshold) push(r, `${s.user}@${s.srcIpAddr}`, [...fails, s], { user: s.user, srcIpAddr: s.srcIpAddr, destHost: s.reptDevName });
      }
    }
    const single = (type, attrsOf) => { for (const e of E.filter(type)) push(r, `${e.reptDevName}|${e.seq}`, [e], attrsOf(e)); };
    if (r.name === "Windows Service Installed") single((e) => e.eventType === "Win-Security-7045", (e) => ({ host: e.reptDevName, service: e.svcName }));
    if (r.name === "Windows Audit Log Cleared") single((e) => e.eventType === "Win-Security-1102", (e) => ({ host: e.reptDevName, user: e.user }));
    if (r.name === "FortiGate IPS Critical Attack Detected") single((e) => e.eventType === "FortiGate-ips-critical", (e) => ({ srcIpAddr: e.srcIpAddr, destIpAddr: e.destIpAddr, ipsSignature: e.ipsSignature }));
    if (r.name === "Outbound Traffic To Malicious IP") single((e) => /^FortiGate-traffic-(accept|close|timeout)/.test(e.eventType) && feed.has(String(e.destIpAddr)), (e) => ({ srcIpAddr: e.srcIpAddr, destIpAddr: e.destIpAddr }));
    if (r.name === "Port Scan From Single Source") {
      const g = new Map();
      for (const e of E.filter((x) => x.eventType === "FortiGate-traffic-deny")) { if (!g.has(e.srcIpAddr)) g.set(e.srcIpAddr, []); g.get(e.srcIpAddr).push(e); }
      for (const [k, list] of g) if (new Set(list.map((x) => x.destIpPort)).size >= r.threshold) push(r, k, list, { srcIpAddr: k });
    }
  }
  return out.sort((a, b) => b.sev - a.sev || a.id - b.id);
};

// ---------- FortiSIEM console (GUI actions typed) ----------
Lab.prototype.siemConsole = function (siem, line) {
  const toks = (line.match(/"[^"]*"|\S+/g) || []).map((t) => t.replace(/^"|"$/g, ""));
  const c = (toks[0] || "").toLowerCase();
  if (!c) return "";
  const ev = () => this.siemEvents(siem);
  if (c === "help" || c === "?") return "FortiSIEM GUI actions:\n  cmdb                              devices discovered from the logs they send\n  analytics key=value ... [group-by=attr] [last=N]   search events (eventType, srcIpAddr, user, reptDevName…)\n  rules                             rule list (enabled, threshold)\n  rule \"<name>\" enable|disable | threshold <n> | exception key=value\n  incidents [status=Active|Cleared]   incidents from enabled rules\n  incident <id> | incident <id> assign <user> | incident <id> clear \"<reason>\"";
  if (c === "cmdb") {
    const seen = new Map();
    for (const e of ev()) seen.set(e.reptDevName, e);
    const rows = [...seen.entries()].map(([n, e]) => `${pad(n, 18)}${pad(e.eventType.startsWith("FortiGate") ? "Fortinet FortiOS" : "Microsoft Windows", 20)}${pad(e.eventType.startsWith("Win") ? e.reptDevIp : "", 16)}last event ${e.date} ${e.time}`);
    return `(GUI: CMDB > Devices)\nName              Type                IP              Status\n${rows.join("\n") || "No devices yet: nothing is sending events to this FortiSIEM."}`;
  }
  if (c === "analytics" || c === "search") {
    let last = 25, by = null;
    const f = {};
    for (const a of toks.slice(1)) { const i = a.indexOf("="); if (i < 0) continue; const k = a.slice(0, i), v = a.slice(i + 1); if (k === "last") last = Number(v) || 25; else if (k === "group-by") by = v; else f[k] = v; }
    const hits = ev().filter((e) => Object.entries(f).every(([k, v]) => { const x = String(e[k] ?? ""); return v.endsWith("*") ? x.startsWith(v.slice(0, -1)) : x === v; }));
    if (by) { const cnt = new Map(); for (const e of hits) cnt.set(e[by] ?? "(none)", (cnt.get(e[by] ?? "(none)") || 0) + 1); return `(GUI: Analytics > group by ${by}) ${hits.length} event(s)\n` + [...cnt.entries()].sort((a, b) => b[1] - a[1]).map(([k, v]) => `${pad(k, 28)}${v}`).join("\n"); }
    return `(GUI: Analytics) ${hits.length} event(s)${Object.keys(f).length ? " where " + Object.entries(f).map(([k, v]) => `${k}=${v}`).join(" ") : ""}\n` + hits.slice(-last).map((e) => `${e.date} ${e.time}  ${pad(e.eventType, 30)}${pad(e.reptDevName, 16)}${e.srcIpAddr ? "src=" + e.srcIpAddr + " " : ""}${e.destIpAddr ? "dst=" + e.destIpAddr + " " : ""}${e.user ? "user=" + e.user + " " : ""}${e.ipsSignature ? 'sig="' + e.ipsSignature + '" ' : ""}${e.svcName ? "service=" + e.svcName : ""}`).join("\n");
  }
  if (c === "rules") return `(GUI: Resources > Rules)\n` + rulesOf(siem).map((r) => `${r.on ? "[on] " : "[off]"} ${pad(r.name, 42)}sev ${r.sev}${r.threshold ? `  threshold ${r.threshold}` : ""}${(r.exceptions || []).length ? `  exceptions ${r.exceptions.length}` : ""}\n       ${r.desc}`).join("\n");
  if (c === "rule") {
    const r = rulesOf(siem).find((x) => x.name.toLowerCase() === String(toks[1] || "").toLowerCase());
    if (!r) return `No rule named "${toks[1] || ""}". Type rules.`;
    const a = (toks[2] || "").toLowerCase();
    if (a === "enable" || a === "disable") { r.on = a === "enable"; this.ver++; return `Rule "${r.name}" ${a}d.`; }
    if (a === "threshold" && Number(toks[3]) > 0) { r.threshold = Number(toks[3]); this.ver++; return `Rule "${r.name}" now triggers at ${r.threshold}.`; }
    if (a === "exception") { const x = {}; for (const kv of toks.slice(3)) { const i = kv.indexOf("="); if (i > 0) x[kv.slice(0, i)] = kv.slice(i + 1); } if (!Object.keys(x).length) return "Usage: rule \"<name>\" exception key=value"; (r.exceptions = r.exceptions || []).push(x); this.ver++; return `Exception added to "${r.name}": ${Object.entries(x).map(([k, v]) => `${k}=${v}`).join(" ")}.`; }
    return `${r.name} · ${r.on ? "enabled" : "disabled"} · severity ${r.sev}${r.threshold ? ` · threshold ${r.threshold}` : ""}\n${r.desc}`;
  }
  if (c === "incidents") {
    const want = (toks.find((t) => t.startsWith("status=")) || "").split("=")[1];
    const inc = this.siemIncidents(siem).filter((i) => !want || i.status.toLowerCase() === want.toLowerCase());
    return `(GUI: Incidents > List)\nID    Sev  Status       First     Last      Count  Rule / key\n` + (inc.map((i) => `${pad(i.id, 6)}${pad(i.sev >= 9 ? "HIGH" : i.sev >= 5 ? "MED" : "LOW", 5)}${pad(i.status, 13)}${pad(i.first, 10)}${pad(i.last, 10)}${pad(i.count, 7)}${i.rule} · ${Object.entries(i.attrs).map(([k, v]) => `${k}=${v}`).join(" ")}`).join("\n") || "No incidents.");
  }
  if (c === "incident") {
    const id = Number(toks[1]);
    const i = this.siemIncidents(siem).find((x) => x.id === id);
    if (!i) return `No incident ${toks[1] || ""}.`;
    const a = (toks[2] || "").toLowerCase();
    const st = siem.siem.inc.get(id) || {};
    if (a === "assign") { st.owner = toks[3] || "analyst"; st.status = st.status || "In Progress"; siem.siem.inc.set(id, st); return `Incident ${id} assigned to ${st.owner}.`; }
    if (a === "clear" || a === "close") { st.status = "Cleared"; st.note = toks.slice(3).join(" "); siem.siem.inc.set(id, st); return `Incident ${id} cleared${st.note ? `: ${st.note}` : ""}.`; }
    return `(GUI: Incident ${id})\nRule: ${i.rule} (severity ${i.sev})\nStatus: ${i.status}${i.owner ? ` · owner ${i.owner}` : ""}\nFirst seen ${i.first}, last seen ${i.last}, ${i.count} event(s)\n${Object.entries(i.attrs).map(([k, v]) => `${k}: ${v}`).join("\n")}\n\nTriggering events:\n` + i.events.slice(0, 20).map((e) => `  ${e.time} ${e.eventType} ${e.raw}`).join("\n");
  }
  return `Unknown action. Type help.`;
};

// ---------- FortiEDR ----------
const EDR_POLICIES = ["Execution Prevention", "Exfiltration Prevention", "Ransomware Prevention", "Device Control"];
function edrState(lab, edr) {
  if (!edr.edr) {
    const sp = edr.spec.fortiedr || {};
    edr.edr = { modes: Object.fromEntries(EDR_POLICIES.map((p) => [p, (sp.modes || {})[p] || "Simulation"])), exceptions: [], cls: new Map(), done: new Map(), isolated: new Set() };
  }
  return edr.edr;
}
Lab.prototype.edrCollectors = function (edr) {
  const out = [];
  for (const h of this.devices.values()) {
    if (!h.spec || !h.spec.edr || h.spec.edr.manager !== edr.id) continue;
    this.quiet = (this.quiet || 0) + 1;
    let ok;
    try { ok = this.probe(h.id, { dst: edr.ip(), proto: 6, dport: 8081, edrMgmt: true }).ok; } finally { this.quiet--; }
    out.push({ h, connected: ok, isolated: edrState(this, edr).isolated.has(h.id) });
  }
  return out;
};
Lab.prototype.edrEvents = function (edr) {
  const st = edrState(this, edr);
  const out = [];
  for (const c of this.edrCollectors(edr)) {
    if (!c.connected) continue;
    for (const e of c.h.edrlog || []) {
      const id = e.id;
      const exc = st.exceptions.find((x) => x.process === e.process && x.rule === e.rule && (x.host === "*" || x.host === c.h.id));
      if (exc) continue;
      const mode = e.mode || st.modes[e.policy] || "Simulation";
      out.push({ ...e, id, host: c.h.id, hostname: c.h.hostname, action: mode === "Prevention" && e.policy ? "Blocked" : "Simulated Block", classification: st.cls.get(id) || e.classification || "Suspicious", handled: st.done.get(id) || null });
    }
  }
  return out.sort((a, b) => a.time.localeCompare(b.time));
};
Lab.prototype.edrConsole = function (edr, line) {
  const toks = (line.match(/"[^"]*"|\S+/g) || []).map((t) => t.replace(/^"|"$/g, ""));
  const c = (toks[0] || "").toLowerCase();
  if (!c) return "";
  const st = edrState(this, edr);
  if (c === "help" || c === "?") return "FortiEDR Central Manager GUI actions:\n  inventory                         collectors and their state\n  policies | policy \"<name>\" prevention|simulation\n  events [host=<id>]                security events\n  event <id> | forensics <id>       details | flow analyzer (process tree)\n  classify <id> malicious|suspicious|pup|likely-safe|safe\n  exception <id> [all|host]          stop this process/rule pair from raising events\n  remediate <id> kill|delete|registry\n  isolate <host> | unisolate <host>";
  if (c === "inventory") return `(GUI: Inventory > Collectors)\nHost              IP              OS        State          Group\n` + (this.edrCollectors(edr).map((x) => `${pad(x.h.hostname, 18)}${pad(intToIp(x.h.ip() || 0), 16)}${pad(x.h.os === "windows" ? "Windows" : "Linux", 10)}${pad(x.isolated ? "Isolated" : x.connected ? "Running" : "Disconnected", 15)}Default`).join("\n") || "No collectors registered.");
  if (c === "policies") return `(GUI: Security Settings > Security Policies, group Default)\n` + EDR_POLICIES.map((p) => `${pad(p, 26)}${st.modes[p]}`).join("\n");
  if (c === "policy") {
    const p = EDR_POLICIES.find((x) => x.toLowerCase() === String(toks[1] || "").toLowerCase());
    const m = (toks[2] || "").toLowerCase();
    if (!p || !["prevention", "simulation"].includes(m)) return `Usage: policy "<name>" prevention|simulation   (policies: ${EDR_POLICIES.join(", ")})`;
    st.modes[p] = m === "prevention" ? "Prevention" : "Simulation"; this.ver++;
    return `${p} is now in ${st.modes[p]} mode.`;
  }
  const evs = this.edrEvents(edr);
  if (c === "events") {
    const h = (toks.find((t) => t.startsWith("host=")) || "").split("=")[1];
    const list = evs.filter((e) => !h || e.host === h || e.hostname === h);
    return `(GUI: Event Viewer)\nID    Time      Host              Process              Classification  Action          Rule\n` + (list.map((e) => `${pad(e.id, 6)}${pad(e.time, 10)}${pad(e.hostname, 18)}${pad(e.process, 21)}${pad(e.classification, 16)}${pad(e.action, 9)}${e.rule}${e.handled ? `  [${e.handled}]` : ""}`).join("\n") || "No security events.");
  }
  const id = Number(toks[1]);
  const e = evs.find((x) => x.id === id);
  if (["event", "forensics", "classify", "exception", "remediate"].includes(c) && !e) return `No event ${toks[1] || ""}.`;
  if (c === "event") return `(GUI: Event ${e.id})\nDevice: ${e.hostname} · ${e.date} ${e.time}\nProcess: ${e.process} (${e.path || "?"})\nHash (SHA-1): ${e.hash || "-"} · Signed: ${e.signed || "no"}\nCommand line: ${e.cmd || "-"}\nPolicy: ${e.policy || "-"} · Rule: ${e.rule}\nAction: ${e.action} · Classification: ${e.classification}${e.dst ? `\nDestinations: ${e.dst}` : ""}${e.target ? `\nTarget: ${e.target}` : ""}`;
  if (c === "forensics") return `(GUI: Forensics > Flow Analyzer, event ${e.id})\n` + (e.chain || [e.parent, e.process].filter(Boolean)).map((p, i) => `${"   ".repeat(i)}${i ? "└─ " : ""}${p}`).join("\n") + `${e.dst ? `\n${"   ".repeat((e.chain || []).length || 2)}└─ connects to ${e.dst}` : ""}${e.target ? `\n${"   ".repeat((e.chain || []).length || 2)}└─ writes ${e.target}` : ""}`;
  if (c === "classify") { const v = { malicious: "Malicious", suspicious: "Suspicious", pup: "PUP", "likely-safe": "Likely Safe", safe: "Safe" }[(toks[2] || "").toLowerCase()]; if (!v) return "Usage: classify <id> malicious|suspicious|pup|likely-safe|safe"; st.cls.set(id, v); return `Event ${id} classified as ${v}.`; }
  if (c === "exception") { const scope = (toks[2] || "all").toLowerCase(); st.exceptions.push({ process: e.process, rule: e.rule, host: scope === "host" ? e.host : "*" }); this.ver++; return `Exception created: ${e.process} no longer triggers "${e.rule}" ${scope === "host" ? `on ${e.hostname}` : "on any collector"}.`; }
  if (c === "remediate") { const a = (toks[2] || "").toLowerCase(); if (!["kill", "delete", "registry"].includes(a)) return "Usage: remediate <id> kill|delete|registry"; st.done.set(id, a === "kill" ? "process terminated" : a === "delete" ? "file deleted" : "registry cleaned"); return `Remediation sent to ${e.hostname}: ${st.done.get(id)}.`; }
  if (c === "isolate" || c === "unisolate") {
    const h = [...this.devices.values()].find((x) => x.spec && x.spec.edr && (x.id === toks[1] || x.hostname === toks[1]));
    if (!h) return `No collector named ${toks[1] || ""}.`;
    if (c === "isolate") st.isolated.add(h.id); else st.isolated.delete(h.id);
    this.ver++;
    return `${h.hostname} ${c === "isolate" ? "isolated: it can only talk to the FortiEDR manager" : "released from isolation"}.`;
  }
  return "Unknown action. Type help.";
};
// isolation: an isolated collector only talks to its manager
Lab.prototype.edrIsolated = function (h) {
  if (!h || !h.spec || !h.spec.edr) return null;
  const edr = this.dev(h.spec.edr.manager);
  return edr && edr.edr && edr.edr.isolated.has(h.id) ? edr : null;
};

// ---------- FortiAnalyzer SOC: event handlers, alerts, incidents ----------
const FAZ_HANDLERS = [
  { name: "IPS - Critical Severity", f: { type: "utm", subtype: "ips", severity: "critical" }, on: true },
  { name: "Antivirus - Malware Detected", f: { type: "utm", subtype: "virus" }, on: true },
  { name: "Web Filter - Blocked Malicious Category", f: { type: "utm", subtype: "webfilter", action: "blocked" }, on: false },
  { name: "VPN - Failed Logins", f: { type: "event", subtype: "vpn", action: "ssl-login-fail" }, on: false, threshold: 5 },
];
function fazSoc(faz) { if (!faz.soc) faz.soc = { handlers: FAZ_HANDLERS.map((h) => ({ ...h, f: { ...h.f } })), inc: [] }; return faz.soc; }
Lab.prototype.fazAlerts = function (faz) {
  const soc = fazSoc(faz);
  const logs = [];
  for (const m of faz.managed.values()) if (m.authorized) logs.push(...m.logs);
  const out = [];
  for (const h of soc.handlers) {
    if (!h.on) continue;
    const hits = logs.filter((r) => Object.entries(h.f).every(([k, v]) => String(r[k] ?? "") === String(v)));
    const g = new Map();
    for (const r of hits) { const k = `${r.devname}|${r.srcip}`; if (!g.has(k)) g.set(k, []); g.get(k).push(r); }
    for (const [k, list] of g) if (list.length >= (h.threshold || 1)) out.push({ id: 100 + out.length, handler: h.name, dev: list[0].devname, srcip: list[0].srcip, dstip: list[list.length - 1].dstip, count: list.length, first: list[0].time, last: list[list.length - 1].time, sample: list[list.length - 1] });
  }
  return out;
};
Lab.prototype.fazSocGui = function (faz, toks) {
  const c = (toks[0] || "").toLowerCase();
  const soc = fazSoc(faz);
  if (c === "handlers") return `(GUI: Incidents & Events > Event Handlers)\n` + soc.handlers.map((h) => `${h.on ? "[on] " : "[off]"} ${pad(h.name, 42)}${Object.entries(h.f).map(([k, v]) => `${k}=${v}`).join(" ")}${h.threshold ? ` threshold=${h.threshold}` : ""}`).join("\n");
  if (c === "handler") {
    const sub = (toks[1] || "").toLowerCase();
    if (sub === "create") {
      const name = toks[2];
      const f = {};
      let thr = 1;
      for (const a of toks.slice(3)) { const [k, v] = a.split("="); if (k === "threshold") thr = Number(v) || 1; else if (k && v !== undefined) f[k] = v; }
      if (!name || !Object.keys(f).length) return 'Usage: handler create "<name>" key=value ... [threshold=N]';
      soc.handlers.push({ name, f, on: true, threshold: thr });
      return `Event handler "${name}" created and enabled.`;
    }
    const h = soc.handlers.find((x) => x.name.toLowerCase() === String(toks[2] || "").toLowerCase());
    if ((sub === "enable" || sub === "disable") && h) { h.on = sub === "enable"; return `Event handler "${h.name}" ${sub}d.`; }
    return 'Usage: handler create "<name>" key=value ... | handler enable|disable "<name>"';
  }
  if (c === "alerts") return `(GUI: Incidents & Events > Event Monitor)\nID   Handler                                   Device          Source          Count  First     Last\n` + (this.fazAlerts(faz).map((a) => `${pad(a.id, 5)}${pad(a.handler, 42)}${pad(a.dev, 16)}${pad(a.srcip || "-", 16)}${pad(a.count, 7)}${pad(a.first, 10)}${a.last}`).join("\n") || "No events.");
  if (c === "incident" && (toks[1] || "").toLowerCase() === "create") {
    const a = this.fazAlerts(faz).find((x) => x.id === Number(toks[2]));
    if (!a) return "Usage: incident create <alert id> [assign=<user>] [category=<text>]";
    const opt = Object.fromEntries(toks.slice(3).map((t) => t.split("=")));
    const inc = { id: `IN${String(soc.inc.length + 1).padStart(8, "0")}`, alert: a, handler: a.handler, srcip: a.srcip, assign: opt.assign || "unassigned", category: opt.category || "Unauthorized Access", status: "New" };
    soc.inc.push(inc);
    return `Incident ${inc.id} created from event ${a.id} (${a.handler}), assigned to ${inc.assign}.`;
  }
  if (c === "incidents") return `(GUI: Incidents & Events > Incidents)\nID          Status  Assigned   Category              Source\n` + (soc.inc.map((i) => `${pad(i.id, 12)}${pad(i.status, 8)}${pad(i.assign, 11)}${pad(i.category, 22)}${i.srcip}`).join("\n") || "No incidents.");
  return null;
};
