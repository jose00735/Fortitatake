// The FortiEDR manager on real telemetry. Collectors (ftkos/agent/edr.go) send what really
// happens on each lab host (CPU and memory from its cgroup, processes, connections, plus
// emulated Windows steps) to the manager over the lab network; this engine reads what reached
// the manager and runs the behaviour rules. A hit becomes a FortiEDR security event in the same
// model the console, the checks and FortiSIEM already use (h.edrlog). In Prevention mode the
// manager acts on the real host: it kills the process or blocks the destination.
import { Lab } from "./sim.js";
import { intToIp } from "./net.js";

const OFFICE = /^(winword|excel|powerpnt|outlook|acrord32|chrome|msedge|firefox|explorer)(\.exe)?$/i;
const SCRIPT = /^(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|bash|sh|python3?)(\.exe)?$/i;
const SERVER = /^(java|sshd|httpd|nginx|w3wp|node|php-fpm|tomcat)(\.exe)?$/i;
const DESTROY = /(vssadmin(\.exe)?\s+delete\s+shadows|wbadmin(\.exe)?\s+delete\s+catalog|bcdedit(\.exe)?\s+\/set\s+\S+\s+recoveryenabled\s+no|wmic\s+shadowcopy\s+delete)/i;

// behaviour rules: name, FortiEDR policy, classification, ATT&CK
export const EDR_RULES = [
  { id: "cpu", rule: "Suspicious Resource Usage", policy: "Execution Prevention", cls: "PUP", attack: "T1496 Resource Hijacking", desc: "One process keeps the host's CPU near its cap for 90 seconds (a miner)." },
  { id: "mem", rule: "Abnormal Memory Allocation", policy: "Ransomware Prevention", cls: "Suspicious", attack: "T1486 staging", desc: "Memory grows by more than 64 MB in a minute, or the host runs out (OOM)." },
  { id: "feed", rule: "Connection To Known Malicious Address", policy: "Exfiltration Prevention", cls: "Malicious", attack: "T1071 Application Layer Protocol", desc: "A connection to a C2 or malware address from the threat feeds, or a lookup of a feed domain." },
  { id: "beacon", rule: "Periodic Beaconing", policy: "Exfiltration Prevention", cls: "Suspicious", attack: "T1071.001 Web Protocols", desc: "Five or more connections to one destination at a steady interval (jitter under 20 %)." },
  { id: "lineage", rule: "Suspicious Process Lineage", policy: "Execution Prevention", cls: "Suspicious", attack: "T1059 Command and Scripting Interpreter", desc: "An Office app, browser or server process starts a script host or shell." },
  { id: "lsass", rule: "Credential Dumping", policy: "Execution Prevention", cls: "Malicious", attack: "T1003.001 LSASS Memory", desc: "rundll32 with comsvcs.dll MiniDump, or another LSASS dump." },
  { id: "recovery", rule: "Recovery Inhibition", policy: "Ransomware Prevention", cls: "Malicious", attack: "T1490 Inhibit System Recovery", desc: "Shadow copies, backup catalogs or boot recovery deleted." },
  { id: "files", rule: "File Encryptor", policy: "Ransomware Prevention", cls: "Malicious", attack: "T1486 Data Encrypted for Impact", desc: "More than 200 files renamed or rewritten in a minute." },
  { id: "persist", rule: "Scheduled Persistence", policy: "Execution Prevention", cls: "Suspicious", attack: "T1053.003 Cron", desc: "A new cron entry or scheduled task points at a temporary path." },
];

const hhmmss = (ms) => { const d = new Date(ms); const p = (n) => String(n).padStart(2, "0"); return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`; };
const day = (lab) => new Date(lab.clock - 5 * 3600000).toISOString().slice(0, 10);

function tel(lab, mgr) {
  mgr.tel = mgr.tel || { hosts: new Map(), seq: 0, raw: [], gaps: 0 };
  return mgr.tel;
}
function hostTel(t, id) {
  if (!t.hosts.has(id)) t.hosts.set(id, { procs: new Map(), perf: [], conns: [], files: [], fired: new Map(), last: 0, top: null });
  return t.hosts.get(id);
}

// one telemetry event that reached the manager
Lab.prototype.edrIngest = function (mgr, ev) {
  const t = tel(this, mgr);
  const h = this.dev(ev.host);
  if (!h || !h.spec || !h.spec.edr || h.spec.edr.manager !== mgr.id) return; // only its own collectors
  t.raw.push(ev); if (t.raw.length > 3000) t.raw.shift();
  const ht = hostTel(t, ev.host);
  ht.last = ev.t || Date.now();
  const fire = (r, info) => this.edrFire(mgr, h, ht, r, info, ev);
  const R = Object.fromEntries(EDR_RULES.map((r) => [r.id, r]));
  switch (ev.kind) {
    case "gap": t.gaps += ev.dropped || 0; break;
    case "perf": {
      ht.perf.push({ t: ev.t, cpu: ev.cpu, mem: ev.mem_mb, top: ev.top });
      ht.perf = ht.perf.filter((p) => p.t > ev.t - 120000);
      const hot = ht.perf.filter((p) => p.t > ev.t - 90000);
      if (hot.length >= 20 && hot.every((p) => p.cpu >= 40) && hot[0].t <= ev.t - 85000) { // the cap is half a core
        const top = ev.top || {};
        const p = top.pid && ht.procs.get(top.pid);
        fire(R.cpu, { process: (p && p.name) || top.name || "unknown", pid: top.pid, cmd: p && p.cmd, parent: p && p.parent, detail: `CPU at ${ev.cpu} % of one core (cap 50 %) for 90 s` });
      }
      const old = ht.perf.find((p) => p.t >= ev.t - 60000);
      if ((old && ev.mem_mb - old.mem >= 64) || ev.oom) {
        const top = ev.top || {};
        const p = top.pid && ht.procs.get(top.pid);
        fire(R.mem, { process: (p && p.name) || top.name || "unknown", pid: top.pid, cmd: p && p.cmd, detail: ev.oom ? "the host ran out of memory" : `memory grew ${ev.mem_mb - old.mem} MB in a minute` });
      }
      break;
    }
    case "proc": {
      ht.procs.set(ev.pid, { name: ev.name, cmd: ev.cmd, parent: ev.parent, ppid: ev.ppid, user: ev.user, t: ev.t, emulated: ev.emulated });
      if (ht.procs.size > 400) ht.procs.delete(ht.procs.keys().next().value);
      const base = { process: ev.name, pid: ev.pid, cmd: ev.cmd, parent: ev.parent, user: ev.user, path: ev.path };
      if (/comsvcs(\.dll)?[,\s]+#?(minidump|24)/i.test(ev.cmd || "") || /procdump.*lsass|sekurlsa/i.test(ev.cmd || "")) fire(R.lsass, { ...base, detail: "LSASS memory dump" });
      else if (DESTROY.test(ev.cmd || "")) fire(R.recovery, { ...base, detail: "recovery removed" });
      else if (/crontab\s+-|schtasks.*\/create/i.test(ev.cmd || "") && /\/tmp\/|appdata\\local\\temp|\\users\\public/i.test(ev.cmd || "")) fire(R.persist, { ...base, detail: "persistence in a temporary path" });
      else if (SCRIPT.test(ev.name || "") && (OFFICE.test(ev.parent || "") || SERVER.test(ev.parent || ""))) fire(R.lineage, { ...base, detail: `${ev.parent} started ${ev.name}` });
      break;
    }
    case "net": case "dns": {
      const what = ev.kind === "dns" ? ev.name : ev.dst;
      const fm = this.feedMatch && this.feedMatch(what);
      if (ev.pid && !ht.procs.has(ev.pid) && ev.process) ht.procs.set(ev.pid, { name: ev.process, cmd: ev.cmd, parent: ev.parent, ppid: ev.ppid, user: ev.user, t: ev.t });
      const p = ev.pid && ht.procs.get(ev.pid);
      if (fm) fire(R.feed, { process: (p && p.name) || ev.process || "unknown", pid: ev.pid, cmd: p && p.cmd, parent: p && p.parent, user: p && p.user, dst: ev.kind === "dns" ? `${ev.name} (DNS)` : `${ev.dst}:${ev.dport}`, dstIp: ev.dst, detail: `${fm.kind === "c2" ? `C2 of ${fm.family || "a botnet"}` : fm.kind} from ${fm.source}` });
      if (ev.kind === "net") {
        ht.conns.push({ t: ev.t, k: `${ev.dst}:${ev.dport}` });
        ht.conns = ht.conns.filter((c) => c.t > ev.t - 900000);
        const same = ht.conns.filter((c) => c.k === `${ev.dst}:${ev.dport}`).map((c) => c.t);
        if (same.length >= 5) {
          const gaps = same.slice(1).map((x, i) => x - same[i]);
          const mean = gaps.reduce((a, b) => a + b, 0) / gaps.length;
          const sd = Math.sqrt(gaps.reduce((a, b) => a + (b - mean) ** 2, 0) / gaps.length);
          if (mean >= 5000 && sd / mean < 0.2) fire(R.beacon, { process: (p && p.name) || ev.process || "unknown", pid: ev.pid, dst: `${ev.dst}:${ev.dport}`, dstIp: ev.dst, detail: `${same.length} connections every ${Math.round(mean / 1000)} s (±${Math.round((sd / mean) * 100)} %)` });
        }
      }
      break;
    }
    case "file": {
      ht.files.push({ t: ev.t, n: ev.count || 1 });
      ht.files = ht.files.filter((f) => f.t > ev.t - 60000);
      const n = ht.files.reduce((a, f) => a + f.n, 0);
      if (n > 200) fire(R.files, { process: ev.process || "unknown", pid: ev.pid, cmd: ev.cmd, target: ev.target, detail: `${n} files ${ev.op || "renamed"} in a minute${ev.ext ? ` to *${ev.ext}` : ""}` });
      break;
    }
  }
};

// a rule fired: one security event per host, rule and process every 5 minutes
Lab.prototype.edrFire = function (mgr, h, ht, r, info, ev) {
  const key = `${r.id}|${info.process}|${info.dstIp || ""}`;
  if (ht.fired.has(key) && ev.t - ht.fired.get(key) < 300000) return;
  ht.fired.set(key, ev.t);
  const st = this.edrStateOf(mgr);
  const mode = st.modes[r.policy] || "Simulation";
  this._edrId = (this._edrId || 1000) + 1;
  const p = info.pid ? ht.procs.get(info.pid) : null;
  const chain = [];
  for (let x = p, guard = 0; x && guard < 6; guard++) { chain.unshift(x.name); x = [...ht.procs.entries()].find(([pid]) => pid === x.ppid)?.[1]; }
  if (!chain.length && info.parent) chain.push(info.parent);
  if (!chain.includes(info.process)) chain.push(info.process);
  const e = { time: hhmmss(ev.t || Date.now()), date: day(this), seq: this._edrId, id: this._edrId, mode, process: info.process, path: info.path || (info.cmd ? info.cmd.split(" ")[0] : ""), parent: info.parent || (chain.length > 1 ? chain[chain.length - 2] : ""), chain, cmd: info.cmd || "", hash: "", signed: "no", policy: r.policy, rule: r.rule, classification: r.cls, attack: r.attack, dst: info.dst, target: info.target, detail: info.detail, real: !ev.emulated, pid: info.pid, dstIp: info.dstIp, user: info.user };
  h.edrlog = h.edrlog || [];
  h.edrlog.push(e);
  this.ver++;
  if (mode === "Prevention") (this.edrActions = this.edrActions || []).push({ host: h.id, kind: r.id === "feed" || r.id === "beacon" ? "block" : "kill", pid: info.pid, ip: info.dstIp, event: e.id });
  if (this.edrForward) this.edrForward(mgr, h, e);
};

Lab.prototype.edrStateOf = function (mgr) {
  // soc.js keeps the console state; make sure it exists (same shape)
  if (!mgr.edr) this.edrConsole(mgr, "policies");
  return mgr.edr;
};

// FortiEDR → FortiSIEM over syslog (when the manager has a syslog destination it can reach)
Lab.prototype.edrForward = function (mgr, h, e) {
  const dest = (mgr.spec.fortiedr && mgr.spec.fortiedr.syslog) || (mgr.edr && mgr.edr.syslog);
  const siem = dest && [...this.devices.values()].find((d) => d.kind === "fortisiem" && (d.id === dest || (d.ip && d.ip() && intToIp(d.ip()) === dest)));
  if (!siem) return;
  this.quiet = (this.quiet || 0) + 1;
  let ok;
  try { ok = this.probe(mgr.id, { dst: siem.ip(), proto: 17, dport: 514 }).ok; } finally { this.quiet--; }
  if (!ok) return;
  // on the real network the same line also travels as a real syslog datagram (edrTick sends it)
  if (this.agentVer) (this.edrSyslog = this.edrSyslog || []).push({ from: mgr.id, to: intToIp(siem.ip()), line: `<${e.classification === "Malicious" ? 9 : 12}>FortiEDR: deviceName="${h.hostname || h.id}" classification="${e.classification}" rule="${e.rule}" process="${e.process}" action="${e.action || e.mode}" destination="${e.dst || ""}" eventId=${e.id}` });
  siem.siem = siem.siem || { events: [], inc: new Map(), rules: null };
  siem.siem.events.push({ date: e.date, time: e.time, seq: Date.now(), eventType: `FortiEDR-${e.classification}-${e.rule.replace(/\s+/g, "-")}`, reptDevName: mgr.hostname || mgr.id, reptDevIpAddr: intToIp(mgr.ip()), hostName: h.hostname || h.id, srcIpAddr: h.ip && h.ip() ? intToIp(h.ip()) : "", destIpAddr: e.dstIp || "", procName: e.process, command: e.cmd, raw: `FortiEDR: ${e.classification} ${e.rule} on ${h.hostname || h.id}: ${e.process}${e.dst ? " -> " + e.dst : ""} (${e.mode})` });
};

// a compact text view of what a collector really sent (for the console's raw data)
export function edrRawFor(lab, mgr, hostId, n = 30) {
  const t = mgr.tel;
  if (!t) return [];
  return t.raw.filter((e) => e.host === hostId).slice(-n);
}

Lab.prototype.edrRulesText = function () {
  return EDR_RULES.map((r) => `${r.rule.padEnd(38)}${r.policy.padEnd(25)}${r.cls.padEnd(11)}${r.attack}\n    ${r.desc}`).join("\n");
};

// ----- endpoint tests: real commands on the live network, nominal telemetry in the simulator -----
export const EDR_TESTS = {
  miner: { label: "Miner (CPU)", rule: "Suspicious Resource Usage", cmd: () => "(awk 'BEGIN{while(1){}}' & p=$!; sleep 120; kill $p 2>/dev/null) >/dev/null 2>&1 &" },
  c2: { label: "Contact a C2 address", rule: "Connection To Known Malicious Address", cmd: (lab) => `wget -q -T 3 -O /dev/null http://${lab.intel.c2[0].ip}/ 2>/dev/null` },
  beacon: { label: "Beacon to a C2", rule: "Periodic Beaconing", cmd: (lab) => `(for i in 1 2 3 4 5 6; do wget -q -T 2 -O /dev/null http://${lab.intel.c2[1].ip}/ ; sleep 6; done) >/dev/null 2>&1 &` },
};

// the simulator's stand-in for a collector's telemetry (same rules, nominal values)
Lab.prototype.edrSimulate = function (hostId, kind) {
  const h = this.dev(hostId);
  if (!h || !h.spec || !h.spec.edr) return `${hostId} has no FortiEDR collector.`;
  const mgr = this.dev(h.spec.edr.manager);
  if (!mgr || !this.intel) return "No FortiEDR manager or lab Internet.";
  this.quiet = (this.quiet || 0) + 1;
  let ok;
  try { ok = this.probe(h.id, { dst: mgr.ip(), proto: 6, dport: 555, edrMgmt: true }).ok; } finally { this.quiet--; }
  if (!ok) return `The test ran on ${h.id}, but its collector can't deliver events to ${mgr.id} on TCP 555.`;
  const t0 = this.clock;
  const ip = h.ip ? intToIp(h.ip()) : "";
  const ev = (dt, e) => this.edrIngest(mgr, { host: h.id, t: t0 + dt, emulated: false, ...e });
  if (kind === "miner") {
    ev(0, { kind: "proc", pid: 4242, ppid: 4200, name: "awk", cmd: "awk BEGIN{while(1){}}", parent: "sh", user: "root" });
    for (let s = 0; s <= 96; s += 2) ev(s * 1000, { kind: "perf", cpu: 50, mem_mb: 2, top: { pid: 4242, name: "awk" } });
  } else if (kind === "c2") {
    const c = this.intel.c2[0];
    ev(0, { kind: "net", pid: 4300, process: "wget", cmd: `wget -q -T 3 -O /dev/null http://${c.ip}/`, parent: "sh", src: ip, sport: 41000, dst: c.ip, dport: 80 });
  } else if (kind === "beacon") {
    const c = this.intel.c2[1];
    for (let i = 0; i < 6; i++) ev(i * 6000, { kind: "net", pid: 4400 + i, process: "wget", cmd: `wget -q -T 2 -O /dev/null http://${c.ip}/`, parent: "sh", src: ip, sport: 42000 + i, dst: c.ip, dport: 80 });
  } else return `Unknown test ${kind}.`;
  this.edrActions = []; // nothing to act on in the simulator: the event records the mode's action
  return `${EDR_TESTS[kind].label} ran on ${h.id} (simulated telemetry).`;
};
