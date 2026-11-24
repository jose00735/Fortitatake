// FortiAnalyzer and FortiManager appliances: device registration, log reception and Log View;
// FortiManager device database, install preview, install and out-of-sync detection.
// Their CLI is the real 8.0.2 command tree; GUI-only workflows are typed as console commands and say so.
import { Lab } from "./sim.js";
import { FortiGate, Table, Entry, tokenize } from "./fgt.js";
import { ipToInt, intToIp } from "./net.js";
import { fmtLog } from "./utm.js";

Lab.prototype.mgmtInit = function (dev) {
  dev.managed = new Map(); // fgt id -> {authorized, adom, logs[], db, synced}
  dev.dbCtx = null;
  dev.gui = (d, toks, line) => (d.kind === "fortianalyzer" ? this.fazGui(d, toks, line) : this.fmgGui(d, toks, line));
};
const mgmtIp = (lab, d) => { const i = lab.fgtIntfs(d).find((x) => x.prefix); return i ? i.prefix.ip : null; };

// FortiGates pointing their logs at this FortiAnalyzer, and whether they can reach it (OFTP, TCP 514)
Lab.prototype.fazSenders = function (faz) {
  const ip = mgmtIp(this, faz);
  const out = [];
  for (const fg of this.devices.values()) {
    if (!(fg instanceof FortiGate) || fg.kind !== "fortigate" || fg.parent || this.haRole(fg) === "secondary") continue;
    const s = fg.obj("log fortianalyzer setting");
    if (fg.one("log fortianalyzer setting", s, "status") !== "enable") continue;
    if (ipToInt(String(fg.one("log fortianalyzer setting", s, "server") || "")) !== ip) continue;
    out.push(fg);
  }
  return out;
};
Lab.prototype.reaches = function (fg, ip, port) {
  // logs and FGFM leave from the egress interface unless a source-ip is configured
  let src;
  if (port === 514) { const s = String(fg.one("log fortianalyzer setting", fg.obj("log fortianalyzer setting"), "source-ip") || ""); src = s && s !== "0.0.0.0" ? ipToInt(s) : undefined; }
  if (port === 541) { const s = String(fg.one("system central-management", fg.obj("system central-management"), "fmg-source-ip") || ""); src = s && s !== "0.0.0.0" ? ipToInt(s) : undefined; }
  const k = `${fg.id}>${ip}:${port}:${src}`;
  if (!this._reach || this._reachVer !== this.ver) { this._reach = new Map(); this._reachVer = this.ver; }
  if (this._reach.has(k)) return this._reach.get(k);
  this.quiet = (this.quiet || 0) + 1;
  let r;
  try { r = this.probe(fg.id, { dst: ip, proto: 6, dport: port, src }); } finally { this.quiet--; }
  this._reach.set(k, r);
  return r;
};
Lab.prototype.forwardLog = function (fg, rec) {
  for (const faz of this.devices.values()) {
    if (faz.kind !== "fortianalyzer") continue;
    if (!this.fazSenders(faz).includes(fg)) continue;
    const m = faz.managed.get(fg.id);
    if (!m || !m.authorized) continue;
    if (!this.reaches(fg, mgmtIp(this, faz), 514).ok) continue;
    m.logs.push(rec);
    if (m.logs.length > 3000) m.logs.shift();
  }
};
function register(lab, mgr, fg, port) {
  let m = mgr.managed.get(fg.id);
  const ok = lab.reaches(fg, mgmtIp(lab, mgr), port).ok;
  if (!m && ok) { m = { authorized: false, adom: "root", logs: [], db: null, synced: null, revisions: [] }; mgr.managed.set(fg.id, m); }
  return { m, ok };
}
const pad = (s, n) => (String(s).length >= n ? String(s) + " " : String(s) + " ".repeat(n - String(s).length));

// ---------- FortiAnalyzer ----------
Lab.prototype.fazGui = function (faz, toks) {
  const c = (toks[0] || "").toLowerCase();
  if (c === "devices") {
    const rows = [];
    for (const fg of this.fazSenders(faz)) { const { m, ok } = register(this, faz, fg, 514); if (m) rows.push(`${pad(fg.hostname(), 18)}${pad(fg.serial, 20)}${pad(m.authorized ? "authorized" : "unauthorized", 14)}${pad(ok ? "connected" : "no OFTP link", 14)}${m.logs.length} logs`); }
    return `(GUI: Device Manager)\nDevice            Serial              Status        Log status    Logs\n${rows.join("\n") || "No devices. FortiGates appear here once they send logs to this FortiAnalyzer."}`;
  }
  if (c === "authorize") {
    const name = toks[1];
    const fg = this.fazSenders(faz).find((d) => d.hostname() === name || d.id === name || d.serial === name);
    if (!fg) return `(GUI: Device Manager > Authorize)\nNo unauthorized device named ${name || "?"}. Run devices.`;
    const { m } = register(this, faz, fg, 514);
    if (!m) return `(GUI) ${fg.hostname()} can't reach this FortiAnalyzer on TCP 514 yet.`;
    m.authorized = true; m.adom = toks[2] || "root";
    return `(GUI: Device Manager > Authorize)\n${fg.hostname()} (${fg.serial}) authorized in ADOM ${m.adom}. Logs from now on are stored.`;
  }
  if (c === "logview" || c === "log-view") {
    const args = toks.slice(1);
    const type = ["traffic", "utm", "event"].includes(args[0]) ? args.shift() : null;
    let last = 20;
    const f = {};
    for (const a of args) { const [k, v] = a.split("="); if (k === "last") last = Number(v) || 20; else if (k && v !== undefined) f[k] = v; }
    const all = [];
    for (const m of faz.managed.values()) if (m.authorized) all.push(...m.logs);
    const hits = all.filter((r) => (!type || r.type === type) && Object.entries(f).every(([k, v]) => String(r[k] ?? "") === v || (v.endsWith("*") && String(r[k] ?? "").startsWith(v.slice(0, -1)))));
    hits.sort((a, b) => b.seq - a.seq);
    return `(GUI: Log View${type ? " > " + type : ""}) ${hits.length} log(s) match${Object.keys(f).length ? " " + Object.entries(f).map(([k, v]) => `${k}=${v}`).join(" ") : ""}\n` + hits.slice(0, last).map(fmtLog).join("\n");
  }
  if (c === "fortiview") {
    const what = (toks[1] || "sources").toLowerCase();
    const all = [];
    for (const m of faz.managed.values()) if (m.authorized) all.push(...m.logs);
    const key = what.startsWith("dest") ? "dstip" : what.startsWith("threat") ? "virus" : what.startsWith("polic") ? "policyid" : "srcip";
    const cnt = new Map();
    for (const r of all) if (r[key] !== undefined) cnt.set(r[key], (cnt.get(r[key]) || 0) + 1);
    return `(GUI: FortiView > Top ${what})\n` + [...cnt.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10).map(([k, v]) => `${pad(k, 22)}${v} logs`).join("\n");
  }
  if (c === "help") return "FortiAnalyzer CLI plus these GUI actions: devices, authorize <device> [adom], logview [traffic|utm|event] key=value ... [last=N], fortiview sources|destinations|threats|policies";
  return null;
};

// ---------- FortiManager ----------
function snapshotOf(fg) { return fg.snapshot(); }
function diffScript(db, fg) {
  const a = db.snapshot(), b = fg.snapshot();
  const lines = [];
  for (const path of Object.keys(a)) {
    if (path === "system ha" || path === "system central-management") continue;
    if (a[path] === b[path]) continue;
    const s = db.P[path];
    if (s && s.t === "table") {
      const live = fg.entries(path).map((e) => e.key), want = db.entries(path).map((e) => e.key);
      const gone = live.filter((k) => !want.includes(k));
      const text = a[path].split("\n");
      if (gone.length) { text.splice(text.length - 1, 0, ...gone.map((k) => `    delete ${/^\d+$/.test(k) ? k : `"${k}"`}`)); }
      lines.push(text.join("\n"));
    } else lines.push(a[path]);
  }
  return lines.join("\n");
}
Lab.prototype.fmgManaged = function (fmg) {
  const ip = mgmtIp(this, fmg);
  const out = [];
  for (const fg of this.devices.values()) {
    if (!(fg instanceof FortiGate) || fg.kind !== "fortigate" || fg.parent || this.haRole(fg) === "secondary") continue;
    const s = fg.obj("system central-management");
    if (fg.one("system central-management", s, "type") !== "fortimanager") continue;
    if (ipToInt(String(fg.val("system central-management", s, "fmg")[0] || "").replace(/"/g, "")) !== ip) continue;
    out.push(fg);
  }
  return out;
};
Lab.prototype.fmgStatus = function (fmg, fg) {
  const m = fmg.managed.get(fg.id);
  if (!m || !m.authorized) return "unauthorized";
  const live = JSON.stringify(snapshotOf(fg)), db = JSON.stringify(snapshotOf(m.db));
  if (live === m.synced && db === m.synced) return "synchronized";
  if (live !== m.synced) return "out of sync (changed on the FortiGate)";
  return "modified (changes waiting to install)";
};
Lab.prototype.fmgGui = function (fmg, toks, line) {
  const c = (toks[0] || "").toLowerCase();
  if (fmg.dbCtx) {
    if (c === "exit" || c === "quit") { const n = fmg.dbCtx; fmg.dbCtx = null; return `(left the device database of ${n})`; }
    return null;
  }
  const find = (name) => this.fmgManaged(fmg).find((d) => d.hostname() === name || d.id === name || d.serial === name);
  if (c === "devices") {
    const rows = this.fmgManaged(fmg).map((fg) => { const { m, ok } = register(this, fmg, fg, 541); return m ? `${pad(fg.hostname(), 18)}${pad(fg.serial, 20)}${pad(ok ? "up" : "down", 8)}${this.fmgStatus(fmg, fg)}` : null; }).filter(Boolean);
    return `(GUI: Device Manager)\nDevice            Serial              FGFM    Config status\n${rows.join("\n") || "No devices. FortiGates appear here once central management points to this FortiManager."}`;
  }
  if (c === "authorize") {
    const fg = find(toks[1]);
    if (!fg) return `(GUI: Device Manager > Authorize) No device named ${toks[1] || "?"}. Run devices.`;
    const { m } = register(this, fmg, fg, 541);
    if (!m) return `(GUI) ${fg.hostname()} can't reach this FortiManager on TCP 541 (FGFM).`;
    m.authorized = true;
    m.db = new FortiGate({ id: fg.id + "-DB", ports: fg.ports, hostname: fg.hostname(), model: fg.model }, fg.schema);
    m.db.cfg = new Map([...fg.cfg].map(([k, n]) => [k, n.clone()]));
    m.synced = JSON.stringify(snapshotOf(fg));
    m.revisions.push({ id: 1, ts: this.clock, note: "Imported at authorization" });
    return `(GUI: Device Manager > Authorize + Import)\n${fg.hostname()} authorized. Configuration and policies imported into the device database and policy package "${fg.hostname()}".`;
  }
  const dev = toks[1] && find(toks[toks.length - 1]);
  const mm = dev && fmg.managed.get(dev.id);
  if (c === "dbconsole" || c === "db") {
    if (!mm || !mm.authorized) return "(GUI) Authorize the device first.";
    fmg.dbCtx = dev.hostname();
    fmg.dbDev = mm.db;
    return `(GUI: Device Manager > ${dev.hostname()} > CLI Configurations)\nYou are editing ${dev.hostname()}'s device database on the FortiManager, not the FortiGate. Type exit to leave.`;
  }
  if (c === "install") {
    if (!mm || !mm.authorized) return "(GUI) Authorize the device first.";
    const preview = (toks[1] || "").toLowerCase() === "preview";
    const st = this.fmgStatus(fmg, dev);
    const script = diffScript(mm.db, dev);
    if (preview) return `(GUI: Install Wizard > Install Preview for ${dev.hostname()})\n${script || "No changes to install."}`;
    if (st.startsWith("out of sync")) return `(GUI: Install Wizard)\nInstall blocked: ${dev.hostname()} was changed locally since the last sync. Retrieve the configuration first (retrieve ${dev.hostname()}) or review the conflict.`;
    if (!script) return "(GUI: Install Wizard) Nothing to install.";
    if (!this.reaches(dev, mgmtIp(this, fmg), 541).ok) return `(GUI: Install Wizard) Install failed: no FGFM connection to ${dev.hostname()}.`;
    const errs = dev.load(script);
    mm.synced = JSON.stringify(snapshotOf(dev));
    mm.db.cfg = new Map([...dev.cfg].map(([k, n]) => [k, n.clone()]));
    mm.revisions.push({ id: mm.revisions.length + 1, ts: this.clock, note: "Installed from FortiManager" });
    this.dirty(dev);
    return `(GUI: Install Wizard)\nInstalling to ${dev.hostname()}...\n${errs.length ? "Install finished with errors:\n" + errs.join("\n") : "Install succeeded. Device and database are synchronized."}`;
  }
  if (c === "retrieve") {
    if (!mm || !mm.authorized) return "(GUI) Authorize the device first.";
    mm.db.cfg = new Map([...dev.cfg].map(([k, n]) => [k, n.clone()]));
    mm.synced = JSON.stringify(snapshotOf(dev));
    mm.revisions.push({ id: mm.revisions.length + 1, ts: this.clock, note: "Retrieved from device" });
    return `(GUI: Device Manager > Retrieve Config) ${dev.hostname()}'s running configuration is now the latest revision in the database.`;
  }
  if (c === "revisions") return mm ? `(GUI: Revision History for ${dev.hostname()})\n` + mm.revisions.map((r) => `${pad(r.id, 4)}${new Date(r.ts).toISOString().slice(0, 16).replace("T", " ")}  ${r.note}`).join("\n") : "(GUI) Unknown device.";
  if (c === "help") return "FortiManager CLI plus these GUI actions: devices, authorize <device>, dbconsole <device> (edit the device database; exit to leave), install preview <device>, install <device>, retrieve <device>, revisions <device>";
  return null;
};

// in a FortiManager's device-database context, typed lines go to the database copy
Lab.prototype.mgmtExec = function (mgr, line) {
  if (mgr.kind === "fortimanager" && mgr.dbCtx && mgr.dbDev) {
    const t = tokenize(line.trim());
    if (t[0] === "exit" && !mgr.dbDev.frames.length) return this.fmgGui(mgr, t, line);
    return mgr.dbDev.run(line);
  }
  return null;
};
Lab.prototype.mgmtPrompt = function (mgr) {
  if (mgr.kind === "fortimanager" && mgr.dbCtx && mgr.dbDev) return `${mgr.hostname()} [${mgr.dbCtx} DB] ${mgr.dbDev.prompt().replace(/^\S+\s*/, "")}`;
  return null;
};

// diagnostics on the appliances' real CLI
Lab.prototype.mgmtDiag = function (mgr, head, words) {
  const w = words.join(" ");
  if (head === "get" && /^system status/.test(w)) return [`Platform Type                   : ${mgr.kind === "fortianalyzer" ? "FAZVM64" : "FMGVM64"}`, `Platform Full Name              : ${mgr.kind === "fortianalyzer" ? "FortiAnalyzer-VM64" : "FortiManager-VM64"}`, `Version                         : v8.0.2-build0000 260115 (GA)`, `Serial Number                   : ${mgr.serial}`, `Hostname                        : ${mgr.hostname()}`, `Admin Domain Configuration      : Disabled`, `Current Time                    : ${new Date(this.clock).toUTCString()}`].join("\n");
  if (head === "diagnose" && /^dvm device list/.test(w)) {
    const list = mgr.kind === "fortianalyzer" ? this.fazSenders(mgr) : this.fmgManaged(mgr);
    const rows = list.map((fg) => { const m = mgr.managed.get(fg.id); return m ? `--- There are currently ${list.length} devices/vdoms managed ---\nTYPE            OID    SN                 HA        IP              NAME                 ADOM                 IPS              FIRMWARE\nfmgfaz-managed  ${170 + list.indexOf(fg)}    ${fg.serial}   -         ${intToIp(this.fgtIntfs(fg).find((i) => i.prefix && i.role === "wan")?.prefix.ip || 0)}    ${fg.hostname().padEnd(20)} ${m.adom.padEnd(20)} 26.00123 (regular) 8.0 MR0 (0000)\n                |- STATUS: dev-db: ${m.authorized ? "modified" : "unknown"}; conf: ${m.authorized ? "in sync" : "unknown"}; cond: ${m.authorized ? "OK" : "unregistered"}; dm: ${m.authorized ? "retrieved" : "none"}; conn: up` : null; }).filter(Boolean);
    return rows.join("\n") || "--- There are currently 0 devices/vdoms managed ---";
  }
  if (head === "diagnose" && /^fortilogd lograte/.test(w)) { let n = 0; for (const m of mgr.managed.values()) n += m.logs.length; return `fortilogd: total ${n} logs, rate ${n ? (n / 60).toFixed(2) : "0.00"} logs/s`; }
  return null;
};
