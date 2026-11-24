// FGCP HA for the lab simulator: cluster formation over the heartbeat, primary election, config sync, failover.
import { Lab } from "./sim.js";
import { FortiGate, Table, Entry } from "./fgt.js";
import { hashStr } from "./fgt.js";
import { hex } from "./net.js";

const HA = "system ha";

Lab.prototype.haCfg = function (fg) {
  const e = fg.obj(HA);
  const one = (a) => fg.one(HA, e, a);
  const hb = fg.val(HA, e, "hbdev").filter((x) => !/^\d+$/.test(x));
  return { mode: one("mode") || "standalone", group: one("group-name") || "", gid: one("group-id") || "0", pw: (e.attrs.get("password") || [""])[0], hbdev: hb,
    priority: Number(one("priority") || 128), override: one("override") === "enable", monitor: fg.val(HA, e, "monitor"), uptime: Number((fg.spec && fg.spec.ha_uptime) || 0), forcedDown: !!fg.haForcedDown };
};

// clusters, recomputed per config version
Lab.prototype.haClusters = function () {
  if (this._ha && this._haVer === this.ver) return this._ha;
  this._haVer = this.ver;
  const fgs = [...this.devices.values()].filter((d) => d instanceof FortiGate && !d.parent && this.haCfg(d).mode !== "standalone");
  const parent = new Map(fgs.map((f) => [f, f]));
  const find = (x) => (parent.get(x) === x ? x : find(parent.get(x)));
  const why = new Map();
  for (let i = 0; i < fgs.length; i++) for (let j = i + 1; j < fgs.length; j++) {
    const a = fgs[i], b = fgs[j], ca = this.haCfg(a), cb = this.haCfg(b);
    const linked = ca.hbdev.some((ia) => { const s = this.segOf(a.id, ia); return s && !s.down && cb.hbdev.some((ib) => this.segOf(b.id, ib) === s); });
    if (!linked) { why.set(a, why.get(a) || "no heartbeat link to the peer"); why.set(b, why.get(b) || "no heartbeat link to the peer"); continue; }
    if (ca.mode !== cb.mode || ca.group !== cb.group || ca.gid !== cb.gid || ca.pw !== cb.pw || a.model !== b.model) {
      const w = ca.group !== cb.group ? "group-name differs" : ca.gid !== cb.gid ? "group-id differs" : ca.pw !== cb.pw ? "HA password differs" : ca.mode !== cb.mode ? "HA mode differs" : "different models";
      why.set(a, w); why.set(b, w); continue;
    }
    parent.set(find(a), find(b));
  }
  const groups = new Map();
  for (const f of fgs) { const r = find(f); if (!groups.has(r)) groups.set(r, []); groups.get(r).push(f); }
  const out = [];
  for (const members of groups.values()) {
    const score = (f) => {
      const c = this.haCfg(f);
      const intfs = this.fgtIntfs(f);
      const mon = c.monitor.filter((m) => { const i = intfs.find((x) => x.name === m); return i && i.up; }).length;
      return { f, c, mon, fail: c.forcedDown ? 1 : 0 };
    };
    const s = members.map(score);
    const cmp = (x, y) => {
      if (x.fail !== y.fail) return x.fail - y.fail;
      if (x.mon !== y.mon) return y.mon - x.mon;
      const byPrio = y.c.priority - x.c.priority, byUp = Math.abs(x.c.uptime - y.c.uptime) > 5 ? y.c.uptime - x.c.uptime : 0, bySerial = y.f.serial.localeCompare(x.f.serial);
      return x.c.override ? byPrio || byUp || bySerial : byUp || byPrio || bySerial;
    };
    s.sort(cmp);
    const p = s[0];
    let reason = "it is the only member";
    if (s.length > 1) {
      const q = s[1];
      reason = p.fail !== q.fail ? "the other unit was forced to fail over" : p.mon !== q.mon ? "it has the most monitored interfaces up" : p.c.override && p.c.priority !== q.c.priority ? "it has the largest value of override priority" : Math.abs(p.c.uptime - q.c.uptime) > 5 && !p.c.override ? "it has the largest value of uptime" : p.c.priority !== q.c.priority ? "it has the largest value of override priority" : "it has the largest value of serialno";
    }
    out.push({ members: s.map((x) => x.f), primary: p.f, reason, scores: s });
  }
  this._ha = { clusters: out, why };
  return this._ha;
};
Lab.prototype.haCluster = function (fg) { return this.haClusters().clusters.find((c) => c.members.includes(fg)); };
Lab.prototype.haRole = function (fg) {
  if (fg.parent) return this.haRole(fg.parent);
  if (this.haCfg(fg).mode === "standalone") return "standalone";
  if (this._haBusy) return "primary";
  this._haBusy = true;
  try { const c = this.haCluster(fg); return !c || c.primary === fg ? "primary" : "secondary"; } finally { this._haBusy = false; }
};

// FGCP synchronises the primary's configuration to the secondaries (HA settings and hostname stay local)
Lab.prototype.haSync = function () {
  if (this._syncing) return;
  this._syncing = true;
  try {
    this.ver++;
    for (const c of this.haClusters().clusters) {
      if (c.members.length < 2) continue;
      for (const sec of c.members) {
        if (sec === c.primary) continue;
        const keepHa = sec.cfg.get(HA), keepGlobal = sec.cfg.get("system global");
        const host = keepGlobal && keepGlobal.attrs.get("hostname");
        sec.cfg = new Map([...c.primary.cfg].map(([k, n]) => [k, n.clone()]));
        // HA settings sync too, except the ones that are per unit
        const ha = c.primary.cfg.get(HA).clone();
        for (const a of ["priority", "override", "ha-uptime-diff-margin", "ha-mgmt-status"]) { const v0 = keepHa && keepHa.attrs.get(a); if (v0) ha.attrs.set(a, v0); else ha.attrs.delete(a); }
        sec.cfg.set(HA, ha);
        if (host) sec.cfg.get("system global").attrs.set("hostname", host);
      }
    }
    this.ver++;
  } finally { this._syncing = false; }
};
Lab.prototype.haSyncAll = function () { this.haSync(); };

function cksum(fg, part) {
  const snap = fg.snapshot();
  let txt = "";
  for (const [k, v] of Object.entries(snap)) if ((part === "global") === /^system (global|admin|ha|interface|dns|settings)/.test(k) && k !== HA) txt += k === "system global" ? v.replace(/set hostname .*\n/, "") : v;
  const h = hashStr(txt);
  return [h, hashStr(txt + "1"), hashStr(txt + "2"), hashStr(txt + "3")].map((x) => hex(x)).join("").match(/../g).slice(0, 16).join(" ");
}

Lab.prototype.haDiag = function (fg, words, raw, head) {
  const w = words.join(" ");
  const c = this.haCfg(fg);
  if (head === "get" && /^system ha status/.test(w)) {
    if (c.mode === "standalone") return `HA Health Status: OK\nModel: ${fg.model}\nMode: standalone`;
    const cl = this.haCluster(fg) || { members: [fg], primary: fg, reason: "it is the only member" };
    const { why } = this.haClusters();
    const mem = cl.members;
    const t = new Date(this.clock).toISOString().slice(0, 19).replace("T", " ");
    const lines = [`HA Health Status: ${mem.length > 1 ? "OK" : "\n    ERROR: no peer found " + (why.get(fg) ? "(" + why.get(fg) + ")" : "")}`, `Model: ${fg.model}`, `Mode: HA ${c.mode === "a-p" ? "A-P" : "A-A"}`, `Group Name: ${c.group}`, `Group ID: ${c.gid}`, `Debug: 0`, `Cluster Uptime: 0 days 3:12:41`, `Cluster state change time: ${t}`, `Primary selected using:`, `    <${t.replace(/-/g, "/")}> vcluster-1: ${cl.primary.serial} is selected as the primary because ${cl.reason}.`, `ses_pickup: ${fg.one(HA, fg.obj(HA), "session-pickup")}`, `override: ${c.override ? "enable" : "disable"}`, `Configuration Status:`];
    for (const m of mem) lines.push(`    ${m.serial}(updated 2 seconds ago): ${mem.length > 1 && cksum(m, "all") === cksum(cl.primary, "all") ? "in-sync" : mem.length > 1 ? "out-of-sync" : "in-sync"}`);
    lines.push(`System Usage stats:`);
    for (const m of mem) lines.push(`    ${m.serial}(updated 2 seconds ago):`, `        sessions=${(m.sessList || []).length}, npu-sessions=0, average-cpu-user/nice/system/idle=1%/0%/0%/99%, memory=34%`);
    lines.push(`HBDEV stats:`);
    for (const m of mem) { lines.push(`    ${m.serial}(updated 2 seconds ago):`); for (const hb of this.haCfg(m).hbdev) { const s = this.segOf(m.id, hb); lines.push(`        ${hb}: physical/1000auto, ${s && !s.down ? "up" : "down"}, rx-bytes/packets/dropped/errors=2214512/9012/0/0, tx=2311020/9233/0/0`); } }
    lines.push(`MONDEV stats:`);
    for (const m of mem) { lines.push(`    ${m.serial}(updated 2 seconds ago):`); for (const mon of this.haCfg(m).monitor) { const i = this.fgtIntfs(m).find((x) => x.name === mon); lines.push(`        ${mon}: physical/1000auto, ${i && i.up ? "up" : "down"}, rx-bytes/packets/dropped/errors=88123120/512334/0/0, tx=67312004/499812/0/0`); } }
    mem.forEach((m, i) => lines.push(`${m === cl.primary ? "Primary  " : "Secondary"}: ${m.hostname().padEnd(16)}, ${m.serial}, HA cluster index = ${i}`));
    lines.push(`number of vcluster: 1`, `vcluster 1: work 169.254.0.${mem.indexOf(cl.primary) + 1}`);
    mem.forEach((m, i) => lines.push(`${m === cl.primary ? "Primary" : "Secondary"}: ${m.serial}, HA operating index = ${m === cl.primary ? 0 : i || 1}`));
    return lines.join("\n");
  }
  if (head === "diagnose" && /^sys ha checksum (cluster|show)/.test(w)) {
    const cl = this.haCluster(fg);
    const mem = cl ? cl.members : [fg];
    return mem.map((m) => `\n================== ${m.serial} ==================\n\nis_manage_primary()=${m === (cl && cl.primary) ? 1 : 0}, is_root_primary()=${m === (cl && cl.primary) ? 1 : 0}\ndebugzone\nglobal: ${cksum(m, "global")}\nroot: ${cksum(m, "root")}\nall: ${cksum(m, "all")}\n\nchecksum\nglobal: ${cksum(m, "global")}\nroot: ${cksum(m, "root")}\nall: ${cksum(m, "all")}`).join("\n");
  }
  if (head === "execute" && /^ha failover set/.test(w)) { fg.haForcedDown = true; this.dirty(fg); return `Caution: This command will trigger an HA failover.\nIt is intended for testing purposes.\nDo you want to continue? (y/n)y\n\nFailover triggered.`; }
  if (head === "execute" && /^ha failover unset/.test(w)) { fg.haForcedDown = false; this.dirty(fg); return "Failover reset."; }
  if (head === "execute" && /^ha synchronize start/.test(w)) { this.haSync(); return "Starting synchronization with primary..."; }
  if (head === "execute" && /^ha manage/.test(w)) return "Use the console tab of the other unit: in FortiTatake each cluster member has its own console.";
  return null;
};
