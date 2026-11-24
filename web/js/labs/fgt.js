// FortiGate device model and CLI shell for FortiTatake labs. No DOM, so Node can test it.
// Config lives in tables and objects shaped by the 8.0.2 schema; behaviour lives in sim.js / diag.js.
import { parsePrefix, ipMaskStr, ipToInt, isIp, maskToLen, hex, rng } from "./net.js";

const STRINGY = new Set(["string", "var-string", "user", "text"]);

// Attributes that point at other objects: used for validation, completion, rename and delete checks.
export const REFS = {
  "firewall policy": { srcintf: "intf", dstintf: "intf", srcaddr: "addr", dstaddr: "daddr", service: "svc", schedule: "sched", poolname: "pool" },
  "router static": { device: "intfonly" },
  "router policy": { "input-device": "intfonly", "output-device": "intfonly" },
  "system dhcp server": { interface: "intfonly" },
  "firewall vip": { extintf: "intfany" },
  "firewall addrgrp": { member: "addr" },
  "firewall vipgrp": { member: "vip", interface: "intfany" },
  "firewall service group": { member: "svc" },
  "system zone": { interface: "intfonly" },
  "system interface": { interface: "intfonly" },
  "firewall address": { "associated-interface": "intf" },
  "system admin": { accprofile: "accprofile" },
};
const MANDATORY = {
  "firewall policy": ["srcintf", "dstintf", "srcaddr", "dstaddr", "service", "schedule"],
  "firewall vip": ["extip", "mappedip"],
};
// The order FortiOS prints common attributes in `show`; the rest follow in the order they were set.
const ORDER = {
  "system interface": ["vdom", "mode", "ip", "allowaccess", "status", "type", "alias", "description", "role", "snmp-index", "interface", "vlanid"],
  "firewall policy": ["name", "uuid", "srcintf", "dstintf", "action", "srcaddr", "dstaddr", "schedule", "service", "utm-status", "inspection-mode", "ssl-ssh-profile", "av-profile", "webfilter-profile", "ips-sensor", "application-list", "logtraffic", "ippool", "poolname", "nat", "comments"],
  "firewall address": ["uuid", "type", "comment", "associated-interface", "subnet", "start-ip", "end-ip", "fqdn"],
  "firewall vip": ["uuid", "comment", "extip", "mappedip", "extintf", "portforward", "protocol", "extport", "mappedport"],
  "router static": ["status", "dst", "gateway", "distance", "priority", "device", "blackhole", "comment"],
  "system dhcp server": ["status", "lease-time", "dns-service", "default-gateway", "netmask", "interface", "dns-server1", "dns-server2"],
};

export class Entry {
  constructor(key) { this.key = key; this.attrs = new Map(); this.children = new Map(); }
  clone() {
    const e = new Entry(this.key);
    for (const [k, v] of this.attrs) e.attrs.set(k, v.slice());
    for (const [k, c] of this.children) e.children.set(k, c.clone());
    return e;
  }
}
export class Table {
  constructor() { this.entries = new Map(); }
  clone() { const t = new Table(); for (const [k, e] of this.entries) t.entries.set(k, e.clone()); return t; }
  list() { return [...this.entries.values()]; }
}

// Split a CLI line into tokens, honouring "double" and 'single' quotes.
export function tokenize(line) {
  const out = [];
  let cur = "", q = null, had = false;
  for (const ch of line) {
    if (q) { if (ch === q) { q = null; } else cur += ch; continue; }
    if (ch === '"' || ch === "'") { q = ch; had = true; continue; }
    if (/\s/.test(ch)) { if (cur || had) out.push(cur); cur = ""; had = false; continue; }
    cur += ch;
  }
  if (cur || had) out.push(cur);
  return out;
}
// The 8.0.2 CLI Reference has no `get` chapter: these are the common ones the simulator answers.
export const GET_CMDS = ["get system status", "get system interface", "get system interface physical", "get system arp", "get system performance status", "get system ha status",
  "get router info routing-table all", "get router info routing-table database", "get router info routing-table details <ip>", "get router info bgp summary", "get router info ospf neighbor",
  "get vpn ipsec tunnel summary", "get system sdwan service"];
const quote = (v) => `"${String(v).replace(/"/g, '\\"')}"`;
const pad = (s, n) => (s.length >= n ? s + " " : s + " ".repeat(n - s.length));

export class FortiGate {
  constructor(spec, schema) {
    this.id = spec.id;
    this.kind = "fortigate";
    this.model = spec.model || "FortiGate-VM64";
    this.version = "v8.0.2";
    this.serial = spec.serial || "FGVM02TM" + String(Math.abs(hashStr(spec.id)) % 100000000).padStart(8, "0");
    this.schema = schema;
    this.P = schema.paths;
    this.cfg = new Map();
    this.frames = [];
    this.history = [];
    this.pending = null; // y/n confirmation
    this.rand = rng(hashStr(spec.id) || 7);
    this.diag = null; // set by the simulator: (dev, tokens, line) => output
    this.ports = (spec.ports || []).map((p) => (typeof p === "string" ? { name: p } : p));
    this.load(factory(this, spec));
    if (spec.config) this.load(spec.config);
    this.history = [];
  }

  // ---------- config access ----------
  hostname() { const g = this.cfg.get("system global"); return (g && g.attrs.get("hostname") || [this.id])[0]; }
  sch(path) { return this.P[path]; }
  inst(path, create = true) {
    let n = this.cfg.get(path);
    if (!n && create) {
      const s = this.P[path];
      if (!s) return null;
      n = s.t === "table" ? new Table() : new Entry(null);
      this.cfg.set(path, n);
    }
    return n;
  }
  entries(path) { const t = this.cfg.get(path); return t instanceof Table ? t.list() : []; }
  entry(path, key) { const t = this.cfg.get(path); return t instanceof Table ? t.entries.get(String(key)) : null; }
  obj(path) { return this.inst(path); }
  // value tokens of an attribute, falling back to the schema default
  val(path, e, attr, childPath) {
    if (!e) return [];
    const v = e.attrs.get(attr);
    if (v) return v;
    const sp = this.specOf(path, attr, childPath);
    return sp && sp.d !== undefined ? splitDefault(sp) : [];
  }
  one(path, e, attr, childPath) { return this.val(path, e, attr, childPath)[0]; }
  specOf(path, attr, childPath) {
    let n = this.P[path];
    for (const c of childPath || []) n = n && n.c && n.c[c];
    return n && n.a[attr];
  }

  // names usable for a reference kind
  refNames(kind) {
    const names = (p) => this.entries(p).map((e) => e.key);
    switch (kind) {
      case "intf": return [...names("system interface"), ...names("system zone"), ...names("system sdwan:zone"), "any"];
      case "intfonly": return names("system interface");
      case "intfany": return [...names("system interface"), "any"];
      case "addr": return [...names("firewall address"), ...names("firewall addrgrp")];
      case "daddr": return [...names("firewall address"), ...names("firewall addrgrp"), ...names("firewall vip"), ...names("firewall vipgrp")];
      case "vip": return names("firewall vip");
      case "svc": return [...names("firewall service custom"), ...names("firewall service group")];
      case "sched": return [...names("firewall schedule recurring"), ...names("firewall schedule onetime"), ...names("firewall schedule group")];
      case "pool": return names("firewall ippool");
      case "accprofile": return [...names("system accprofile"), "super_admin", "prof_admin"];
      default: return [];
    }
  }

  // ---------- CLI ----------
  prompt() {
    const f = this.frames[this.frames.length - 1];
    return f ? `${this.hostname()} (${f.label}) # ` : `${this.hostname()} # `;
  }
  load(script) {
    const errs = [];
    for (const raw of String(script).split("\n")) {
      const line = raw.trim();
      if (!line || line.startsWith("#")) continue;
      const out = this.exec(line, true);
      if (/Command fail|parse error|not found/i.test(out)) errs.push(`${line}: ${out.trim()}`);
    }
    while (this.frames.length) this.exec("end", true);
    if (errs.length && typeof console !== "undefined") console.warn(`[${this.id}] config load:`, errs.join("\n"));
    return errs;
  }
  // run one typed line, return the text the console shows (without the next prompt)
  run(line) {
    const h = { line, ts: Date.now(), frame: this.frames.map((f) => f.label).join("/") };
    this.history.push(h);
    h.out = this.exec(line, false);
    return h.out;
  }

  exec(line, quiet) {
    const t = line.trim();
    if (!t) return "";
    if (this.pending) {
      const p = this.pending; this.pending = null;
      if (/^y/i.test(t)) return p() || "";
      return "";
    }
    const toks = tokenize(t);
    const f = this.frames[this.frames.length - 1];
    const cmd = toks[0];
    try {
      if (!f) return this.top(toks, t);
      if (f.type === "table") return this.inTable(f, toks, t);
      return this.inEntry(f, toks, t);
    } catch (e) {
      return `Command fail. ${e.message}`;
    }
  }

  top(toks, line) {
    const c = pick(toks[0], ["config", "show", "get", "diagnose", "execute", "exit", "tree", "alias"]);
    if (!c) return "Unknown action 0\nCommand fail. Return code -1";
    if (c === "config") {
      const path = this.matchPath(toks.slice(1));
      if (!path) return `command parse error before '${toks[1] || ""}'\nCommand fail. Return code -61`;
      return this.enter(path);
    }
    if (c === "show") {
      let rest = toks.slice(1), full = false;
      if (rest[0] && "full-configuration".startsWith(rest[0]) && rest[0].length >= 4) { full = true; rest = rest.slice(1); }
      if (!rest.length) return this.showAll(full);
      const path = this.matchPath(rest.filter((x) => !this.cfg.has(x)).slice(0, 4)) || this.matchPath(rest.slice(0, rest.length - 1));
      if (!path) return `command parse error before '${rest[0]}'\nCommand fail. Return code -61`;
      const n = path.split(" ").length;
      const key = rest.length > n ? rest[n] : null;
      return this.showPath(path, full, key);
    }
    if (c === "exit") return "";
    if (c === "tree") return Object.keys(this.P).slice(0, 60).map((p) => "-- " + p).join("\n");
    if (this.diag) return this.diag(this, toks, line);
    return "Command fail. Return code -1";
  }

  matchPath(toks) {
    if (!toks.length) return null;
    const words = toks.join(" ");
    if (this.P[words]) return words;
    const cands = Object.keys(this.P).filter((p) => {
      const w = p.split(" ");
      return w.length === toks.length && w.every((x, i) => x.startsWith(toks[i]));
    });
    if (cands.length === 1) return cands[0];
    const exact = cands.filter((p) => p.split(" ").every((x, i) => x === toks[i] || i === toks.length - 1));
    return exact.length === 1 ? exact[0] : null;
  }

  enter(path) {
    const s = this.P[path];
    const label = path.split(" ").pop();
    if (s.t === "table") {
      this.frames.push({ type: "table", path, sch: s, table: this.inst(path), label, child: [] });
    } else {
      const live = this.inst(path);
      this.frames.push({ type: "object", path, sch: s, entry: live.clone(), commit: (e) => this.cfg.set(path, e), label, child: [] });
    }
    return "";
  }

  // ----- table context: edit, delete, move, rename, clone, purge, show, end -----
  inTable(f, toks, line) {
    const c = pick(toks[0], ["edit", "delete", "purge", "rename", "clone", "move", "show", "get", "end", "abort", "next"]);
    const table = f.table;
    switch (c) {
      case "edit": {
        if (toks.length < 2) return "command parse error before 'edit'\nCommand fail. Return code -61";
        let key = toks[1];
        const keySpec = f.sch.a[f.sch.k];
        if (keySpec && keySpec.y === "integer") {
          if (!/^\d+$/.test(key)) return `value parse error before '${key}'\nCommand fail. Return code -651`;
          if (key === "0") {
            const ids = table.list().map((e) => Number(e.key));
            key = String((ids.length ? Math.max(...ids) : 0) + 1);
          }
        }
        const live = table.entries.get(key);
        const e = live ? live.clone() : new Entry(key);
        if (!live) {
          const sp = f.sch.a.uuid;
          if (sp && f.child.length === 0) e.attrs.set("uuid", [this.uuid()]);
        }
        const out = !live && toks[1] === "0" ? `new entry '${key}' added` : "";
        this.frames.push({ type: "entry", path: f.path, sch: f.sch, entry: e, table, isNew: !live, label: key, child: f.child, commit: (en) => { table.entries.set(en.key, en); } });
        return out;
      }
      case "delete": {
        const key = toks[1];
        if (!table.entries.has(key)) return "entry not found in datasource\nCommand fail. Return code -3";
        if (f.child.length === 0) {
          const users = this.usersOf(f.path, key);
          if (users.length) return `The entry is used by other ${users.length} entries\nCommand fail. Return code -23`;
        }
        table.entries.delete(key);
        return "";
      }
      case "purge":
        this.pending = () => { table.entries.clear(); return ""; };
        return "This operation will clear all table!\nDo you want to continue? (y/n)";
      case "rename": {
        // rename <old> to <new>
        const [, a, to, b] = toks;
        if (to !== "to" || !b) return "command parse error before 'rename'\nCommand fail. Return code -61";
        const e = table.entries.get(a);
        if (!e) return "entry not found in datasource\nCommand fail. Return code -3";
        if (table.entries.has(b)) return "Duplicate entry name\nCommand fail. Return code -15";
        const list = table.list().map((x) => (x === e ? Object.assign(e, { key: b }) : x));
        table.entries = new Map(list.map((x) => [x.key, x]));
        this.renameRefs(f.path, a, b);
        return "";
      }
      case "clone": {
        const [, a, to, b] = toks;
        const e = table.entries.get(a);
        if (to !== "to" || !b || !e) return "entry not found in datasource\nCommand fail. Return code -3";
        const n = e.clone(); n.key = b;
        if (n.attrs.has("uuid")) n.attrs.set("uuid", [this.uuid()]);
        table.entries.set(b, n);
        return "";
      }
      case "move": {
        // move <id> before|after <id>
        const [, a, where, b] = toks;
        if (!table.entries.has(a) || !table.entries.has(b) || !["before", "after"].includes(where)) return "entry not found in datasource\nCommand fail. Return code -3";
        const list = table.list().filter((x) => x.key !== a);
        const i = list.findIndex((x) => x.key === b);
        list.splice(where === "before" ? i : i + 1, 0, table.entries.get(a));
        table.entries = new Map(list.map((x) => [x.key, x]));
        return "";
      }
      case "show": {
        const full = toks[1] && "full-configuration".startsWith(toks[1]) && toks[1].length >= 4;
        const key = full ? toks[2] : toks[1];
        return this.renderTable(f.path, f.sch, table, 0, !!full, key, f.child.length ? f.label : null);
      }
      case "get": return table.list().map((e) => `== [ ${e.key} ]\n` + this.getLines(f.sch, e, true)).join("\n");
      case "end": case "abort": case "next":
        this.frames.pop();
        return "";
      default:
        return `command parse error before '${toks[0]}'\nCommand fail. Return code -61`;
    }
  }

  // ----- entry / object context: set, unset, append, select, config <child>, show, get, next, end, abort -----
  inEntry(f, toks, line) {
    const c = pick(toks[0], ["set", "unset", "append", "select", "unselect", "config", "show", "get", "next", "end", "abort"]);
    const e = f.entry;
    switch (c) {
      case "set": case "append": case "select": case "unselect": {
        const name = pick(toks[1], Object.keys(f.sch.a), true);
        if (!name) return `command parse error before '${toks[1] || ""}'\nCommand fail. Return code -61`;
        const sp = f.sch.a[name];
        const vals = toks.slice(2);
        if (!vals.length) return `command parse error before '${name}'\nCommand fail. Return code -61`;
        const r = this.validate(f, name, sp, vals);
        if (r.err) return r.err;
        if (c === "set") e.attrs.set(name, r.val);
        else if (c === "append" || c === "select") e.attrs.set(name, uniq([...(e.attrs.get(name) || []), ...r.val]));
        else e.attrs.set(name, (e.attrs.get(name) || []).filter((v) => !r.val.includes(v)));
        return "";
      }
      case "unset": {
        const name = pick(toks[1], Object.keys(f.sch.a), true);
        if (!name) return `command parse error before '${toks[1] || ""}'\nCommand fail. Return code -61`;
        e.attrs.delete(name);
        return "";
      }
      case "config": {
        const names = Object.keys(f.sch.c || {});
        const name = pick(toks[1], names, true);
        if (!name) return `command parse error before '${toks[1] || ""}'\nCommand fail. Return code -61`;
        const cs = f.sch.c[name];
        let inst = e.children.get(name);
        if (!inst) { inst = cs.t === "table" ? new Table() : new Entry(null); e.children.set(name, inst); }
        const child = [...f.child, name];
        if (cs.t === "table") this.frames.push({ type: "table", path: f.path, sch: cs, table: inst, label: name, child });
        else this.frames.push({ type: "object", path: f.path, sch: cs, entry: inst, label: name, child, commit: () => {} });
        return "";
      }
      case "show": {
        const full = toks[1] && "full-configuration".startsWith(toks[1]) && toks[1].length >= 4;
        if (f.type === "object") return this.renderObject(f.child.length ? f.label : f.path, f.sch, e, 0, !!full, f.path);
        const t = new Table(); t.entries.set(e.key, e);
        return this.renderTable(f.path, f.sch, t, 0, !!full, null, f.child.length ? this.frames[this.frames.length - 2].label : null);
      }
      case "get": return this.getLines(f.sch, e, false);
      case "next": {
        if (f.type !== "entry") return "";
        const err = this.commitEntry(f);
        if (err) return err;
        this.frames.pop();
        return "";
      }
      case "end": {
        if (f.type === "entry") {
          const err = this.commitEntry(f);
          if (err) return err;
          this.frames.pop();
          this.frames.pop();
          return "";
        }
        if (f.commit) f.commit(e);
        this.frames.pop();
        return "";
      }
      case "abort":
        this.frames.pop();
        if (f.type === "entry") this.frames.pop();
        return "";
      default:
        return `command parse error before '${toks[0]}'\nCommand fail. Return code -61`;
    }
  }

  commitEntry(f) {
    if (f.child.length === 0) {
      for (const m of MANDATORY[f.path] || []) {
        if (!f.entry.attrs.get(m) || !f.entry.attrs.get(m).length) {
          return `node_check_object fail! for ${m}\n\nattribute set operator error, -3, discard the setting\nCommand fail. Return code -3`;
        }
      }
    }
    f.commit(f.entry);
    if (this.onCommit) this.onCommit(this, f.path, f.entry.key);
    return "";
  }

  validate(f, name, sp, vals) {
    const bad = (v, code = 651) => ({ err: `value parse error before '${v}'\nCommand fail. Return code -${code}` });
    const y = sp.y || "string";
    if (y === "option") {
      const out = [];
      for (const v of vals) {
        const o = sp.o ? pick(v, sp.o, true) : v;
        if (!o) return bad(v);
        out.push(o);
      }
      if (!sp.m && out.length > 1) return { err: `command parse error before '${vals[1]}'\nCommand fail. Return code -61` };
      return { val: out };
    }
    if (y === "integer") {
      if (vals.length > 1) return { err: `command parse error before '${vals[1]}'\nCommand fail. Return code -61` };
      if (!/^-?\d+$/.test(vals[0])) return bad(vals[0]);
      const n = Number(vals[0]);
      if ((sp.mn !== undefined && n < sp.mn) || (sp.mx !== undefined && n > sp.mx)) return bad(vals[0]);
      return { val: [String(n)] };
    }
    if (/^ipv4-classnet|^ipv4-address|^ipv4-netmask/.test(y)) {
      const txt = vals.join(" ");
      if (/netmask/.test(y)) { return maskToLen(txt) === null ? bad(txt) : { val: [txt] }; }
      if (/^ipv4-address/.test(y)) {
        if (vals.length !== 1 || !isIp(vals[0])) return bad(vals[0]);
        return { val: [vals[0]] };
      }
      const p = parsePrefix(txt, y === "ipv4-classnet-host" ? 32 : 32);
      if (!p || vals.length > 2) return bad(vals[0]);
      if (y === "ipv4-classnet-host") return { val: [ipMaskStr(p)] };
      return { val: [ipMaskStr({ ip: (p.ip & (p.len ? (0xffffffff << (32 - p.len)) >>> 0 : 0)) >>> 0, len: p.len })] };
    }
    if (/^password/.test(y)) return { val: [vals.join(" ")] };
    // strings and references
    if (!sp.m && vals.length > 1 && STRINGY.has(y) && name !== "comment" && name !== "comments" && name !== "description") {
      if (y !== "user") return { err: `command parse error before '${vals[1]}'\nCommand fail. Return code -61` };
    }
    const kind = f.child.length === 0 && REFS[f.path] && REFS[f.path][name];
    if (kind) {
      const okNames = this.refNames(kind);
      for (const v of vals) {
        if (!okNames.includes(v) && !(kind === "addr" && v === "all") && !(kind === "daddr" && v === "all")) {
          return { err: `entry not found in datasource\n\nvalue parse error before '${v}'\nCommand fail. Return code -3` };
        }
      }
    }
    if (f.path === "system zone" && name === "interface" && f.child.length === 0) {
      for (const v of vals) {
        const used = this.entries("firewall policy").filter((p) => ["srcintf", "dstintf"].some((a) => (p.attrs.get(a) || []).includes(v)));
        if (used.length) return { err: `Interface ${v} is used by firewall policy ${used.map((p) => p.key).join(", ")}; remove it from the policies first.\nCommand fail. Return code -23` };
      }
    }
    if (sp.ml && vals.some((v) => v.length > sp.ml)) return bad(vals.find((v) => v.length > sp.ml));
    if (y === "user" && !sp.m) return { val: [vals.join(" ")] };
    return { val: vals };
  }

  usersOf(path, key) {
    const out = [];
    for (const [p, refs] of Object.entries(REFS)) {
      for (const e of this.entries(p)) {
        for (const [attr, kind] of Object.entries(refs)) {
          if (!kindCovers(kind, path)) continue;
          if ((e.attrs.get(attr) || []).includes(key)) out.push(`${p} ${e.key}`);
        }
      }
    }
    return out;
  }
  renameRefs(path, a, b) {
    for (const [p, refs] of Object.entries(REFS)) {
      for (const e of this.entries(p)) {
        for (const [attr, kind] of Object.entries(refs)) {
          if (!kindCovers(kind, path)) continue;
          const v = e.attrs.get(attr);
          if (v && v.includes(a)) e.attrs.set(attr, v.map((x) => (x === a ? b : x)));
        }
      }
    }
  }
  uuid() {
    const r = () => hex(Math.floor(this.rand() * 4294967296));
    const a = r(), b = r(), c = r(), d = r();
    return `${a}-${b.slice(0, 4)}-51ef-${c.slice(0, 4)}-${c.slice(4)}${d}`.slice(0, 36);
  }

  // ---------- rendering ----------
  fmt(sp, vals) {
    const y = (sp && sp.y) || "string";
    if (/^password/.test(y)) return "ENC " + Buffer64(vals[0] || "");
    if (STRINGY.has(y) && y !== "user") return vals.map(quote).join(" ");
    if (y === "user") return vals.map((v) => (/\s/.test(v) || /[a-z]/i.test(v) && !/^\d/.test(v) ? quote(v) : v)).join(" ");
    return vals.join(" ");
  }
  attrOrder(path, sch, e, full, child) {
    const keys = full ? Object.keys(sch.a) : [...e.attrs.keys()];
    const pref = (!child && ORDER[path]) || [];
    const rest = keys.filter((k) => !pref.includes(k));
    return [...pref.filter((k) => keys.includes(k)), ...(full ? rest.sort() : rest)].filter((k) => k !== sch.k && !k.includes(" "));
  }
  renderBody(path, sch, e, ind, full, child) {
    const sp = " ".repeat(ind);
    const lines = [];
    for (const k of this.attrOrder(path, sch, e, full, child)) {
      if (k.startsWith("<")) continue;
      const s = sch.a[k];
      let v = e.attrs.get(k);
      if (!v) {
        if (!full) continue;
        v = s && s.d !== undefined ? splitDefault(s) : [];
        if (!v.length) { lines.push(`${sp}set ${k} ${STRINGY.has(s && s.y) && s.y !== "user" ? '""' : ""}`.trimEnd()); continue; }
      } else if (!full && s && s.d !== undefined && v.join(" ") === String(s.d) && k !== "uuid") continue;
      lines.push(`${sp}set ${k} ${this.fmt(s, v)}`);
    }
    for (const [name, inst] of e.children) {
      const cs = sch.c && sch.c[name];
      if (!cs) continue;
      if (inst instanceof Table) { if (inst.entries.size || full) lines.push(this.renderTable(name, cs, inst, ind, full, null, name, true)); }
      else { const body = this.renderBody(name, cs, inst, ind + 4, full, true); if (body || full) lines.push(`${sp}config ${name}\n${body}${body ? "\n" : ""}${sp}end`); }
    }
    return lines.filter(Boolean).join("\n");
  }
  renderTable(path, sch, table, ind, full, onlyKey, childName, nested) {
    const sp = " ".repeat(ind);
    const keyIsInt = sch.a[sch.k] && sch.a[sch.k].y === "integer";
    const out = [`${sp}config ${childName || path}`];
    for (const e of table.list()) {
      if (onlyKey && e.key !== onlyKey) continue;
      out.push(`${sp}    edit ${keyIsInt ? e.key : quote(e.key)}`);
      const body = this.renderBody(path, sch, e, ind + 8, full, !!childName);
      if (body) out.push(body);
      out.push(`${sp}    next`);
    }
    out.push(`${sp}end`);
    return out.join("\n");
  }
  renderObject(path, sch, e, ind, full, realPath) {
    const body = this.renderBody(realPath || path, sch, e, ind + 4, full, path !== realPath);
    return `config ${path}\n${body}${body ? "\n" : ""}end`;
  }
  showPath(path, full, key) {
    const s = this.P[path];
    const n = this.inst(path);
    if (s.t === "table") return this.renderTable(path, s, n, 0, full, key);
    return this.renderObject(path, s, n, 0, full);
  }
  showAll(full) {
    const out = [`#config-version=FGVM64-8.0.2-FW-build0000:opmode=0:vdom=0:user=admin`, `#conf_file_ver=0`, `#buildno=0000`, `#global_vdom=1`];
    for (const [path, n] of this.cfg) {
      const s = this.P[path];
      if (n instanceof Table && !n.entries.size) continue;
      if (n instanceof Entry && !n.attrs.size && !n.children.size && !full) continue;
      out.push(n instanceof Table ? this.renderTable(path, s, n, 0, full) : this.renderObject(path, s, n, 0, full));
    }
    return out.join("\n");
  }
  getLines(sch, e, compact) {
    const lines = [];
    const keys = Object.keys(sch.a).filter((k) => !k.startsWith("<") && !k.includes(" ") && k !== sch.k);
    for (const k of compact ? [...e.attrs.keys()] : keys) {
      const s = sch.a[k];
      const v = e.attrs.get(k) || (s.d !== undefined ? splitDefault(s) : []);
      const txt = s.m && STRINGY.has(s.y) ? v.map(quote).join(" ") : /^password/.test(s.y || "") ? "*" : v.join(" ");
      lines.push(`${pad(k, 20)}: ${txt}`);
    }
    for (const name of Object.keys(sch.c || {})) lines.push(`${pad(name, 20)}:`);
    return lines.join("\n");
  }

  // ---------- help and completion ----------
  candidates(toks, partial) {
    const f = this.frames[this.frames.length - 1];
    const n = toks.length; // tokens already complete before the one being typed
    if (!f) {
      if (n === 0) return ["config", "show", "get", "diagnose", "execute", "exit"];
      const c = pick(toks[0], ["config", "show", "get", "diagnose", "execute"]);
      if (c === "config" || c === "show") {
        const words = toks.slice(1);
        const set = new Set();
        for (const p of Object.keys(this.P)) {
          const w = p.split(" ");
          if (w.length > words.length && words.every((x, i) => w[i].startsWith(x))) set.add(w[words.length]);
        }
        if (c === "show" && words.length === 0) set.add("full-configuration");
        return [...set].sort();
      }
      if (c === "get" || c === "diagnose" || c === "execute") {
        const set = new Set();
        for (const cmd of [...this.schema.cmds, ...GET_CMDS]) {
          const w = cmd.split(" ").filter((x) => !/^[<{[]/.test(x));
          if (w[0] !== c || w.length <= n) continue;
          if (toks.slice(1).every((x, i) => w[i + 1] && w[i + 1].startsWith(x))) set.add(w[n]);
        }
        return [...set].sort();
      }
      return [];
    }
    if (f.type === "table") {
      if (n === 0) return ["edit", "delete", "purge", "rename", "clone", ...(f.path === "firewall policy" ? ["move"] : []), "show", "get", "end", "abort"];
      if (["edit", "delete", "rename", "clone", "move"].includes(pick(toks[0], ["edit", "delete", "rename", "clone", "move"]))) return f.table.list().map((e) => e.key);
      return [];
    }
    if (n === 0) return [...(f.type === "entry" ? ["next"] : []), "set", "unset", "append", "select", "unselect", ...(Object.keys(f.sch.c || {}).length ? ["config"] : []), "show", "get", "end", "abort"];
    const c = pick(toks[0], ["set", "unset", "append", "select", "unselect", "config"]);
    if (c === "config") return n === 1 ? Object.keys(f.sch.c || {}) : [];
    if (n === 1) return Object.keys(f.sch.a).filter((k) => !k.startsWith("<"));
    if (c === "unset") return [];
    const name = pick(toks[1], Object.keys(f.sch.a), true);
    const sp = name && f.sch.a[name];
    if (!sp) return [];
    if (sp.o) return sp.o;
    const kind = f.child.length === 0 && REFS[f.path] && REFS[f.path][name];
    if (kind) return [...this.refNames(kind), ...(kind === "addr" || kind === "daddr" ? ["all"] : [])].filter((v, i, a) => a.indexOf(v) === i);
    return [];
  }
  // `?` help text for the line typed so far
  help(line) {
    const body = line.replace(/\?$/, "");
    const toks = tokenize(body);
    const trailing = /\s$/.test(body) || body === "";
    const done = trailing ? toks : toks.slice(0, -1);
    const part = trailing ? "" : toks[toks.length - 1] || "";
    const f = this.frames[this.frames.length - 1];
    let c = this.candidates(done, part).filter((x) => x.startsWith(part));
    if (f && f.type !== "table" && done.length === 1 && ["set", "append", "select"].includes(pick(done[0], ["set", "append", "select"]))) {
      return c.map((k) => `${pad(k, 26)}${describe(f.sch.a[k])}`).join("\n");
    }
    if (f && f.type !== "table" && done.length >= 2) {
      const name = pick(done[1], Object.keys(f.sch.a), true);
      const sp = name && f.sch.a[name];
      if (sp && !c.length) return `<${sp.y}>    ${describe(sp)}`;
    }
    return c.length ? c.join("\n") : "<Enter>";
  }
  // Tab completion: returns the completed line (or the same line plus a list of choices)
  complete(line) {
    const toks = tokenize(line);
    const trailing = /\s$/.test(line) || line === "";
    const done = trailing ? toks : toks.slice(0, -1);
    const part = trailing ? "" : toks[toks.length - 1] || "";
    const c = this.candidates(done, part).filter((x) => x.startsWith(part));
    if (c.length === 1) {
      const needsQuote = /\s/.test(c[0]);
      return { line: (done.length ? done.map((t) => (/\s/.test(t) ? quote(t) : t)).join(" ") + " " : "") + (needsQuote ? quote(c[0]) : c[0]) + " ", choices: [] };
    }
    if (c.length > 1) {
      let common = c[0];
      for (const x of c) while (!x.startsWith(common)) common = common.slice(0, -1);
      return { line: (done.length ? done.join(" ") + " " : "") + (common.length > part.length ? common : part), choices: c };
    }
    return { line, choices: [] };
  }

  snapshot() {
    const o = {};
    for (const [p, n] of this.cfg) o[p] = n instanceof Table ? this.renderTable(p, this.P[p], n, 0, false) : this.renderObject(p, this.P[p], n, 0, false);
    return o;
  }
}

function kindCovers(kind, path) {
  const m = {
    intf: ["system interface", "system zone"], intfonly: ["system interface"], intfany: ["system interface"],
    addr: ["firewall address", "firewall addrgrp"], daddr: ["firewall address", "firewall addrgrp", "firewall vip", "firewall vipgrp"],
    vip: ["firewall vip"], svc: ["firewall service custom", "firewall service group"],
    sched: ["firewall schedule recurring", "firewall schedule onetime", "firewall schedule group"], pool: ["firewall ippool"],
  };
  return (m[kind] || []).includes(path);
}
function describe(sp) {
  if (!sp) return "";
  if (sp.o) return (sp.m ? "multiple: " : "") + sp.o.slice(0, 8).join("|") + (sp.o.length > 8 ? "|..." : "");
  if (sp.y === "integer") return `integer${sp.mn !== undefined ? ` ${sp.mn}-${sp.mx}` : ""}`;
  return `${sp.y}${sp.m ? " (one or more)" : ""}${sp.ml ? `, max ${sp.ml}` : ""}`;
}
function splitDefault(sp) {
  const d = String(sp.d);
  if (/^ipv4-classnet/.test(sp.y || "")) return [d];
  return d === "" ? [] : d.split(" ");
}
function uniq(a) { return a.filter((v, i) => a.indexOf(v) === i); }
// unique-prefix match of a typed word against choices (exact wins); null when ambiguous or unknown
export function pick(w, choices, exactFirst = true) {
  if (w === undefined || w === null) return null;
  if (choices.includes(w)) return w;
  const c = choices.filter((x) => x.startsWith(w));
  return c.length === 1 ? c[0] : null;
}
export function hashStr(s) {
  let h = 2166136261;
  for (const ch of String(s)) { h ^= ch.charCodeAt(0); h = Math.imul(h, 16777619); }
  return h >>> 0;
}
function Buffer64(s) {
  let h = hashStr(s), out = "";
  for (let i = 0; i < 6; i++) { out += hex(h); h = Math.imul(h ^ (h >>> 13), 2246822507) >>> 0; }
  return out.slice(0, 44);
}

// Factory defaults written as CLI so they go through the same parser.
const SERVICES = [
  ["ALL", "set protocol IP"], ["ALL_TCP", 'set tcp-portrange 1-65535'], ["ALL_UDP", 'set udp-portrange 1-65535'],
  ["ALL_ICMP", "set protocol ICMP"], ["PING", "set protocol ICMP\nset icmptype 8"], ["HTTP", "set tcp-portrange 80"],
  ["HTTPS", "set tcp-portrange 443"], ["DNS", "set tcp-portrange 53\nset udp-portrange 53"], ["SSH", "set tcp-portrange 22"],
  ["TELNET", "set tcp-portrange 23"], ["FTP", "set tcp-portrange 21"], ["SMTP", "set tcp-portrange 25"], ["SMTPS", "set tcp-portrange 465"],
  ["IMAPS", "set tcp-portrange 993"], ["NTP", "set tcp-portrange 123\nset udp-portrange 123"], ["RDP", "set tcp-portrange 3389"],
  ["SNMP", "set tcp-portrange 161-162\nset udp-portrange 161-162"], ["SMB", "set tcp-portrange 445"], ["LDAP", "set tcp-portrange 389"],
  ["KERBEROS", "set tcp-portrange 88\nset udp-portrange 88"], ["MYSQL", "set tcp-portrange 3306"], ["MS-SQL", "set tcp-portrange 1433 1434"],
  ["SIP", "set udp-portrange 5060"], ["SYSLOG", "set udp-portrange 514"], ["DHCP", "set udp-portrange 67-68"],
  ["TRACEROUTE", "set udp-portrange 33434-33535"], ["IKE", "set udp-portrange 500 4500"],
];
function factory(dev, spec) {
  const host = spec.hostname || spec.id;
  const lines = [`config system global`, `set hostname "${host}"`, `set alias "${spec.model || "FortiGate-VM64"}"`, `end`, `config system interface`];
  dev.ports.forEach((p, i) => {
    lines.push(`edit "${p.name}"`, `set vdom "root"`, `set type physical`, `set snmp-index ${i + 1}`);
    if (p.role) lines.push(`set role ${p.role}`);
    lines.push("next");
  });
  lines.push("end", "config firewall address", 'edit "all"', "next", 'edit "none"', "set subnet 0.0.0.0 255.255.255.255", "next", "end");
  lines.push("config firewall service custom");
  for (const [n, body] of SERVICES) lines.push(`edit "${n}"`, ...body.split("\n"), "next");
  lines.push("end", "config firewall schedule recurring", 'edit "always"', "set day sunday monday tuesday wednesday thursday friday saturday", "next", "end");
  lines.push("config system admin", 'edit "admin"', 'set accprofile "super_admin"', 'set vdom "root"', "next", "end");
  return lines.join("\n");
}
