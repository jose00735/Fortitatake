// The FortiGate IPS for labs: threat packs (content/threats) are the only signatures.
// - sensor compile: `config ips sensor` entries pick signatures by rule id, severity, location,
//   OS, application, protocol or CVE, each with an action (pass, block, reset, default);
// - the real engine: compile.js turns each policy's sensor into an NFQUEUE rule and the agent
//   matches (ftkos/agent/ips.go);
// - the simulator: the same matcher on the same requests, so both engines agree;
// - utm/ips logs in FortiOS fields, for the log views, FortiAnalyzer and FortiSIEM.
// The matcher mirrors tools/build_threats.py and the agent's.
import { Lab } from "./sim.js";
import { intToIp, ipToInt } from "./net.js";

export const ATTACKER_IP = "198.51.100.66"; // the lab Internet's attacker (documentation space)

export function fillRequest(tpl, vars) {
  let t = tpl.replace(/\{\{target_host\}\}/g, vars.target || "web.lab").replace(/\{\{sinkhole\}\}/g, vars.sinkhole || "198.51.100.250").replace(/\{\{token\}\}/g, vars.token || "ftk-0000");
  t = t.split("\n").join("\r\n");
  if (!t.includes("\r\n\r\n")) t += "\r\n\r\n";
  return t;
}

export function httpBuffers(p) {
  const i = p.indexOf("\r\n\r\n");
  const head = i < 0 ? p : p.slice(0, i), body = i < 0 ? "" : p.slice(i + 4);
  const lines = head.split("\r\n");
  const f = lines[0].split(" ");
  let uri = f[1] || "";
  try { uri = decodeURIComponent(uri); } catch (e) { /* malformed escapes stay as sent */ }
  return { method: f[0] || "", uri, header: lines.slice(1).join("\r\n"), body, raw: p };
}

const reCache = new Map();
function condOk(c, b) {
  const s = b[c.buf] || "";
  if (c.regex !== undefined) {
    const k = c.regex + (c.nocase ? "/i" : "");
    if (!reCache.has(k)) reCache.set(k, new RegExp(c.regex, c.nocase ? "i" : ""));
    return reCache.get(k).test(s);
  }
  return c.nocase ? s.toLowerCase().includes(c.contains.toLowerCase()) : s.includes(c.contains);
}
export function sigMatches(sig, bufs, port) {
  if (sig.ports && sig.ports.length && port !== undefined && !sig.ports.includes(port)) return false;
  return sig.match.every((c) => condOk(c, bufs));
}

const SEV = ["info", "low", "medium", "high", "critical"];
const defaultAction = (pack) => (SEV.indexOf(pack.severity) >= 3 ? "block" : "pass");
// built-in sensors a FortiGate ships with (the ones labs are likely to name)
const BUILTIN = {
  default: [{ action: "default" }],
  all_default: [{ action: "default" }],
  all_default_pass: [{ action: "pass" }],
  high_security: [{ severity: ["medium", "high", "critical"], action: "block" }, { action: "default" }],
  protect_http_server: [{ location: ["server"], protocol: ["HTTP"], action: "default" }],
  protect_client: [{ location: ["client"], action: "default" }],
};

export function allSigs(packs) {
  const out = [];
  for (const p of packs || []) for (const s of p.signatures) out.push({ sig: s, pack: p });
  return out;
}

// the signatures a sensor enables, each with the action it takes: [{sig, pack, action}]
export function sensorSigs(lab, fg, name) {
  const sigs = allSigs(lab.threats);
  const e = fg.entry("ips sensor", name);
  let entries;
  if (e) {
    entries = [];
    const ent = e.children.get("entries");
    for (const x of ent ? ent.list() : []) {
      const a = (k) => x.attrs.get(k) || [];
      if ((a("status")[0] || "enable") === "disable") continue;
      entries.push({ rule: a("rule").map(Number), severity: a("severity"), location: a("location"), os: a("os"), application: a("application"), protocol: a("protocol"), cve: a("cve"), action: a("action")[0] || "default" });
    }
  } else if (BUILTIN[name]) entries = BUILTIN[name];
  else return [];
  const lc = (v) => String(v).toLowerCase();
  const hit = (want, have) => !want || !want.length || want.some((w) => lc(w) === "all") || want.some((w) => have.map(lc).includes(lc(w)));
  const out = [];
  for (const { sig, pack } of sigs) {
    for (const en of entries) {
      if (en.rule && en.rule.length) { if (!en.rule.includes(sig.id)) continue; }
      else if (!(hit(en.severity, [pack.severity]) && hit(en.location, [pack.location || "server"]) && hit(en.os, (pack.target && pack.target.os) || []) && hit(en.application, (pack.target && pack.target.app) || []) && hit(en.protocol, ["HTTP"]) && hit(en.cve, pack.cve || []))) continue;
      const action = en.action === "default" ? defaultAction(pack) : en.action;
      out.push({ sig, pack, action });
      break;
    }
  }
  return out;
}

// deep inspection on a policy: its SSL/SSH profile inspects HTTPS content
export function deepInspects(fg, pol) {
  const name = fg.one("firewall policy", pol, "ssl-ssh-profile") || "no-inspection";
  if (name === "deep-inspection" && !fg.entry("firewall ssl-ssh-profile", name)) return true;
  const p = fg.entry("firewall ssl-ssh-profile", name);
  if (!p) return false;
  const https = p.children.get("https");
  const mode = https ? (https.attrs.get("status") || ["deep-inspection"])[0] : "deep-inspection";
  return mode === "deep-inspection";
}

// one entry per accept policy that runs an IPS sensor
export function ipsPlan(lab, fg) {
  const out = [];
  if (!lab.threats || !lab.threats.length) return out;
  for (const p of fg.entries("firewall policy")) {
    if (fg.one("firewall policy", p, "action") !== "accept" || fg.one("firewall policy", p, "status") === "disable") continue;
    const sensor = fg.one("firewall policy", p, "ips-sensor");
    if (!sensor || fg.one("firewall policy", p, "utm-status") !== "enable") continue;
    const sigs = sensorSigs(lab, fg, sensor);
    if (!sigs.length) continue;
    out.push({ policy: Number(p.key), sensor, deep: deepInspects(fg, p), sigs, ports: [...new Set(sigs.flatMap((s) => s.sig.ports || []))].sort((a, b) => a - b) });
  }
  return out;
}

// the nftables table for the real engine (one queue per policy)
export function ipsNft(lab, fg, plan) {
  if (!plan.length) return "";
  const g = fg.obj && fg.obj("ips global");
  const failOpen = g && fg.one("ips global", g, "fail-open") === "enable";
  const rules = plan.map((p, i) => `  ct mark ${p.policy} ct direction original ct original packets < 12 tcp dport { ${p.ports.join(", ")} } queue num ${i + 1}${failOpen ? " bypass" : ""}`);
  return `table ip ftkips {
 set blk { type ipv4_addr . inet_service . ipv4_addr . inet_service; flags timeout; }
 chain ips_fwd { type filter hook forward priority filter + 5; policy accept;
  meta mark 0x7f1c0000 reject with tcp reset
  ip saddr . tcp sport . ip daddr . tcp dport @blk drop
${rules.join("\n")}
 }
}`;
}

// the agent's ips.load request
export function ipsLoadReq(fg, plan) {
  const sigs = new Map();
  for (const p of plan) for (const s of p.sigs) sigs.set(s.sig.id, { id: s.sig.id, ports: s.sig.ports || [], match: s.sig.match });
  return { op: "ips.load", ns: fg.id, sigs: [...sigs.values()], rules: plan.map((p, i) => ({ queue: i + 1, policy: p.policy, deep: p.deep, sigs: p.sigs.map((s) => ({ id: s.sig.id, action: s.action })) })) };
}

const LEVEL = { critical: "alert", high: "warning", medium: "warning", low: "notice", info: "information" };
// a FortiOS utm/ips log record for one hit
export function ipsLogRec(lab, fg, h) {
  const found = allSigs(lab.threats).find((x) => x.sig.id === h.sig);
  if (!found) return null;
  const { pack, sig } = found;
  const intf = (ip) => { const n = ipToInt(ip); const i = lab.fgtIntfs(fg).find((x) => x.prefix && (x.prefix.ip >>> (32 - x.prefix.len)) === (n >>> (32 - x.prefix.len))); return i ? i.name : ""; };
  const rt = (ip) => { const r = lab.fgtLookup(fg, ipToInt(ip)); return r ? r.dev : ""; };
  return {
    logid: "0419016384", type: "utm", subtype: "ips", eventtype: "signature", level: LEVEL[pack.severity] || "warning", severity: pack.severity,
    srcip: h.src, srcport: h.sport, srcintf: intf(h.src) || rt(h.src), dstip: h.dst, dstport: h.dport, dstintf: intf(h.dst) || rt(h.dst),
    policyid: h.policy, proto: 6, service: h.dport === 443 ? "HTTPS" : h.dport === 80 ? "HTTP" : `tcp/${h.dport}`,
    attack: pack.name, attackid: sig.id, cve: (pack.cve || []).join(" "), ref: `FortiTatake threat pack ${pack.id}`,
    action: h.action === "block" ? "dropped" : h.action === "reset" ? "reset" : "detected",
    msg: `${pack.location === "client" ? "applications3" : "web_server"}: ${pack.name}`, url: h.uri ? h.uri.slice(0, 200) : undefined,
  };
}

// ----- simulator parity: an attack request through the simulated FortiGate -----
// res is a probe result (the request's path); returns {fg, policy, hit, rec} or null when nothing matched
Lab.prototype.ipsInspect = function (res, payload, port, tls) {
  const ev = ((res.fwd && res.fwd.fgt) || []).find((e) => !e.reply && e.policy && e.policy !== "0" && !e.drop);
  if (!ev) return null;
  const fg = this.dev(ev.dev);
  const plan = ipsPlan(this, fg).find((p) => String(p.policy) === String(ev.policy));
  if (!plan || (tls && !plan.deep)) return null;
  const b = httpBuffers(payload);
  for (const s of plan.sigs.slice().sort((a, c) => a.sig.id - c.sig.id)) {
    if (!sigMatches(s.sig, b, port)) continue;
    const h = { policy: plan.policy, sig: s.sig.id, action: s.action, src: intToIp(res.req.src), sport: res.req.sport, dst: intToIp(res.seenDst !== undefined ? res.seenDst : res.req.dst), dport: port, uri: b.uri };
    const rec = ipsLogRec(this, fg, h);
    if (rec && !this.quiet) this.storeLog(fg, { ...this.ipsStamp(), devname: fg.hostname(), devid: fg.serial, vd: "root", ...rec, seq: Date.now() });
    return { fg, policy: plan.policy, hit: h, pack: s.pack };
  }
  return null;
};
Lab.prototype.ipsStamp = function () { const d = new Date(this.clock - 5 * 3600000); return { date: d.toISOString().slice(0, 10), time: d.toISOString().slice(11, 19) }; };

// ----- the attack runner, simulator side (the live one is the agent's attack.run) -----
// from: a device id, or "@attacker" for the lab Internet's attacker address
export function attackSource(lab, from) {
  if (from === "@attacker" || !from) {
    const cloud = [...lab.devices.values()].find((d) => d.kind === "cloud");
    return cloud ? { id: cloud.id, ip: ATTACKER_IP, label: `Internet attacker (${ATTACKER_IP})` } : null;
  }
  const d = lab.dev(from);
  const ip = d && d.ip && d.ip();
  return ip ? { id: d.id, ip: intToIp(ip), label: `${d.id} (${intToIp(ip)})` } : null;
}
export function attackTarget(lab, to) {
  if (/^\d+\.\d+\.\d+\.\d+$/.test(to)) return { ip: to, host: to };
  const ip = lab.names.get(String(to).toLowerCase());
  if (ip !== undefined) return { ip: intToIp(ip), host: to };
  const d = lab.dev(to);
  if (d && d.ip && d.ip()) return { ip: intToIp(d.ip()), host: d.hostname || d.id };
  return null;
}
export function attackRequests(pack, host, token) {
  return pack.generator.variants.map((v) => ({ name: v.name, raw: fillRequest(v.request, { target: host, token }) }));
}

// outcome per variant: blocked | reset | reached | failed, with the policy and signature when the IPS acted
export const TLS_PORTS = [443, 8443, 10443];
export function attackPort(pack, port) {
  const p = Number(port) || pack.generator.port;
  return { port: p, tls: p === pack.generator.port ? !!pack.generator.tls : TLS_PORTS.includes(p) };
}
Lab.prototype.attackSim = function (from, to, packId, portOpt) {
  const pack = (this.threats || []).find((p) => p.id === packId);
  const src = attackSource(this, from), dst = attackTarget(this, to);
  if (!pack || !src || !dst) return { error: !pack ? `no threat pack ${packId}` : !src ? `no source ${from}` : `no target ${to}` };
  const { port, tls } = attackPort(pack, portOpt);
  const out = [];
  for (const rq of attackRequests(pack, dst.host, "ftk-sim")) {
    const res = this.probe(src.id, { dst: ipToInt(dst.ip), proto: 6, dport: port, src: ipToInt(src.ip) });
    if (!res.ok) { out.push({ variant: rq.name, outcome: "failed", detail: res.drop ? res.drop.reason : "no answer" }); continue; }
    const hit = this.ipsInspect(res, rq.raw, port, tls);
    if (hit && hit.hit.action !== "pass") out.push({ variant: rq.name, outcome: hit.hit.action === "reset" ? "reset" : "blocked", policy: hit.policy, sig: hit.hit.sig, detail: `IPS ${hit.hit.action} on policy ${hit.policy}, signature ${hit.hit.sig}` });
    else out.push({ variant: rq.name, outcome: "reached", policy: hit ? hit.policy : undefined, sig: hit ? hit.hit.sig : undefined, detail: `${res.reached}${hit ? ` (IPS logged signature ${hit.hit.sig}, action pass)` : ""}` });
  }
  return { pack, src, dst, port, tls, results: out };
};
