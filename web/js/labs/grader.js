// Grader: runs a lab part's checks against the live simulation and explains each result in plain words.
import { ipToInt, intToIp, parsePrefix, inPrefix, prefixStr } from "./net.js";
import { PROTO } from "./sim.js";
import { FortiGate } from "./fgt.js";

const P = (x) => (typeof x === "number" ? x : ipToInt(x));

export function runChecks(lab, checks, answers = {}) {
  return checks.map((c) => {
    try { return { id: c.id, text: c.text, ...one(lab, c, answers) }; }
    catch (e) { return { id: c.id, text: c.text, pass: false, detail: "Check error: " + e.message }; }
  });
}

function one(lab, c, answers) {
  if (c.probe) return probeCheck(lab, c.probe);
  if (c.config) return configCheck(lab, c.config);
  if (c.dhcp) return dhcpCheck(lab, c.dhcp);
  if (c.route) return routeCheck(lab, c.route);
  if (c.ran) return ranCheck(lab, c.ran);
  if (c.backup) return backupCheck(lab, c.backup);
  if (c.answer) return answerCheck(c, answers[c.id]);
  if (c.tunnel) return tunnelCheck(lab, c.tunnel);
  if (c.ha) return haCheck(lab, c.ha);
  if (c.client) return clientCheck(lab, c.client);
  if (c.sdwan) return sdwanCheck(lab, c.sdwan);
  if (c.all) { const r = c.all.map((x) => one(lab, x, answers)); return { pass: r.every((x) => x.pass), detail: r.filter((x) => !x.pass).map((x) => x.detail).join(" ") || r[0].detail }; }
  return { pass: false, detail: "Unknown check type" };
}

export function parseFrom(lab, from) {
  // "PC1" | "INTERNET:100.25.7.9" (a client somewhere on the Internet) | "FGT"
  const [id, ip] = String(from).split(":");
  return { id, src: ip ? ipToInt(ip) : undefined };
}

export function probeCheck(lab, pr) {
  const { id, src } = parseFrom(lab, pr.from);
  let dst = pr.to;
  const savedClock = lab.clock;
  if (pr.at) lab.clock = Date.parse(pr.at);
  try { return probeInner(lab, pr, id, src, dst); } finally { if (pr.at) lab.clock = savedClock; }
}
function probeInner(lab, pr, id, src, dst) {
  if (String(dst).startsWith("@")) {
    const d = lab.dev(dst.slice(1));
    const ip = d && d.ip ? d.ip() : null;
    if (!ip) return { pass: false, detail: `${dst.slice(1)} has no IP address yet.` };
    dst = intToIp(ip);
  }
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(dst)) {
    const r = lab.resolve(id, dst);
    if (r.err && pr.expect !== "fail") return { pass: false, detail: `${pr.from} could not resolve ${dst}: ${r.err}.` };
    dst = r.ip;
  } else dst = ipToInt(dst);
  const proto = PROTO[pr.proto || "icmp"];
  const res = lab.probe(id, { dst, proto, dport: pr.port || 0, src });
  const fgEv = (res.fwd && res.fwd.fgt || []).filter((e) => !e.reply);
  const ev = pr.on ? fgEv.find((e) => e.dev === pr.on) : fgEv[0];
  const what = `${pr.proto ? pr.proto.toUpperCase() : "ping"}${pr.port ? " " + pr.port : ""} from ${pr.from.split(":")[0]} to ${pr.to}`;
  const story = explain(res, ev);
  if ((pr.expect || "ok") === "fail") {
    if (res.ok) return { pass: false, detail: `${what} still gets through${ev && ev.policy ? ` (allowed by policy ${ev.policy})` : ""}. It should be blocked.` };
    if (pr.blocked_by_policy !== undefined && (!ev || String(ev.policy) !== String(pr.blocked_by_policy))) return { pass: false, detail: `${what} is blocked, but not by the policy the ticket asks for. ${story}` };
    return { pass: true, detail: `${what} is blocked. ${story}` };
  }
  if (!res.ok) return { pass: false, detail: `${what} fails. ${story}` };
  const probs = [];
  if (pr.policy !== undefined && ev && String(ev.policy) !== String(pr.policy)) probs.push(`it matched policy ${ev.policy}, not ${pr.policy}`);
  if (pr.snat && ev && (ev.snat === undefined || ev.snat !== P(pr.snat))) probs.push(`it left with source ${ev.snat !== undefined ? intToIp(ev.snat) : intToIp(res.req.src)} instead of ${pr.snat}`);
  if (pr.no_snat && ev && ev.snat !== undefined) probs.push(`it was source-NATed to ${intToIp(ev.snat)}, but the server must see the real client IP`);
  if (pr.dnat && ev && ev.dnat !== P(pr.dnat)) probs.push(`it reached ${ev.dnat !== undefined ? intToIp(ev.dnat) : "no internal server"} instead of ${pr.dnat}`);
  if (pr.egress && ev && ev.out !== pr.egress) probs.push(`it left through ${ev.out} instead of ${pr.egress}`);
  if (pr.seen_src && res.seenSrc !== P(pr.seen_src)) probs.push(`the server saw the client as ${intToIp(res.seenSrc)} instead of ${pr.seen_src}`);
  if (pr.reach && res.reached !== pr.reach) probs.push(`it was answered by ${res.reached}, not ${pr.reach}`);
  if (probs.length) return { pass: false, detail: `${what} works, but ${probs.join("; ")}.` };
  return { pass: true, detail: `${what} works${ev && ev.policy && ev.policy !== "0" ? ` (policy ${ev.policy}${ev.snat !== undefined ? `, SNAT to ${intToIp(ev.snat)}` : ""}${ev.dnat !== undefined ? `, DNAT to ${intToIp(ev.dnat)}` : ""})` : ""}.` };
}

// Turn a probe result into one sentence about what the network did.
export function explain(res, ev) {
  if (res.ok) return "";
  const d = res.drop || {};
  if (d.localIn) return `The FortiGate dropped it as traffic to itself: ${d.reason}.`;
  if (d.rpf) return `The FortiGate dropped it: ${d.reason} (reverse path check).`;
  if (d.policy !== undefined) return `The FortiGate dropped it: ${d.reason}.`;
  if (d.noroute) return `The FortiGate has no route to the destination.`;
  if (d.privateSrc) return `The FortiGate let it out, but with the private source ${intToIp(res.req && res.req.src)}; the ISP can't route the reply back (missing SNAT?).`;
  if (d.refused) return `It reached the server, but ${d.reason}.`;
  if (d.mtu) return `It was dropped: ${d.reason}.`;
  if (res.replyLost) return `The request arrived, but the reply was lost: ${d.reason || "no way back"} at ${d.dev}.`;
  return d.reason ? `It stopped at ${d.dev}: ${d.reason}.` : "It got no answer.";
}

function getDev(lab, id) { const d = lab.dev(id); if (!d) throw new Error("unknown device " + id); return d; }

function configCheck(lab, c) {
  const fg = getDev(lab, c.dev);
  if (!(fg instanceof FortiGate)) throw new Error(c.dev + " is not a FortiGate");
  let entries;
  const s = fg.P[c.path];
  if (!s) throw new Error("unknown path " + c.path);
  if (s.t === "table") entries = c.key !== undefined ? [fg.entry(c.path, String(c.key))].filter(Boolean) : fg.entries(c.path);
  else entries = [fg.obj(c.path)];
  if (c.where) entries = entries.filter((e) => Object.entries(c.where).every(([k, v]) => matchVal(fg.val(c.path, e, k), v)));
  const label = c.label || `${c.path}${c.key !== undefined ? ` ${c.key}` : ""}`;
  if (c.exists === false) return entries.length ? { pass: false, detail: `${label} should not exist.` } : { pass: true, detail: `${label} is gone.` };
  if (!entries.length) return { pass: false, detail: c.missing || `${label}: no matching entry yet.` };
  if (c.count !== undefined && entries.length !== c.count) return { pass: false, detail: `${label}: expected ${c.count} entries, found ${entries.length}.` };
  if (!c.attr) return { pass: true, detail: `${label} is configured.` };
  const ok = entries.some((e) => {
    const v = fg.val(c.path, e, c.attr);
    if (c.equals !== undefined) return matchVal(v, c.equals);
    if (c.has) return [].concat(c.has).every((x) => v.includes(String(x)));
    if (c.lacks) return [].concat(c.lacks).every((x) => !v.includes(String(x)));
    if (c.in_prefix) return v.length && inPrefix(parsePrefix(v.join(" ")).ip, parsePrefix(c.in_prefix));
    return v.length > 0;
  });
  if (ok) return { pass: true, detail: `${label} ${c.attr} is right.` };
  const cur = fg.val(c.path, entries[0], c.attr).join(" ") || "(not set)";
  return { pass: false, detail: c.fail || `${label} ${c.attr} is "${cur}".` };
}
function matchVal(v, want) {
  const w = String(want);
  if (w.startsWith("~")) return new RegExp(w.slice(1), "i").test(v.join(" "));
  const vp = parsePrefix(v.join(" ")), wp = parsePrefix(w);
  if (vp && wp && /\d+\.\d+/.test(w)) return vp.ip === wp.ip && vp.len === wp.len;
  return v.join(" ") === w || (v.length === 1 && v[0] === w);
}

function dhcpCheck(lab, c) {
  const h = getDev(lab, c.host);
  lab.renew(h);
  if (!h.lease) return { pass: false, detail: `${c.host} gets no DHCP lease.` };
  const p = parsePrefix(c.in);
  if (p && !inPrefix(h.lease.prefix.ip, p)) return { pass: false, detail: `${c.host} got ${intToIp(h.lease.prefix.ip)}, outside ${c.in}.` };
  if (c.gw && h.lease.gw !== ipToInt(c.gw)) return { pass: false, detail: `${c.host} got gateway ${h.lease.gw ? intToIp(h.lease.gw) : "none"} instead of ${c.gw}.` };
  if (c.dns && !h.lease.dns.includes(ipToInt(c.dns))) return { pass: false, detail: `${c.host} got DNS ${h.lease.dns.map(intToIp).join(", ") || "none"} instead of ${c.dns}.` };
  return { pass: true, detail: `${c.host} leased ${intToIp(h.lease.prefix.ip)}/${h.lease.prefix.len}, gateway ${h.lease.gw ? intToIp(h.lease.gw) : "none"}.` };
}

function routeCheck(lab, c) {
  const fg = getDev(lab, c.dev);
  const { active } = lab.fgtRoutes(fg);
  const want = parsePrefix(c.dst);
  const r = active.find((x) => x.dst.ip === want.ip && x.dst.len === want.len && (!c.via || x.gw === ipToInt(c.via)) && (!c.intf || x.dev === c.intf));
  if (c.absent) return r ? { pass: false, detail: `${c.dst} is still in the routing table.` } : { pass: true, detail: `${c.dst} is not in the routing table.` };
  return r ? { pass: true, detail: `${prefixStr(r.dst)} is active via ${r.gw ? intToIp(r.gw) : r.dev}.` } : { pass: false, detail: `No active route to ${c.dst}${c.via ? ` via ${c.via}` : ""}.` };
}

function ranCheck(lab, c) {
  const d = getDev(lab, c.dev);
  const re = new RegExp(c.cmd, "i");
  const hit = (d.history || []).some((h) => re.test(h.line));
  return hit ? { pass: true, detail: c.ok || "Done." } : { pass: false, detail: c.fail || `You haven't run that on ${c.dev} yet.` };
}

function backupCheck(lab, c) {
  const fg = getDev(lab, c.dev);
  const b = fg.backups || [];
  if (!b.length) return { pass: false, detail: `No configuration backup was taken on ${c.dev}.` };
  if (c.before_changes) {
    const firstChange = (fg.history || []).findIndex((h) => /^\s*(set|unset|append|delete|purge|move|rename)\b/.test(h.line));
    const firstBackup = (fg.history || []).findIndex((h) => /execute\s+backup\s+config/i.test(h.line) && !/fail/i.test(h.out || ""));
    if (firstChange !== -1 && (firstBackup === -1 || firstBackup > firstChange)) return { pass: false, detail: "A backup exists, but it was taken after you started changing the config." };
  }
  return { pass: true, detail: "Configuration backed up." };
}

function answerCheck(c, given) {
  if (given === undefined || given === null || String(given).trim() === "") return { pass: false, detail: "Answer the question." };
  const g = String(given).toLowerCase().replace(/\s+/g, " ").trim();
  const ok = [].concat(c.answer.accept).some((a) => (String(a).startsWith("~") ? new RegExp(String(a).slice(1), "i").test(g) : g === String(a).toLowerCase()));
  return ok ? { pass: true, detail: c.answer.why || "Correct." } : { pass: false, detail: c.answer.hint || "Not quite. Look at the evidence again." };
}

function tunnelCheck(lab, c) {
  const fg = getDev(lab, c.dev);
  const info = lab.tunnelInfo(fg, c.name);
  if (!info) return { pass: false, detail: `${c.dev} has no tunnel ${c.name}.` };
  if (c.phase1 && !c.up) return info.p1up ? { pass: true, detail: `Phase 1 of ${c.name} is up.` } : { pass: false, detail: `Phase 1 of ${c.name} is down: ${info.reason}.` };
  if (c.up === false) return info.up ? { pass: false, detail: `${c.name} is up but shouldn't be.` } : { pass: true, detail: `${c.name} is down.` };
  return info.up ? { pass: true, detail: `${c.name} is up (${(info.p2 || []).filter((x) => x.up).length} selector(s)).` } : { pass: false, detail: `${c.name} is down: ${info.reason}.` };
}
function haCheck(lab, c) {
  const fg = getDev(lab, c.dev);
  const role = lab.haRole(fg);
  const cl = lab.haCluster ? lab.haCluster(fg) : null;
  const size = cl ? cl.members.length : 1;
  if (c.size && size !== c.size) return { pass: false, detail: `${c.dev} sees ${size} cluster member(s), expected ${c.size}.${lab.haClusters && lab.haClusters().why.get(fg) ? " Reason: " + lab.haClusters().why.get(fg) + "." : ""}` };
  if (c.role && role !== c.role) return { pass: false, detail: `${c.dev} is ${role}, expected ${c.role}.` };
  return { pass: true, detail: `${c.dev} is ${role}${size > 1 ? ` in a ${size}-unit cluster` : ""}.` };
}
function clientCheck(lab, c) {
  const h = getDev(lab, c.host);
  const up = !!(h.vpn && h.vpn.up);
  if (c.connected === false) return up ? { pass: false, detail: `${c.host} is still connected.` } : { pass: true, detail: `${c.host} is disconnected.` };
  if (!up) return { pass: false, detail: `${c.host}'s FortiClient isn't connected. Run forticlient connect on it.` };
  if (c.in && !inPrefix(h.vpn.ip, parsePrefix(c.in))) return { pass: false, detail: `${c.host} got ${intToIp(h.vpn.ip)}, outside ${c.in}.` };
  if (c.split === true && !h.vpn.split) return { pass: false, detail: `${c.host} sends all its traffic through the VPN; split tunnelling isn't on.` };
  return { pass: true, detail: `${c.host} is connected with ${intToIp(h.vpn.ip)}.` };
}
function sdwanCheck(lab, c) {
  const fg = getDev(lab, c.dev);
  const cfg = lab.sdwanCfg(fg);
  if (!cfg.on) return { pass: false, detail: "SD-WAN is disabled." };
  const m = cfg.members.find((x) => x.intf === c.member);
  if (!m) return { pass: false, detail: `${c.member} is not an SD-WAN member.` };
  const alive = lab.memberAlive(fg, cfg, m);
  if (c.alive !== undefined && alive !== c.alive) return { pass: false, detail: `${c.member} is ${alive ? "alive" : "dead"}.` };
  return { pass: true, detail: `${c.member} is an SD-WAN member and ${alive ? "alive" : "dead"}.` };
}
