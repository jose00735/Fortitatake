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

export function checkOne(lab, c, answers) { return one(lab, c, answers); }
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
  if (c.web) return webCheck(lab, c.web);
  if (c.attack) return attackCheck(lab, c.attack);
  if (c.faz) return fazCheck(lab, c.faz);
  if (c.fmg) return fmgCheck(lab, c.fmg);
  if (c.login) return loginCheck(lab, c.login);
  if (c.authserver) return authServerCheck(lab, c.authserver);
  if (c.fsso) return fssoCheck(lab, c.fsso);
  if (c.ospf) return ospfCheck(lab, c.ospf);
  if (c.bgp) return bgpCheck(lab, c.bgp);
  if (c.fsw) return fswCheck(lab, c.fsw);
  if (c.siem) return siemCheck(lab, c.siem);
  if (c.edr) return edrCheck(lab, c.edr);
  if (c.fazinc) return fazIncCheck(lab, c.fazinc);
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
  // `as: [user, password]` logs the PC in through the FortiGate's auth page for this probe only
  const fgs = [...lab.devices.values()].filter((d) => d instanceof FortiGate);
  const savedAuth = pr.as || pr.fresh ? fgs.map((f) => [f, f.authList]) : null;
  try {
    if (pr.fresh || pr.as) for (const f of fgs) f.authList = [];
    if (pr.as) {
      const h = lab.dev(id);
      lab.probe(id, { dst: ipToInt("142.250.78.4"), proto: 6, dport: 80 });
      const r = lab.portalLogin(h, pr.as[0], pr.as[1]);
      if (!r.ok && (pr.expect || "ok") !== "fail") return { pass: false, detail: `${pr.as[0]} can't log in from ${id}: ${r.err}.` };
    }
    return probeInner(lab, pr, id, src, dst);
  } finally {
    if (pr.at) lab.clock = savedClock;
    if (savedAuth) { for (const [f, a] of savedAuth) f.authList = a; lab.ver++; }
  }
}

function loginCheck(lab, c) {
  const h = lab.dev(c.from);
  const fgs = [...lab.devices.values()].filter((d) => d instanceof FortiGate);
  const saved = fgs.map((f) => [f, f.authList]);
  try {
    for (const f of fgs) f.authList = [];
    lab.probe(c.from, { dst: ipToInt("142.250.78.4"), proto: 6, dport: 80 });
    const r = lab.portalLogin(h, c.user, c.pass);
    const want = (c.expect || "ok") === "ok";
    if (want && !r.ok) return { pass: false, detail: `${c.user} can't log in from ${c.from}: ${r.err}.` };
    if (!want && r.ok) return { pass: false, detail: `${c.user} can still log in from ${c.from} (groups ${r.groups.join(", ")}).` };
    if (want && c.group && !r.groups.includes(c.group)) return { pass: false, detail: `${c.user} logs in, but lands in ${r.groups.join(", ")} instead of ${c.group}.` };
    return { pass: true, detail: want ? `${c.user} logs in from ${c.from} (${r.groups.join(", ")}).` : `${c.user} is refused, as it should be.` };
  } finally { for (const [f, a] of saved) f.authList = a; lab.ver++; }
}

function authServerCheck(lab, c) {
  const fg = lab.dev(c.dev);
  const r = c.kind === "radius" ? lab.radiusAuth(fg, c.server, c.user, c.pass) : lab.ldapAuth(fg, c.server, c.user, c.pass);
  const want = (c.expect || "ok") === "ok";
  if (want && !r.ok) return { pass: false, detail: `${c.server} doesn't authenticate ${c.user}: ${r.err}.` };
  if (!want && r.ok) return { pass: false, detail: `${c.server} still authenticates ${c.user}.` };
  if (want && c.group && !(r.groups || []).some((g) => g.toLowerCase().includes(c.group.toLowerCase()))) return { pass: false, detail: `${c.server} authenticates ${c.user} but returns no ${c.group} membership (got ${(r.groups || []).join(", ") || "none"}).` };
  return { pass: true, detail: want ? `${c.server} authenticates ${c.user}${r.groups && r.groups.length ? ` with ${r.groups.length} group(s)` : ""}.` : `${c.server} refuses ${c.user}.` };
}

function ospfCheck(lab, c) {
  const o = lab.controlPlane().ospf.get(c.dev);
  if (!o) return { pass: false, detail: `${c.dev} isn't running OSPF (no network statement covers an interface).` };
  const n = o.nbrs.find((x) => x.peer.sp.id === c.neighbor);
  if (!n) return { pass: false, detail: `${c.dev} has no OSPF neighbor ${c.neighbor}: no hellos on a shared segment (is the link's subnet in a network statement, and the interface not passive?).` };
  const want = c.state || "Full";
  if (n.state !== want) return { pass: false, detail: `${c.dev} ↔ ${c.neighbor} is ${n.state || "down"}${n.why ? `: ${n.why}` : ""}.` };
  return { pass: true, detail: `${c.dev} ↔ ${c.neighbor} is ${n.state}${n.role ? "/" + n.role : ""}.` };
}

function bgpCheck(lab, c) {
  const b = lab.controlPlane().bgp.get(c.dev);
  if (!b) return { pass: false, detail: `${c.dev} isn't running BGP (no local AS).` };
  const s = b.sessions.find((x) => x.n.ip === ipToInt(c.peer));
  if (!s) return { pass: false, detail: `${c.dev} has no BGP neighbor ${c.peer}.` };
  if (s.state !== (c.state || "Established")) return { pass: false, detail: `${c.dev} → ${c.peer} is ${s.state}${s.why ? `: ${s.why}` : ""}.` };
  if (c.received !== undefined) { const n = ((b.adjIn.get(s.n.ip) || {}).routes || new Map()).size; if (n !== c.received) return { pass: false, detail: `${c.dev} receives ${n} prefixes from ${c.peer}, expected ${c.received}.` }; }
  return { pass: true, detail: `${c.dev} → ${c.peer} is Established.` };
}

function siemCheck(lab, c) {
  const siem = getDev(lab, c.dev);
  if (c.receiving) return lab.siemReceiving(siem, c.receiving) ? { pass: true, detail: `${c.receiving} is sending syslog to ${c.dev} right now.` } : { pass: false, detail: `${c.receiving}'s syslog isn't reaching ${c.dev}: check the syslog server address, port, source and the route.` };
  if (c.test_rule) {
    const hit = lab.siemTestRule(siem, c.test_rule, c.attack || []);
    if (hit === null) return { pass: false, detail: `${c.dev} has no custom rule named "${c.test_rule}". Write it with rule new.` };
    const fp = lab.siemTestRule(siem, c.test_rule, c.baseline || []);
    if (!hit) return { pass: false, detail: `"${c.test_rule}" stays quiet on the attack replay: check its filters, grouping and threshold against the attack's events.` };
    if (fp) return { pass: false, detail: `"${c.test_rule}" fires on the attack, but also ${fp} time(s) on the normal week: it would page someone for nothing. Narrow it.` };
    return { pass: true, detail: `"${c.test_rule}" fires on the attack replay and stays quiet on a week of normal activity.` };
  }
  if (c.cmdb) { const ok = lab.siemEvents(siem).some((e) => e.reptDevName === c.cmdb); return ok ? { pass: true, detail: `${c.cmdb} is sending events to ${c.dev}.` } : { pass: false, detail: `${c.dev} has received nothing from ${c.cmdb}.` }; }
  if (c.events) { const n = lab.siemEvents(siem).filter((e) => Object.entries(c.events).every(([k, v]) => String(e[k] ?? "") === String(v))).length; return n ? { pass: true, detail: `${n} matching event(s) in ${c.dev}.` } : { pass: false, detail: `No events in ${c.dev} match ${Object.entries(c.events).map(([k, v]) => `${k}=${v}`).join(" ")}.` }; }
  const inc = lab.siemIncidents(siem).filter((i) => i.rule === c.incident && Object.entries(c.attrs || {}).every(([k, v]) => String(i.attrs[k]) === String(v)));
  if (c.exists === false) return inc.filter((i) => !c.status || i.status === c.status).length ? { pass: false, detail: `${c.dev} still raises "${c.incident}"${inc[0] ? ` (incident ${inc[0].id})` : ""}.` } : { pass: true, detail: `No "${c.incident}" incident.` };
  if (!inc.length) return { pass: false, detail: `${c.dev} has no "${c.incident}" incident${c.attrs ? ` for ${Object.entries(c.attrs).map(([k, v]) => `${k}=${v}`).join(" ")}` : ""}.` };
  if (c.status && !inc.some((i) => i.status === c.status)) return { pass: false, detail: `Incident ${inc[0].id} is ${inc[0].status}, not ${c.status}.` };
  if (c.owner && !inc.some((i) => i.owner)) return { pass: false, detail: `Incident ${inc[0].id} isn't assigned to anyone.` };
  return { pass: true, detail: `Incident ${inc[0].id} (${c.incident}) is ${inc[0].status}.` };
}

function edrCheck(lab, c) {
  const edr = getDev(lab, c.dev);
  if (c.collector) { const x = lab.edrCollectors(edr).find((y) => y.h.id === c.collector); if (!x) return { pass: false, detail: `${c.collector} has no FortiEDR collector.` }; return x.connected ? { pass: true, detail: `${c.collector}'s collector is connected.` } : { pass: false, detail: `${c.collector}'s collector can't reach ${c.dev} on TCP 8081.` }; }
  const st = edr.edr || { modes: {}, isolated: new Set(), exceptions: [], cls: new Map(), done: new Map() };
  if (c.isolated !== undefined) { const is = st.isolated && st.isolated.has(c.host); return is === c.isolated ? { pass: true, detail: `${c.host} is ${is ? "" : "not "}isolated.` } : { pass: false, detail: `${c.host} is ${is ? "" : "not "}isolated.` }; }
  if (c.policy) { const m = (st.modes || {})[c.policy] || "Simulation"; return m === c.mode ? { pass: true, detail: `${c.policy} is in ${m} mode.` } : { pass: false, detail: `${c.policy} is in ${m} mode, not ${c.mode}.` }; }
  if (c.exception) { const ok = (st.exceptions || []).some((x) => x.process === c.exception && (!c.rule || x.rule === c.rule) && (!c.scope || (c.scope === "host" ? x.host !== "*" : x.host === "*"))); return ok ? { pass: true, detail: `An exception covers ${c.exception}.` } : { pass: false, detail: `No exception for ${c.exception}${c.rule ? ` on "${c.rule}"` : ""}.` }; }
  if (c.syslog !== undefined) { const v = st.syslog || null; return v === c.syslog ? { pass: true, detail: `Security events go to ${v} as syslog.` } : { pass: false, detail: `Syslog export is ${v || "off"}.` }; }
  if (c.rule && !c.exception) {
    const e = lab.edrEvents(edr).filter((x) => x.rule === c.rule && (!c.host || x.host === c.host)).pop();
    if (!e) return { pass: false, detail: `No "${c.rule}" event${c.host ? ` from ${c.host}` : ""} in ${c.dev}.` };
    if (c.action && e.action !== c.action) return { pass: false, detail: `"${c.rule}" on ${e.hostname} was ${e.action}, not ${c.action}.` };
    return { pass: true, detail: `"${c.rule}" on ${e.hostname}: ${e.process}, ${e.classification}, ${e.action}.` };
  }
  if (c.event) { const e = lab.edrEvents(edr).find((x) => x.process === c.event); if (!e) return { pass: false, detail: `No event for ${c.event} in ${c.dev}.` }; if (c.classification && e.classification !== c.classification) return { pass: false, detail: `${c.event} is classified ${e.classification}.` }; if (c.handled && !e.handled) return { pass: false, detail: `${c.event} hasn't been remediated.` }; if (c.action && e.action !== c.action) return { pass: false, detail: `${c.event} was ${e.action}, not ${c.action}.` }; return { pass: true, detail: `${c.event}: ${e.classification}, ${e.action}${e.handled ? `, ${e.handled}` : ""}.` }; }
  return { pass: false, detail: "Unknown EDR check." };
}

function fazIncCheck(lab, c) {
  const faz = getDev(lab, c.dev);
  const inc = ((faz.soc && faz.soc.inc) || []).filter((i) => (!c.handler || i.handler === c.handler) && (!c.srcip || i.srcip === c.srcip));
  if (!inc.length) return { pass: false, detail: `${c.dev} has no incident${c.handler ? ` from "${c.handler}"` : ""}${c.srcip ? ` for ${c.srcip}` : ""}.` };
  if (c.assigned && inc[0].assign === "unassigned") return { pass: false, detail: `Incident ${inc[0].id} isn't assigned.` };
  return { pass: true, detail: `Incident ${inc[0].id} (${inc[0].handler}) exists${inc[0].assign !== "unassigned" ? `, assigned to ${inc[0].assign}` : ""}.` };
}

function fswCheck(lab, c) {
  const sw = lab.dev(c.dev);
  const st = lab.fslState(sw);
  if (!st.up || !st.up.fg) return { pass: false, detail: `${c.dev} isn't on a FortiLink interface: the FortiGate port it's cabled to needs \`set fortilink enable\` (or membership of the FortiLink aggregate).` };
  const want = c.state || "authorized";
  if (want === "authorized" && !st.authorized) return { pass: false, detail: `${c.dev} (${sw.serial}) is ${st.state} on ${st.up.fg.id}: not authorized yet.` };
  return { pass: true, detail: `${c.dev} is ${st.state} on ${st.up.fl}.` };
}

function fssoCheck(lab, c) {
  const fg = lab.dev(c.dev);
  const ag = lab.fssoAgents(fg);
  const a = c.agent ? ag.find((x) => x.name === c.agent) : ag[0];
  if (!a) return { pass: false, detail: `${c.dev} has no FSSO collector agent configured.` };
  if (a.status !== "connected") return { pass: false, detail: `FSSO agent ${a.name} is ${a.status}: ${a.why}.` };
  return { pass: true, detail: `FSSO agent ${a.name} is connected with ${a.logons.length} logon(s).` };
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
  if (c.expect === "fail") return h.lease ? { pass: false, detail: `${c.host} still gets a lease (${intToIp(h.lease.prefix.ip)}).` } : { pass: true, detail: `${c.host} gets no address.` };
  if (!h.lease) return { pass: false, detail: `${c.host} gets no DHCP lease.` };
  const p = parsePrefix(c.in);
  if (p && !inPrefix(h.lease.prefix.ip, p)) return { pass: false, detail: `${c.host} got ${intToIp(h.lease.prefix.ip)}, outside ${c.in}.` };
  if (c.gw && h.lease.gw !== ipToInt(c.gw)) return { pass: false, detail: `${c.host} got gateway ${h.lease.gw ? intToIp(h.lease.gw) : "none"} instead of ${c.gw}.` };
  if (c.dns && !h.lease.dns.includes(ipToInt(c.dns))) return { pass: false, detail: `${c.host} got DNS ${h.lease.dns.map(intToIp).join(", ") || "none"} instead of ${c.dns}.` };
  return { pass: true, detail: `${c.host} leased ${intToIp(h.lease.prefix.ip)}/${h.lease.prefix.len}, gateway ${h.lease.gw ? intToIp(h.lease.gw) : "none"}.` };
}

function routeCheck(lab, c) {
  const fg = getDev(lab, c.dev);
  const active = fg instanceof FortiGate ? lab.fgtRoutes(fg).active : lab.routerDynamic(fg);
  const want = parsePrefix(c.dst);
  const r = active.find((x) => x.dst.ip === want.ip && x.dst.len === want.len && (!c.via || x.gw === ipToInt(c.via)) && (!c.intf || x.dev === c.intf) && (!c.type || x.type === c.type || (c.type === "O" && String(x.type).startsWith("O"))));
  if (c.type && !c.absent && !r) {
    const other = active.find((x) => x.dst.ip === want.ip && x.dst.len === want.len);
    if (other) return { pass: false, detail: `${c.dst} is in the table on ${c.dev}, but as ${other.type} (distance ${other.distance}), not ${c.type}.` };
  }
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
  if (c.hc) {
    const hc = cfg.hcs.find((h) => h.name === c.hc);
    if (!hc) return { pass: false, detail: `No health check ${c.hc}.` };
    if (!hc.members.includes(m.seq)) return { pass: false, detail: `${c.hc} doesn't probe ${c.member}.` };
    const r = lab.memberHealth(fg, m, hc);
    if (!r.alive) return { pass: false, detail: `${c.hc} says ${c.member} is dead${r.why ? `: ${r.why}` : ""}.` };
    if (c.sla && !r.sla[0]) return { pass: false, detail: `${c.member} is alive but misses SLA 1 (latency ${r.latency.toFixed(1)} ms, loss ${r.loss}%).` };
    return { pass: true, detail: `${c.hc}: ${c.member} alive, latency ${r.latency.toFixed(1)} ms${c.sla ? ", SLA met" : ""}.` };
  }
  return { pass: true, detail: `${c.member} is an SD-WAN member and ${alive ? "alive" : "dead"}.` };
}

function webCheck(lab, c) {
  const { id } = parseFrom(lab, c.from);
  const m = String(c.url).match(/^(https?):\/\/([^/:]+)(?::(\d+))?(\/.*)?$/i);
  const scheme = m[1].toLowerCase(), host = m[2], port = Number(m[3] || (scheme === "https" ? 443 : 80)), path = m[4] || "/";
  const r = lab.resolve(id, host);
  if (r.err) return { pass: false, detail: `${c.from} could not resolve ${host}.` };
  const p = lab.probe(id, { dst: r.ip, proto: 6, dport: port });
  let verdict = "unreachable", w = null;
  if (p.ok) {
    const cloud = [...lab.devices.values()].find((d) => d.kind === "cloud" && d.hosts.some((x) => x.ip === p.seenDst));
    const ch = cloud && cloud.hosts.find((x) => x.ip === p.seenDst);
    w = lab.webInspect(id, p, { scheme, host, path, file: ch && ch.files[path] });
    verdict = w.verdict;
  }
  const want = c.expect || "allowed";
  const label = `${c.from} → ${c.url}`;
  if (verdict !== want) return { pass: false, detail: `${label}: ${verdict === "unreachable" ? "the connection itself fails (" + explain(p) + ")" : verdict === "blocked" ? `blocked by ${w.by === "av" ? "antivirus" : "the web filter"}` : verdict === "cert-error" ? "certificate error: " + w.reason : "allowed"}, expected ${want}.` };
  if (c.by && w && w.by !== c.by) return { pass: false, detail: `${label}: blocked, but by ${w.by === "av" ? "antivirus" : "the web filter"} instead of ${c.by === "av" ? "antivirus" : "the web filter"}.` };
  return { pass: true, detail: `${label}: ${verdict}${w && w.by ? ` by ${w.by === "av" ? "antivirus" : "the web filter"}` : ""}.` };
}
function fazCheck(lab, c) {
  const faz = getDev(lab, c.dev);
  const fg = c.device ? getDev(lab, c.device) : null;
  const m = fg && faz.managed.get(fg.id);
  if (c.authorized && (!m || !m.authorized)) return { pass: false, detail: `${c.device} is not authorized on ${c.dev}${lab.fazSenders(faz).includes(fg) ? " (it is sending, run devices / authorize)" : " (it isn't sending logs to it yet)"}.` };
  if (c.logs) {
    const logs = m ? m.logs : [];
    const f = c.logs;
    // an allowed session ends as action=close (TCP) or timeout on a real FortiGate: both mean accepted
    const same = (k, have, want) => String(have) === String(want) || (k === "action" && want === "accept" && ["close", "timeout", "accept"].includes(String(have)));
    const hits = logs.filter((r) => Object.entries(f).every(([k, v]) => same(k, r[k], v)));
    if (!hits.length) return { pass: false, detail: `${c.dev} has no ${Object.entries(f).map(([k, v]) => `${k}=${v}`).join(" ")} logs from ${c.device}.` };
    return { pass: true, detail: `${c.dev} holds ${hits.length} matching log(s) from ${c.device}.` };
  }
  return { pass: true, detail: `${c.device} is authorized on ${c.dev}.` };
}
function fmgCheck(lab, c) {
  const fmg = getDev(lab, c.dev);
  const fg = getDev(lab, c.device);
  const st = lab.fmgStatus(fmg, fg);
  if (c.status && !st.startsWith(c.status)) return { pass: false, detail: `${c.device} on ${c.dev}: ${st}.` };
  return { pass: true, detail: `${c.device} on ${c.dev}: ${st}.` };
}

// an attack from a threat pack: every request blocked (or reset), or every one reaching the server
function attackCheck(lab, a) {
  lab.quiet = (lab.quiet || 0) + 1;
  let r;
  try { r = lab.attackSim(a.from || "@attacker", a.to, a.pack, a.port); } finally { lab.quiet--; }
  if (r.error) return { pass: false, detail: r.error };
  const want = a.expect || "blocked";
  const okFor = { allowed: ["reached"], reset: ["reset"], blocked: ["blocked", "reset"], stopped: ["blocked", "reset", "failed"] }[want] || ["blocked", "reset"];
  const bad = r.results.filter((x) => !okFor.includes(x.outcome) || (a.policy && x.policy !== undefined && String(x.policy) !== String(a.policy)));
  if (!bad.length) return { pass: true, detail: `${r.pack.id}: ${r.results.map((x) => `${x.variant} ${x.outcome}`).join(", ")}.` };
  const x = bad[0];
  return { pass: false, detail: `${r.pack.id} ${x.variant}: ${x.outcome} (${x.detail}); expected ${want}.` };
}
