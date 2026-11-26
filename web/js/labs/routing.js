// Dynamic routing for the lab simulator: OSPF (adjacency rules, SPF, intra/inter-area, externals, stub areas,
// default origination) and BGP (sessions, eBGP/iBGP rules, next-hop handling, route reflection, prefix lists,
// route maps, best-path selection). Speakers are FortiGates (`router ospf` / `router bgp`) and lab routers with an
// `ospf:` or `bgp:` spec. The result is cached per configuration version.
//
// Router spec examples:
//   ospf: { router_id: 10.20.255.2, interfaces: [{ name: vlan50, area: 0.0.0.0, cost: 10, hello: 10, dead: 40,
//           auth: { type: md5, key: "..." }, mtu: 1500, passive: false, type: broadcast }],
//           redistribute_connected: false, default_originate: false }
//   bgp:  { as: 64600, router_id: 10.255.255.1, neighbors: [{ ip: 10.255.0.2, remote_as: 65010, password: "" }],
//           networks: [100.64.0.0/24], originate_default: false, internet: [8.8.8.0/24] }
import { Lab } from "./sim.js";
import { FortiGate } from "./fgt.js";
import { ipToInt, intToIp, parsePrefix, inPrefix, prefixStr, network } from "./net.js";

const AREA0 = "0.0.0.0";
const normArea = (a) => { const s = String(a ?? AREA0); return /^\d+$/.test(s) ? intToIp(Number(s)) : s; };
const pfx = (p) => ({ ip: network(p), len: p.len });
const pkey = (p) => prefixStr(p);
const lc = (x) => String(x || "").toLowerCase();

// ---------- speakers ----------
function fgSpeaker(lab, fg) {
  const intfs = lab.fgtIntfs(fg).filter((i) => i.prefix);
  return { id: fg.id, dev: fg, fg: true, intfs: intfs.map((i) => ({ name: i.name, prefix: i.prefix, seg: i.seg, up: i.up, mtu: i.mtu, loopback: i.type === "loopback" })) };
}
function routerSpeaker(lab, r) {
  return { id: r.id, dev: r, fg: false, intfs: r.ifaces.filter((i) => i.prefix).map((i) => ({ name: i.name, prefix: i.prefix, seg: lab.segOf(r.id, i.name), up: i.up && !!lab.segOf(r.id, i.name), mtu: r.mtu || 1500 })) };
}
function autoRid(sp) {
  const lo = sp.intfs.filter((i) => i.loopback && i.up).map((i) => i.prefix.ip);
  const all = sp.intfs.filter((i) => i.up).map((i) => i.prefix.ip);
  const pick = (lo.length ? lo : all).sort((a, b) => b - a)[0];
  return pick || 0;
}

// ---------- OSPF config ----------
function ospfCfg(lab, sp) {
  if (sp.fg) {
    const fg = sp.dev, P = "router ospf";
    const root = fg.cfg.get(P);
    if (!root) return null;
    const kid = (n) => { const t = root.children.get(n); return t ? t.list() : []; };
    const nets = kid("network").map((e) => ({ prefix: parsePrefix(fg.val(P, e, "prefix", ["network"]).join(" ") || "0.0.0.0 0.0.0.0"), area: normArea(fg.val(P, e, "area", ["network"])[0]) }));
    if (!nets.length) return null;
    const areas = new Map(kid("area").map((e) => [normArea(e.key), { type: fg.val(P, e, "type", ["area"])[0] || "regular", auth: fg.val(P, e, "authentication", ["area"])[0] || "none", defCost: Number(fg.val(P, e, "default-cost", ["area"])[0] || 10) }]));
    const oifs = kid("ospf-interface").map((e) => {
      const v = (a) => fg.val(P, e, a, ["ospf-interface"])[0];
      const md5 = e.children.get("md5-keys");
      return { name: e.key, intf: v("interface"), cost: Number(v("cost") || 0), type: v("network-type") || "broadcast", hello: Number(v("hello-interval") || 0), dead: Number(v("dead-interval") || 0),
        auth: v("authentication") || "none", key: (e.attrs.get("authentication-key") || [""])[0], md5: md5 ? md5.list().map((k) => [k.key, (k.attrs.get("key-string") || [""])[0]]) : [], mtuIgnore: v("mtu-ignore") === "enable", mtu: Number(v("mtu") || 0), prio: Number(v("priority") ?? 1), status: v("status") !== "disable" };
    });
    const passive = fg.val(P, root, "passive-interface");
    const defMetric = Number(fg.one(P, root, "default-metric") || 10);
    const redis = new Map(kid("redistribute").map((e) => [e.key, { on: fg.val(P, e, "status", ["redistribute"])[0] === "enable", metric: Number(fg.val(P, e, "metric", ["redistribute"])[0] || 0) || defMetric, mtype: fg.val(P, e, "metric-type", ["redistribute"])[0] || "2" }]));
    const ifs = [];
    for (const i of sp.intfs) {
      const net = nets.find((n) => n.prefix && inPrefix(i.prefix.ip, n.prefix));
      if (!net) continue;
      const o = oifs.find((x) => x.intf === i.name) || {};
      if (o.status === false) continue;
      const ar = areas.get(net.area) || { type: "regular", auth: "none", defCost: 10 };
      const auth = o.auth && o.auth !== "none" ? o.auth : ar.auth === "md5" || ar.auth === "message-digest" ? "message-digest" : ar.auth === "text" ? "text" : "none";
      ifs.push({ ...i, area: net.area, areaType: ar.type, cost: o.cost || 10, type: o.type || "broadcast", hello: o.hello || (o.type === "non-broadcast" ? 30 : 10), dead: o.dead || (o.hello ? o.hello * 4 : o.type === "non-broadcast" ? 120 : 40),
        auth, key: auth === "text" ? o.key || "" : auth === "message-digest" ? (o.md5 || []).map((k) => k.join(":")).join("|") : "", mtuIgnore: !!o.mtuIgnore, mtu: o.mtu || i.mtu || 1500, prio: o.prio ?? 1, passive: passive.includes(i.name) });
    }
    const rid = ipToInt(fg.one(P, root, "router-id") || "0.0.0.0") || autoRid(sp);
    const dio = fg.one(P, root, "default-information-originate") || "disable";
    return { rid, ifs, areas, redis, dio, dioMetric: Number(fg.one(P, root, "default-information-metric") || 10), dioType: fg.one(P, root, "default-information-metric-type") || "2" };
  }
  const o = sp.dev.spec && sp.dev.spec.ospf;
  if (!o) return null;
  const ifs = [];
  for (const c of o.interfaces || []) {
    const i = sp.intfs.find((x) => x.name === c.name);
    if (!i) continue;
    const auth = c.auth ? (c.auth.type === "md5" ? "message-digest" : c.auth.type) : "none";
    ifs.push({ ...i, area: normArea(c.area || AREA0), areaType: c.area_type || "regular", cost: c.cost || 10, type: c.type || "broadcast", hello: c.hello || 10, dead: c.dead || (c.hello ? c.hello * 4 : 40), auth, key: c.auth ? (auth === "message-digest" ? `${c.auth.id || 1}:${c.auth.key}` : c.auth.key) : "", mtuIgnore: !!c.mtu_ignore, mtu: c.mtu || i.mtu, prio: c.priority ?? 1, passive: !!c.passive });
  }
  return { rid: ipToInt(o.router_id || "0.0.0.0") || autoRid(sp), ifs, areas: new Map(), redis: new Map([["connected", { on: !!o.redistribute_connected, metric: 20, mtype: "2" }], ["static", { on: !!o.redistribute_static, metric: 20, mtype: "2" }]]), dio: o.default_originate ? "always" : "disable", dioMetric: 10, dioType: "2" };
}

function adjacency(a, ai, b, bi) {
  if (ai.prefix.len !== bi.prefix.len || network(ai.prefix) !== network(bi.prefix)) return { state: null, why: "network mask mismatch" };
  if (ai.area !== bi.area) return { state: null, why: `area mismatch (${ai.area} vs ${bi.area})` };
  if (ai.hello !== bi.hello) return { state: null, why: `Hello interval mismatch (${ai.hello} vs ${bi.hello})` };
  if (ai.dead !== bi.dead) return { state: null, why: `Router Dead interval mismatch (${ai.dead} vs ${bi.dead})` };
  if ((ai.areaType === "stub") !== (bi.areaType === "stub") || (ai.areaType === "nssa") !== (bi.areaType === "nssa")) return { state: null, why: "E-bit (stub area flag) mismatch" };
  if (ai.auth !== bi.auth) return { state: null, why: `authentication type mismatch (${ai.auth} vs ${bi.auth})` };
  if (ai.auth !== "none" && ai.key !== bi.key) return { state: null, why: "authentication key mismatch" };
  if (a.rid === b.rid) return { state: null, why: `duplicate router ID ${intToIp(a.rid)}` };
  if ((ai.type === "point-to-point") !== (bi.type === "point-to-point")) return { state: "2-Way", why: "network type mismatch (point-to-point vs broadcast): no DR agreement, no full adjacency" };
  if (ai.mtu !== bi.mtu && !ai.mtuIgnore && !bi.mtuIgnore) return { state: "ExStart", why: `MTU mismatch (${ai.mtu} vs ${bi.mtu}): database description packets are refused` };
  return { state: "Full", why: "" };
}

function runOspf(lab, speakers, baseRoutes) {
  const S = new Map();
  for (const sp of speakers) { const c = ospfCfg(lab, sp); if (c) S.set(sp.id, { sp, ...c, nbrs: [], routes: [], lsas: [] }); }
  const list = [...S.values()];
  // neighbors
  for (let x = 0; x < list.length; x++) for (let y = x + 1; y < list.length; y++) {
    const a = list[x], b = list[y];
    for (const ai of a.ifs) for (const bi of b.ifs) {
      if (!ai.up || !bi.up || ai.passive || bi.passive || !ai.seg || ai.seg !== bi.seg) continue;
      const r = adjacency(a, ai, b, bi);
      a.nbrs.push({ peer: b, intf: ai, pintf: bi, state: r.state, why: r.why });
      b.nbrs.push({ peer: a, intf: bi, pintf: ai, state: r.state, why: r.why });
    }
  }
  // DR/BDR per broadcast segment (for display)
  for (const s of list) for (const n of s.nbrs) {
    if (n.intf.type === "point-to-point") { n.role = "-"; continue; }
    const seg = n.intf.seg;
    const members = list.flatMap((z) => z.ifs.filter((i) => i.seg === seg && i.up && !i.passive && i.prio > 0).map((i) => ({ z, i })));
    members.sort((p, q) => (q.i.prio - p.i.prio) || (q.z.rid - p.z.rid));
    n.role = members[0] && members[0].z === n.peer ? "DR" : members[1] && members[1].z === n.peer ? "Backup" : "DROther";
  }
  // externals each speaker originates
  const ext = new Map();
  for (const s of list) {
    const out = [];
    const rib = baseRoutes.get(s.sp.id) || [];
    const inOspf = (d) => s.ifs.some((i) => network(i.prefix) === d.ip && i.prefix.len === d.len);
    const rc = s.redis.get("connected"), rs = s.redis.get("static");
    if (rc && rc.on) for (const r of rib.filter((r) => r.type === "C")) if (!inOspf(r.dst)) out.push({ dst: r.dst, metric: rc.metric || 20, etype: rc.mtype === "1" ? "E1" : "E2" });
    if (rs && rs.on) for (const r of rib.filter((r) => r.type === "S" && !r.blackhole && r.dst.len > 0)) out.push({ dst: r.dst, metric: rs.metric || 20, etype: rs.mtype === "1" ? "E1" : "E2" });
    const hasDefault = rib.some((r) => r.dst.len === 0 && r.type !== "O");
    if (s.dio === "always" || (s.dio === "enable" && hasDefault)) out.push({ dst: { ip: 0, len: 0 }, metric: s.dioMetric, etype: s.dioType === "1" ? "E1" : "E2" });
    ext.set(s.sp.id, out);
  }
  // SPF from each speaker over Full adjacencies
  for (const s of list) {
    const dist = new Map([[s, 0]]), first = new Map();
    const q = [s];
    const done = new Set();
    while (q.length) {
      q.sort((a, b) => dist.get(a) - dist.get(b));
      const u = q.shift();
      if (done.has(u)) continue;
      done.add(u);
      for (const n of u.nbrs) {
        if (n.state !== "Full" || !n.intf.up) continue;
        const d = dist.get(u) + n.intf.cost;
        if (!dist.has(n.peer) || d < dist.get(n.peer)) { dist.set(n.peer, d); first.set(n.peer, u === s ? { gw: n.pintf.prefix.ip, dev: n.intf.name } : first.get(u)); q.push(n.peer); }
      }
    }
    const myAreas = new Set(s.ifs.map((i) => i.area));
    const stubOnly = s.ifs.length && s.ifs.every((i) => i.areaType === "stub");
    const best = new Map();
    const offer = (r) => { const k = pkey(r.dst); const cur = best.get(k); const rank = (x) => ({ O: 0, "O IA": 1, "O E1": 2, "O E2": 3 })[x.type]; if (!cur || rank(r) < rank(cur) || (rank(r) === rank(cur) && (r.metric < cur.metric || (r.metric === cur.metric && (r.fwd || 0) < (cur.fwd || 0))))) best.set(k, r); };
    const connected = (d) => s.ifs.some((i) => network(i.prefix) === d.ip && i.prefix.len === d.len) || (baseRoutes.get(s.sp.id) || []).some((r) => r.type === "C" && r.dst.ip === d.ip && r.dst.len === d.len);
    for (const [z, d] of dist) {
      if (z === s) continue;
      const hop = first.get(z);
      if (!hop) continue;
      for (const i of z.ifs) {
        if (!i.up) continue;
        const dst = pfx(i.prefix);
        if (connected(dst)) continue;
        const intra = myAreas.has(i.area);
        if (stubOnly && !intra) continue;
        offer({ type: intra ? "O" : "O IA", dst, gw: hop.gw, dev: hop.dev, distance: 110, metric: d + i.cost, adv: z.rid, area: i.area });
      }
      if (!stubOnly) for (const e of ext.get(z.sp.id) || []) {
        if (connected(e.dst)) continue;
        offer({ type: e.etype === "E1" ? "O E1" : "O E2", dst: e.dst, gw: hop.gw, dev: hop.dev, distance: 110, metric: e.etype === "E1" ? e.metric + d : e.metric, fwd: d, adv: z.rid });
      }
      // stub areas: the ABR injects a default route
      if (stubOnly && z.ifs.some((i) => i.area === AREA0) && z.ifs.some((i) => i.areaType === "stub")) offer({ type: "O IA", dst: { ip: 0, len: 0 }, gw: hop.gw, dev: hop.dev, distance: 110, metric: d + 10, adv: z.rid });
    }
    s.routes = [...best.values()];
    s.extOut = ext.get(s.sp.id) || [];
  }
  return S;
}

// ---------- BGP ----------
function prefixListOk(fg, name, dst) {
  if (!name) return true;
  const pl = fg.entry("router prefix-list", name);
  if (!pl) return true; // FortiOS: a missing list permits
  const rules = pl.children.get("rule");
  for (const r of rules ? rules.list() : []) {
    const v = (a) => fg.val("router prefix-list", r, a, ["rule"])[0];
    const p = parsePrefix(String(fg.val("router prefix-list", r, "prefix", ["rule"]).join(" ") || "0.0.0.0 0.0.0.0").replace(/^any$/, "0.0.0.0/0"));
    if (!p) continue;
    const ge = v("ge") !== undefined && v("ge") !== "" ? Number(v("ge")) : null, le = v("le") !== undefined && v("le") !== "" ? Number(v("le")) : null;
    const inside = dst.len >= p.len && inPrefix(dst.ip, p);
    const lenOk = ge === null && le === null ? dst.len === p.len : dst.len >= (ge ?? p.len) && dst.len <= (le ?? 32);
    if (inside && lenOk) return (v("action") || "permit") === "permit";
  }
  return false; // implicit deny
}
function routeMap(fg, name, route) {
  if (!name) return route;
  const rm = fg.entry("router route-map", name);
  if (!rm) return null;
  const rules = rm.children.get("rule");
  for (const r of rules ? rules.list() : []) {
    const v = (a) => fg.val("router route-map", r, a, ["rule"]);
    const pl = v("match-ip-address")[0];
    if (pl && !prefixListOk(fg, pl, route.dst)) continue;
    if ((v("action")[0] || "permit") === "deny") return null;
    const out = { ...route, aspath: [...route.aspath] };
    const lp = v("set-local-preference")[0]; if (lp !== undefined && lp !== "") out.lp = Number(lp);
    const w = v("set-weight")[0]; if (w !== undefined && w !== "") out.weight = Number(w);
    const m = v("set-metric")[0]; if (m !== undefined && m !== "") out.med = Number(m);
    const pre = v("set-aspath"); if (pre.length) out.prepend = pre.map(Number).filter((x) => x);
    return out;
  }
  return null; // no rule matched: deny
}

function bgpCfg(lab, sp) {
  if (sp.fg) {
    const fg = sp.dev, P = "router bgp";
    const root = fg.cfg.get(P);
    const as = root ? Number(fg.one(P, root, "as") || 0) : 0;
    if (!as) return null;
    const kid = (n) => { const t = root.children.get(n); return t ? t.list() : []; };
    const nbrs = kid("neighbor").map((e) => {
      const v = (a) => fg.val(P, e, a, ["neighbor"])[0];
      return { ip: ipToInt(e.key), remoteAs: Number(v("remote-as") || 0), updSrc: v("update-source") || "", multihop: v("ebgp-enforce-multihop") === "enable", pw: (e.attrs.get("password") || [""])[0],
        rmIn: v("route-map-in") || "", rmOut: v("route-map-out") || "", plIn: v("prefix-list-in") || "", plOut: v("prefix-list-out") || "", nhs: v("next-hop-self") === "enable",
        rrc: v("route-reflector-client") === "enable", shut: (v("shutdown") || "disable") !== "disable", allowas: v("allowas-in-enable") === "enable", defOrig: v("capability-default-originate") === "enable",
        weight: v("weight") && v("weight") !== "4294967295" ? Number(v("weight")) : 0 };
    });
    const nets = kid("network").map((e) => ({ prefix: parsePrefix(fg.val(P, e, "prefix", ["network"]).join(" ") || "0.0.0.0 0.0.0.0"), rm: fg.val(P, e, "route-map", ["network"])[0] || "" })).filter((n) => n.prefix);
    const redis = new Map(kid("redistribute").map((e) => [e.key, { on: fg.val(P, e, "status", ["redistribute"])[0] === "enable", rm: fg.val(P, e, "route-map", ["redistribute"])[0] || "" }]));
    return { as, rid: ipToInt(fg.one(P, root, "router-id") || "0.0.0.0") || autoRid(sp), nbrs, nets, redis, importCheck: fg.one(P, root, "network-import-check") !== "disable",
      lpDefault: Number(fg.one(P, root, "default-local-preference") || 100), distExt: 20, distInt: 200 };
  }
  const b = sp.dev.spec && sp.dev.spec.bgp;
  if (!b) return null;
  return { as: Number(b.as), rid: ipToInt(b.router_id || "0.0.0.0") || autoRid(sp), lpDefault: 100, distExt: 20, distInt: 200, importCheck: false,
    nbrs: (b.neighbors || []).map((n) => ({ ip: ipToInt(n.ip), remoteAs: Number(n.remote_as), pw: n.password || "", updSrc: "", multihop: !!n.multihop, rmIn: "", rmOut: "", plIn: "", plOut: "", nhs: !!n.next_hop_self, rrc: !!n.rr_client, shut: !!n.shutdown, allowas: false, defOrig: !!n.default_originate, weight: 0, max: n.max_prefix || 0 })),
    nets: [...(b.networks || []), ...(b.internet || [])].map((p) => ({ prefix: parsePrefix(p) })).filter((n) => n.prefix), originateDefault: !!b.originate_default, redis: new Map() };
}

function runBgp(lab, speakers, ribOf, ownerOf) {
  const B = new Map();
  for (const sp of speakers) { const c = bgpCfg(lab, sp); if (c) B.set(sp.id, { sp, ...c, sessions: [], rib: new Map(), adjIn: new Map(), adjOut: new Map() }); }
  const lookup = (spId, ip) => { const rs = (ribOf(spId) || []).filter((r) => inPrefix(ip, r.dst)); if (!rs.length) return null; const m = Math.max(...rs.map((r) => r.dst.len)); return rs.filter((r) => r.dst.len === m).sort((a, b) => a.distance - b.distance)[0]; };
  const srcIpFor = (s, n) => {
    if (n.updSrc) { const i = s.sp.intfs.find((x) => x.name === n.updSrc); return i ? i.prefix.ip : null; }
    const rt = lookup(s.sp.id, n.ip);
    if (!rt) return null;
    const i = s.sp.intfs.find((x) => x.name === rt.dev && x.up);
    return i ? i.prefix.ip : null;
  };
  // sessions
  for (const s of B.values()) for (const n of s.nbrs) {
    const sess = { n, peer: null, state: "Active", why: "", src: null, ebgp: n.remoteAs !== s.as };
    s.sessions.push(sess);
    if (n.shut) { sess.state = "Idle (Admin)"; sess.why = "neighbor is shut down"; continue; }
    const owner = ownerOf(n.ip);
    sess.src = srcIpFor(s, n);
    if (!sess.src || !lookup(s.sp.id, n.ip)) { sess.state = "Active"; sess.why = `no route to ${intToIp(n.ip)}`; continue; }
    const t = owner && B.get(owner);
    if (!t) { sess.state = "Active"; sess.why = owner ? `${owner} doesn't run BGP` : `nothing answers on ${intToIp(n.ip)}:179`; continue; }
    const direct = s.sp.intfs.some((i) => i.up && inPrefix(n.ip, i.prefix));
    if (sess.ebgp && !direct && !n.multihop) { sess.state = "Active"; sess.why = "eBGP peer isn't directly connected (TTL 1): enable ebgp-enforce-multihop"; continue; }
    if (!lookup(owner, sess.src)) { sess.state = "Active"; sess.why = `the peer has no route back to ${intToIp(sess.src)}`; continue; }
    const back = t.nbrs.find((x) => x.ip === sess.src);
    if (!back) { sess.state = "Active"; sess.why = `the peer has no neighbor ${intToIp(sess.src)} (wrong update-source or peer config)`; continue; }
    if (back.shut) { sess.state = "Idle"; sess.why = "the peer has shut the session down"; continue; }
    if (back.remoteAs !== s.as) { sess.state = "Idle"; sess.why = `NOTIFICATION: OPEN Message Error/Bad Peer AS (peer expects AS ${back.remoteAs}, we are ${s.as})`; continue; }
    if (n.remoteAs !== t.as) { sess.state = "Idle"; sess.why = `NOTIFICATION: OPEN Message Error/Bad Peer AS (we expect AS ${n.remoteAs}, peer is ${t.as})`; continue; }
    if ((n.pw || "") !== (back.pw || "")) { sess.state = "Active"; sess.why = "TCP MD5 signature mismatch: the peer drops our SYNs"; continue; }
    if (sess.ebgp && !back.multihop && !t.sp.intfs.some((i) => i.up && inPrefix(sess.src, i.prefix))) { sess.state = "Active"; sess.why = "the peer requires a directly connected eBGP neighbor"; continue; }
    sess.state = "Established"; sess.peer = t; sess.peerSess = back;
  }
  // originate
  for (const s of B.values()) {
    const rib = ribOf(s.sp.id) || [];
    const loc = [];
    for (const net of s.nets) {
      const dst = pfx(net.prefix);
      if (s.importCheck && !rib.some((r) => r.dst.ip === dst.ip && r.dst.len === dst.len)) continue;
      loc.push({ dst, aspath: [], nh: 0, lp: s.lpDefault, med: 0, origin: "i", weight: 32768, local: true });
    }
    for (const [kind, code] of [["connected", "C"], ["static", "S"], ["ospf", "O"]]) {
      const rd = s.redis.get(kind);
      if (!rd || !rd.on) continue;
      for (const r of rib) if ((code === "O" ? r.type.startsWith("O") : r.type === code) && !r.blackhole) {
        let x = { dst: r.dst, aspath: [], nh: 0, lp: s.lpDefault, med: r.metric || 0, origin: "?", weight: 32768, local: true };
        if (rd.rm && s.sp.fg) x = routeMap(s.sp.dev, rd.rm, x);
        if (x) loc.push(x);
      }
    }
    if (s.originateDefault) loc.push({ dst: { ip: 0, len: 0 }, aspath: [], nh: 0, lp: 100, med: 0, origin: "i", weight: 32768, local: true });
    s.local = loc;
    for (const r of loc) s.rib.set(pkey(r.dst), [r]);
  }
  const better = (s, a, b) => {
    if (a.weight !== b.weight) return a.weight > b.weight;
    if (a.lp !== b.lp) return a.lp > b.lp;
    if (!!a.local !== !!b.local) return !!a.local;
    if (a.aspath.length !== b.aspath.length) return a.aspath.length < b.aspath.length;
    const o = { i: 0, e: 1, "?": 2 };
    if (o[a.origin] !== o[b.origin]) return o[a.origin] < o[b.origin];
    if (a.aspath[0] === b.aspath[0] && a.med !== b.med) return a.med < b.med;
    if (!!a.ebgp !== !!b.ebgp) return !!a.ebgp;
    if (a.peerRid !== b.peerRid) return (a.peerRid || 0) < (b.peerRid || 0);
    return (a.from || 0) < (b.from || 0);
  };
  const valid = (s, r) => r.local || !!lookup(s.sp.id, r.nh);
  const bestOf = (s, k) => { const c = (s.rib.get(k) || []).filter((r) => valid(s, r)); let b = null; for (const r of c) if (!b || better(s, r, b)) b = r; return b; };
  // propagate until stable
  for (let round = 0; round < 14; round++) {
    let changed = false;
    for (const s of B.values()) for (const sess of s.sessions) {
      if (sess.state !== "Established") continue;
      const t = sess.peer, n = sess.n, back = sess.peerSess;
      const out = new Map();
      for (const k of s.rib.keys()) {
        const r = bestOf(s, k);
        if (!r) continue;
        if (r.from === n.ip && r.fromAs === t.as) continue; // don't send back
        if (!sess.ebgp && !r.local && !r.ebgp) {
          // iBGP-learned: only a route reflector passes it on
          const fromClient = r.fromRrc;
          if (!(n.rrc || fromClient)) continue;
        }
        let x = { ...r, aspath: [...r.aspath] };
        if (sess.ebgp && !x.local) x.med = 0; // MED doesn't cross AS boundaries
        if (s.sp.fg && !prefixListOk(s.sp.dev, n.plOut, x.dst)) continue;
        if (s.sp.fg && n.rmOut) { x = routeMap(s.sp.dev, n.rmOut, x); if (!x) continue; }
        if (sess.ebgp) { x.aspath = [s.as, ...(x.prepend || []), ...x.aspath]; x.nh = sess.src; x.lp = undefined; }
        else { if (x.local || n.nhs) x.nh = sess.src; if (x.prepend) x.aspath = [...x.prepend, ...x.aspath]; }
        delete x.prepend;
        out.set(k, x);
      }
      if (sess.n.defOrig && !out.has("0.0.0.0/0")) out.set("0.0.0.0/0", { dst: { ip: 0, len: 0 }, aspath: sess.ebgp ? [s.as] : [], nh: sess.src, origin: "i", med: 0 });
      s.adjOut.set(n.ip, out);
      // receiver side
      const got = [];
      for (const [k, x0] of out) {
        if (x0.aspath.includes(t.as) && !(back && back.allowas)) continue;
        let x = { ...x0, aspath: [...x0.aspath], lp: sess.ebgp ? t.lpDefault : x0.lp ?? t.lpDefault, weight: back ? back.weight : 0, local: false, from: sess.src, fromAs: s.as, ebgp: sess.ebgp, peerRid: s.rid, fromRrc: back ? back.rrc : false };
        if (t.sp.fg && back && !prefixListOk(t.sp.dev, back.plIn, x.dst)) continue;
        if (t.sp.fg && back && back.rmIn) { x = routeMap(t.sp.dev, back.rmIn, x); if (!x) continue; if (x.prepend) { x.aspath = [...x.prepend, ...x.aspath]; delete x.prepend; } }
        got.push([k, x]);
      }
      const prev = t.adjIn.get(sess.src);
      const sig = JSON.stringify(got.map(([k, x]) => [k, x.nh, x.aspath, x.lp, x.weight, x.med]));
      if (!prev || prev.sig !== sig) {
        changed = true;
        t.adjIn.set(sess.src, { sig, routes: new Map(got) });
        // rebuild t's rib from local + all adjIn
        t.rib = new Map();
        for (const r of t.local) t.rib.set(pkey(r.dst), [r]);
        for (const a of t.adjIn.values()) for (const [k, x] of a.routes) { if (!t.rib.has(k)) t.rib.set(k, []); t.rib.get(k).push(x); }
      }
    }
    if (!changed) break;
  }
  for (const s of B.values()) {
    s.best = new Map();
    for (const k of s.rib.keys()) { const b = bestOf(s, k); if (b) s.best.set(k, b); }
    s.installed = [...s.best.values()].filter((r) => !r.local).map((r) => {
      const via = lookup(s.sp.id, r.nh);
      // a next hop that isn't on a connected subnet is resolved through the IGP (recursive)
      return via ? { type: "B", dst: r.dst, gw: via.type === "C" ? r.nh : via.gw, nh: r.nh, dev: via.dev, distance: r.ebgp ? s.distExt : s.distInt, metric: r.med || 0, priority: 0, recursive: via.type !== "C" } : null;
    }).filter(Boolean);
  }
  return B;
}

// ---------- control plane ----------
Lab.prototype.controlPlane = function () {
  if (this._cp && this._cpVer === this.ver) return this._cp;
  if (this._cpBusy) return { ospf: new Map(), bgp: new Map(), routes: new Map() };
  this._cpBusy = true;
  try {
    const speakers = [];
    for (const d of this.devices.values()) {
      if (d instanceof FortiGate && d.product === "fortios") speakers.push(fgSpeaker(this, d));
      else if (d.kind === "router" && d.spec && (d.spec.ospf || d.spec.bgp)) speakers.push(routerSpeaker(this, d));
    }
    const base = new Map();
    const baseOf = (sp) => sp.fg ? this.fgtRoutes(sp.dev).active : [
      ...sp.intfs.filter((i) => i.up).map((i) => ({ type: "C", dst: pfx(i.prefix), dev: i.name, distance: 0 })),
      ...sp.dev.routes.filter((r) => r.via !== null || r.dev === "internet").map((r) => ({ type: "S", dst: r.dst, gw: r.via, dev: r.via ? (sp.intfs.find((i) => inPrefix(r.via, i.prefix)) || {}).name : "internet", distance: 1 })),
    ];
    for (const sp of speakers) base.set(sp.id, baseOf(sp));
    const ospf = runOspf(this, speakers, base);
    const withOspf = new Map();
    for (const sp of speakers) {
      const o = ospf.get(sp.id);
      const own = base.get(sp.id).filter((r) => r.type !== "B");
      const extra = o ? o.routes.filter((r) => !own.some((x) => x.dst.ip === r.dst.ip && x.dst.len === r.dst.len && x.distance <= r.distance)) : [];
      withOspf.set(sp.id, [...own, ...extra]);
    }
    const owner = new Map();
    for (const sp of speakers) for (const i of sp.intfs) if (i.up) owner.set(i.prefix.ip, sp.id);
    const bgp = runBgp(this, speakers, (id) => withOspf.get(id), (ip) => owner.get(ip));
    const routes = new Map();
    for (const sp of speakers) {
      const o = ospf.get(sp.id), b = bgp.get(sp.id);
      routes.set(sp.id, [...(o ? o.routes : []), ...(b ? b.installed : [])]);
    }
    this._cp = { ospf, bgp, routes };
    this._cpVer = this.ver;
    return this._cp;
  } finally { this._cpBusy = false; }
};
Lab.prototype.dynRoutes = function (dev) { return this.controlPlane().routes.get(dev.id) || []; };

// ---------- consoles ----------
const age = () => "00:12:" + String(17 + Math.floor(Math.random() * 40)).padStart(2, "0");
Lab.prototype.routingDiag = function (dev, words, head) {
  const w = words.join(" ");
  const cp = this.controlPlane();
  if (head === "get" && /^router info ospf neighbor/.test(w)) {
    const o = cp.ospf.get(dev.id);
    if (!o) return "";
    const rows = o.nbrs.filter((n) => n.state).map((n) => `${intToIp(n.peer.rid).padEnd(16)}${String(n.pintf.prio).padStart(3)}   ${(n.state + "/" + (n.role || "-")).padEnd(16)}00:00:3${Math.floor(Math.random() * 9)}    ${intToIp(n.pintf.prefix.ip).padEnd(16)}${n.intf.name}`);
    return [`OSPF process 0, VRF 0:`, `Neighbor ID     Pri   State           Dead Time   Address         Interface`, ...rows].join("\n");
  }
  if (head === "get" && /^router info ospf interface/.test(w)) {
    const o = cp.ospf.get(dev.id);
    if (!o) return "";
    const only = words[4];
    return o.ifs.filter((i) => !only || i.name === only).map((i) => {
      const ns = o.nbrs.filter((n) => n.intf === i);
      return `${i.name} is ${i.up ? "up" : "down"}, line protocol is ${i.up ? "up" : "down"}\n  Internet Address ${intToIp(i.prefix.ip)}/${i.prefix.len}, Area ${i.area}, MTU ${i.mtu}\n  Process ID 0, VRF 0, Router ID ${intToIp(o.rid)}, Network Type ${i.type.toUpperCase().replace(/-/g, "_")}, Cost: ${i.cost}\n  Transmit Delay is 1 sec, State ${i.passive ? "Passive" : ns.some((n) => n.state === "Full") ? "DR" : "Waiting"}, Priority ${i.prio}\n  Timer intervals configured, Hello ${i.hello}, Dead ${i.dead}, Wait ${i.dead}, Retransmit 5\n  ${i.auth === "none" ? "" : `${i.auth === "text" ? "Simple password" : "Cryptographic"} authentication enabled\n  `}Neighbor Count is ${ns.length}, Adjacent neighbor count is ${ns.filter((n) => n.state === "Full").length}`;
    }).join("\n\n");
  }
  if (head === "get" && /^router info ospf database/.test(w)) {
    const o = cp.ospf.get(dev.id);
    if (!o) return "";
    const all = [...cp.ospf.values()].filter((z) => z === o || o.routes.some((r) => r.adv === z.rid));
    const lines = [`                OSPF Router with ID (${intToIp(o.rid)}) (Process ID 0, VRF 0)`, ``];
    for (const area of [...new Set(o.ifs.map((i) => i.area))]) {
      lines.push(`                Router Link States (Area ${area})`, ``, `Link ID         ADV Router      Age  Seq#       CkSum  Link count`);
      for (const z of all.filter((z) => z.ifs.some((i) => i.area === area))) lines.push(`${intToIp(z.rid).padEnd(16)}${intToIp(z.rid).padEnd(16)} 412 0x80000006 0x3a1c ${z.ifs.filter((i) => i.area === area).length}`);
      lines.push(``);
    }
    const ext = all.flatMap((z) => (z.extOut || []).map((e) => ({ z, e })));
    if (ext.length) { lines.push(`                AS External Link States`, ``, `Link ID         ADV Router      Age  Seq#       CkSum  Route`); for (const { z, e } of ext) lines.push(`${intToIp(e.dst.ip).padEnd(16)}${intToIp(z.rid).padEnd(16)} 412 0x80000002 0x5b2e ${e.etype}  ${prefixStr(e.dst)} [0x0]`); }
    return lines.join("\n");
  }
  if (head === "get" && /^router info bgp summary/.test(w)) {
    const b = cp.bgp.get(dev.id);
    if (!b) return "";
    const pfx = (s) => s.state === "Established" ? String((b.adjIn.get(s.n.ip) || { routes: new Map() }).routes.size) : s.state;
    return [`VRF 0 BGP router identifier ${intToIp(b.rid)}, local AS number ${b.as}`, `BGP table version is ${3 + b.best.size}`, `${new Set([...b.best.values()].map((r) => r.aspath.join(" "))).size} BGP AS-PATH entries`, `0 BGP community entries`, ``,
      `Neighbor        V         AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd`,
      ...b.sessions.map((s) => `${intToIp(s.n.ip).padEnd(16)}4 ${String(s.n.remoteAs).padStart(10)} ${String(s.state === "Established" ? 312 : 0).padStart(7)} ${String(s.state === "Established" ? 309 : 0).padStart(7)} ${String(s.state === "Established" ? 3 + b.best.size : 0).padStart(8)}    0    0 ${s.state === "Established" ? "00:51:07" : "never   "} ${s.state === "Established" ? pfx(s).padStart(8) : s.state}`),
      ``, `Total number of neighbors ${b.sessions.length}`].join("\n");
  }
  if (head === "get" && /^router info bgp (network|route)/.test(w)) {
    const b = cp.bgp.get(dev.id);
    if (!b) return "";
    const rows = [];
    for (const [k, rs] of [...b.rib.entries()].sort()) for (const r of rs) {
      const best = b.best.get(k) === r;
      const ok = r.local || !!r.nh;
      rows.push(`${ok ? "*" : " "}${best ? ">" : " "}${!r.local && !r.ebgp ? "i" : " "}${k.padEnd(18)}${(r.local ? "0.0.0.0" : intToIp(r.nh)).padEnd(20)}${String(r.med || 0).padStart(6)} ${String(r.lp ?? 100).padStart(6)} ${String(r.weight).padStart(6)}        0 ${[...r.aspath, r.origin].join(" ")} <-/${best ? 1 : 0}>`);
    }
    return [`VRF 0 BGP table version is ${3 + b.best.size}, local router ID is ${intToIp(b.rid)}`, `Status codes: s suppressed, d damped, h history, * valid, > best, i - internal,`, `              S Stale`, `Origin codes: i - IGP, e - EGP, ? - incomplete`, ``, `   Network          Next Hop            Metric LocPrf Weight RouteTag Path`, ...rows, ``, `Total number of prefixes ${b.rib.size}`].join("\n");
  }
  const m = w.match(/^router info bgp neighbors (\S+) (advertised-routes|received-routes|routes)/);
  if (head === "get" && m) {
    const b = cp.bgp.get(dev.id);
    if (!b) return "";
    const ip = ipToInt(m[1]);
    const sess = b.sessions.find((s) => s.n.ip === ip);
    if (!sess) return `% No such neighbor or address family`;
    const set = m[2] === "advertised-routes" ? b.adjOut.get(ip) : (b.adjIn.get(ip) || {}).routes;
    const rows = [...(set || new Map()).entries()].map(([k, r]) => `*> ${k.padEnd(18)}${intToIp(r.nh || 0).padEnd(20)}${String(r.med || 0).padStart(6)} ${String(r.lp ?? "").padStart(6)} ${String(r.weight ?? 0).padStart(6)} ${[...r.aspath, r.origin].join(" ")}`);
    return [`   Network          Next Hop            Metric LocPrf Weight Path`, ...rows, ``, `Total number of prefixes ${rows.length}`].join("\n");
  }
  if (head === "get" && /^router info bgp neighbors/.test(w)) {
    const b = cp.bgp.get(dev.id);
    if (!b) return "";
    return b.sessions.map((s) => `BGP neighbor is ${intToIp(s.n.ip)}, remote AS ${s.n.remoteAs}, local AS ${b.as}, ${s.ebgp ? "external" : "internal"} link\n  BGP version 4, remote router ID ${s.peer ? intToIp(s.peer.rid) : "0.0.0.0"}\n  BGP state = ${s.state}${s.state === "Established" ? ", up for 00:51:07" : ""}\n${s.why ? `  Last reset never, ${s.why}\n` : ""}  Local host: ${s.src ? intToIp(s.src) : "0.0.0.0"}, Local port: 179\n  Foreign host: ${intToIp(s.n.ip)}, Foreign port: 179`).join("\n\n");
  }
  if (head === "diagnose" && /^ip router (ospf|bgp) (all|level)/.test(w)) {
    const proto = words[2];
    dev.dbg[proto] = !/disable/.test(w);
    if (proto === "ospf" && dev.dbg.ospf) { const o = cp.ospf.get(dev.id); for (const n of (o ? o.nbrs : []).filter((n) => n.state !== "Full")) dev.async.push(`OSPF: RECV[Hello]: From ${intToIp(n.peer.rid)} via ${n.intf.name}:${intToIp(n.intf.prefix.ip)}: ${n.why}`); }
    if (proto === "bgp" && dev.dbg.bgp) { const b = cp.bgp.get(dev.id); for (const s of (b ? b.sessions : []).filter((s) => s.state !== "Established")) dev.async.push(`BGP: ${intToIp(s.n.ip)} [FSM] ${s.state}: ${s.why}`); }
    return "";
  }
  if (head === "execute" && /^router clear (bgp|ospf)/.test(w)) { this.ver++; return ""; }
  return null;
};

// ISP/carrier routers: dynamic routes and read-only show commands
Lab.prototype.routerDynamic = function (r) { return this.controlPlane().routes.get(r.id) || []; };
Lab.prototype.routerShow = function (r, t) {
  const cp = this.controlPlane();
  if (/^show ip ospf nei/.test(t)) {
    const o = cp.ospf.get(r.id);
    if (!o) return "% OSPF is not running";
    return ["Neighbor ID     Pri State           Dead Time Address         Interface", ...o.nbrs.filter((n) => n.state).map((n) => `${intToIp(n.peer.rid).padEnd(16)}${String(n.pintf.prio).padStart(3)} ${(n.state + "/" + (n.role || "-")).padEnd(16)}00:00:33  ${intToIp(n.pintf.prefix.ip).padEnd(16)}${n.intf.name}`)].join("\n");
  }
  if (/^show (ip )?bgp sum/.test(t)) {
    const b = cp.bgp.get(r.id);
    if (!b) return "% BGP not active";
    return [`BGP router identifier ${intToIp(b.rid)}, local AS number ${b.as}`, ``, `Neighbor        V    AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd`,
      ...b.sessions.map((s) => `${intToIp(s.n.ip).padEnd(16)}4 ${String(s.n.remoteAs).padStart(5)}     211     208        9    0    0 ${s.state === "Established" ? "00:51:07" : "never   "} ${s.state === "Established" ? String((b.adjIn.get(s.n.ip) || { routes: new Map() }).routes.size).padStart(8) : s.state}`)].join("\n");
  }
  if (/^show (ip )?bgp( |$)/.test(t)) {
    const b = cp.bgp.get(r.id);
    if (!b) return "% BGP not active";
    return ["   Network          Next Hop            Metric LocPrf Weight Path", ...[...b.best.entries()].sort().map(([k, x]) => `*> ${k.padEnd(18)}${(x.local ? "0.0.0.0" : intToIp(x.nh)).padEnd(20)}${String(x.med || 0).padStart(6)} ${String(x.lp ?? "").padStart(6)} ${String(x.weight).padStart(6)} ${[...x.aspath, x.origin].join(" ")}`)].join("\n");
  }
  return null;
};

// ---------- FRR (FortiTatake OS stage 4): the same configuration, as FRR runs it ----------
// One frr.conf per speaker. The real network then learns its OSPF and BGP routes from real
// protocol exchanges between the namespaces; compile.js stops installing the simulator's.
function frrPrefixLists(fg, names) {
  const out = [];
  for (const name of names) {
    const pl = fg.entry("router prefix-list", name);
    if (!pl) continue;
    const rules = pl.children.get("rule");
    let seq = 5;
    for (const r of rules ? rules.list() : []) {
      const v = (a) => fg.val("router prefix-list", r, a, ["rule"])[0];
      const p = parsePrefix(String(fg.val("router prefix-list", r, "prefix", ["rule"]).join(" ") || "0.0.0.0 0.0.0.0").replace(/^any$/, "0.0.0.0/0"));
      if (!p) continue;
      const ge = v("ge"), le = v("le");
      out.push(`ip prefix-list ${name} seq ${seq} ${v("action") || "permit"} ${prefixStr(pfx(p))}${ge ? ` ge ${ge}` : ""}${le ? ` le ${le}` : ""}`);
      seq += 5;
    }
    if (seq === 5) out.push(`ip prefix-list ${name} seq 5 deny any`);
  }
  return out;
}
function frrRouteMaps(fg, names, pls) {
  const out = [];
  for (const name of names) {
    const rm = fg.entry("router route-map", name);
    if (!rm) { out.push(`route-map ${name} deny 10`); continue; }
    const rules = rm.children.get("rule");
    let n = 10;
    for (const r of rules ? rules.list() : []) {
      const v = (a) => fg.val("router route-map", r, a, ["rule"]);
      out.push(`route-map ${name} ${v("action")[0] || "permit"} ${n}`);
      const pl = v("match-ip-address")[0];
      if (pl) { out.push(` match ip address prefix-list ${pl}`); pls.add(pl); }
      const lp = v("set-local-preference")[0]; if (lp) out.push(` set local-preference ${lp}`);
      const w = v("set-weight")[0]; if (w) out.push(` set weight ${w}`);
      const m = v("set-metric")[0]; if (m) out.push(` set metric ${m}`);
      const pre = v("set-aspath"); if (pre.length) out.push(` set as-path prepend ${pre.join(" ")}`);
      n += 10;
    }
  }
  return out;
}

// the frr.conf for one device, or "" when it speaks neither protocol
Lab.prototype.frrConf = function (dev) {
  const sp = dev instanceof FortiGate ? fgSpeaker(this, dev) : dev.kind === "router" ? routerSpeaker(this, dev) : null;
  if (!sp) return { conf: "", daemons: [] };
  const o = ospfCfg(this, sp), b = bgpCfg(this, sp);
  if (!o && !b) return { conf: "", daemons: [] };
  const L = [`frr defaults traditional`, `hostname ${dev.id}`, `log syslog warnings`, `service integrated-vtysh-config`, `!`];
  const daemons = [];
  const pls = new Set(), rms = new Set();
  if (o) {
    daemons.push("ospfd");
    for (const i of o.ifs) {
      L.push(`interface ${i.name}`, ` ip ospf area ${i.area}`, ` ip ospf hello-interval ${i.hello}`, ` ip ospf dead-interval ${i.dead}`, ` ip ospf cost ${i.cost}`, ` ip ospf priority ${i.prio}`);
      if (i.type === "point-to-point") L.push(` ip ospf network point-to-point`);
      if (i.mtuIgnore) L.push(` ip ospf mtu-ignore`);
      if (i.auth === "text") L.push(` ip ospf authentication`, ` ip ospf authentication-key ${String(i.key).slice(0, 8)}`);
      if (i.auth === "message-digest") { L.push(` ip ospf authentication message-digest`); for (const k of String(i.key).split("|").filter(Boolean)) { const [id, ...key] = k.split(":"); L.push(` ip ospf message-digest-key ${Number(id) || 1} md5 ${key.join(":").slice(0, 16)}`); } }
      if (i.passive) L.push(` ip ospf passive`);
      L.push(`!`);
    }
    L.push(`router ospf`, ` ospf router-id ${intToIp(o.rid)}`);
    for (const [a, ar] of o.areas) { if (ar.type === "stub") L.push(` area ${a} stub`); else if (ar.type === "nssa") L.push(` area ${a} nssa`); }
    for (const i of o.ifs) { if (i.areaType === "stub" && !o.areas.has(i.area)) L.push(` area ${i.area} stub`); }
    for (const [k, r] of o.redis) if (r.on && ["connected", "static", "bgp"].includes(k)) L.push(` redistribute ${k} metric ${r.metric} metric-type ${r.mtype}`);
    if (o.dio && o.dio !== "disable") L.push(` default-information originate${o.dio === "always" ? " always" : ""} metric ${o.dioMetric} metric-type ${o.dioType}`);
    L.push(`!`);
  }
  if (b) {
    daemons.push("bgpd");
    L.push(`router bgp ${b.as}`, ` bgp router-id ${intToIp(b.rid)}`, ` no bgp ebgp-requires-policy`, ` no bgp default ipv4-unicast`, ` bgp bestpath as-path multipath-relax`);
    if (!b.importCheck) L.push(` no bgp network import-check`);
    for (const n of b.nbrs) {
      const ip = intToIp(n.ip);
      L.push(` neighbor ${ip} remote-as ${n.remoteAs}`);
      if (n.pw) L.push(` neighbor ${ip} password ${n.pw}`);
      if (n.updSrc) L.push(` neighbor ${ip} update-source ${n.updSrc}`);
      if (n.multihop) L.push(` neighbor ${ip} ebgp-multihop 255`);
      if (n.shut) L.push(` neighbor ${ip} shutdown`);
      L.push(` neighbor ${ip} timers 3 9`, ` neighbor ${ip} timers connect 5`);
    }
    L.push(` address-family ipv4 unicast`);
    for (const n of b.nets) L.push(`  network ${prefixStr(pfx(n.prefix))}${n.rm ? ` route-map ${n.rm}` : ""}`), n.rm && rms.add(n.rm);
    for (const [k, r] of b.redis || []) if (r.on && ["connected", "static", "ospf"].includes(k)) { L.push(`  redistribute ${k}${r.rm ? ` route-map ${r.rm}` : ""}`); if (r.rm) rms.add(r.rm); }
    for (const n of b.nbrs) {
      const ip = intToIp(n.ip);
      L.push(`  neighbor ${ip} activate`);
      if (n.nhs) L.push(`  neighbor ${ip} next-hop-self`);
      if (n.rrc) L.push(`  neighbor ${ip} route-reflector-client`);
      if (n.allowas) L.push(`  neighbor ${ip} allowas-in`);
      if (n.defOrig || b.originateDefault) L.push(`  neighbor ${ip} default-originate`);
      if (n.weight) L.push(`  neighbor ${ip} weight ${n.weight}`);
      if (n.max) L.push(`  neighbor ${ip} maximum-prefix ${n.max}`);
      if (n.plIn) { L.push(`  neighbor ${ip} prefix-list ${n.plIn} in`); pls.add(n.plIn); }
      if (n.plOut) { L.push(`  neighbor ${ip} prefix-list ${n.plOut} out`); pls.add(n.plOut); }
      if (n.rmIn) { L.push(`  neighbor ${ip} route-map ${n.rmIn} in`); rms.add(n.rmIn); }
      if (n.rmOut) { L.push(`  neighbor ${ip} route-map ${n.rmOut} out`); rms.add(n.rmOut); }
    }
    L.push(` exit-address-family`, `!`);
  }
  if (sp.fg) {
    const maps = frrRouteMaps(dev, [...rms], pls);
    L.push(...frrPrefixLists(dev, [...pls]), ...maps);
  }
  L.push(`line vty`, `!`);
  return { conf: L.join("\n") + "\n", daemons };
};
