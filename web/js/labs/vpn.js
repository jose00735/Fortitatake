// IPsec for the lab simulator: route-based site-to-site tunnels between FortiGates and FortiClient dial-up.
// Negotiation compares what both ends would agree in IKE: version, proposals, DH groups, PSK, mode, IDs and selectors.
import { Lab } from "./sim.js";
import { FortiGate, Entry } from "./fgt.js";
import { ipToInt, intToIp, parsePrefix, inPrefix, network, hex } from "./net.js";
import { fgView, viewsAt, routerViews, ikeProposals } from "./ike.js";

const P1 = "vpn ipsec phase1-interface", P2 = "vpn ipsec phase2-interface";
const v = (fg, path, e, a) => fg.val(path, e, a);
const o = (fg, path, e, a) => fg.one(path, e, a);

// FortiOS creates the tunnel interface for every phase1-interface
Lab.prototype.onCommit = function (fg, path, key) {
  if (path === P1) {
    const p1 = fg.entry(P1, key);
    const t = fg.inst("system interface");
    let e = t.entries.get(key);
    if (!e) { e = new Entry(key); t.entries.set(key, e); e.attrs.set("vdom", [fg.vdomName || "root"]); }
    e.attrs.set("type", ["tunnel"]);
    e.attrs.set("interface", [o(fg, P1, p1, "interface") || ""]);
  }
};
Lab.prototype.postLoad = function (fg) { for (const p of fg.entries(P1)) this.onCommit(fg, P1, p.key); };
Lab.prototype.onDelete = function (fg, path, key) {
  if (path === P1) { const t = fg.inst("system interface"); const e = t.entries.get(key); if (e && fg.one("system interface", e, "type") === "tunnel") t.entries.delete(key); }
};

const within = (inner, outer) => outer.len <= inner.len && inPrefix(inner.ip, outer);
const inter = (a, b) => a.filter((x) => b.includes(x));

// local IP of the phase1's interface
function p1Local(lab, fg, p1) {
  const i = lab.fgtIntfs(fg).find((x) => x.name === o(fg, P1, p1, "interface"));
  return i && i.prefix ? i.prefix.ip : null;
}
function ownerOf(lab, ip) {
  for (const d of lab.devices.values()) {
    if (d instanceof FortiGate) { if (lab.haRole(d) === "secondary") continue; const i = lab.fgtIntfs(d).find((x) => x.prefix && x.prefix.ip === ip); if (i) return { dev: d, intf: i.name }; }
    else if (d.kind === "router") { const i = d.ifaces.find((x) => x.prefix && x.prefix.ip === ip && x.up !== false); if (i) return { dev: d, intf: i.name }; }
  }
  return null;
}
function p1Peer(lab, fg, p1) {
  // static peers: the device that owns remote-gw (a FortiGate or a third-party router) and its tunnel that accepts us
  const me = fgView(lab, fg, p1);
  const own = ownerOf(lab, me.remoteGw);
  if (!own || own.dev === fg) return null;
  const cands = viewsAt(lab, me.remoteGw).filter((x) => x.dev === own.dev);
  const exact = cands.find((x) => x.type !== "dynamic" && x.remoteGw === me.local);
  const dyn = cands.find((x) => x.type === "dynamic");
  const q = exact || dyn || null;
  return { fg: own.dev, dev: own.dev, intf: { name: own.intf }, view: q, p1: q ? { key: q.name } : null, cands };
}

// Full negotiation result for a static phase1 (cached per config state)
Lab.prototype.negotiate = function (fg, p1name) {
  const p1 = fg.entry(P1, p1name);
  if (!p1) return { up: false, reason: "no such phase1" };
  if (o(fg, P1, p1, "type") === "dynamic") { const sp = this.fgDialPeers(fg, p1name); return { up: this.dialClients(fg, p1name).length > 0 || sp.length > 0, dial: true, spokes: sp, reason: "dial-up: up while a client or a spoke is connected" }; }
  const log = [];
  const name = p1name;
  const M = fgView(this, fg, p1);
  const me = M.local;
  const rgwS = o(fg, P1, p1, "remote-gw");
  const ver = M.ver;
  const conn = 10 + (this.clock % 40);
  log.push(`ike 0:${name}: created connection: 0x${hex(0x5a3c1e00 + conn, 8)} ${ver === "2" ? 3 : 5} ${intToIp(me || 0)}->${rgwS}:500.`);
  if (!me) return { up: false, reason: `the phase1 interface has no IP`, log };
  // underlay: can IKE reach the peer?
  const peer = p1Peer(this, fg, p1);
  this.quiet = (this.quiet || 0) + 1;
  let reach;
  try { reach = this.probe(fg.id, { dst: ipToInt(rgwS), proto: 17, dport: 500, src: me }); } finally { this.quiet--; }
  const sent = ver === "2" ? `ike 0:${name}:${conn}: sent IKE msg (SA_INIT): ${intToIp(me)}:500->${rgwS}:500, len=596, vrf=0, id=${hex(0x8f1e2d3c)}${hex(0x4b5a6978)}/0000000000000000` : `ike 0:${name}:${conn}: initiator: main mode is sending 1st message...\nike 0:${name}:${conn}: sent IKE msg (ident_i1send): ${intToIp(me)}:500->${rgwS}:500, len=556, vrf=0, id=${hex(0x8f1e2d3c)}${hex(0x4b5a6978)}/0000000000000000`;
  log.push(sent);
  if (!peer || !reach.ok) {
    log.push(sent, sent, `ike 0:${name}:${conn}: negotiation timeout, deleting`);
    return { up: false, reason: !peer ? `nothing answers IKE at ${rgwS}` : `IKE to ${rgwS} gets no answer (${reach.drop ? reach.drop.reason : "no reply"})`, log, unreachable: true };
  }
  const Q = peer.view;
  const pf = peer.dev;
  const third = pf.kind === "router";
  if (!Q) {
    log.push(sent, `ike 0:${name}:${conn}: negotiation timeout, deleting`);
    return { up: false, reason: `${pf.id} has no ${third ? "crypto profile" : "phase1"} for ${intToIp(me)} on ${peer.intf.name}`, log, peerLog: [`ike 0: comes ${intToIp(me)}:500->${rgwS}:500,ifindex=3,vrf=0....`, `ike 0: IKE${ver === "2" ? "v2" : ""} exchange=${ver === "2" ? "SA_INIT" : "Identity Protection"} id=${hex(0x8f1e2d3c)}${hex(0x4b5a6978)}/0000000000000000 len=596`, `ike 0: no gateway matches ${intToIp(me)}, ignoring the request`], noGateway: true };
  }
  const pname = Q.name;
  const qver = Q.ver;
  if (qver !== ver) {
    log.push(sent, `ike 0:${name}:${conn}: negotiation timeout, deleting`);
    return { up: false, reason: `IKE version mismatch (${name} v${ver}, ${pf.id} v${qver})`, log, peerLog: [`ike 0: comes ${intToIp(me)}:500->${rgwS}:500,ifindex=3,vrf=0....`, `ike 0: ignoring IKEv${ver} packet: gateway ${pname} is configured for IKEv${qver}`], mismatch: "version" };
  }
  log.push(`ike 0:${name}:${conn}: received IKE msg (${ver === "2" ? "SA_INIT" : "ident_r1send"}): ${rgwS}:500->${intToIp(me)}:500, len=${ver === "2" ? 0 : 0}, vrf=0, id=${hex(0x8f1e2d3c)}${hex(0x4b5a6978)}/0000000000000000`.replace("len=0, ", "len=36, "));
  const props = inter(M.proposals, Q.proposals);
  const dhs = inter(M.dhgrps, Q.dhgrps);
  if (!props.length || !dhs.length) {
    if (ver === "2") log.push(`ike 0:${name}:${conn}: received notify type NO_PROPOSAL_CHOSEN`, `ike 0:${name}:${conn}: negotiation failure`);
    else log.push(`ike 0:${name}:${conn}: negotiation failure`, `ike 0:${name}:${conn}: no SA proposal chosen`);
    return { up: false, reason: !props.length ? `no common phase1 proposal (${M.proposals.join(" ")} vs ${Q.proposals.join(" ")})` : `no common DH group (${M.dhgrps.join(" ")} vs ${Q.dhgrps.join(" ")})`, log, mismatch: "proposal",
      peerLog: [`ike 0:${pname}:${conn}: incoming proposal:`, ...M.proposals.map((x) => `ike 0:${pname}:${conn}: proposal id = 1: protocol = IKEv${ver}: encapsulation = IKEv${ver}/none: type=ENCR, val=${x.split("-")[0].toUpperCase()}`), `ike 0:${pname}:${conn}: no SA proposal chosen`] };
  }
  if (ver === "1" && M.mode !== Q.mode) {
    log.push(`ike 0:${name}:${conn}: negotiation failure`);
    return { up: false, reason: "IKEv1 mode mismatch (main vs aggressive)", log, mismatch: "mode" };
  }
  if (M.psk !== Q.psk) {
    if (ver === "2") log.push(`ike 0:${name}:${conn}: initiator received SA_INIT response`, `ike 0:${name}:${conn}: sent IKE msg (AUTH): ${intToIp(me)}:500->${rgwS}:500, len=256, vrf=0`, `ike 0:${name}:${conn}: received notify type AUTHENTICATION_FAILED`);
    else log.push(`ike 0:${name}:${conn}: probable pre-shared secret mismatch`);
    return { up: false, reason: "pre-shared key mismatch", log, mismatch: "psk", peerLog: [ver === "2" ? `ike 0:${pname}:${conn}: auth verify done: FAILED` : `ike 0:${pname}:${conn}: probable pre-shared secret mismatch`] };
  }
  if (Q.peerid && Q.peerid !== M.localid) {
    log.push(`ike 0:${name}:${conn}: received notify type AUTHENTICATION_FAILED`);
    return { up: false, reason: `peer ID mismatch (${pf.id} expects '${Q.peerid}', ${fg.id} sends '${M.localid || intToIp(me)}')`, log, mismatch: "id" };
  }
  log.push(ver === "2" ? `ike 0:${name}:${conn}: initiator received SA_INIT response` : `ike 0:${name}:${conn}: ISAKMP SA ${hex(0x8f1e2d3c)}${hex(0x4b5a6978)}/${hex(0x1d2c3b4a)}${hex(0x59687786)} key 32:${hex(0xa1b2c3d4)}...`);
  log.push(`ike 0:${name}:${conn}: established IKE SA ${hex(0x8f1e2d3c)}${hex(0x4b5a6978)}/${hex(0x1d2c3b4a)}${hex(0x59687786)}`);
  // phase 2
  const p2s = [];
  for (const mp of M.p2s) {
    const src = mp.src, dst = mp.dst;
    const peers = Q.p2s;
    let ok = null, why = peers.length ? "" : `${pf.id} has no phase2 for ${pname}`;
    for (const r of peers) {
      if (!(within(src, r.dst) && within(dst, r.src))) { why = `selectors don't mirror (${fmtSel(src)}→${fmtSel(dst)} vs ${pf.id} ${fmtSel(r.src)}→${fmtSel(r.dst)})`; continue; }
      if (!inter(mp.proposals, r.proposals).length) { why = "no common phase2 proposal"; continue; }
      // IKEv2 builds the first child SA inside IKE_AUTH, without a key exchange: a PFS mismatch only shows at the first rekey
      const pfsBad = mp.pfs !== r.pfs ? "PFS enabled on one side only" : mp.pfs && !inter(mp.dhgrps, r.dhgrps).length ? "no common phase2 DH group" : "";
      if (pfsBad && ver === "1") { why = pfsBad; continue; }
      ok = r; if (pfsBad) ok = { ...r, rekeyFails: pfsBad }; break;
    }
    if (ok) log.push(`ike 0:${name}:${conn}:${mp.name}:${conn + 1}: added IPsec SA: SPIs=${hex(0x6a1b2c3d)}/${hex(0x9e8f7a6b)}`, `ike 0:${name}:${conn}:${mp.name}:${conn + 1}: sending SNMP tunnel UP trap`);
    else log.push(ver === "2" ? `ike 0:${name}:${conn}:${mp.name}:${conn + 1}: received notify type ${/PFS|DH|proposal/.test(why) ? "NO_PROPOSAL_CHOSEN" : "TS_UNACCEPTABLE"}` : `ike 0:${name}:${conn}:${mp.name}:${conn + 1}: no matching phase2 found`);
    p2s.push({ name: mp.name, up: !!ok, reason: ok ? "" : why, src, dst, peer: ok ? ok.name : null, rekeyFails: ok ? ok.rekeyFails || "" : "" });
  }
  const anyUp = p2s.some((x) => x.up);
  return { up: anyUp, p1up: true, p2: p2s, peer: { fg: pf, p1: pname, gw: ipToInt(rgwS), view: Q, third }, local: me, log, reason: anyUp ? "" : p2s.length ? `phase 1 is up, phase 2 is not: ${p2s[0].reason}` : "phase 1 is up but there is no phase2-interface", ver, prop: props[0], dh: dhs[0] };
};
function fmtSel(p) { return p.len === 0 ? "0.0.0.0/0" : `${intToIp(network(p))}/${p.len}`; }

// A tunnel is usable when phase 1 and at least one phase 2 are up, on both sides
Lab.prototype.tunnelUp = function (fg, name) {
  if (!fg.entry(P1, name)) return false;
  const k = `${fg.id}|${name}`;
  if (!this._tun || this._tunVer !== this.ver) { this._tun = new Map(); this._tunVer = this.ver; }
  const c = this._tun.get(k);
  if (c) return c.up;
  if (this._tunDepth) return false; // underlay probes run with tunnels considered down
  // a dial-up phase1 is up while someone is dialled in: its spokes negotiate (and cache) their own tunnels
  if (o(fg, P1, fg.entry(P1, name), "type") === "dynamic") { this._tun.set(k, { up: false, pending: true }); const r = this.negotiate(fg, name); this._tun.set(k, r); return r.up; }
  this._tunDepth = 1;
  try { const r = this.negotiate(fg, name); this._tun.set(k, r); return r.up; } finally { this._tunDepth = 0; }
};
Lab.prototype.tunnelInfo = function (fg, name) { this.tunnelUp(fg, name); return (this._tun || new Map()).get(`${fg.id}|${name}`); };

Lab.prototype.ikeAccepted = function (fg, intf, src) {
  return fg.entries(P1).some((p) => o(fg, P1, p, "interface") === intf);
};

// routes for connected dial-up clients (add-route)
Lab.prototype.extraRoutes = function (fg) {
  const out = [];
  for (const h of this.devices.values()) {
    if (!h.vpn || !h.vpn.up || h.vpn.fgt !== fg.id) continue;
    const p1 = fg.entry(P1, h.vpn.p1);
    if (p1 && o(fg, P1, p1, "add-route") !== "disable") out.push({ type: "S", dst: { ip: h.vpn.ip, len: 32 }, gw: h.vpn.under, dev: h.vpn.p1, distance: 15, priority: 0, dial: true });
  }
  return out;
};
Lab.prototype.dialClients = function (fg, p1name) { return [...this.devices.values()].filter((h) => h.vpn && h.vpn.up && h.vpn.fgt === fg.id && h.vpn.p1 === p1name); };

// encrypt and hand the packet to the other end of the tunnel
Lab.prototype.tunnelForward = function (fg, outI, out, res, tl, done, ev) {
  const name = outI.name;
  const p1 = fg.entry(P1, name);
  tl.push(["ipsecdev_hard_start_xmit", 135, `enter IPSec interface-${name}`]);
  // dial-up: deliver to the client that owns the address
  if (o(fg, P1, p1, "type") === "dynamic") {
    const c = this.dialClients(fg, name).find((h) => h.vpn.ip === out.dst);
    if (!c) {
      // a FortiGate spoke whose phase 2 covers the destination (hub-and-spoke on one dial-up phase1)
      const sp = this.fgDialPeers(fg, name).find((x) => x.info.p2.some((y) => y.up && inPrefix(out.dst, y.src) && inPrefix(out.src, y.dst)));
      if (sp) {
        if (ev.in === name) this.advpnOffer(fg, name, res.path[res.path.length - 2], sp, tl);
        tl.push(["esp_output4", 1394, "IPsec encrypt/auth"], ["ipsec_output_finish", 622, `send to ${intToIp(sp.info.local)} via intf-${o(fg, P1, p1, "interface")}`]);
        done();
        ev.tunnel = name;
        this.sniff(fg, o(fg, P1, p1, "interface"), "out", { src: ipToInt(o(fg, P1, p1, "remote-gw") || "0.0.0.0") || sp.info.peer.gw, dst: sp.info.local, proto: 50, sport: 0, dport: 0 });
        return { dev: sp.fg, port: sp.p1, pkt: { ...out } };
      }
      tl.push(["ipsec_common_output4", 1000, "no matching IPsec selector, drop"]); done(); res.drop = { dev: fg.id, reason: `no dial-up client with ${intToIp(out.dst)}` }; return null;
    }
    tl.push(["esp_output4", 1394, "IPsec encrypt/auth"], ["ipsec_output_finish", 622, `send to ${intToIp(c.vpn.under)} via intf-${o(fg, P1, p1, "interface")}`]);
    done();
    ev.tunnel = name;
    return { dev: c, port: "vpn", pkt: out };
  }
  const info = this.tunnelInfo(fg, name);
  // ADVPN: a shortcut to the spoke behind the destination goes direct, past the hub
  const sc = this.advpnShortcut(fg, name, out.dst);
  if (sc) {
    tl.push(["esp_output4", 1394, "IPsec encrypt/auth"], ["ipsec_output_finish", 622, `send to ${intToIp(sc.to.info.local)} via intf-${o(fg, P1, p1, "interface")} (shortcut ${sc.name})`]);
    done();
    ev.tunnel = sc.name;
    this.sniff(fg, o(fg, P1, p1, "interface"), "out", { src: info.local, dst: sc.to.info.local, proto: 50, sport: 0, dport: 0 });
    return { dev: sc.to.fg, port: sc.to.p1, pkt: { ...out } };
  }
  const sa = info && info.p2 && info.p2.find((x) => x.up && inPrefix(out.src, x.src) && inPrefix(out.dst, x.dst));
  if (!sa) {
    tl.push(["ipsec_common_output4", 1000, "no matching IPsec selector, drop"]);
    done(); ev.drop = "selector";
    res.drop = { dev: fg.id, reason: `no IPsec selector on ${name} covers ${intToIp(out.src)} → ${intToIp(out.dst)}`, selector: true };
    return null;
  }
  // tunnel MTU: the underlay's smallest MTU minus the ESP overhead
  const pmtu = this.pathMtu(fg, info) - 74;
  if (out.size && out.df && out.size > pmtu) { done(); res.drop = { dev: fg.id, reason: `packet of ${out.size} bytes with DF set exceeds the tunnel MTU (${pmtu})`, mtu: pmtu }; return null; }
  tl.push(["esp_output4", 1394, "IPsec encrypt/auth"], ["ipsec_output_finish", 622, `send to ${intToIp(info.peer.gw)} via intf-${o(fg, P1, p1, "interface")}`]);
  done();
  ev.tunnel = name;
  this.sniff(fg, o(fg, P1, p1, "interface"), "out", { src: info.local, dst: info.peer.gw, proto: 50, sport: 0, dport: 0 });
  return { dev: info.peer.fg, port: info.peer.p1, pkt: { ...out, ttl: out.ttl } };
};
// ----- hub-and-spoke and ADVPN -----
// FortiGates dialled in to a dial-up phase1: spokes whose static tunnel negotiated with it
Lab.prototype.fgDialPeers = function (hub, p1name) {
  const out = [];
  for (const d of this.devices.values()) {
    if (!(d instanceof FortiGate) || d === hub || d.kind !== "fortigate") continue;
    for (const p of d.entries(P1)) {
      if (o(d, P1, p, "type") === "dynamic" || !ipToInt(o(d, P1, p, "remote-gw") || "0.0.0.0")) continue;
      const info = this.tunnelInfo(d, p.key);
      if (info && info.up && info.peer && info.peer.fg === hub && info.peer.p1 === p1name) out.push({ fg: d, p1: p.key, info });
    }
  }
  return out;
};
// The hub forwarded spoke A's traffic back out of the same dial-up phase1 to spoke B: with
// auto-discovery-sender on the hub it offers A a shortcut; A (auto-discovery-receiver) negotiates it with B
// straight over the Internet using its own phase1 settings, and B has to accept them (receiver on too).
function advpnCheck(lab, hub, p1name, a, b) {
  const hp = hub.entry(P1, p1name);
  if (!hp || o(hub, P1, hp, "auto-discovery-sender") !== "enable") return `${hub.id} ${p1name}: auto-discovery-sender is disabled, no shortcut offer is sent`;
  const A = fgView(lab, a.fg, a.p1), B = fgView(lab, b.fg, b.p1);
  if (!A.advpn.receiver) return `${a.fg.id} ${a.p1}: auto-discovery-receiver is disabled, the shortcut offer is ignored`;
  if (!B.advpn.receiver) return `${b.fg.id} ${b.p1}: auto-discovery-receiver is disabled, it refuses the shortcut`;
  if (A.ver !== B.ver || !inter(A.proposals, B.proposals).length || !inter(A.dhgrps, B.dhgrps).length || A.psk !== B.psk) return `${a.fg.id} and ${b.fg.id} don't share IKE settings for the shortcut`;
  lab.quiet = (lab.quiet || 0) + 1;
  let reach;
  try { reach = lab.probe(a.fg.id, { dst: B.local, proto: 17, dport: 500, src: A.local }); } finally { lab.quiet--; }
  if (!reach.ok) return `IKE from ${intToIp(A.local)} to ${intToIp(B.local)} gets no answer (${reach.drop ? reach.drop.reason : "no reply"})`;
  return "";
}
Lab.prototype.advpnOffer = function (hub, p1name, fromId, b, tl) {
  const a = this.fgDialPeers(hub, p1name).find((x) => x.fg.id === fromId);
  if (!a || a.fg === b.fg) return;
  this._advpn = this._advpn || new Map();
  const key = [`${a.fg.id}|${a.p1}`, `${b.fg.id}|${b.p1}`].sort().join("<>");
  const why = advpnCheck(this, hub, p1name, a, b);
  const log = (fg, line) => { if (fg.dbg && fg.dbg.ike && fg.dbg.enabled && !this.quiet) fg.async.push(line); };
  if (why) { if (tl) tl.push(["ike_shortcut", 0, `no shortcut ${a.fg.id} <-> ${b.fg.id}: ${why}`]); log(hub, `ike 0:${p1name}: shortcut not offered: ${why}`); return; }
  if (this._advpn.has(key)) return;
  this._advpn.set(key, { a: { fg: a.fg, p1: a.p1 }, b: { fg: b.fg, p1: b.p1 }, hub: hub.id, hp1: p1name, at: this.clock });
  log(hub, `ike 0:${p1name}_0: send shortcut-offer ${intToIp(b.info.local)} to ${intToIp(a.info.local)}`);
  log(a.fg, `ike 0:${a.p1}: recv shortcut-offer ${intToIp(b.info.local)}, initiating shortcut ${a.p1}_0`);
  log(a.fg, `ike 0:${a.p1}_0: established IKE SA (shortcut) ${intToIp(a.info.local)}->${intToIp(b.info.local)}:500`);
  log(b.fg, `ike 0:${b.p1}_0: shortcut from ${intToIp(a.info.local)} accepted`);
};
// shortcuts this FortiGate's phase1 has, still valid now: [{name, to: {fg, p1, info}, at}]
Lab.prototype.advpnShortcuts = function (fg, p1name) {
  if (!this._advpn || !this._advpn.size) return [];
  const out = [];
  for (const sc of this._advpn.values()) {
    const me = sc.a.fg === fg && sc.a.p1 === p1name ? sc.a : sc.b.fg === fg && sc.b.p1 === p1name ? sc.b : null;
    if (!me) continue;
    const other = me === sc.a ? sc.b : sc.a;
    const hub = this.dev(sc.hub);
    const peers = hub ? this.fgDialPeers(hub, sc.hp1) : [];
    const A = peers.find((x) => x.fg === me.fg && x.p1 === me.p1), B = peers.find((x) => x.fg === other.fg && x.p1 === other.p1);
    if (!A || !B || advpnCheck(this, hub, sc.hp1, A, B)) continue;
    out.push({ name: `${p1name}_${out.length}`, to: B, at: sc.at });
  }
  return out;
};
Lab.prototype.advpnShortcut = function (fg, p1name, dst) {
  if (this._tunDepth) return null;
  return this.advpnShortcuts(fg, p1name).find((sc) => sc.to.info.p2.some((y) => y.up && inPrefix(dst, y.src))) || null;
};

// ----- third-party peers (lab routers with an ipsec spec) -----
// The FortiGate's negotiation decides the tunnel; the router side reads it back.
Lab.prototype.routerTunnel = function (r, name) {
  for (const d of this.devices.values()) {
    if (!(d instanceof FortiGate) || d.kind !== "fortigate") continue;
    for (const p of d.entries(P1)) {
      if (o(d, P1, p, "type") === "dynamic" || ipToInt(o(d, P1, p, "remote-gw") || "0.0.0.0") === 0) continue;
      const own = r.ifaces.some((i) => i.prefix && i.prefix.ip === ipToInt(o(d, P1, p, "remote-gw")));
      if (!own) continue;
      const info = this.tunnelInfo(d, p.key);
      if (info && info.peer && info.peer.fg === r && info.peer.p1 === name) return { fg: d, p1: p.key, info };
    }
  }
  return null;
};
Lab.prototype.routerTunnelOut = function (r, name, pkt, res) {
  const t = this.routerTunnel(r, name);
  if (!t || !t.info.up) { res.drop = { dev: r.id, reason: `${name} has no IPsec SA (IKE is not up)` }; return null; }
  const sa = t.info.p2.find((x) => x.up && inPrefix(pkt.src, x.dst) && inPrefix(pkt.dst, x.src));
  if (!sa) { res.drop = { dev: r.id, reason: `no IPsec selector on ${name} covers ${intToIp(pkt.src)} → ${intToIp(pkt.dst)}`, selector: true }; return null; }
  return { dev: t.fg, port: t.p1, pkt };
};

Lab.prototype.pathMtu = function (fg, info) {
  this.quiet = (this.quiet || 0) + 1;
  let r;
  try { r = this.send(fg.id, { src: info.local, dst: info.peer.gw, proto: 17, sport: 500, dport: 500, ttl: 64 }); } finally { this.quiet--; }
  let m = 1500;
  for (const id of r.path) { const d = this.dev(id); if (d && d.mtu) m = Math.min(m, d.mtu); }
  return m;
};

// ----- FortiClient (dial-up) -----
Lab.prototype.clientTunnel = function (h, pkt, res) {
  const fg = this.dev(h.vpn.fgt);
  const inc = h.vpn.split;
  if (inc && !inc.some((p) => inPrefix(pkt.dst, p))) return null;
  return { dev: fg, port: h.vpn.p1, pkt };
};
Lab.prototype.forticlient = function (h, args) {
  const vs = h.vpnSpec;
  const cmd = (args[0] || "status").toLowerCase();
  if (!vs) return "FortiClient is not installed on this computer.";
  if (cmd === "status") return h.vpn && h.vpn.up ? `Connection: ${vs.name || "VPN"}\nStatus: Connected\nIP address: ${intToIp(h.vpn.ip)}\nRemote gateway: ${vs.gw}\nSplit tunnel: ${h.vpn.split ? h.vpn.split.map((p) => intToIp(network(p)) + "/" + p.len).join(", ") : "off (all traffic)"}` : `Connection: ${vs.name || "VPN"}\nStatus: Disconnected`;
  if (cmd === "disconnect") { h.vpn = null; this.dirty(); return "Disconnected."; }
  if (cmd !== "connect") return "Usage: forticlient connect | status | disconnect";
  const gw = ipToInt(vs.gw);
  this.quiet = (this.quiet || 0) + 1;
  let reach;
  try { reach = this.probe(h.id, { dst: gw, proto: 17, dport: 500 }); } finally { this.quiet--; }
  const lines = [`Connecting to ${vs.gw} (IPsec IKEv${vs.ike || 2})...`];
  if (!reach.ok) return lines.concat(`Error: the remote gateway did not respond. (${reach.drop ? reach.drop.reason : "no reply"})`).join("\n");
  let fg = null, intf = null;
  for (const d of this.devices.values()) { if (!(d instanceof FortiGate) || this.haRole(d) === "secondary") continue; const i = this.fgtIntfs(d).find((x) => x.prefix && x.prefix.ip === gw); if (i) { fg = d; intf = i; break; } }
  const p1 = fg && fg.entries(P1).find((q) => o(fg, P1, q, "type") === "dynamic" && o(fg, P1, q, "interface") === intf.name);
  if (!p1) return lines.concat("Error: the remote gateway did not respond. (no dial-up phase1 on that interface)").join("\n");
  const fail = (m) => { fg.dbg.ikeLog = (fg.dbg.ikeLog || []).concat(m.log || []); return lines.concat("Error: " + m.text).join("\n"); };
  if (o(fg, P1, p1, "ike-version") !== String(vs.ike || 2)) return fail({ text: "the VPN negotiation timed out (IKE version)." });
  if (!inter(vs.proposal || ["aes256-sha256", "aes128-sha256"], v(fg, P1, p1, "proposal")).length || !inter((vs.dhgrp || [14, 20]).map(String), v(fg, P1, p1, "dhgrp")).length)
    return fail({ text: "the VPN negotiation failed (no matching proposal).", log: [`ike 0:${p1.key}: received notify type NO_PROPOSAL_CHOSEN`] });
  if ((p1.attrs.get("psksecret") || [""])[0] !== vs.psk) return fail({ text: "authentication failed (pre-shared key).", log: [`ike 0:${p1.key}: auth verify done: FAILED`] });
  // XAuth / EAP user check
  const ver = o(fg, P1, p1, "ike-version");
  const grp = o(fg, P1, p1, "authusrgrp");
  const wantsUser = grp && (ver === "2" ? o(fg, P1, p1, "eap") === "enable" : o(fg, P1, p1, "xauthtype") !== "disable");
  if (ver === "2" && o(fg, P1, p1, "eap") === "enable" && !grp) return fail({ text: "user authentication failed (EAP is on but no user group is set)." });
  if (wantsUser) {
    const g = fg.entry("user group", grp);
    const u = vs.user && fg.entry("user local", vs.user);
    const pw = u && (u.attrs.get("passwd") || [""])[0];
    if (!g || !u || pw !== vs.password || fg.one("user local", u, "status") === "disable" || !fg.val("user group", g, "member").includes(vs.user)) return fail({ text: `credential or SSO login failure for ${vs.user || "user"}.`, log: [`ike 0:${p1.key}: XAUTH user "${vs.user}" failed authentication`] });
  }
  if (o(fg, P1, p1, "mode-cfg") !== "enable") return fail({ text: "the VPN connected but no IP address was assigned (mode-cfg disabled).", log: [] });
  const start = ipToInt(o(fg, P1, p1, "ipv4-start-ip") || "0.0.0.0");
  if (!start) return fail({ text: "no IP address pool configured on the gateway." });
  const used = this.dialClients(fg, p1.key).length;
  const ip = start + used;
  let split = null;
  const inc = o(fg, P1, p1, "ipv4-split-include");
  if (inc) {
    const a = fg.entry("firewall address", inc), gr = fg.entry("firewall addrgrp", inc);
    if (a) split = [parsePrefix(fg.one("firewall address", a, "subnet"))];
    else if (gr) split = fg.val("firewall addrgrp", gr, "member").map((m) => fg.entry("firewall address", m)).filter(Boolean).map((x) => parsePrefix(fg.one("firewall address", x, "subnet")));
  }
  h.vpn = { up: true, fgt: fg.id, p1: p1.key, ip, split, under: h.ip() };
  this.dirty();
  return lines.concat(`Connected. IP address: ${intToIp(ip)}`, split ? `Split tunnel: ${split.map((p) => intToIp(network(p)) + "/" + p.len).join(", ")}` : "All traffic goes through the VPN.").join("\n");
};

// ----- diagnostics -----
Lab.prototype.vpnDiag = function (fg, words, raw) {
  const d = fg.dbg;
  const w = words.join(" ");
  if (/^debug application ike/.test(w)) { d.ike = Number(raw[3] || -1) !== 0; return ""; }
  if (/^vpn ike gateway (clear|flush)|^vpn ike restart|^vpn tunnel (up|flush|reset)/.test(w)) {
    const which = raw.slice(4).find((x) => fg.entry(P1, x)) || raw.slice(3).find((x) => fg.entry(P1, x));
    for (const p of fg.entries(P1)) {
      if (which && p.key !== which) continue;
      if (o(fg, P1, p, "type") === "dynamic") continue;
      const info = this.negotiate(fg, p.key);
      if (d.ike && d.enabled) fg.async.push(...info.log);
      if (info.peerLog && info.peer === undefined) {
        const peer = p1Peer(this, fg, p);
        if (peer && peer.fg.dbg && peer.fg.dbg.ike && peer.fg.dbg.enabled) peer.fg.async.push(...info.peerLog);
      }
    }
    const dl = fg.dbg.ikeLog || [];
    if (d.ike && d.enabled && dl.length) { fg.async.push(...dl); fg.dbg.ikeLog = []; }
    return "";
  }
  if (/^vpn ike gateway list/.test(w)) {
    const out = [];
    for (const p of fg.entries(P1)) {
      if (o(fg, P1, p, "type") === "dynamic") {
        for (const c of this.dialClients(fg, p.key)) out.push(`vd: root/0\nname: ${p.key}_0\nversion: ${o(fg, P1, p, "ike-version")}\ninterface: ${o(fg, P1, p, "interface")} 3\naddr: ${intToIp(p1Local(this, fg, p) || 0)}:4500 -> ${intToIp(c.vpn.under)}:64916\ncreated: 42s ago\nassigned IPv4 address: ${intToIp(c.vpn.ip)}/255.255.255.255\nIKE SA: created 1/1  established 1/1  time 20/20/20 ms\nIPsec SA: created 1/1  established 1/1  time 0/0/0 ms\n`);
        continue;
      }
      const info = this.tunnelInfo(fg, p.key) || {};
      const est = info.p1up ? "1/1" : "0/1";
      out.push(`vd: root/0\nname: ${p.key}\nversion: ${o(fg, P1, p, "ike-version")}\ninterface: ${o(fg, P1, p, "interface")} 3\naddr: ${intToIp(p1Local(this, fg, p) || 0)}:500 -> ${o(fg, P1, p, "remote-gw")}:500\ncreated: 1824s ago\nIKE SA: created 1/1  established ${est}  time ${info.p1up ? "10/10/10" : "0/0/0"} ms\nIPsec SA: created ${(info.p2 || []).length}/${(info.p2 || []).length}  established ${(info.p2 || []).filter((x) => x.up).length}/${(info.p2 || []).length}  time 0/0/0 ms\n` +
        (info.p1up ? `\n  id/spi: 12 8f1e2d3c4b5a6978/1d2c3b4a59687786\n  direction: initiator\n  status: established 1824-1824s ago = 10ms\n  proposal: ${info.prop || ""}\n  child: no\n  PPK: no\n  message-id sent/recv: 4/0\n  lifetime/rekey: ${o(fg, P1, p, "keylife")}/${Number(o(fg, P1, p, "keylife")) - 1844}\n  DPD sent/recv: 00000000/00000000\n` : ""));
    }
    return out.join("\n") || "";
  }
  if (/^vpn tunnel list/.test(w)) {
    const out = ["list all ipsec tunnel in vd 0"];
    for (const p of fg.entries(P1)) {
      if (o(fg, P1, p, "type") === "dynamic") {
        this.fgDialPeers(fg, p.key).forEach((sp, i) => out.push("------------------------------------------------------", `name=${p.key}_${i} ver=${o(fg, P1, p, "ike-version")} serial=${3 + i} ${intToIp(p1Local(this, fg, p) || 0)}:0->${intToIp(sp.info.local)}:0 tun_id=${intToIp(sp.info.local)} dst_mtu=1500 dpd-link=on weight=1`,
          `bound_if=3 lgwy=static/1 tun=intf mode=dial_inst/3 encap=none/4776 options[12a8]=npu rgwy-chg frag-rfc  run_state=0 role=primary accept_traffic=1 overlay_id=0`, `parent=${p.key} index=${i}`,
          `proxyid_num=1 child_num=0 refcnt=5 ilast=2 olast=2 ad=${o(fg, P1, p, "auto-discovery-sender") === "enable" ? "s/1" : "/0"}`, `stat: rxp=96 txp=94 rxb=11520 txb=7896`,
          ...sp.info.p2.filter((x) => x.up).map((x) => `proxyid=${x.peer || p.key} proto=0 sa=1 ref=2 serial=1\n  src: 0:0.0.0.0/0.0.0.0:0\n  dst: 0:${intToIp(network(x.src))}/${maskOf(x.src.len)}:0`)));
        continue;
      }
      const info = this.tunnelInfo(fg, p.key) || {};
      out.push("------------------------------------------------------", `name=${p.key} ver=${o(fg, P1, p, "ike-version")} serial=1 ${intToIp(p1Local(this, fg, p) || 0)}:0->${o(fg, P1, p, "remote-gw")}:0 tun_id=${o(fg, P1, p, "remote-gw")} tun_id6=::10.0.0.1 dst_mtu=1500 dpd-link=on weight=1`,
        `bound_if=3 lgwy=static/1 tun=intf mode=auto/1 encap=none/552 options[0228]=npu frag-rfc  run_state=0 role=primary accept_traffic=1 overlay_id=0`,
        `proxyid_num=${(info.p2 || []).length} child_num=0 refcnt=${info.up ? 4 : 2} ilast=2 olast=2 ad=/0`, `stat: rxp=${info.up ? 112 : 0} txp=${info.up ? 109 : 0} rxb=${info.up ? 13440 : 0} txb=${info.up ? 9156 : 0}`, `dpd: mode=on-demand on=1 idle=20000ms retry=3 count=0 seqno=0`, `natt: mode=none draft=0 interval=0 remote_port=0`);
      for (const x of info.p2 || []) out.push(`proxyid=${x.name} proto=0 sa=${x.up ? 1 : 0} ref=2 serial=1 auto-negotiate`, `  src: 0:${intToIp(network(x.src))}/${maskOf(x.src.len)}:0`, `  dst: 0:${intToIp(network(x.dst))}/${maskOf(x.dst.len)}:0`, ...(x.up ? [`  SA:  ref=3 options=10226 type=00 soft=0 mtu=1438 expire=42863/0B replaywin=2048`, `       seqno=6e esn=0 replaywin_lastseq=00000070 qat=0 rekey=0 hash_search_len=1`, `  life: type=01 bytes=0/0 timeout=43186/43200`] : []));
      for (const sc of this.advpnShortcuts(fg, p.key)) out.push("------------------------------------------------------", `name=${sc.name} ver=${o(fg, P1, p, "ike-version")} serial=${7 + out.length % 9} ${intToIp(p1Local(this, fg, p) || 0)}:0->${intToIp(sc.to.info.local)}:0 tun_id=${intToIp(sc.to.info.local)} dst_mtu=1500 dpd-link=on weight=1`,
        `bound_if=3 lgwy=static/1 tun=intf mode=dial_inst/3 encap=none/4744 options[1288]=npu rgwy-chg frag-rfc  run_state=0 role=primary accept_traffic=1 overlay_id=0`, `parent=${p.key} index=${sc.name.split("_").pop()}`,
        `proxyid_num=1 child_num=0 refcnt=5 ilast=1 olast=1 ad=r/2`, `stat: rxp=18 txp=17 rxb=2160 txb=1428`, `proxyid=${p.key} proto=0 sa=1 ref=2 serial=1 adr`, `  src: 0:0.0.0.0/0.0.0.0:0`, `  dst: 0:0.0.0.0/0.0.0.0:0`);
    }
    return out.join("\n");
  }
  return null;
};
function maskOf(len) { const m = len === 0 ? 0 : (0xffffffff << (32 - len)) >>> 0; return intToIp(m); }

Lab.prototype.vpnSummary = function (fg) {
  const out = [];
  for (const p of fg.entries(P1)) {
    if (o(fg, P1, p, "type") === "dynamic") {
      let n = 0;
      for (const c of this.dialClients(fg, p.key)) out.push(`'${p.key}_${n++}' ${intToIp(c.vpn.under)}:64916  selectors(total,up): 1/1  rx(pkt,err): 24/0  tx(pkt,err): 22/0`);
      for (const sp of this.fgDialPeers(fg, p.key)) out.push(`'${p.key}_${n++}' ${intToIp(sp.info.local)}:0  selectors(total,up): ${sp.info.p2.length}/${sp.info.p2.filter((x) => x.up).length}  rx(pkt,err): 96/0  tx(pkt,err): 94/0`);
      continue;
    }
    const info = this.tunnelInfo(fg, p.key) || {};
    const n = (info.p2 || []).length, up = (info.p2 || []).filter((x) => x.up).length;
    out.push(`'${p.key}' ${o(fg, P1, p, "remote-gw")}:0  selectors(total,up): ${n}/${up}  rx(pkt,err): ${up ? 112 : 0}/0  tx(pkt,err): ${up ? 109 : 0}/${info.p1up ? 0 : 3}`);
    for (const sc of this.advpnShortcuts(fg, p.key)) out.push(`'${sc.name}' ${intToIp(sc.to.info.local)}:0  selectors(total,up): 1/1  rx(pkt,err): 18/0  tx(pkt,err): 17/0`);
  }
  return out.join("\n");
};

// ----- the third-party router's side, as Cisco IOS-XE shows it -----
const IOS_ENC = { aes128: "aes-cbc-128", aes192: "aes-cbc-192", aes256: "aes-cbc-256", aes128gcm: "aes-gcm-128", aes256gcm: "aes-gcm-256", "3des": "3des", des: "des", chacha20poly1305: "chacha20-poly1305" };
const IOS_TS_ENC = { aes128: "esp-aes", aes192: "esp-aes 192", aes256: "esp-aes 256", aes128gcm: "esp-gcm", aes256gcm: "esp-gcm 256", "3des": "esp-3des", des: "esp-des", null: "esp-null" };
const IOS_TS_INT = { md5: "esp-md5-hmac", sha1: "esp-sha-hmac", sha256: "esp-sha256-hmac", sha384: "esp-sha384-hmac", sha512: "esp-sha512-hmac" };
const splitP = (p) => { const i = p.indexOf("-"); return i < 0 ? [p, ""] : [p.slice(0, i), p.slice(i + 1)]; };
const maskStr = (len) => maskOf(len);

Lab.prototype.routerCryptoConfig = function (r) {
  const views = routerViews(this, r);
  if (!views.length) return [];
  const L = [];
  views.forEach((vw, n) => {
    const tag = vw.name.toUpperCase();
    if (vw.ver === "2") {
      vw.proposals.forEach((p, i) => {
        const [e, h] = splitP(p);
        L.push(`crypto ikev2 proposal ${tag}-PROP-${i + 1}`, ` encryption ${IOS_ENC[e] || e}`, ...(/^prf/.test(h) ? [` prf ${h.slice(3)}`] : [` integrity ${h}`]), ` group ${vw.dhgrps.join(" ")}`, "!");
      });
      L.push(`crypto ikev2 policy ${tag}-POL`, ` match address local ${intToIp(vw.local || 0)}`, ...vw.proposals.map((_, i) => ` proposal ${tag}-PROP-${i + 1}`), "!",
        `crypto ikev2 keyring ${tag}-KEYS`, ` peer ${intToIp(vw.remoteGw)}`, `  address ${intToIp(vw.remoteGw)}`, `  pre-shared-key 6 ${hex(0x5a4f3c2b + n * 977, 8)}${hex(0x1e0d9c8b, 8)}AAB`, " !", "!",
        `crypto ikev2 profile ${tag}-PROFILE`, ` match identity remote ${vw.peerid ? `fqdn ${vw.peerid}` : `address ${intToIp(vw.remoteGw)} 255.255.255.255`}`, ` identity local ${vw.localid ? `fqdn ${vw.localid}` : "address " + intToIp(vw.local || 0)}`, " authentication remote pre-share", " authentication local pre-share", ` keyring local ${tag}-KEYS`, "!");
    } else {
      vw.proposals.forEach((p, i) => {
        const [e, h] = splitP(p);
        L.push(`crypto isakmp policy ${(i + 1) * 10}`, ` encryption ${(IOS_ENC[e] || e).replace("-cbc-", " ").replace("aes 128", "aes")}`, ` hash ${h === "sha1" ? "sha" : h}`, " authentication pre-share", ` group ${vw.dhgrps[0]}`, "!");
      });
      L.push(`crypto isakmp key 6 ${hex(0x5a4f3c2b + n * 977, 8)}AAB address ${intToIp(vw.remoteGw)}`, ...(vw.mode === "aggressive" ? ["crypto isakmp aggressive-mode enable"] : []), "!");
    }
    vw.p2s.forEach((p, i) => {
      const parts = [];
      for (const x of p.proposals) { const [e, h] = splitP(x); parts.push([IOS_TS_ENC[e] || `esp-${e}`, /gcm|chacha/.test(e) || !h ? "" : IOS_TS_INT[h] || `esp-${h}-hmac`].filter(Boolean).join(" ")); }
      L.push(`crypto ipsec transform-set ${tag}-TS${i + 1} ${parts[0] || "esp-aes 256 esp-sha256-hmac"}`, " mode tunnel", "!");
    });
    const p = vw.p2s[0];
    const vti = vw.p2s.length === 1 && p.src.len === 0 && p.dst.len === 0;
    if (vti) {
      L.push(`crypto ipsec profile ${tag}-IPSEC`, ` set transform-set ${tag}-TS1`, ...(p.pfs ? [` set pfs group${p.dhgrps[0]}`] : []), ...(vw.ver === "2" ? [` set ikev2-profile ${tag}-PROFILE`] : []), "!",
        `interface ${vw.name}`, ` ip unnumbered ${vw.wan}`, ` tunnel source ${vw.wan}`, " tunnel mode ipsec ipv4", ` tunnel destination ${intToIp(vw.remoteGw)}`, ` tunnel protection ipsec profile ${tag}-IPSEC`, "!");
    } else {
      vw.p2s.forEach((x, i) => L.push(`ip access-list extended ${tag}-ACL${i + 1}`, ` 10 permit ip ${intToIp(network(x.src))} ${wild(x.src.len)} ${intToIp(network(x.dst))} ${wild(x.dst.len)}`, "!"));
      vw.p2s.forEach((x, i) => L.push(`crypto map ${tag}-MAP ${(i + 1) * 10} ipsec-isakmp`, ` set peer ${intToIp(vw.remoteGw)}`, ` set transform-set ${tag}-TS${i + 1}`, ...(x.pfs ? [` set pfs group${x.dhgrps[0]}`] : []), ...(vw.ver === "2" ? [` set ikev2-profile ${tag}-PROFILE`] : []), ` match address ${tag}-ACL${i + 1}`));
      L.push("!", `! crypto map ${tag}-MAP is applied on ${vw.wan}; ${vw.name} stands for the protected traffic in this lab`, "!");
    }
  });
  return L;
};
function wild(len) { const m = len === 0 ? 0 : (0xffffffff << (32 - len)) >>> 0; return intToIp(~m >>> 0); }

Lab.prototype.routerCrypto = function (r, t) {
  const views = routerViews(this, r);
  if (!views.length || !/^sh(o(w)?)? cry/.test(t)) return null;
  const w = t.split(/\s+/).slice(2).join(" ");
  const st = views.map((vw) => ({ vw, t: this.routerTunnel(r, vw.name) }));
  if (/^(ikev2|isakmp) sa/.test(w) || /^(ikev2|isakmp)$/.test(w)) {
    const v2 = /^ikev2/.test(w);
    const up = st.filter((x) => x.t && x.t.info.p1up && (x.vw.ver === "2") === v2);
    if (!v2) return ["IPv4 Crypto ISAKMP SA", "dst             src             state          conn-id status", ...up.map((x, i) => `${intToIp(x.vw.local).padEnd(16)}${intToIp(x.vw.remoteGw).padEnd(16)}QM_IDLE        ${1001 + i} ACTIVE`)].join("\n");
    return [" IPv4 Crypto IKEv2  SA", "", "Tunnel-id Local                 Remote                fvrf/ivrf            Status", ...up.flatMap((x, i) => {
      const [e, h] = splitP(x.t.info.prop || x.vw.proposals[0]);
      return [`${String(i + 1).padEnd(10)}${(intToIp(x.vw.local) + "/500").padEnd(22)}${(intToIp(x.vw.remoteGw) + "/500").padEnd(22)}none/none            READY`,
        `      Encr: ${(IOS_ENC[e] || e).toUpperCase().replace(/-(\d+)$/, "")}, keysize: ${(/\d{3}/.exec(e) || ["0"])[0]}, PRF: ${(h.replace("prf", "") || "sha256").toUpperCase()}, Hash: ${(h.replace("prf", "") || "sha256").toUpperCase()}, DH Grp:${x.t.info.dh}, Auth sign: PSK, Auth verify: PSK`,
        "      Life/Active Time: 86400/1824 sec"];
    })].join("\n");
  }
  if (/^ipsec sa/.test(w)) {
    return st.map(({ vw, t: x }) => {
      const sas = vw.p2s.map((p) => ({ p, up: !!(x && x.info.up && x.info.p2.some((y) => y.up && y.peer === p.name)) }));
      return [`interface: ${vw.name}`, `    Crypto map tag: ${vw.name}-head-0, local addr ${intToIp(vw.local || 0)}`, "", "   protected vrf: (none)",
        ...sas.flatMap(({ p, up }) => [`   local  ident (addr/mask/prot/port): (${intToIp(network(p.src))}/${maskStr(p.src.len)}/0/0)`, `   remote ident (addr/mask/prot/port): (${intToIp(network(p.dst))}/${maskStr(p.dst.len)}/0/0)`, `   current_peer ${intToIp(vw.remoteGw)} port 500`, "     PERMIT, flags={origin_is_acl,}",
          `    #pkts encaps: ${up ? 112 : 0}, #pkts encrypt: ${up ? 112 : 0}, #pkts digest: ${up ? 112 : 0}`, `    #pkts decaps: ${up ? 109 : 0}, #pkts decrypt: ${up ? 109 : 0}, #pkts verify: ${up ? 109 : 0}`, "",
          `     local crypto endpt.: ${intToIp(vw.local || 0)}, remote crypto endpt.: ${intToIp(vw.remoteGw)}`, `     current outbound spi: ${up ? "0x9E8F7A6B(2660202091)" : "0x0(0)"}`, `     PFS (Y/N): ${p.pfs ? "Y" : "N"}, DH group: ${p.pfs ? "group" + p.dhgrps[0] : "none"}`, ""])].join("\n");
    }).join("\n");
  }
  return "% Try: show crypto ikev2 sa | show crypto isakmp sa | show crypto ipsec sa";
};
