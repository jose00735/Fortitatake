// IPsec for the lab simulator: route-based site-to-site tunnels between FortiGates and FortiClient dial-up.
// Negotiation compares what both ends would agree in IKE: version, proposals, DH groups, PSK, mode, IDs and selectors.
import { Lab } from "./sim.js";
import { FortiGate, Entry } from "./fgt.js";
import { ipToInt, intToIp, parsePrefix, inPrefix, network, hex } from "./net.js";

const P1 = "vpn ipsec phase1-interface", P2 = "vpn ipsec phase2-interface";
const v = (fg, path, e, a) => fg.val(path, e, a);
const o = (fg, path, e, a) => fg.one(path, e, a);

// FortiOS creates the tunnel interface for every phase1-interface
Lab.prototype.onCommit = function (fg, path, key) {
  if (path === P1) {
    const p1 = fg.entry(P1, key);
    const t = fg.inst("system interface");
    let e = t.entries.get(key);
    if (!e) { e = new Entry(key); t.entries.set(key, e); }
    e.attrs.set("vdom", ["root"]);
    e.attrs.set("type", ["tunnel"]);
    e.attrs.set("interface", [o(fg, P1, p1, "interface") || ""]);
  }
};
Lab.prototype.postLoad = function (fg) { for (const p of fg.entries(P1)) this.onCommit(fg, P1, p.key); };
Lab.prototype.onDelete = function (fg, path, key) {
  if (path === P1) { const t = fg.inst("system interface"); const e = t.entries.get(key); if (e && fg.one("system interface", e, "type") === "tunnel") t.entries.delete(key); }
};

function selector(fg, p2, side) {
  const t = o(fg, P2, p2, `${side}-addr-type`) || "subnet";
  if (t === "name") {
    const n = o(fg, P2, p2, `${side}-name`);
    const a = n && fg.entry("firewall address", n);
    return a ? parsePrefix(fg.one("firewall address", a, "subnet")) : { ip: 0, len: 0 };
  }
  if (t === "ip") return { ip: ipToInt(o(fg, P2, p2, `${side}-start-ip`) || "0.0.0.0"), len: 32 };
  const p = parsePrefix(o(fg, P2, p2, `${side}-subnet`) || "0.0.0.0 0.0.0.0");
  return p || { ip: 0, len: 0 };
}
const within = (inner, outer) => outer.len <= inner.len && inPrefix(inner.ip, outer);
const inter = (a, b) => a.filter((x) => b.includes(x));

// local IP of the phase1's interface
function p1Local(lab, fg, p1) {
  const i = lab.fgtIntfs(fg).find((x) => x.name === o(fg, P1, p1, "interface"));
  return i && i.prefix ? i.prefix.ip : null;
}
function p1Peer(lab, fg, p1) {
  // static peers only: find the FortiGate that owns remote-gw and its phase1 that accepts us
  const rgw = ipToInt(o(fg, P1, p1, "remote-gw") || "0.0.0.0");
  const me = p1Local(lab, fg, p1);
  for (const d of lab.devices.values()) {
    if (!(d instanceof FortiGate) || d === fg || lab.haRole(d) === "secondary") continue;
    const intf = lab.fgtIntfs(d).find((i) => i.prefix && i.prefix.ip === rgw);
    if (!intf) continue;
    const cands = d.entries(P1).filter((q) => o(d, P1, q, "interface") === intf.name);
    const exact = cands.find((q) => o(d, P1, q, "type") !== "dynamic" && ipToInt(o(d, P1, q, "remote-gw") || "0.0.0.0") === me);
    const dyn = cands.find((q) => o(d, P1, q, "type") === "dynamic");
    return { fg: d, intf, p1: exact || dyn || null, cands };
  }
  return null;
}

// Full negotiation result for a static phase1 (cached per config state)
Lab.prototype.negotiate = function (fg, p1name) {
  const p1 = fg.entry(P1, p1name);
  if (!p1) return { up: false, reason: "no such phase1" };
  if (o(fg, P1, p1, "type") === "dynamic") return { up: this.dialClients(fg, p1name).length > 0, dial: true, reason: "dial-up: up while a client is connected" };
  const log = [];
  const name = p1name;
  const me = p1Local(this, fg, p1);
  const rgwS = o(fg, P1, p1, "remote-gw");
  const ver = o(fg, P1, p1, "ike-version");
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
  const q = peer.p1;
  const pf = peer.fg;
  if (!q) {
    log.push(sent, `ike 0:${name}:${conn}: negotiation timeout, deleting`);
    return { up: false, reason: `${pf.id} has no phase1 for ${intToIp(me)} on ${peer.intf.name}`, log, peerLog: [`ike 0: comes ${intToIp(me)}:500->${rgwS}:500,ifindex=3,vrf=0....`, `ike 0: IKE${ver === "2" ? "v2" : ""} exchange=${ver === "2" ? "SA_INIT" : "Identity Protection"} id=${hex(0x8f1e2d3c)}${hex(0x4b5a6978)}/0000000000000000 len=596`, `ike 0: no gateway matches ${intToIp(me)}, ignoring the request`], noGateway: true };
  }
  const pname = q.key;
  const qver = o(pf, P1, q, "ike-version");
  if (qver !== ver) {
    log.push(sent, `ike 0:${name}:${conn}: negotiation timeout, deleting`);
    return { up: false, reason: `IKE version mismatch (${name} v${ver}, ${pf.id} v${qver})`, log, peerLog: [`ike 0: comes ${intToIp(me)}:500->${rgwS}:500,ifindex=3,vrf=0....`, `ike 0: ignoring IKEv${ver} packet: gateway ${pname} is configured for IKEv${qver}`], mismatch: "version" };
  }
  log.push(`ike 0:${name}:${conn}: received IKE msg (${ver === "2" ? "SA_INIT" : "ident_r1send"}): ${rgwS}:500->${intToIp(me)}:500, len=${ver === "2" ? 0 : 0}, vrf=0, id=${hex(0x8f1e2d3c)}${hex(0x4b5a6978)}/0000000000000000`.replace("len=0, ", "len=36, "));
  const props = inter(v(fg, P1, p1, "proposal"), v(pf, P1, q, "proposal"));
  const dhs = inter(v(fg, P1, p1, "dhgrp"), v(pf, P1, q, "dhgrp"));
  if (!props.length || !dhs.length) {
    if (ver === "2") log.push(`ike 0:${name}:${conn}: received notify type NO_PROPOSAL_CHOSEN`, `ike 0:${name}:${conn}: negotiation failure`);
    else log.push(`ike 0:${name}:${conn}: negotiation failure`, `ike 0:${name}:${conn}: no SA proposal chosen`);
    return { up: false, reason: !props.length ? `no common phase1 proposal (${v(fg, P1, p1, "proposal").join(" ")} vs ${v(pf, P1, q, "proposal").join(" ")})` : `no common DH group (${v(fg, P1, p1, "dhgrp").join(" ")} vs ${v(pf, P1, q, "dhgrp").join(" ")})`, log, mismatch: "proposal",
      peerLog: [`ike 0:${pname}:${conn}: incoming proposal:`, ...v(fg, P1, p1, "proposal").map((x) => `ike 0:${pname}:${conn}: proposal id = 1: protocol = IKEv${ver}: encapsulation = IKEv${ver}/none: type=ENCR, val=${x.split("-")[0].toUpperCase()}`), `ike 0:${pname}:${conn}: no SA proposal chosen`] };
  }
  if (ver === "1" && o(fg, P1, p1, "mode") !== o(pf, P1, q, "mode")) {
    log.push(`ike 0:${name}:${conn}: negotiation failure`);
    return { up: false, reason: "IKEv1 mode mismatch (main vs aggressive)", log, mismatch: "mode" };
  }
  if ((p1.attrs.get("psksecret") || [""])[0] !== (q.attrs.get("psksecret") || [""])[0]) {
    if (ver === "2") log.push(`ike 0:${name}:${conn}: initiator received SA_INIT response`, `ike 0:${name}:${conn}: sent IKE msg (AUTH): ${intToIp(me)}:500->${rgwS}:500, len=256, vrf=0`, `ike 0:${name}:${conn}: received notify type AUTHENTICATION_FAILED`);
    else log.push(`ike 0:${name}:${conn}: probable pre-shared secret mismatch`);
    return { up: false, reason: "pre-shared key mismatch", log, mismatch: "psk", peerLog: [ver === "2" ? `ike 0:${pname}:${conn}: auth verify done: FAILED` : `ike 0:${pname}:${conn}: probable pre-shared secret mismatch`] };
  }
  const peerid = (q.attrs.get("peerid") || [""])[0], localid = (p1.attrs.get("localid") || [""])[0];
  if (peerid && peerid !== localid) {
    log.push(`ike 0:${name}:${conn}: received notify type AUTHENTICATION_FAILED`);
    return { up: false, reason: `peer ID mismatch (${pf.id} expects '${peerid}', ${fg.id} sends '${localid || intToIp(me)}')`, log, mismatch: "id" };
  }
  log.push(ver === "2" ? `ike 0:${name}:${conn}: initiator received SA_INIT response` : `ike 0:${name}:${conn}: ISAKMP SA ${hex(0x8f1e2d3c)}${hex(0x4b5a6978)}/${hex(0x1d2c3b4a)}${hex(0x59687786)} key 32:${hex(0xa1b2c3d4)}...`);
  log.push(`ike 0:${name}:${conn}: established IKE SA ${hex(0x8f1e2d3c)}${hex(0x4b5a6978)}/${hex(0x1d2c3b4a)}${hex(0x59687786)}`);
  // phase 2
  const p2s = [];
  for (const p2 of fg.entries(P2).filter((x) => o(fg, P2, x, "phase1name") === p1name)) {
    const src = selector(fg, p2, "src"), dst = selector(fg, p2, "dst");
    const peers = pf.entries(P2).filter((x) => o(pf, P2, x, "phase1name") === pname);
    let ok = null, why = peers.length ? "" : `${pf.id} has no phase2 for ${pname}`;
    for (const r of peers) {
      const rs = selector(pf, r, "src"), rd = selector(pf, r, "dst");
      if (!(within(src, rd) && within(dst, rs))) { why = `selectors don't mirror (${fmtSel(src)}→${fmtSel(dst)} vs ${pf.id} ${fmtSel(rs)}→${fmtSel(rd)})`; continue; }
      if (!inter(v(fg, P2, p2, "proposal"), v(pf, P2, r, "proposal")).length) { why = "no common phase2 proposal"; continue; }
      if (o(fg, P2, p2, "pfs") !== o(pf, P2, r, "pfs")) { why = "PFS enabled on one side only"; continue; }
      if (o(fg, P2, p2, "pfs") === "enable" && !inter(v(fg, P2, p2, "dhgrp"), v(pf, P2, r, "dhgrp")).length) { why = "no common phase2 DH group"; continue; }
      ok = r; break;
    }
    if (ok) log.push(`ike 0:${name}:${conn}:${p2.key}:${conn + 1}: added IPsec SA: SPIs=${hex(0x6a1b2c3d)}/${hex(0x9e8f7a6b)}`, `ike 0:${name}:${conn}:${p2.key}:${conn + 1}: sending SNMP tunnel UP trap`);
    else log.push(ver === "2" ? `ike 0:${name}:${conn}:${p2.key}:${conn + 1}: received notify type TS_UNACCEPTABLE` : `ike 0:${name}:${conn}:${p2.key}:${conn + 1}: no matching phase2 found`);
    p2s.push({ name: p2.key, up: !!ok, reason: ok ? "" : why, src, dst, peer: ok ? ok.key : null });
  }
  const anyUp = p2s.some((x) => x.up);
  return { up: anyUp, p1up: true, p2: p2s, peer: { fg: pf, p1: pname, gw: ipToInt(rgwS) }, local: me, log, reason: anyUp ? "" : p2s.length ? `phase 1 is up, phase 2 is not: ${p2s[0].reason}` : "phase 1 is up but there is no phase2-interface", ver };
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
    if (!c) { tl.push(["ipsec_common_output4", 1000, "no matching IPsec selector, drop"]); done(); res.drop = { dev: fg.id, reason: `no dial-up client with ${intToIp(out.dst)}` }; return null; }
    tl.push(["esp_output4", 1394, "IPsec encrypt/auth"], ["ipsec_output_finish", 622, `send to ${intToIp(c.vpn.under)} via intf-${o(fg, P1, p1, "interface")}`]);
    done();
    ev.tunnel = name;
    return { dev: c, port: "vpn", pkt: out };
  }
  const info = this.tunnelInfo(fg, name);
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
        if (peer && peer.fg.dbg.ike && peer.fg.dbg.enabled) peer.fg.async.push(...info.peerLog);
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
        (info.p1up ? `\n  id/spi: 12 8f1e2d3c4b5a6978/1d2c3b4a59687786\n  direction: initiator\n  status: established 1824-1824s ago = 10ms\n  proposal: ${inter(v(fg, P1, p, "proposal"), info.peer ? v(info.peer.fg, P1, info.peer.fg.entry(P1, info.peer.p1), "proposal") : [])[0] || ""}\n  child: no\n  PPK: no\n  message-id sent/recv: 4/0\n  lifetime/rekey: ${o(fg, P1, p, "keylife")}/${Number(o(fg, P1, p, "keylife")) - 1844}\n  DPD sent/recv: 00000000/00000000\n` : ""));
    }
    return out.join("\n") || "";
  }
  if (/^vpn tunnel list/.test(w)) {
    const out = ["list all ipsec tunnel in vd 0"];
    for (const p of fg.entries(P1)) {
      if (o(fg, P1, p, "type") === "dynamic") continue;
      const info = this.tunnelInfo(fg, p.key) || {};
      out.push("------------------------------------------------------", `name=${p.key} ver=${o(fg, P1, p, "ike-version")} serial=1 ${intToIp(p1Local(this, fg, p) || 0)}:0->${o(fg, P1, p, "remote-gw")}:0 tun_id=${o(fg, P1, p, "remote-gw")} tun_id6=::10.0.0.1 dst_mtu=1500 dpd-link=on weight=1`,
        `bound_if=3 lgwy=static/1 tun=intf mode=auto/1 encap=none/552 options[0228]=npu frag-rfc  run_state=0 role=primary accept_traffic=1 overlay_id=0`,
        `proxyid_num=${(info.p2 || []).length} child_num=0 refcnt=${info.up ? 4 : 2} ilast=2 olast=2 ad=/0`, `stat: rxp=${info.up ? 112 : 0} txp=${info.up ? 109 : 0} rxb=${info.up ? 13440 : 0} txb=${info.up ? 9156 : 0}`, `dpd: mode=on-demand on=1 idle=20000ms retry=3 count=0 seqno=0`, `natt: mode=none draft=0 interval=0 remote_port=0`);
      for (const x of info.p2 || []) out.push(`proxyid=${x.name} proto=0 sa=${x.up ? 1 : 0} ref=2 serial=1 auto-negotiate`, `  src: 0:${intToIp(network(x.src))}/${maskOf(x.src.len)}:0`, `  dst: 0:${intToIp(network(x.dst))}/${maskOf(x.dst.len)}:0`, ...(x.up ? [`  SA:  ref=3 options=10226 type=00 soft=0 mtu=1438 expire=42863/0B replaywin=2048`, `       seqno=6e esn=0 replaywin_lastseq=00000070 qat=0 rekey=0 hash_search_len=1`, `  life: type=01 bytes=0/0 timeout=43186/43200`] : []));
    }
    return out.join("\n");
  }
  return null;
};
function maskOf(len) { const m = len === 0 ? 0 : (0xffffffff << (32 - len)) >>> 0; return intToIp(m); }

Lab.prototype.vpnSummary = function (fg) {
  const out = [];
  for (const p of fg.entries(P1)) {
    if (o(fg, P1, p, "type") === "dynamic") { for (const c of this.dialClients(fg, p.key)) out.push(`'${p.key}_0' ${intToIp(c.vpn.under)}:64916  selectors(total,up): 1/1  rx(pkt,err): 24/0  tx(pkt,err): 22/0`); continue; }
    const info = this.tunnelInfo(fg, p.key) || {};
    const n = (info.p2 || []).length, up = (info.p2 || []).filter((x) => x.up).length;
    out.push(`'${p.key}' ${o(fg, P1, p, "remote-gw")}:0  selectors(total,up): ${n}/${up}  rx(pkt,err): ${up ? 112 : 0}/0  tx(pkt,err): ${up ? 109 : 0}/${info.p1up ? 0 : 3}`);
  }
  return out.join("\n");
};
