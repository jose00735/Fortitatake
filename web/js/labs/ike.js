// IKE settings as one shape for every kind of peer, and their strongSwan form.
// A view is what one end of a tunnel would offer and accept in IKE: a FortiGate's phase1-interface
// with its phase2-interface entries, or a third-party router's `ipsec:` spec (lab routers present
// it as Cisco IOS-XE crypto config). The simulator negotiates two views (vpn.js); on FortiTatake OS
// each view becomes a swanctl connection and strongSwan negotiates it for real (agent 0.16+).
import { ipToInt, intToIp, parsePrefix, network, inPrefix } from "./net.js";

const P1 = "vpn ipsec phase1-interface", P2 = "vpn ipsec phase2-interface";

// FortiOS DH group numbers in strongSwan's names
export const DH = { 1: "modp768", 2: "modp1024", 5: "modp1536", 14: "modp2048", 15: "modp3072", 16: "modp4096", 17: "modp6144", 18: "modp8192", 19: "ecp256", 20: "ecp384", 21: "ecp521", 27: "ecp224bp", 28: "ecp256bp", 29: "ecp384bp", 30: "ecp512bp", 31: "curve25519", 32: "curve448" };

function encName(e) {
  const g = /^(aes(?:128|192|256))gcm$/.exec(e);
  if (g) return `${g[1]}gcm16`;
  return /^(aes128|aes192|aes256|3des|des|chacha20poly1305|null)$/.test(e) ? e : null; // ARIA and SEED have no strongSwan name here
}
const integName = (i) => (/^(md5|sha1|sha256|sha384|sha512|prfsha1|prfsha256|prfsha384|prfsha512)$/.test(i) ? i : null);

// "aes256-sha256" -> {enc, integ}; "aes256gcm" (phase 2) -> {enc}; "chacha20poly1305-prfsha256" -> {enc, integ}
function split(p) {
  const i = p.indexOf("-");
  return i < 0 ? { enc: p, integ: "" } : { enc: p.slice(0, i), integ: p.slice(i + 1) };
}

// phase 1: one strongSwan proposal per FortiOS proposal, each with all the DH groups (FortiOS pairs them the same way)
export function ikeProposals(props, dhs) {
  const groups = dhs.map((d) => DH[d]).filter(Boolean);
  const out = [];
  for (const p of props) {
    const { enc, integ } = split(p);
    const e = encName(enc), i = integName(integ);
    if (!e || !i || !groups.length) continue;
    out.push([e, i, ...groups].join("-"));
  }
  return out;
}

// phase 2 (ESP): with PFS each proposal carries the DH groups, without it none
export function espProposals(props, pfs, dhs) {
  const groups = pfs ? dhs.map((d) => DH[d]).filter(Boolean) : [];
  const out = [];
  for (const p of props) {
    const { enc, integ } = split(p);
    const e = encName(enc);
    if (!e) continue;
    const aead = /gcm16$|chacha20poly1305/.test(e);
    const i = aead ? "" : integ === "null" ? "" : integName(integ);
    if (!aead && i === null) continue;
    if (pfs && !groups.length) continue;
    out.push([e, ...(i ? [i] : []), ...groups].join("-"));
  }
  return out;
}

const pfx = (p) => (p.len === 0 ? "0.0.0.0/0" : `${intToIp(network(p))}/${p.len}`);

function fgSelector(fg, p2, side) {
  const o = (a) => fg.one(P2, p2, a);
  const t = o(`${side}-addr-type`) || "subnet";
  if (t === "name") {
    const n = o(`${side}-name`);
    const a = n && fg.entry("firewall address", n);
    return (a && parsePrefix(fg.one("firewall address", a, "subnet"))) || { ip: 0, len: 0 };
  }
  if (t === "ip") return { ip: ipToInt(o(`${side}-start-ip`) || "0.0.0.0"), len: 32 };
  const raw = fg.val(P2, p2, `${side}-subnet`).join(" ");
  return (!raw || raw === "0.0.0.0" ? { ip: 0, len: 0 } : parsePrefix(raw)) || { ip: 0, len: 0 };
}

// a FortiGate phase1-interface as a view
export function fgView(lab, fg, p1) {
  if (typeof p1 === "string") p1 = fg.entry(P1, p1);
  if (!p1) return null;
  const o = (a) => fg.one(P1, p1, a), v = (a) => fg.val(P1, p1, a);
  const wan = o("interface");
  const i = lab.fgtIntfs(fg).find((x) => x.name === wan);
  const idx = fg.entries(P1).findIndex((x) => x.key === p1.key);
  return {
    dev: fg, kind: "fortigate", name: p1.key, ifId: idx + 1, wan, type: o("type") || "static",
    local: i && i.prefix ? i.prefix.ip : null, remoteGw: ipToInt(o("remote-gw") || "0.0.0.0"),
    ver: o("ike-version") || "2", mode: o("mode") || "main", proposals: v("proposal"), dhgrps: v("dhgrp"),
    psk: (p1.attrs.get("psksecret") || [""])[0], localid: (p1.attrs.get("localid") || [""])[0], peerid: (p1.attrs.get("peerid") || [""])[0],
    advpn: { sender: o("auto-discovery-sender") === "enable", receiver: o("auto-discovery-receiver") === "enable", networkId: Number(o("network-id") || 0) },
    p2s: fg.entries(P2).filter((x) => fg.one(P2, x, "phase1name") === p1.key).map((x) => ({
      name: x.key, src: fgSelector(fg, x, "src"), dst: fgSelector(fg, x, "dst"),
      proposals: fg.val(P2, x, "proposal"), pfs: fg.one(P2, x, "pfs") !== "disable", dhgrps: fg.val(P2, x, "dhgrp"),
    })),
  };
}

// a lab router's `ipsec:` entries as views. Spec, per tunnel:
//   {name: Tunnel10, iface: Gi1, peer: 200.31.20.2, ike: 2, proposal: [aes256-sha256], dhgrp: [14], psk, localid?, peerid?,
//    p2: [{name?, local: 10.99.0.0/24, remote: 10.20.0.0/16, proposal: [aes256-sha256], pfs: 14 | [14] | false}]}
export function routerViews(lab, r) {
  const spec = (r.spec && r.spec.ipsec) || [];
  return spec.map((t, idx) => {
    const i = r.ifaces.find((x) => x.name === t.iface) || r.ifaces[0];
    return {
      dev: r, kind: "router", name: t.name, ifId: idx + 1, wan: i && i.name, type: "static",
      local: i && i.prefix ? i.prefix.ip : null, remoteGw: ipToInt(t.peer || "0.0.0.0"),
      ver: String(t.ike || 2), mode: t.mode || "main", proposals: (t.proposal || ["aes256-sha256"]).map(String), dhgrps: (t.dhgrp || [14]).map(String),
      psk: String(t.psk || ""), localid: t.localid || "", peerid: t.peerid || "",
      advpn: { sender: false, receiver: false, networkId: 0 },
      p2s: (t.p2 || [{}]).map((x, j) => {
        const pfs = x.pfs === false ? false : x.pfs === undefined ? (t.dhgrp || [14]) : x.pfs; // PFS with the phase 1 groups unless set
        return { name: x.name || `${t.name}-${j + 1}`, src: parsePrefix(x.local || "0.0.0.0/0") || { ip: 0, len: 0 }, dst: parsePrefix(x.remote || "0.0.0.0/0") || { ip: 0, len: 0 },
          proposals: (x.proposal || t.proposal || ["aes256-sha256"]).map(String), pfs: pfs !== false, dhgrps: (pfs === false ? [] : [].concat(pfs)).map(String) };
      }),
    };
  });
}

// every view that terminates on this address (the other end of a tunnel to it)
export function viewsAt(lab, ip) {
  const out = [];
  for (const d of lab.devices.values()) {
    if (d.kind === "fortigate" && d.entries) {
      if (lab.haRole && lab.haRole(d) === "secondary") continue;
      for (const p of d.entries(P1)) { const vw = fgView(lab, d, p); if (vw && vw.local === ip) out.push(vw); }
    } else if (d.kind === "router") for (const vw of routerViews(lab, d)) if (vw.local === ip) out.push(vw);
  }
  return out;
}

// ---------------------------------------------------------------- strongSwan (swanctl.conf)
const q = (s) => `"${String(s).replace(/["\\]/g, "")}"`;
export const cname = (s) => String(s).replace(/[^A-Za-z0-9_.-]/g, "_");

// one device's views as a swanctl.conf; `peerIds` maps a view name to the IDs the other end may send
export function swanConf(views, peerIds = {}) {
  const conns = [], secrets = [];
  for (const vw of views) {
    if (!vw.local || !vw.remoteGw || vw.type === "dynamic") continue;
    const ike = ikeProposals(vw.proposals, vw.dhgrps);
    const me = intToIp(vw.local), peer = intToIp(vw.remoteGw);
    const lid = vw.localid || me;
    // one end initiates (the lower address), the other answers: no simultaneous IKE_SA_INIT collisions
    const init = vw.local < vw.remoteGw;
    const children = vw.p2s.map((p) => {
      const esp = espProposals(p.proposals, p.pfs, p.dhgrps);
      return `      ${cname(p.name)} {
        local_ts = ${pfx(p.src)}
        remote_ts = ${pfx(p.dst)}
        esp_proposals = ${esp.length ? esp.join(", ") : "aes128-sha256-modp2048"}
        if_id_in = ${vw.ifId}
        if_id_out = ${vw.ifId}
        mode = tunnel
        start_action = ${init ? "start" : "none"}
        dpd_action = ${init ? "restart" : "clear"}
        rekey_time = 43200
      }`;
    });
    conns.push(`  ${cname(vw.name)} {
    version = ${vw.ver === "1" ? 1 : 2}
    local_addrs = ${me}
    remote_addrs = ${peer}
    proposals = ${ike.length ? ike.join(", ") : "aes128-sha256-modp2048"}
    aggressive = ${vw.ver === "1" && vw.mode === "aggressive" ? "yes" : "no"}
    mobike = no
    encap = no
    keyingtries = 0
    unique = no
    dpd_delay = 5s
    local {
      auth = psk
      id = ${q(lid)}
    }
    remote {
      auth = psk
      id = ${vw.peerid ? q(vw.peerid) : "%any"}
    }
    children {
${children.join("\n")}
    }
  }`);
    const ids = [...new Set([lid, peer, vw.peerid, ...(peerIds[vw.name] || [])].filter(Boolean))];
    secrets.push(`  ike-${cname(vw.name)} {
    secret = ${q(vw.psk)}
${ids.map((x, i) => `    id-${i} = ${q(x)}`).join("\n")}
  }`);
  }
  if (!conns.length) return "";
  return `connections {\n${conns.join("\n")}\n}\nsecrets {\n${secrets.join("\n")}\n}\n`;
}

// does a selector pair cover this packet
export const covers = (p2, src, dst) => inPrefix(src, p2.src) && inPrefix(dst, p2.dst);
