// Topology drawing for the Labs screen: devices, segments and live link state as one SVG.
import { intToIp, prefixStr } from "./net.js";
import { FortiGate } from "./fgt.js";

const esc = (t) => String(t ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function glyph(d, x, y) {
  switch (d.kind) {
    case "fortigate":
      return `<rect x="${x - 56}" y="${y - 22}" width="112" height="44" rx="5" class="tp-fgt"/>
        <g class="tp-fgt-ports">${[0, 1, 2, 3, 4, 5, 6].map((i) => `<rect x="${x - 45 + i * 13}" y="${y + 7}" width="9" height="7" rx="1"/>`).join("")}</g>
        <text x="${x}" y="${y - 2}" class="tp-fgt-t" text-anchor="middle">FortiGate</text>`;
    case "router":
      return `<circle cx="${x}" cy="${y}" r="20" class="tp-box"/><path d="M${x - 9} ${y - 4}h14l-4-4M${x + 9} ${y + 4}h-14l4 4" class="tp-line-ink"/>`;
    case "cloud":
      return `<path d="M${x - 70} ${y + 18}h140a24 24 0 0 0 0-40a34 34 0 0 0-62-14a28 28 0 0 0-52 10a22 22 0 0 0-26 44z" class="tp-cloud"/>
        <text x="${x}" y="${y + 6}" text-anchor="middle" class="tp-cloud-t">Internet</text>`;
    case "fortiswitch":
      return `<rect x="${x - 50}" y="${y - 13}" width="100" height="26" rx="4" class="tp-fsw"/>
        <g class="tp-fsw-ports">${[0, 1, 2, 3, 4, 5, 6, 7, 8, 9].map((i) => `<rect x="${x - 42 + i * 8.6}" y="${y + 3}" width="6" height="5" rx="1"/>`).join("")}</g>
        <text x="${x}" y="${y - 1}" text-anchor="middle" class="tp-fsw-t">FortiSwitch</text>`;
    case "server":
      return `<rect x="${x - 14}" y="${y - 19}" width="28" height="38" rx="3" class="tp-box"/><path d="M${x - 8} ${y - 9}h16M${x - 8} ${y - 2}h16M${x - 8} ${y + 5}h10" class="tp-line-ink"/>`;
    case "fortimanager": case "fortianalyzer": case "fortisiem": case "fortiedr":
      return `<rect x="${x - 52}" y="${y - 20}" width="104" height="40" rx="5" class="tp-mgr"/>
        <g class="tp-mgr-leds">${[0, 1, 2].map((i) => `<circle cx="${x - 40 + i * 8}" cy="${y + 11}" r="2"/>`).join("")}</g>
        <text x="${x}" y="${y + 1}" text-anchor="middle" class="tp-mgr-t">${{ fortimanager: "FortiManager", fortianalyzer: "FortiAnalyzer", fortisiem: "FortiSIEM", fortiedr: "FortiEDR" }[d.kind]}</text>`;
    default:
      return `<rect x="${x - 18}" y="${y - 16}" width="36" height="24" rx="3" class="tp-box"/><path d="M${x - 6} ${y + 12}h12M${x} ${y + 8}v4" class="tp-line-ink"/>`;
  }
}

function sub(lab, d) {
  if (d instanceof FortiGate) return d.model.replace("FortiGate-", "FG-").replace("FortiManager-", "FMG-").replace("FortiAnalyzer-", "FAZ-");
  if (d.kind === "router") return d.label || "";
  if (d.kind === "fortiswitch") return d.model.replace("FortiSwitch-", "FS-");
  if (d.kind === "cloud") return "";
  const a = d.addr && d.addr();
  if (a) return `${intToIp(a.ip)}/${a.len}`;
  return d.dhcp ? "no lease" : "";
}

// returns an SVG string; `sel` is the device whose console is open
export function drawTopology(run, sel) {
  const lab = run.lab;
  const L = run.def.topology.layout || {};
  const pos = (id) => L[id] || [480, 280];
  const links = [];
  const portLabels = [];
  // parallel links between the same two devices are drawn side by side
  const pairKey = (a, b) => [a, b].sort().join("|");
  const pairTotal = new Map(), pairSeen = new Map();
  const segs = lab.baseSegments || lab.segments;
  for (const seg of segs) { const mem = seg.members.filter((m) => lab.dev(m.dev)); if (mem.length === 2) { const k = pairKey(mem[0].dev, mem[1].dev); pairTotal.set(k, (pairTotal.get(k) || 0) + 1); } }
  for (const seg of segs) {
    const mem = seg.members.filter((m) => lab.dev(m.dev));
    const statusOf = (m) => {
      const d = lab.dev(m.dev);
      if (seg.down || m.down) return "down";
      if (seg.cable) {
        const sw = mem.map((x) => lab.dev(x.dev)).find((x) => x.kind === "fortiswitch");
        const st = sw && lab.fslState ? lab.fslState(sw) : null;
        if (!st || !st.authorized) return "noip";
        if (d.kind === "fortiswitch" || d instanceof FortiGate) return "up";
        return d.dhcp && !d.lease ? "noip" : "up";
      }
      if (d instanceof FortiGate) {
        const i = lab.fgtIntfs(d).find((x) => x.seg === seg);
        if (!i) return "unset";
        return i.up ? (i.prefix ? "up" : "noip") : "down";
      }
      if (d.dhcp && !d.lease) return "noip";
      return "up";
    };
    const hub = mem.length > 2 ? (L["seg:" + seg.id] || avg(mem.map((m) => pos(m.dev)))) : null;
    if (hub) {
      links.push(`<rect x="${hub[0] - 34}" y="${hub[1] - 7}" width="68" height="14" rx="3" class="tp-switch"/>${seg.label ? `<text x="${hub[0] + 40}" y="${hub[1] + 4}" class="tp-seg-t">${esc(seg.label)}</text>` : ""}`);
      for (const m of mem) {
        const p = pos(m.dev);
        const st = statusOf(m);
        links.unshift(`<line x1="${p[0]}" y1="${p[1]}" x2="${hub[0]}" y2="${hub[1]}" class="tp-link ${st}"/>`);
        if (m.port && lab.dev(m.dev) instanceof FortiGate) portLabels.push(portLabel(p, hub, m.port + (m.vlan ? `.${m.vlan}` : ""), st, "fortigate", 1, "switch"));
      }
    } else if (mem.length === 2) {
      const [a, b] = mem;
      let pa = pos(a.dev), pb = pos(b.dev);
      const k = pairKey(a.dev, b.dev), tot = pairTotal.get(k) || 1, idx = pairSeen.get(k) || 0;
      pairSeen.set(k, idx + 1);
      if (tot > 1) {
        const off = (idx - (tot - 1) / 2) * 16, dx = pb[0] - pa[0], dy = pb[1] - pa[1], len = Math.hypot(dx, dy) || 1;
        const ox = (-dy / len) * off, oy = (dx / len) * off;
        pa = [pa[0] + ox, pa[1] + oy]; pb = [pb[0] + ox, pb[1] + oy];
      }
      const st = [statusOf(a), statusOf(b)].includes("down") ? "down" : [statusOf(a), statusOf(b)].includes("noip") ? "noip" : "up";
      links.unshift(`<line x1="${pa[0]}" y1="${pa[1]}" x2="${pb[0]}" y2="${pb[1]}" class="tp-link ${st}"/>`);
      for (const [m, p, q, o] of [[a, pa, pb, b], [b, pb, pa, a]]) {
        if (!m.port || lab.dev(m.dev).kind === "cloud" || m.port === "eth0") continue;
        const dv = lab.dev(m.dev);
        // access ports of a switch are labelled at the device end, so a dense switch stays readable
        if (dv.kind === "fortiswitch" && m.port !== dv.uplink) portLabels.push(portLabel(q, p, m.port, statusOf(m), lab.dev(o.dev).kind, 1, "fortiswitch"));
        else portLabels.push(portLabel(p, q, m.port + (m.vlan ? `.${m.vlan}` : ""), statusOf(m), dv.kind, 1, lab.dev(o.dev).kind));
      }
    }
  }
  const nodes = lab.order.map((id) => {
    const d = lab.dev(id);
    const [x, y] = pos(id);
    const s = sub(lab, d);
    const off = d.kind === "fortigate" ? 40 : 38;
    return `<g class="tp-node ${sel === id ? "sel" : ""} ${d.kind === "cloud" ? "" : "click"}" data-dev="${esc(id)}" ${d.kind === "cloud" ? "" : `tabindex="0" role="button" aria-label="Open the console of ${esc(id)}"`}>
      ${glyph(d, x, y)}
      ${d.kind === "cloud" ? "" : `<text x="${x}" y="${y + off}" text-anchor="middle" class="tp-name">${esc(id)}</text>`}
      ${s ? `<text x="${x}" y="${y + off + 16}" text-anchor="middle" class="tp-sub">${esc(s)}</text>` : ""}
    </g>`;
  });
  const xs = lab.order.map((id) => pos(id)[0]), ys = lab.order.map((id) => pos(id)[1]);
  const vx = Math.min(0, Math.min(...xs) - 90), vy = Math.min(0, Math.min(...ys) - 60);
  const vw = Math.max(960, Math.max(...xs) + 90) - vx, vh = Math.max(560, Math.max(...ys) + 55) - vy;
  return `<svg viewBox="${vx} ${vy} ${vw} ${vh}" class="topo" role="img" aria-label="Network topology">${links.join("")}${portLabels.join("")}${nodes.join("")}</svg>`;
}
function avg(ps) { return [ps.reduce((a, p) => a + p[0], 0) / ps.length, ps.reduce((a, p) => a + p[1], 0) / ps.length]; }
function extent(kind, dx, dy) {
  const horiz = Math.abs(dx) > Math.abs(dy);
  const E = { fortigate: [58, 24, 62], router: [22, 22, 54], cloud: [72, 30, 30], switch: [36, 8, 8] };
  const e = E[kind] || [22, 22, 54];
  return horiz ? e[0] : dy < 0 ? e[1] : e[2];
}
function portLabel(from, to, text, st, kind = "host", side = 1, otherKind = "host") {
  const dx = to[0] - from[0], dy = to[1] - from[1];
  const len = Math.hypot(dx, dy) || 1;
  const w = text.length * 7.6 + 12;
  const horiz = Math.abs(dx) > Math.abs(dy);
  let dist = extent(kind, dx, dy) + (horiz ? w / 2 : 11) + 4;
  let px = 0, py = 0;
  const room = len - extent(otherKind, -dx, -dy) - 14;
  if (dist > room) {
    // short link: keep the label near this end and push it sideways so both ends' labels fit
    dist = Math.max(10, Math.min(dist, room));
    px = (-dy / len) * 22 * side; py = (dx / len) * 22 * side;
  }
  const x = from[0] + (dx / len) * dist + px, y = from[1] + (dy / len) * dist + py;
  return `<g class="tp-port ${st}"><rect x="${x - w / 2}" y="${y - 10}" width="${w}" height="19" rx="9"/><text x="${x}" y="${y + 4}" text-anchor="middle">${esc(text)}</text></g>`;
}
