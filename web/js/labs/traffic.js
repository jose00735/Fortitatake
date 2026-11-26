// Office traffic: the everyday flows of a small office, generated for real on the lab
// network by FortiTatake OS (agent gen.* ops). Five generators: web, dns, smb, mail, voice.
// A lab can name a profile (`traffic:` in its topology); otherwise one is derived from the
// devices: PCs browse, resolve names and read mail, a NAS serves files, phones call a PBX.
// Everything is seeded from the lab, so a run repeats.

import { intToIp } from "./net.js";

// stand-ins in the lab's Internet (documentation space, never routed outside the lab)
export const OFFICE_NET = {
  mail: { name: "mail.office-mail.lab", ip: "198.51.100.25", binds: [["tcp", 25], ["tcp", 587], ["tcp", 993]] },
  saas: { name: "app.office-saas.lab", ip: "198.51.100.80", binds: [["tcp", 443]] },
  ntp: { name: "ntp.office.lab", ip: "198.51.100.123", binds: [["udp", 123]] },
};

// sites the web generator visits: real names, resolved through the lab's DNS path (the relay
// gives real answers) and answered by the Internet stand-in web server
const SITES = ["www.google.com", "outlook.office.com", "www.wikipedia.org", "www.eltiempo.com", "www.bancolombia.com", "www.youtube.com", "www.minsalud.gov.co", "www.fortinet.com"];
const NAMES = [...SITES, "login.microsoftonline.com", "update.microsoft.com", "time.windows.com", "api.whatsapp.com", "www.dian.gov.co", "cdn.jsdelivr.net"];

export const GEN_KINDS = ["web", "dns", "smb", "mail", "voice"];
export const GEN_INFO = {
  web: "Web browsing: DNS, then HTTP/HTTPS pages of 1-6 objects",
  dns: "Name resolution: A/AAAA lookups, about 3% NXDOMAIN, NTP",
  smb: "File share: SMB2 sessions with reads and writes (TCP 445)",
  mail: "Mail and SaaS: SMTP 587 with STARTTLS, IMAPS 993, HTTPS API calls",
  voice: "Voice: SIP on UDP 5060 and RTP at 50 packets/s",
};

const isNas = (d) => d.kind === "server" && (d.services.has("tcp/445") || /nas|file|fs\d|share/i.test(d.id));
const isPbx = (d) => d.kind === "server" && (d.services.has("udp/5060") || /pbx|voip|sip/i.test(d.id));
const isPhone = (d) => d.kind === "host" && (/phone|voip|tel/i.test(d.id) || (d.spec && d.spec.phone));

// which generators each device runs: the lab's profile, or one derived from its devices
export function trafficProfile(lab) {
  const devs = [...lab.devices.values()];
  const spec = lab.def && lab.def.traffic;
  const hosts = {};
  if (spec && spec.hosts) for (const [id, kinds] of Object.entries(spec.hosts)) hosts[id] = [].concat(kinds).filter((k) => GEN_KINDS.includes(k));
  else {
    const nas = devs.some(isNas), pbx = devs.some(isPbx);
    for (const d of devs.filter((x) => x.kind === "host")) {
      if (isPhone(d)) { if (pbx) hosts[d.id] = ["voice"]; continue; }
      // a PC behind an ISP router (a teleworker at home) browses and reads mail; the file share and the PBX are office-only
      const gw = d.gateway ? d.gateway() : null;
      const home = gw && devs.some((r) => r.kind === "router" && (r.ifaces || []).some((i) => i.prefix && i.prefix.ip === gw));
      hosts[d.id] = ["web", "dns", "mail", ...(nas && !home ? ["smb"] : []), ...(pbx && !home && /recep|front|admin/i.test(d.id) ? ["voice"] : [])];
    }
  }
  return { hosts, rate: Number((spec && spec.rate) || 1) };
}

// extra listeners and addresses for the stand-ins (called by compile when traffic is on)
export function trafficCompile(lab, out) {
  if (!lab.traffic || !lab.traffic.on) return;
  const cloud = out.topo.internet && out.topo.internet.ns;
  if (cloud) {
    const l = out.listen.find((x) => x.ns === cloud);
    for (const s of Object.values(OFFICE_NET)) {
      out.topo.addrs.push({ dev: cloud, if: "lo", cidr: s.ip + "/32" });
      if (l) { for (const [proto, port] of s.binds) l.binds.push({ ip: s.ip, proto, port }); l.names = { ...(l.names || {}), [s.name]: s.ip }; }
    }
  }
  for (const d of lab.devices.values()) {
    const l = out.listen.find((x) => x.ns === d.id);
    if (!l) continue;
    const add = (proto, port) => { if (!l.binds.some((b) => b.proto === proto && b.port === port)) l.binds.push({ proto, port }); };
    if (isNas(d)) add("tcp", 445);
    if (isPbx(d)) { add("udp", 5060); add("udp", 16384); }
  }
}

// the generators to start: [{id, ns, kind, resolver, targets, names, seed, rate}]
export function trafficPlan(lab, rate = 1) {
  const prof = trafficProfile(lab);
  const devs = [...lab.devices.values()];
  const ipOf = (d) => (d.ip && d.ip() ? intToIp(d.ip()) : null);
  const nas = devs.filter(isNas).filter(ipOf), pbx = devs.filter(isPbx).filter(ipOf);
  // web servers the lab itself publishes, by the names its DNS gives them (a DMZ server is
  // reached through its VIP, as a user would), plus the Internet hosts the lab defines
  const labWeb = [];
  const webIps = new Set();
  for (const d of devs) {
    if (d.kind === "server" && ipOf(d) && (d.services.has("tcp/80") || d.services.has("tcp/443"))) webIps.add(ipOf(d));
    if (d.kind === "cloud") for (const h of d.hosts) if (h.name && (h.services.has("tcp/80") || h.services.has("tcp/443"))) labWeb.push({ name: h.name, ip: intToIp(h.ip), tls: h.services.has("tcp/443"), port: h.services.has("tcp/443") ? 443 : 80 });
  }
  const cloudIps = new Set(devs.filter((d) => d.kind === "cloud").flatMap((d) => d.hosts.map((h) => intToIp(h.ip))));
  for (const [name, ip] of lab.names || []) {
    const a = intToIp(ip);
    if (labWeb.some((w) => w.name === name) || cloudIps.has(a)) continue; // Internet hosts: only those with a web server (above)
    if (webIps.has(a) || !/^(10|192\.168|172\.(1[6-9]|2\d|3[01]))\./.test(a)) labWeb.push({ name, ip: a, tls: true, port: 443 }); // a published server (VIP)
  }
  const seed0 = [...String((lab.def && lab.def.title) || "lab")].reduce((a, c) => (a * 31 + c.charCodeAt(0)) >>> 0, 7);
  const out = [];
  for (const [id, kinds] of Object.entries(prof.hosts)) {
    const d = lab.devices.get(id);
    if (!d || !ipOf(d)) continue;
    const dns = d.dnsServers ? d.dnsServers() : [];
    const resolver = dns.length ? intToIp(dns[0]) : "";
    kinds.forEach((kind, i) => {
      const g = { id: `${id}/${kind}`, ns: id, kind, resolver, seed: (seed0 + i * 7919 + id.length * 104729) % 2147483647, rate: rate * prof.rate, targets: [], names: [] };
      if (kind === "web") g.targets = [...SITES.map((name) => ({ name, tls: !/eltiempo|wikipedia/.test(name) })), ...labWeb];
      if (kind === "dns") { g.names = [...NAMES, ...labWeb.map((w) => w.name)]; g.targets = [{ name: OFFICE_NET.ntp.name, ip: OFFICE_NET.ntp.ip }]; }
      if (kind === "smb") g.targets = nas.map((n) => ({ name: n.hostname || n.id, ip: ipOf(n), port: 445 }));
      if (kind === "mail") g.targets = [{ name: OFFICE_NET.mail.name, ip: OFFICE_NET.mail.ip, port: 587 }, { name: OFFICE_NET.mail.name, ip: OFFICE_NET.mail.ip, port: 993 }, { name: OFFICE_NET.saas.name, ip: OFFICE_NET.saas.ip, port: 443 }];
      if (kind === "voice") g.targets = pbx.map((p) => ({ name: p.hostname || p.id, ip: ipOf(p), port: 5060 }));
      if (kind === "dns" || g.targets.length) out.push(g);
    });
  }
  return out;
}

// ----- the baseline recorder: a compressed workday, kept per lab -----
// At 120x a 9-hour day (08:00-17:00) takes 4.5 minutes. Events get the virtual time.
export const BASELINE_RATE = 120;
export const BASELINE_HOURS = 9;

export function virtualTime(startMs, nowMs, rate = BASELINE_RATE) {
  const v = new Date(2026, 0, 5, 8, 0, 0).getTime() + (nowMs - startMs) * rate; // a Monday, 08:00
  const d = new Date(v);
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

export function summarize(events) {
  const by = {};
  for (const e of events) {
    const k = e.kind;
    by[k] = by[k] || { flows: 0, ok: 0, bytes: 0, dst: {} };
    by[k].flows++;
    if (e.ok) by[k].ok++;
    by[k].bytes += e.bytes || 0;
    const key = `${e.dst}:${e.port}`;
    by[k].dst[key] = (by[k].dst[key] || 0) + 1;
  }
  return by;
}

export const fmtBytes = (b) => (b >= 1 << 20 ? (b / (1 << 20)).toFixed(1) + " MB" : b >= 1024 ? (b / 1024).toFixed(0) + " KB" : b + " B");
