// Threat intel in the labs: indicators from the app's feed snapshot (abuse.ch Feodo Tracker,
// ThreatFox, URLhaus, OpenPhish), picked with the lab's seed and sinkholed in the lab Internet.
// Every picked C2 address and feed host is a lab Internet host: it answers, logs what reaches
// it, and never leads anywhere real. Without a snapshot yet, clearly labelled stand-ins are used.
// FortiGate side: `config system external-resource` (type address) entries whose resource
// names a C2 or malware feed hold these addresses, so policies can block them.
import { Lab } from "./sim.js";
import { ipToInt, intToIp } from "./net.js";

// stand-ins (documentation space) when the app has no snapshot yet
export const STANDIN = {
  date: null, standin: true,
  sources: [{ name: "stand-in", url: "", terms: "lab stand-ins: no feed snapshot on this device yet", count: 0 }],
  c2: [["192.0.2.66", 443, "QakBot"], ["192.0.2.67", 8080, "Emotet"], ["192.0.2.68", 443, "Cobalt Strike"], ["192.0.2.69", 3333, "XMRig pool"], ["192.0.2.70", 447, "TrickBot"], ["192.0.2.71", 443, "Sliver"], ["192.0.2.72", 8443, "Pikabot"], ["192.0.2.73", 443, "Latrodectus"]].map(([ip, port, family]) => ({ ip, port, family, source: "stand-in" })),
  domains: ["cdn-update-check.lab-c2.example", "telemetry-sync.lab-c2.example", "api-msupdate.lab-c2.example", "static-files.lab-c2.example", "pool.lab-miner.example", "beacon.lab-c2.example"].map((domain, i) => ({ domain, family: ["Cobalt Strike", "Sliver", "QakBot", "Emotet", "XMRig pool", "Pikabot"][i], source: "stand-in" })),
  urls: ["http://files.lab-malware.example/inv/Factura.iso", "http://files.lab-malware.example/i.sh", "http://dl.lab-malware.example/x", "http://dl.lab-malware.example/upd.exe", "http://files.lab-malware.example/doc.zip", "http://dl.lab-malware.example/k"].map((url) => ({ url, host: new URL(url).hostname, threat: "malware_download", source: "stand-in" })),
  phish: ["https://login-microsoftonline.lab-phish.example/common/oauth2", "https://secure-bancolombia.lab-phish.example/login", "https://dian-notificaciones.lab-phish.example/factura", "https://docs-share.lab-phish.example/view"].map((url) => ({ url, host: new URL(url).hostname, threat: "phishing", source: "stand-in" })),
};

const isV4 = (s) => /^\d+\.\d+\.\d+\.\d+$/.test(s);
// a host name or IP we may sinkhole: not private, not one the lab already uses
const usable = (ip) => isV4(ip) && !/^(10|127|0|169\.254|192\.168|172\.(1[6-9]|2\d|3[01])|22[4-9]|2[3-5]\d)\./.test(ip);

function rng(seed) { let s = seed >>> 0 || 1; return () => { s ^= s << 13; s >>>= 0; s ^= s >> 17; s ^= s << 5; s >>>= 0; return s / 4294967296; }; }
function pickN(list, n, r) { const a = list.slice(); const out = []; while (a.length && out.length < n) out.push(a.splice(Math.floor(r() * a.length), 1)[0]); return out; }

// the indicators one lab uses: same snapshot + same lab = same picks
export function pickIntel(snap, seedText) {
  const s = snap && (snap.c2 || []).length ? snap : STANDIN;
  const r = rng([...String(seedText)].reduce((a, c) => (a * 31 + c.charCodeAt(0)) >>> 0, 7));
  const c2 = pickN([...new Map(s.c2.filter((x) => usable(x.ip)).map((x) => [x.ip, x])).values()], 8, r);
  const domains = pickN(s.domains || [], 6, r);
  const urls = pickN((s.urls || []).filter((u) => u.host && !isV4(u.host)), 6, r);
  const phish = pickN((s.phish || []).filter((u) => u.host && !isV4(u.host)), 4, r);
  return { date: s.date, standin: !!s.standin, sources: s.sources || [], c2, domains, urls, phish };
}

// the web stand-in that answers feed URL hosts (documentation space)
export const SINKHOLE_WEB = "198.51.100.200";

// add the picked indicators to the lab Internet (simulator and real network alike)
Lab.prototype.installIntel = function (snap) {
  const cloud = [...this.devices.values()].find((d) => d.kind === "cloud");
  if (!cloud) return;
  this.intel = pickIntel(snap, (this.def && this.def.title) || "lab");
  const used = new Set(cloud.hosts.map((h) => h.ip));
  const add = (name, ip, services) => {
    const n = ipToInt(ip);
    let h = cloud.hosts.find((x) => x.ip === n);
    if (!h) { if (used.has(n)) return; h = { name: name || "", ip: n, services: new Set(["icmp"]), dns: false, files: {}, pinned: false, intel: true }; cloud.hosts.push(h); used.add(n); }
    for (const s of services) h.services.add(s);
    if (name) this.names.set(name.toLowerCase(), n);
  };
  for (const c of this.intel.c2) add("", c.ip, [`tcp/${c.port}`, "tcp/80", "tcp/443"]);
  // feed domains resolve to the picked C2 addresses, in turn
  this.intel.domains.forEach((d, i) => { const c = this.intel.c2[i % Math.max(1, this.intel.c2.length)]; if (c) this.names.set(d.domain, ipToInt(c.ip)); });
  add("", SINKHOLE_WEB, ["tcp/80", "tcp/443"]);
  for (const u of [...this.intel.urls, ...this.intel.phish]) this.names.set(u.host, ipToInt(SINKHOLE_WEB));
};

// what an address or name is in the lab's feeds, or null
Lab.prototype.feedMatch = function (x) {
  if (!this.intel) return null;
  const s = String(x).toLowerCase();
  const c = this.intel.c2.find((y) => y.ip === s);
  if (c) return { kind: "c2", ...c };
  const d = this.intel.domains.find((y) => y.domain === s);
  if (d) return { kind: "domain", ...d };
  const u = [...this.intel.urls, ...this.intel.phish].find((y) => y.host === s);
  if (u) return { kind: u.threat === "phishing" ? "phishing" : "malware-url", ...u };
  if (s === SINKHOLE_WEB) return { kind: "malware-url", source: "sinkhole" };
  return null;
};

// `config system external-resource` type address: what it holds in the lab
Lab.prototype.externalAddrs = function (fg, name) {
  const e = fg.entry("system external-resource", name);
  if (!e || !this.intel) return null;
  const type = fg.one("system external-resource", e, "type") || "category";
  if (type !== "address") return null;
  if (fg.one("system external-resource", e, "status") === "disable") return [];
  const res = String(fg.one("system external-resource", e, "resource") || "").toLowerCase();
  if (/feodo|threatfox|c2|botnet|ipblocklist/.test(res)) return this.intel.c2.map((c) => ipToInt(c.ip));
  if (/urlhaus|malware|phish/.test(res)) return [ipToInt(SINKHOLE_WEB)];
  return [];
};

export function intelSummary(lab) {
  const i = lab.intel;
  if (!i) return "No lab Internet in this lab.";
  const head = i.standin ? "Threat intel: lab stand-ins (open the OS screen with Internet access so FortiTatake can download today's feeds)." : `Threat intel snapshot ${i.date} (${i.sources.filter((s) => !s.error).map((s) => s.name).join(", ")}).`;
  return [head, "C2 addresses (sinkholed in the lab Internet):", ...i.c2.map((c) => `  ${c.ip.padEnd(16)}${String(c.port).padEnd(6)}${c.family || "?"} · ${c.source}`), "C2 domains:", ...i.domains.map((d) => `  ${d.domain} · ${d.family || "?"} · ${d.source}`), "Malware URLs:", ...i.urls.map((u) => `  ${u.url}`), "Phishing URLs:", ...i.phish.map((u) => `  ${u.url}`)].join("\n");
}
