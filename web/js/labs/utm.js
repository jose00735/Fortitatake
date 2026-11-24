// Security profiles for the lab simulator: SSL inspection, URL filter and antivirus on web requests,
// plus the traffic and UTM logs a FortiGate produces (and forwards to a FortiAnalyzer).
import { Lab } from "./sim.js";
import { ipToInt, intToIp, inPrefix, parsePrefix } from "./net.js";

const SSL = "firewall ssl-ssh-profile";

function wildcard(pat, host) {
  const re = new RegExp("^" + String(pat).toLowerCase().replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".") + "$");
  return re.test(host);
}
function sslMode(lab, fg, name, host, dstIp) {
  const p = fg.entry(SSL, name || "no-inspection");
  if (!p) return "disable";
  const https = p.children.get("https");
  let mode = https ? (https.attrs.get("status") || ["deep-inspection"])[0] : "deep-inspection";
  const ex = p.children.get("ssl-exempt");
  if (mode === "deep-inspection" && ex) {
    for (const e of ex.list()) {
      const t = (e.attrs.get("type") || ["fortiguard-category"])[0];
      if (t === "wildcard-fqdn" && wildcard((e.attrs.get("wildcard-fqdn") || [""])[0], host)) return "exempt";
      if (t === "address") { const n = (e.attrs.get("address") || [""])[0]; if (lab.addrMatch(fg, n, dstIp)) return "exempt"; }
      if (t === "regex" && new RegExp((e.attrs.get("regex") || ["^$"])[0], "i").test(host)) return "exempt";
    }
  }
  return mode;
}

// Inspect a web request that the firewall policy already allowed. Returns {verdict, status, body, reason}.
Lab.prototype.webInspect = function (fromId, res, url) {
  const ev = ((res.fwd && res.fwd.fgt) || []).find((e) => !e.reply && e.policy && e.policy !== "0" && !e.drop);
  if (!ev) return { verdict: "allowed" };
  const fg = this.dev(ev.dev);
  const pol = fg.entry("firewall policy", ev.policy);
  if (!pol || fg.one("firewall policy", pol, "utm-status") !== "enable") return { verdict: "allowed", fg, pol };
  const host = url.host.toLowerCase(), path = url.path || "/", https = url.scheme === "https";
  const dstIp = res.seenDst;
  let mode = https ? sslMode(this, fg, fg.one("firewall policy", pol, "ssl-ssh-profile"), host, dstIp) : "clear";
  const client = this.dev(fromId);
  const cloud = [...this.devices.values()].find((d) => d.kind === "cloud" && d.hosts.some((x) => x.ip === dstIp));
  const ch = cloud && cloud.hosts.find((x) => x.ip === dstIp);
  if (mode === "deep-inspection" && ch && ch.pinned) return { verdict: "cert-error", fg, pol, reason: `${host} pins its certificate, so the FortiGate's re-signed one is rejected` };
  if (mode === "deep-inspection" && client && client.spec && client.spec.trusts_ca === false) {
    return { verdict: "cert-error", fg, pol, reason: "the client doesn't trust the FortiGate CA that re-signs the certificate" };
  }
  const seeHost = mode !== "disable";
  const seePath = mode === "clear" || mode === "deep-inspection";
  const seeBody = seePath;
  const base = { srcip: res.req.src, dstip: dstIp, hostname: host, url: seePath ? path : "/", policyid: pol.key, inIntf: ev.in, outIntf: ev.out };
  let skipAv = false;
  // URL filter
  const wfName = fg.one("firewall policy", pol, "webfilter-profile");
  const wf = wfName && fg.entry("webfilter profile", wfName);
  if (wf && seeHost) {
    const web = wf.children.get("web");
    const tid = web ? (web.attrs.get("urlfilter-table") || ["0"])[0] : "0";
    const tbl = tid !== "0" && fg.entry("webfilter urlfilter", tid);
    const entries = tbl && tbl.children.get("entries");
    for (const e of entries ? entries.list() : []) {
      if ((e.attrs.get("status") || ["enable"])[0] === "disable") continue;
      const pat = String((e.attrs.get("url") || [""])[0]).toLowerCase();
      const type = (e.attrs.get("type") || ["simple"])[0];
      const target = seePath ? host + path : host;
      let hit = false;
      if (type === "wildcard") hit = wildcard(pat, host) || wildcard(pat, target);
      else if (type === "regex") hit = new RegExp(pat, "i").test(target);
      else hit = pat.includes("/") ? seePath && target.startsWith(pat) : host === pat || host.endsWith("." + pat) && false || host === pat;
      if (!hit) continue;
      const action = (e.attrs.get("action") || ["exempt"])[0];
      if (action === "block") {
        this.logUtm(fg, { ...base, subtype: "webfilter", eventtype: "urlfilter", action: "blocked", msg: "URL was blocked because it is in the URL filter list", urlfilteridx: e.key });
        return { verdict: "blocked", by: "webfilter", fg, pol, status: 403, body: `<html><head><title>Web Page Blocked</title></head><body><h1>Web Page Blocked!</h1><p>The page you have requested has been blocked, because the URL is banned.</p><p>URL: ${https ? "https" : "http"}://${host}${seePath ? path : "/"}</p></body></html>` };
      }
      if (action === "monitor") { this.logUtm(fg, { ...base, subtype: "webfilter", eventtype: "urlfilter", action: "passthrough", msg: "URL was monitored", urlfilteridx: e.key }); continue; }
      if (action === "exempt") { skipAv = true; break; }
      if (action === "allow") break;
    }
  }
  // antivirus
  const avName = fg.one("firewall policy", pol, "av-profile");
  const av = avName && fg.entry("antivirus profile", avName);
  const target = this.dev("INTERNET") ? null : null;
  const file = (url.file || "").toLowerCase();
  if (av && seeBody && !skipAv && file) {
    const http = av.children.get("http");
    const scan = http ? (http.attrs.get("av-scan") || ["disable"])[0] : "disable";
    if (scan !== "disable" && file === "eicar") {
      const fname = path.split("/").pop() || "file";
      this.logUtm(fg, { ...base, subtype: "virus", eventtype: "infected", action: scan === "block" ? "blocked" : "monitored", virus: "EICAR_TEST_FILE", filename: fname, msg: "File is infected." });
      if (scan === "block") return { verdict: "blocked", by: "av", fg, pol, status: 403, body: `<html><head><title>High Security Alert</title></head><body><h1>High Security Alert</h1><p>You are not permitted to download the file "${fname}" because it is infected with the virus "EICAR_TEST_FILE".</p><p>URL: ${https ? "https" : "http"}://${host}${path}</p></body></html>` };
    }
  }
  return { verdict: "allowed", fg, pol, mode };
};

// ----- logs -----
let logSeq = 1000;
function stamp(lab) { const d = new Date(lab.clock - 5 * 3600000); return { date: d.toISOString().slice(0, 10), time: d.toISOString().slice(11, 19) }; }
Lab.prototype.logTraffic = function (fg, pol, p) {
  const lt = pol ? fg.one("firewall policy", pol, "logtraffic") : null;
  if (p.action === "accept" && lt !== "all") return;
  if (p.action === "deny") {
    if (pol && lt === "disable") return;
    if (!pol && fg.one("log setting", fg.obj("log setting"), "fwpolicy-implicit-log") !== "enable") return;
  }
  const svc = p.proto === 1 ? "PING" : p.proto === 6 ? ({ 80: "HTTP", 443: "HTTPS", 22: "SSH", 3389: "RDP", 445: "SMB", 1433: "MS-SQL", 53: "DNS" }[p.dport] || `tcp/${p.dport}`) : p.proto === 17 ? ({ 53: "DNS", 123: "NTP", 5060: "SIP", 500: "IKE" }[p.dport] || `udp/${p.dport}`) : `proto/${p.proto}`;
  const rec = { ...stamp(this), logid: p.action === "deny" ? "0000000013" : "0000000013", type: "traffic", subtype: "forward", level: p.action === "deny" ? "warning" : "notice", devname: fg.hostname(), devid: fg.serial, vd: "root",
    srcip: intToIp(p.src), srcport: p.sport || 0, srcintf: p.inIntf, dstip: intToIp(p.dnat !== undefined ? p.dnat : p.dst), dstport: p.dport || 0, dstintf: p.outIntf, proto: p.proto, action: p.action, policyid: Number(p.policyid) || 0, service: svc,
    ...(p.transip !== undefined ? { transip: intToIp(p.transip) } : {}), sentbyte: p.action === "accept" ? 1204 : 0, rcvdbyte: p.action === "accept" ? 5320 : 0, seq: ++logSeq };
  this.storeLog(fg, rec);
};
Lab.prototype.logUtm = function (fg, p) {
  const rec = { ...stamp(this), logid: p.subtype === "virus" ? "0211008192" : "0316013056", type: "utm", subtype: p.subtype, eventtype: p.eventtype, level: "warning", devname: fg.hostname(), devid: fg.serial, vd: "root", policyid: Number(p.policyid), srcip: intToIp(p.srcip), dstip: intToIp(p.dstip), srcintf: p.inIntf, dstintf: p.outIntf, hostname: p.hostname, url: p.url, action: p.action, msg: p.msg, ...(p.virus ? { virus: p.virus, filename: p.filename } : {}), seq: ++logSeq };
  this.storeLog(fg, rec);
};
Lab.prototype.storeLog = function (fg, rec) {
  fg.logs = fg.logs || [];
  fg.logs.push(rec);
  if (fg.logs.length > 2000) fg.logs.shift();
  this.forwardLog && this.forwardLog(fg, rec);
};
export function fmtLog(r) {
  return Object.entries(r).filter(([k]) => k !== "seq").map(([k, v]) => (typeof v === "number" ? `${k}=${v}` : `${k}="${v}"`)).join(" ").replace(/^date="([^"]+)" time="([^"]+)"/, "date=$1 time=$2");
}
