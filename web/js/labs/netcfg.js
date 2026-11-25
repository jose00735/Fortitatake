// Network configuration on lab PCs, servers and ISP routers: static addressing, gateway, DNS,
// the files that hold them (resolv.conf, hosts, netplan) and an IOS-style configuration mode.
// Changes go into the simulator's device objects and bump lab.ver, so the real network
// (FortiTatake OS) is rebuilt from them on the next live tick.
import { ipToInt, intToIp, maskToLen, maskStr, parsePrefix, inPrefix } from "./net.js";

// ---------- helpers ----------
// split a command line, keeping "quoted strings" together and stripping the quotes
export function words(line) {
  const out = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m;
  while ((m = re.exec(line))) out.push((m[1] ?? m[2] ?? m[3]).replace(/^([\w-]+[=:])["'](.*)["']$/, "$1$2"));
  return out;
}
const isIp = (s) => typeof s === "string" && /^\d+\.\d+\.\d+\.\d+$/.test(s) && ipToInt(s) !== null;
const isMask = (s) => isIp(s) && maskToLen(ipToInt(s)) !== null && maskToLen(ipToInt(s)) !== undefined && maskToLen(ipToInt(s)) >= 0;
const cidr = (s) => { const m = String(s || "").match(/^(\d+\.\d+\.\d+\.\d+)\/(\d{1,2})$/); return m && isIp(m[1]) && +m[2] <= 32 ? { ip: ipToInt(m[1]), len: +m[2] } : null; };

function changed(lab) {
  if (lab.dirty) lab.dirty(); else lab.ver = (lab.ver || 0) + 1;
}

// Set a host's addressing. cfg: { dhcp } or { ip, len, gw (string|null), dns (string[]) }; fields left undefined keep their value.
export function setHost(lab, h, cfg) {
  if (cfg.dhcp === true) {
    h.dhcp = true; h.static = null; h.lease = null;
    if (cfg.dns !== undefined) h.dnsOverride = cfg.dns.length ? cfg.dns : null; else h.dnsOverride = null;
    lab.renew(h);
  } else {
    if (cfg.ip !== undefined) {
      h.dhcp = false; h.lease = null;
      h.static = cfg.ip === null ? null : { ip: cfg.ip, len: cfg.len };
    }
    if (cfg.gw !== undefined) h.gw = cfg.gw;
    if (cfg.dns !== undefined) { h.dns = cfg.dns; h.dnsOverride = null; }
  }
  changed(lab);
}

// ---------- files ----------
const WIN_HOSTS = "c:\\windows\\system32\\drivers\\etc\\hosts";
const NETPLAN = "/etc/netplan/50-cloud-init.yaml";
const normPath = (h, p) => (h.os === "windows" ? String(p).replace(/\//g, "\\").toLowerCase() : String(p));

function hostsBody(h) {
  return [...(h.hostsMap || new Map()).entries()].map(([n, ip]) => `${intToIp(ip)}\t${n}`).join("\n");
}
// the current text of a config file, generated from the device's state unless the user saved their own
export function readFile(h, path) {
  const p = normPath(h, path);
  h.fs = h.fs || {};
  if (h.fs[p] !== undefined) return h.fs[p];
  const a = h.addr ? h.addr() : null;
  if (h.os === "windows") {
    if (p === WIN_HOSTS) return "# Copyright (c) 1993-2009 Microsoft Corp.\r\n#\r\n# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\r\n#\r\n# localhost name resolution is handled within DNS itself.\r\n#\t127.0.0.1       localhost\r\n#\t::1             localhost\r\n".replace(/\r/g, "") + (h.hostsMap && h.hostsMap.size ? hostsBody(h) + "\n" : "");
    return null;
  }
  if (p === "/etc/resolv.conf") {
    const ns = h.dnsServers ? h.dnsServers() : [];
    return `# This is /run/systemd/resolve/resolv.conf managed by man:systemd-resolved(8).\n# Edits here take effect at once in this lab; netplan is the lasting place for DNS.\n\n${ns.map((s) => `nameserver ${intToIp(s)}`).join("\n") || "# no DNS servers known"}\noptions edns0 trust-ad\nsearch lab.local\n`;
  }
  if (p === "/etc/hosts") return `127.0.0.1 localhost\n127.0.1.1 ${h.hostname.toLowerCase()}\n\n# The following lines are desirable for IPv6 capable hosts\n::1     ip6-localhost ip6-loopback\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters\n${h.hostsMap && h.hostsMap.size ? "\n" + hostsBody(h) + "\n" : ""}`;
  if (p === "/etc/hostname") return h.hostname.toLowerCase() + "\n";
  if (p === NETPLAN) {
    if (h.dhcp) return `# This file is generated from information provided by the datasource.\nnetwork:\n  version: 2\n  ethernets:\n    eth0:\n      dhcp4: true\n`;
    const dns = (h.dns || []).length ? `      nameservers:\n        addresses: [${h.dns.join(", ")}]\n` : "";
    return `# This file is generated from information provided by the datasource.\nnetwork:\n  version: 2\n  ethernets:\n    eth0:\n      dhcp4: false\n      addresses:\n        - ${a ? `${intToIp(a.ip)}/${a.len}` : "192.0.2.10/24"}\n${h.gw ? `      routes:\n        - to: default\n          via: ${h.gw}\n` : ""}${dns}`;
  }
  return null;
}
export const FILES = { linux: ["/etc/hosts", "/etc/hostname", "/etc/resolv.conf", NETPLAN], windows: [WIN_HOSTS] };
const canWrite = (h, p) => (h.os === "windows" ? normPath(h, p) === WIN_HOSTS : FILES.linux.includes(p) || p.startsWith("/home/") || p.startsWith("/tmp/") || p.startsWith("~/") || !p.includes("/"));

function parseHosts(text) {
  const m = new Map();
  for (const raw of String(text).split("\n")) {
    const l = raw.replace(/#.*/, "").trim();
    if (!l) continue;
    const [ip, ...names] = l.split(/\s+/);
    if (!isIp(ip) || ip.startsWith("127.") ) continue;
    for (const n of names) m.set(n.toLowerCase(), ipToInt(ip));
  }
  return m;
}

// Minimal netplan reader: the first ethernet's dhcp4, IPv4 addresses, default route and nameservers.
export function parseNetplan(text) {
  const res = { dhcp: false, addrs: [], gw: null, dns: [], errors: [] };
  let nsIndent = -1, routeVia = null, routeDefault = false;
  const lines = String(text).replace(/\t/g, "  ").split("\n");
  if (/\t/.test(text)) res.errors.push("tabs are not allowed in YAML; use spaces");
  for (const raw of lines) {
    const line = raw.replace(/#.*/, "");
    if (!line.trim()) continue;
    const ind = line.length - line.trimStart().length;
    const t = line.trim();
    if (nsIndent >= 0 && ind <= nsIndent) nsIndent = -1;
    if (/^nameservers:/.test(t)) { nsIndent = ind; continue; }
    let m;
    if ((m = t.match(/^dhcp4:\s*(\S+)/))) res.dhcp = /^(true|yes|on)$/i.test(m[1]);
    if ((m = t.match(/^gateway4:\s*(\S+)/))) res.gw = m[1];
    const inline = t.match(/^addresses:\s*\[([^\]]*)\]/);
    const item = t.match(/^-\s*"?([\d./]+)"?\s*$/);
    const vals = inline ? inline[1].split(",").map((x) => x.trim().replace(/["']/g, "")).filter(Boolean) : item ? [item[1]] : [];
    for (const v of vals) {
      if (nsIndent >= 0) { if (isIp(v)) res.dns.push(v); else res.errors.push(`nameserver "${v}" is not an IPv4 address`); }
      else if (cidr(v)) res.addrs.push(cidr(v));
      else if (/\d/.test(v)) res.errors.push(`address "${v}" needs a prefix length, like ${v}/24`);
    }
    if ((m = t.match(/^-?\s*to:\s*(\S+)/))) routeDefault = /^(default|0\.0\.0\.0\/0)$/.test(m[1]);
    if ((m = t.match(/^via:\s*(\S+)/)) && routeDefault) { routeVia = m[1]; routeDefault = false; }
  }
  if (routeVia) res.gw = routeVia;
  if (res.gw && !isIp(res.gw)) { res.errors.push(`gateway "${res.gw}" is not an IPv4 address`); res.gw = null; }
  if (!/^\s*network:/m.test(text)) res.errors.push("missing the top-level network: key");
  return res;
}

// Save a file from the editor (or a shell redirect). Returns a message for the console, or "".
export function writeFile(lab, h, path, text) {
  const p = normPath(h, path);
  h.fs = h.fs || {};
  h.fs[p] = text;
  if (p === WIN_HOSTS || p === "/etc/hosts") { h.hostsMap = parseHosts(text); changed(lab); return ""; }
  if (p === "/etc/resolv.conf") {
    const ns = [...String(text).matchAll(/^\s*nameserver\s+(\S+)/gm)].map((m) => m[1]).filter(isIp);
    h.dnsOverride = ns.length ? ns : null;
    changed(lab);
    return "";
  }
  if (p === "/etc/hostname") { const n = String(text).trim().split(/\s+/)[0]; if (n) h.hostname = n; return ""; }
  return "";
}

// /etc/hosts and the Windows hosts file come before DNS for ping, curl and friends (not for nslookup)
export function hostsEntry(h, name) {
  if (!h || !h.hostsMap || !name) return null;
  const v = h.hostsMap.get(String(name).toLowerCase());
  return v === undefined ? null : v;
}

// ---------- Windows ----------
const IFNAMES = ["ethernet0", "ethernet", "ethernet 0"];
const ifOk = (n) => IFNAMES.includes(String(n || "").toLowerCase());
// netsh takes "name=value" or positional values
function kv(args, keys) {
  const o = {}; const pos = [];
  for (const a of args) { const m = a.match(/^([a-z]+)=(.*)$/i); if (m) o[m[1].toLowerCase()] = m[2]; else pos.push(a); }
  let i = 0;
  for (const k of keys) if (o[k] === undefined && i < pos.length) o[k] = pos[i++];
  return o;
}
const NETSH_IF_ERR = "The filename, directory name, or volume label syntax is incorrect.\n(This lab PC has one adapter: \"Ethernet0\".)";

function winShowConfig(h) {
  const a = h.addr();
  const gw = h.gateway();
  const dns = h.dnsServers();
  return `\nConfiguration for interface "Ethernet0"\n    DHCP enabled:                         ${h.dhcp ? "Yes" : "No"}\n    IP Address:                           ${a ? intToIp(a.ip) : "0.0.0.0"}\n    Subnet Prefix:                        ${a ? `${intToIp(a.ip & (a.len ? (0xffffffff << (32 - a.len)) >>> 0 : 0))}/${a.len} (mask ${maskStr(a.len)})` : "-"}\n    Default Gateway:                      ${gw ? intToIp(gw) : ""}\n    Gateway Metric:                       0\n    InterfaceMetric:                      25\n    ${h.dhcp && !h.dnsOverride ? "DNS servers configured through DHCP" : "Statically Configured DNS Servers"}:  ${dns.map(intToIp).join("\n                                          ") || "None"}\n    Register with which suffix:           Primary only\n`;
}

function netsh(lab, h, args) {
  const a = args.map((x) => x.toLowerCase());
  // netsh interface ip|ipv4 <verb> <what> ...
  if (!["interface", "int", "i"].includes(a[0])) return `The following command was not found: ${args.join(" ")}.`;
  if (["set", "s"].includes(a[1]) && ["interface", "int"].includes(a[2])) {
    const o = kv(args.slice(3), ["name", "admin"]);
    if (!ifOk(o.name)) return NETSH_IF_ERR;
    const st = String(o.admin || o.adminstate || "").toLowerCase();
    if (!/^(enabled?|disabled?)$/.test(st)) return "Usage: netsh interface set interface name=\"Ethernet0\" admin=enable|disable";
    h.down = /^disabled?$/.test(st);
    changed(lab);
    return "";
  }
  if (!["ip", "ipv4"].includes(a[1])) return `The following command was not found: ${args.join(" ")}.`;
  const verb = a[2], what = a[3] || "";
  if (verb === "show") {
    if (/^(config|addresses|address|dnsservers|dns)$/.test(what)) return winShowConfig(h);
    return "Usage: netsh interface ip show config";
  }
  if (verb === "set" && /^address/.test(what)) {
    const o = kv(args.slice(4), ["name", "source", "address", "mask", "gateway", "gwmetric"]);
    if (!ifOk(o.name)) return NETSH_IF_ERR;
    let src = String(o.source || "").toLowerCase();
    if (isIp(o.source)) { o.gateway = o.mask; o.mask = o.address; o.address = o.source; src = "static"; }
    if (src === "dhcp") { setHost(lab, h, { dhcp: true }); return ""; }
    if (src !== "static") return "Usage: netsh interface ip set address name=\"Ethernet0\" static <address> <mask> [<gateway>]\n       netsh interface ip set address name=\"Ethernet0\" dhcp";
    const p = cidr(o.address) || (isIp(o.address) && isMask(o.mask) ? { ip: ipToInt(o.address), len: maskToLen(ipToInt(o.mask)) } : null);
    if (!p) return "The parameter is incorrect.\n(Expected: static <address> <mask> [<gateway>], for example static 10.10.10.50 255.255.255.0 10.10.10.1)";
    const gw = o.gateway && String(o.gateway).toLowerCase() !== "none" ? o.gateway : null;
    if (gw && !isIp(gw)) return "The parameter is incorrect.";
    const warn = gw && !inPrefix(ipToInt(gw), p) ? "\nWarning: the default gateway is not on the same network segment (subnet) defined by the IP address and subnet mask." : "";
    setHost(lab, h, { ip: p.ip, len: p.len, gw: gw || null, dns: h.dhcp ? [] : undefined });
    return warn.trim();
  }
  if ((verb === "set" || verb === "add" || verb === "delete" || verb === "del") && /^dns/.test(what)) {
    const o = kv(args.slice(4), verb === "set" ? ["name", "source", "address", "register"] : ["name", "address", "index"]);
    if (!ifOk(o.name)) return NETSH_IF_ERR;
    if (verb === "set") {
      let src = String(o.source || "").toLowerCase();
      if (isIp(o.source)) { o.address = o.source; src = "static"; }
      if (src === "dhcp") { h.dnsOverride = null; if (!h.dhcp) h.dns = []; changed(lab); return ""; }
      if (src !== "static" || !(isIp(o.address) || String(o.address).toLowerCase() === "none")) return "Usage: netsh interface ip set dns name=\"Ethernet0\" static <address>|none\n       netsh interface ip set dns name=\"Ethernet0\" dhcp";
      const list = String(o.address).toLowerCase() === "none" ? [] : [o.address];
      if (h.dhcp) { h.dnsOverride = list.length ? list : null; changed(lab); } else setHost(lab, h, { dns: list });
      return "";
    }
    const cur = h.dnsOverride || (h.dhcp ? (h.lease ? h.lease.dns.map(intToIp) : []) : [...(h.dns || [])]);
    if (verb === "add") {
      if (!isIp(o.address)) return "The parameter is incorrect.";
      if (cur.includes(o.address)) return "The object already exists.";
      const idx = Math.max(1, Math.min(cur.length + 1, Number(o.index) || cur.length + 1));
      cur.splice(idx - 1, 0, o.address);
    } else {
      const addr = String(o.address || "").toLowerCase();
      if (addr === "all") cur.length = 0;
      else { const i = cur.indexOf(o.address); if (i < 0) return "Element not found."; cur.splice(i, 1); }
    }
    if (h.dhcp) h.dnsOverride = cur; else h.dns = cur;
    changed(lab);
    return "";
  }
  return "Commands this lab PC knows:\n  netsh interface ip show config\n  netsh interface ip set address name=\"Ethernet0\" static <ip> <mask> [<gateway>] | dhcp\n  netsh interface ip set dns name=\"Ethernet0\" static <ip> | dhcp\n  netsh interface ip add dns name=\"Ethernet0\" <ip> index=2\n  netsh interface ip delete dns name=\"Ethernet0\" all|<ip>\n  netsh interface set interface name=\"Ethernet0\" admin=enable|disable";
}

// PowerShell networking cmdlets (typed at the prompt or after "powershell -c")
function psArgs(args) {
  const o = {};
  for (let i = 0; i < args.length; i++) {
    const m = args[i].match(/^-([a-z]+)(?::(.*))?$/i);
    if (!m) continue;
    if (m[2] !== undefined) { o[m[1].toLowerCase()] = m[2]; continue; }
    const v = [];
    while (i + 1 < args.length && !/^-[a-z]/i.test(args[i + 1])) v.push(args[++i]);
    o[m[1].toLowerCase()] = v.length ? v.join(" ") : true;
  }
  return o;
}
const psList = (s) => String(s || "").replace(/[()@"']/g, " ").split(/[\s,]+/).filter(Boolean);
const PS_IF_ERR = (n) => `Get-NetAdapter : No MSFT_NetAdapter objects found with property 'Name' equal to '${n}'.\n(This lab PC has one adapter: Ethernet0.)`;

function powershell(lab, h, cmd, args) {
  const o = psArgs(args);
  const alias = o.interfacealias || o.name || o.alias;
  const needIf = () => (alias === undefined || ifOk(alias) ? null : PS_IF_ERR(alias));
  switch (cmd) {
    case "get-netipconfiguration": case "gip": {
      const a = h.addr(), gw = h.gateway();
      return `\nInterfaceAlias       : Ethernet0\nInterfaceIndex       : 5\nInterfaceDescription : Intel(R) 82574L Gigabit Network Connection\nIPv4Address          : ${a ? intToIp(a.ip) : ""}\nIPv4DefaultGateway   : ${gw ? intToIp(gw) : ""}\nDNSServer            : ${h.dnsServers().map(intToIp).join("\n                       ")}\n`;
    }
    case "get-netipaddress": {
      const a = h.addr();
      return a ? `\nIPAddress         : ${intToIp(a.ip)}\nInterfaceIndex    : 5\nInterfaceAlias    : Ethernet0\nAddressFamily     : IPv4\nType              : Unicast\nPrefixLength      : ${a.len}\nPrefixOrigin      : ${h.dhcp ? "Dhcp" : "Manual"}\nAddressState      : Preferred\n` : "";
    }
    case "new-netipaddress": {
      const e = needIf(); if (e) return e;
      const ip = o.ipaddress, len = Number(o.prefixlength);
      if (!isIp(ip) || !(len >= 0 && len <= 32)) return "New-NetIPAddress : Invalid parameter IPAddress or PrefixLength.\n(Example: New-NetIPAddress -InterfaceAlias Ethernet0 -IPAddress 10.10.10.50 -PrefixLength 24 -DefaultGateway 10.10.10.1)";
      if (!h.dhcp && h.static) return "New-NetIPAddress : Instance MSFT_NetIPAddress already exists\n(Remove the current address first: Remove-NetIPAddress -InterfaceAlias Ethernet0 -Confirm:$false)";
      const gw = typeof o.defaultgateway === "string" ? o.defaultgateway : null;
      if (gw && !isIp(gw)) return "New-NetIPAddress : Invalid parameter DefaultGateway.";
      if (gw && h.gw && !h.dhcp) return "New-NetIPAddress : Instance DefaultGateway already exists";
      setHost(lab, h, { ip: ipToInt(ip), len, gw: gw || (h.dhcp ? null : h.gw), dns: h.dhcp ? [] : undefined });
      return `\nIPAddress         : ${ip}\nInterfaceIndex    : 5\nInterfaceAlias    : Ethernet0\nAddressFamily     : IPv4\nType              : Unicast\nPrefixLength      : ${len}\nPrefixOrigin      : Manual\nAddressState      : Tentative\n`;
    }
    case "remove-netipaddress": {
      const e = needIf(); if (e) return e;
      setHost(lab, h, { ip: null, gw: h.gw });
      return "";
    }
    case "set-netipinterface": {
      const e = needIf(); if (e) return e;
      const d = String(o.dhcp || "").toLowerCase();
      if (d === "enabled") { setHost(lab, h, { dhcp: true }); return ""; }
      if (d === "disabled") { if (h.dhcp) setHost(lab, h, { ip: null, gw: null, dns: [] }); return ""; }
      return "Set-NetIPInterface : use -Dhcp Enabled or -Dhcp Disabled";
    }
    case "set-dnsclientserveraddress": {
      const e = needIf(); if (e) return e;
      if (o.resetserveraddresses) { h.dnsOverride = null; if (!h.dhcp) h.dns = []; changed(lab); return ""; }
      const list = psList(o.serveraddresses);
      if (!list.length || !list.every(isIp)) return "Set-DnsClientServerAddress : Invalid parameter ServerAddresses.\n(Example: Set-DnsClientServerAddress -InterfaceAlias Ethernet0 -ServerAddresses (\"10.10.10.1\",\"1.1.1.1\"))";
      if (h.dhcp) { h.dnsOverride = list; changed(lab); } else setHost(lab, h, { dns: list });
      return "";
    }
    case "get-dnsclientserveraddress":
      return `\nInterfaceAlias               Interface Address ServerAddresses\n                             Index     Family\n--------------               --------- ------- ---------------\nEthernet0                            5 IPv4    {${h.dnsServers().map(intToIp).join(", ")}}\n`;
    case "new-netroute": case "remove-netroute": {
      const dst = o.destinationprefix;
      if (dst && !/^0\.0\.0\.0\/0$/.test(dst)) return "This lab PC keeps a default route only (-DestinationPrefix 0.0.0.0/0).";
      if (cmd === "remove-netroute") { setHost(lab, h, { gw: null }); return ""; }
      if (!isIp(o.nexthop)) return "New-NetRoute : Invalid parameter NextHop.";
      setHost(lab, h, { gw: o.nexthop });
      return "";
    }
    case "disable-netadapter": case "enable-netadapter": {
      const e = needIf(); if (e) return e;
      h.down = cmd === "disable-netadapter"; changed(lab); return "";
    }
    case "clear-dnsclientcache": return "";
    default: return null;
  }
}

// ---------- Linux ----------
const EPERM = "RTNETLINK answers: Operation not permitted";

function linuxIp(lab, h, args, root) {
  const [obj, verb, ...rest] = args;
  const o = (obj || "").toLowerCase();
  const isA = o && "address".startsWith(o), isR = o && "route".startsWith(o) && o !== "r" ? true : o === "r" || o === "ro", isL = o && "link".startsWith(o);
  const v = (verb || "").toLowerCase();
  const devOk = (r) => { const i = r.indexOf("dev"); return i < 0 || r[i + 1] === (h.port || "eth0"); };
  if (isA && ["add", "del", "delete", "flush", "replace", "change"].includes(v)) {
    if (!root) return EPERM;
    if (!devOk(rest)) return `Cannot find device "${rest[rest.indexOf("dev") + 1]}"`;
    if (v === "flush") { setHost(lab, h, { ip: null, gw: null }); return ""; }
    const p = cidr(rest[0]);
    if (!p) return `Error: any valid prefix is expected rather than "${rest[0] || ""}".`;
    if (v === "del" || v === "delete") {
      const a = h.addr();
      if (!a || a.ip !== p.ip) return "RTNETLINK answers: Cannot assign requested address";
      setHost(lab, h, { ip: null, gw: null });
      return "";
    }
    const a = h.addr();
    if (v === "add" && a && a.ip === p.ip) return "RTNETLINK answers: File exists";
    setHost(lab, h, { ip: p.ip, len: p.len, gw: h.dhcp ? null : h.gw, dns: h.dhcp ? (h.lease ? h.lease.dns.map(intToIp) : []) : undefined });
    return a && v === "add" ? `(FortiTatake: lab hosts keep one IPv4 address, so ${intToIp(a.ip)}/${a.len} was replaced)` : "";
  }
  if (isR && ["add", "del", "delete", "replace", "change", "append"].includes(v)) {
    if (!root) return EPERM;
    const dst = (rest[0] || "").toLowerCase();
    if (dst !== "default" && dst !== "0.0.0.0/0") return "FortiTatake: lab hosts keep a default route only (ip route add default via <gateway>).";
    if (v === "del" || v === "delete") { if (!h.gateway()) return "RTNETLINK answers: No such process"; setHost(lab, h, { gw: null }); return ""; }
    const i = rest.indexOf("via"); const gw = i >= 0 ? rest[i + 1] : null;
    if (!isIp(gw)) return "Error: inet address is expected rather than \"" + (gw || "") + "\".";
    if (!h.addr()) return "Error: Nexthop has invalid gateway.";
    if (!inPrefix(ipToInt(gw), h.addr())) return "Error: Nexthop has invalid gateway.";
    if (v === "add" && h.gateway()) return "RTNETLINK answers: File exists";
    if (h.dhcp) { const a = h.addr(); setHost(lab, h, { ip: a.ip, len: a.len, gw, dns: h.lease ? h.lease.dns.map(intToIp) : [] }); }
    else setHost(lab, h, { gw });
    return "";
  }
  if (isL && v === "set") {
    if (!root) return EPERM;
    const dev = rest[0] === "dev" ? rest[1] : rest[0];
    if (dev !== (h.port || "eth0")) return `Cannot find device "${dev}"`;
    if (rest.includes("down")) { h.down = true; changed(lab); return ""; }
    if (rest.includes("up")) { h.down = false; changed(lab); return ""; }
    return "Usage: ip link set eth0 up|down";
  }
  return null;
}

function netplanCmd(lab, h, args, root) {
  const v = (args[0] || "").toLowerCase();
  if (v === "get") { const c = parseNetplan(readFile(h, NETPLAN)); return `network:\n  ethernets:\n    eth0:\n      dhcp4: ${c.dhcp}\n${c.addrs.length ? `      addresses:\n${c.addrs.map((x) => `      - "${intToIp(x.ip)}/${x.len}"`).join("\n")}\n` : ""}${c.gw ? `      routes:\n      - to: "default"\n        via: "${c.gw}"\n` : ""}${c.dns.length ? `      nameservers:\n        addresses:\n${c.dns.map((x) => `        - ${x}`).join("\n")}\n` : ""}  version: 2`; }
  if (v !== "apply" && v !== "try" && v !== "generate") return "usage: netplan [-h] [--debug] {help,apply,generate,get,info,set,status,try}";
  if (!root) return "Permission denied (you need to be root): use sudo netplan " + v;
  const c = parseNetplan(readFile(h, NETPLAN));
  if (c.errors.length) return `${NETPLAN}: ${c.errors[0]}\n(nothing was applied)`;
  if (v === "generate") return "";
  if (c.dhcp) setHost(lab, h, { dhcp: true, dns: c.dns });
  else {
    if (!c.addrs.length) return `${NETPLAN}: eth0 has no addresses and dhcp4 is off\n(nothing was applied)`;
    const p = c.addrs[0];
    if (c.gw && !inPrefix(ipToInt(c.gw), p)) return `${NETPLAN}: eth0: gateway ${c.gw} is not inside ${intToIp(p.ip)}/${p.len}\n(nothing was applied)`;
    setHost(lab, h, { ip: p.ip, len: p.len, gw: c.gw, dns: c.dns });
  }
  return v === "try" ? "Do you want to keep these settings?\n\nPress ENTER before the timeout to accept the new configuration\n\nConfiguration accepted." : "";
}

// ---------- entry point for hosts and servers ----------
// Returns console text, "" for silent success, or null when the line isn't a configuration command.
// An editor request comes back as lab.pendingEdit = { dev, path, text, readOnly, app }.
export function hostConfig(lab, h, line) {
  const win = h.os === "windows";
  // the editor saves through this internal line, so saves replay with the lab's command log
  if (line.startsWith("\u0001write ")) { const nl = line.indexOf("\n"); const path = line.slice(7, nl < 0 ? undefined : nl); return writeFile(lab, h, path, nl < 0 ? "" : line.slice(nl + 1)) || ""; }
  let w = words(line.trim());
  if (!w.length) return null;
  let root = false;
  if (!win && w[0] === "sudo") { root = true; w = w.slice(1); if (w[0] === "-i" || w[0] === "su") return "FortiTatake: use sudo in front of each command here."; }
  if (!w.length) return "usage: sudo command";
  const c = w[0].toLowerCase();
  if (win) {
    if (c === "netsh") return netsh(lab, h, w.slice(1));
    if (c === "powershell" || c === "pwsh") {
      const i = w.findIndex((x) => /^-(c|command)$/i.test(x));
      const rest = i >= 0 ? w.slice(i + 1) : w.slice(1);
      if (!rest.length) return "Windows PowerShell\nCopyright (C) Microsoft Corporation. All rights reserved.\n\n(FortiTatake: run one cmdlet at a time, e.g. powershell -c Get-NetIPConfiguration)";
      return powershell(lab, h, rest[0].toLowerCase(), rest.slice(1)) ?? `The term '${rest[0]}' is not recognized as the name of a cmdlet, function, script file, or operable program.`;
    }
    if (/^[a-z]+-[a-z]+$/i.test(w[0])) { const r = powershell(lab, h, c, w.slice(1)); if (r !== null) return r; }
    if (c === "route" && /^(add|delete|change)$/i.test(w[1] || "")) {
      const v = w[1].toLowerCase(), dst = w[2];
      if (dst !== "0.0.0.0") return "FortiTatake: this lab PC keeps a default route only (route add 0.0.0.0 mask 0.0.0.0 <gateway>).";
      if (v === "delete") { setHost(lab, h, { gw: null }); return " OK!"; }
      const gw = w[3] && w[3].toLowerCase() === "mask" ? w[5] : w[3];
      if (!isIp(gw)) return "Route: bad gateway address " + (gw || "");
      if (v === "add" && h.gateway()) return "The route addition failed: The object already exists.";
      setHost(lab, h, { gw });
      return " OK!";
    }
    if (c === "ipconfig" && /^\/flushdns$/i.test(w[1] || "")) return "\nWindows IP Configuration\n\nSuccessfully flushed the DNS Resolver Cache.";
    if (c === "type" || c === "more") {
      const t = readFile(h, w[1] || "");
      return t === null ? "The system cannot find the file specified." : t;
    }
    if (c === "notepad" || c === "notepad.exe" || c === "edit") {
      const path = w[1] || WIN_HOSTS;
      const t = readFile(h, path);
      if (t === null) return `Notepad: this lab PC can edit ${WIN_HOSTS} (the hosts file).`;
      lab.pendingEdit = { dev: h.id, path: normPath(h, path) === WIN_HOSTS ? "C:\\Windows\\System32\\drivers\\etc\\hosts" : path, text: t, readOnly: false, app: "notepad" };
      return "";
    }
    return null;
  }
  // Linux
  if (c === "ip") return linuxIp(lab, h, w.slice(1), root);
  if (c === "netplan") return netplanCmd(lab, h, w.slice(1), root);
  if (c === "dhclient") {
    if (!root) return "dhclient: Permission denied (use sudo)";
    if (w.includes("-r")) { h.lease = null; changed(lab); return ""; }
    if (!h.dhcp) { setHost(lab, h, { dhcp: true }); return h.lease ? "" : "No DHCPOFFERS received."; }
    const ok = lab.renew(h); changed(lab); return ok ? "" : "No DHCPOFFERS received.";
  }
  if (c === "resolvectl" || (c === "systemd-resolve" && w[1] === "--status")) {
    const ns = h.dnsServers().map(intToIp);
    return `Global\n       Protocols: -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported\nresolv.conf mode: stub\n\nLink 2 (eth0)\n    Current Scopes: DNS\n         Protocols: +DefaultRoute -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported\nCurrent DNS Server: ${ns[0] || ""}\n       DNS Servers: ${ns.join(" ")}\n        DNS Domain: lab.local`;
  }
  if (c === "hostnamectl") {
    if (w[1] === "set-hostname" && w[2]) { if (!root) return "Could not set static hostname: Access denied"; h.hostname = w[2]; return ""; }
    return ` Static hostname: ${h.hostname.toLowerCase()}\n       Icon name: computer-vm\n         Chassis: vm\nOperating System: Ubuntu 24.04.1 LTS\n          Kernel: Linux 6.8.0-48-generic\n    Architecture: x86-64`;
  }
  if (c === "cat" || c === "less" || c === "more" || c === "head") {
    const path = w.slice(1).find((x) => !x.startsWith("-"));
    if (!path) return null;
    const t = readFile(h, path);
    return t === null ? `${c}: ${path}: No such file or directory` : t.replace(/\n$/, "");
  }
  if (c === "ls") {
    const path = (w.slice(1).find((x) => !x.startsWith("-")) || "").replace(/\/$/, "");
    if (path === "/etc/netplan") return "50-cloud-init.yaml";
    if (path === "/etc") return "hostname  hosts  netplan  resolv.conf  ssh  systemd";
    return null;
  }
  if (["nano", "vi", "vim", "vim.tiny", "pico", "editor", "nvim"].includes(c)) {
    const path = w.slice(1).find((x) => !x.startsWith("-") && !x.startsWith("+"));
    if (!path) return `${c}: FortiTatake opens files by name here, e.g. ${c} /etc/netplan/50-cloud-init.yaml`;
    let t = readFile(h, path);
    const known = t !== null || canWrite(h, path);
    if (!known) return `${c}: ${path}: this lab host has no such file`;
    if (t === null) t = "";
    const sys = path.startsWith("/etc/");
    lab.pendingEdit = { dev: h.id, path, text: t, readOnly: sys && !root, app: "nano", note: c !== "nano" && c !== "pico" && c !== "editor" ? `(${c} opens FortiTatake's nano-style editor)` : "" };
    return "";
  }
  return null;
}

// ---------- IOS-style configuration mode on ISP routers ----------
export function routerPrompt(r) {
  const n = r.hostname || r.id;
  const m = r.mode || "user";
  return m === "user" ? `${n}>` : m === "priv" ? `${n}#` : m === "config" ? `${n}(config)#` : `${n}(config-if)#`;
}
const findIf = (r, name) => {
  const n = String(name || "").toLowerCase().replace(/\s+/g, "");
  return r.ifaces.find((i) => i.name.toLowerCase() === n) || r.ifaces.find((i) => n && i.name.toLowerCase().startsWith(n)) || null;
};
const ab = (word, full, min = 2) => word && word.length >= Math.min(min, full.length) && full.startsWith(word);

export function routerConfig(lab, r, line) {
  const raw = line.trim();
  const t = raw.toLowerCase().split(/\s+/).filter(Boolean);
  r.mode = r.mode || "user";
  if (!t.length || t[0] === "help" || t[0] === "?") return null;
  const m = r.mode;
  // leaving and entering modes
  if (m === "user" && ab(t[0], "enable", 2)) { r.mode = "priv"; return ""; }
  if (m !== "user" && ab(t[0], "disable", 4)) { r.mode = "user"; return ""; }
  if (m === "priv" && ab(t[0], "enable", 2)) return "";
  if ((m === "config" || m === "if") && (t[0] === "end" || raw === "\u001a")) { r.mode = "priv"; r.cfgIf = null; return ""; }
  if (m === "if" && t[0] === "exit") { r.mode = "config"; r.cfgIf = null; return ""; }
  if (m === "config" && t[0] === "exit") { r.mode = "priv"; return ""; }
  if (ab(t[0], "configure", 4) && (!t[1] || ab(t[1], "terminal", 1))) {
    if (m === "user") return "                ^\n% Invalid input detected at '^' marker.\n(Type enable first: configuration needs privileged mode.)";
    if (m === "priv") { r.mode = "config"; return "Enter configuration commands, one per line.  End with CNTL/Z."; }
  }
  if (m === "priv" && (ab(t[0], "write", 2) || (t[0] === "copy" && t[1] && t[1].startsWith("run")))) return "Building configuration...\n[OK]";
  if (m !== "config" && m !== "if") return null; // exec commands (show, ping, ...) are answered by diag.js
  if (t[0] === "do") return { exec: raw.replace(/^do\s+/i, "") };
  const no = t[0] === "no";
  const w = no ? t.slice(1) : t;
  const rw = no ? raw.split(/\s+/).slice(1) : raw.split(/\s+/);
  // global configuration
  if (ab(w[0], "interface", 3)) {
    const i = findIf(r, rw.slice(1).join(""));
    if (!i) return `% Invalid interface. This router has: ${r.ifaces.map((x) => x.name).join(", ")}`;
    r.mode = "if"; r.cfgIf = i.name;
    return "";
  }
  if (ab(w[0], "hostname", 3)) { if (no) { r.hostname = null; return ""; } if (!rw[1]) return "% Incomplete command."; r.hostname = rw[1]; return ""; }
  if (w[0] === "ip" && ab(w[1], "route", 2) && m === "config") {
    const [dst, mask, nh] = rw.slice(2);
    if (!isIp(dst) || !isMask(mask)) return "% Incomplete command.\n(ip route <network> <mask> <next-hop|Null0>)";
    const dp = { ip: ipToInt(dst), len: maskToLen(ipToInt(mask)) };
    const same = (x) => x.dst.ip === dp.ip && x.dst.len === dp.len;
    if (no) {
      const before = r.routes.length;
      r.routes = r.routes.filter((x) => !(same(x) && (!nh || (isIp(nh) ? x.via === ipToInt(nh) : x.via === null))));
      if (r.routes.length === before) return "%No matching route to delete";
      changed(lab); return "";
    }
    if (!nh) return "% Incomplete command.";
    if (!isIp(nh) && !/^null0$/i.test(nh)) {
      const i = findIf(r, nh);
      if (!i) return "% Invalid next hop.";
      return "FortiTatake: give a next-hop address (or Null0); exit-interface-only routes aren't modelled.";
    }
    const via = isIp(nh) ? ipToInt(nh) : null;
    if (via !== null && !r.ifaces.some((i) => i.up !== false && i.prefix && inPrefix(via, i.prefix))) return `%Next hop ${nh} isn't on a connected network of this router; the route stays inactive.`;
    r.routes = r.routes.filter((x) => !(same(x) && x.via === via));
    r.routes.push({ dst: dp, via, dev: via === null ? "null" : null, user: true });
    changed(lab);
    return "";
  }
  if (w[0] === "ip" && ab(w[1], "name-server", 3)) { r.dns = no ? [] : rw.slice(2).filter(isIp); return ""; }
  if (w[0] === "ip" && ab(w[1], "domain", 3)) return "";
  if (ab(w[0], "banner", 3) || ab(w[0], "service", 3) || ab(w[0], "logging", 3) || ab(w[0], "username", 3) || ab(w[0], "line", 2) || ab(w[0], "enable", 2)) return "(FortiTatake: accepted, but not modelled in this lab)";
  // interface configuration
  if (m === "if") {
    const i = r.ifaces.find((x) => x.name === r.cfgIf);
    if (w[0] === "ip" && ab(w[1], "address", 2)) {
      if (no) { i.prefix = null; changed(lab); return ""; }
      const [ip, mask] = rw.slice(2);
      if (!isIp(ip) || !isMask(mask)) return "% Incomplete command.\n(ip address <address> <mask>, for example ip address 203.0.113.1 255.255.255.252)";
      const p = { ip: ipToInt(ip), len: maskToLen(ipToInt(mask)) };
      const clash = r.ifaces.find((x) => x !== i && x.prefix && (inPrefix(p.ip, x.prefix) || inPrefix(x.prefix.ip, p)));
      if (clash) return `% ${intToIp(p.ip & ((0xffffffff << (32 - p.len)) >>> 0))} overlaps with ${clash.name}`;
      i.prefix = p;
      changed(lab);
      return "";
    }
    if (ab(w[0], "shutdown", 2)) {
      const was = i.up !== false;
      i.up = no;
      changed(lab);
      if (no && !was) return `%LINK-3-UPDOWN: Interface ${i.name}, changed state to up\n%LINEPROTO-5-UPDOWN: Line protocol on Interface ${i.name}, changed state to up`;
      if (!no && was) return `%LINK-5-CHANGED: Interface ${i.name}, changed state to administratively down\n%LINEPROTO-5-UPDOWN: Line protocol on Interface ${i.name}, changed state to down`;
      return "";
    }
    if (ab(w[0], "description", 3)) { i.description = no ? "" : rw.slice(1).join(" "); return ""; }
    if (ab(w[0], "mtu", 3) || ab(w[0], "speed", 3) || ab(w[0], "duplex", 3) || ab(w[0], "negotiation", 3)) return "(FortiTatake: accepted, but not modelled in this lab)";
  }
  return "                ^\n% Invalid input detected at '^' marker.";
}

export const ROUTER_CONFIG_HELP = "Configuration: enable, configure terminal, interface <name>, ip address <ip> <mask>, [no] shutdown, description <text>, ip route <net> <mask> <next-hop|Null0>, no ip route ..., hostname <name>, ip name-server <ip>, do <command>, exit, end, write memory";

// Lines that change config: the live console sends them to the simulator first, not to the real-network readers.
export function isConfigLine(d, line) {
  const s = line.trim().replace(/^sudo\s+/, "");
  if (d.kind === "router") return (d.mode && d.mode !== "user" && d.mode !== "priv") || /^(en|ena|enab|enabl|enable|conf|confi|config|configu|configur|configure)\b/i.test(s);
  if (/^ip\s+\S+\s+(add|del|delete|flush|replace|change|append|set)\b/i.test(s)) return true;
  if (/^route\s+(add|delete|change)\b/i.test(s)) return true;
  return false;
}
