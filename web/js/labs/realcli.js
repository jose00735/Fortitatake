import { hostsEntry } from "./netcfg.js";
import { ipToInt, intToIp } from "./net.js";
// Host and ISP-router troubleshooting commands answered from the real network when the lab is live:
// the Linux tool runs in the device's namespace on FortiTatake OS and its output is printed the way
// Windows CMD, a Linux box or a Cisco IOS router would print it. Returns null for commands the
// simulator answers (or when the device isn't one of these).

const exec = async (call, ns, argv, ms = 20000) => (await call({ op: "ns.exec", ns, argv, timeout_ms: ms }, ms + 3000)).stdout || "";
const pad = (s, n) => (String(s).length >= n ? String(s) + " " : String(s) + " ".repeat(n - String(s).length));
const isIp = (s) => /^\d+\.\d+\.\d+\.\d+$/.test(s);
const lenMask = (len) => { const m = len === 0 ? 0 : (0xffffffff << (32 - len)) >>> 0; return [24, 16, 8, 0].map((s) => (m >>> s) & 255).join("."); };
const mac = (m, win) => (m || "00:00:00:00:00:00").replace(/:/g, win ? "-" : ":");

// ping output (busybox or iputils) -> [{seq, ttl, ms}] plus whether anything said "unreachable"
function parsePing(text) {
  const rep = [];
  for (const m of text.matchAll(/bytes from \S+?:? (?:icmp_)?seq=(\d+) ttl=(\d+) time=([\d.]+) ms/g)) rep.push({ seq: Number(m[1]), ttl: Number(m[2]), ms: Number(m[3]) });
  return { rep, unreach: /unreachable/i.test(text) };
}

// A real DNS lookup from the device's namespace to its configured DNS server (or the one given):
// the query crosses the lab like any packet, so it shows in sniffers, sessions and logs. What it
// learns is remembered by the lab, so the simulator and the real network agree on the address.
const dnsCache = new Map(); // one command, one lookup: the simulator pass and the real pass share it
export async function realResolve(call, lab, h, name, server) {
  if (isIp(name)) return { ip: name };
  const key = `${h.id}|${name.toLowerCase()}|${server || ""}`;
  const hit = dnsCache.get(key);
  if (hit && Date.now() - hit.at < 5000) return hit.r;
  const r = await realResolveNow(call, lab, h, name, server);
  dnsCache.set(key, { at: Date.now(), r });
  return r;
}
async function realResolveNow(call, lab, h, name, server) {
  const servers = server && isIp(server) ? [ipToInt(server)] : h.dnsServers ? h.dnsServers() : [];
  if (!servers.length) return { err: "none" };
  for (const s of servers) {
    let r;
    try { r = await call({ op: "dns.query", ns: h.id, server: intToIp(s), name }, 6000); }
    catch (e) {
      if (!/unknown op/i.test(e.message)) continue;
      const x = lab.resolve(h.id, name); // an OS build from before v0.9.0
      return x.err ? { err: /timed out/.test(x.err) ? "timeout" : "nxdomain", server: intToIp(s) } : { ip: intToIp(x.ip), all: [intToIp(x.ip)], server: intToIp(x.server) };
    }
    if (r.error) continue;
    if (r.rcode === 3 || !(r.addrs || []).length) return { err: "nxdomain", server: intToIp(s), ms: r.ms };
    if (lab.learnName) lab.learnName(name, r.addrs[0]);
    return { ip: r.addrs[0], all: r.addrs, server: intToIp(s), ms: r.ms, ttl: r.ttl };
  }
  return { err: "timeout", server: intToIp(servers[0]) };
}

export async function realHostCmd(call, lab, h, line) {
  const t = line.trim().split(/\s+/);
  const c = (t[0] || "").toLowerCase();
  const win = h.os === "windows";
  const ns = h.id;
  const target = async (name) => { if (isIp(name)) return name; const he = hostsEntry(h, name); if (he !== null) return intToIp(he); const r = await realResolve(call, lab, h, name); return r.err ? null : r.ip; };

  if (c === "nslookup" || c === "dig") {
    const args = t.slice(1).filter((a) => !a.startsWith("-") && !a.startsWith("+"));
    const name = args[0];
    if (!name) return null;
    const r = await realResolve(call, lab, h, name, args[1]);
    const srv = r.server || "";
    if (c === "dig") {
      if (r.err === "timeout" || r.err === "none") return ";; communications error: timed out\n;; no servers could be reached";
      const ans = (r.all || []).map((a) => `${name}.\t\t${r.ttl || 60}\tIN\tA\t${a}`).join("\n");
      return `; <<>> DiG 9.18.28-0ubuntu0.24.04.1-Ubuntu <<>> ${name}\n;; global options: +cmd\n;; Got answer:\n;; ->>HEADER<<- opcode: QUERY, status: ${r.err ? "NXDOMAIN" : "NOERROR"}\n\n;; QUESTION SECTION:\n;${name}.\t\t\tIN\tA\n${ans ? "\n;; ANSWER SECTION:\n" + ans + "\n" : ""}\n;; Query time: ${Math.max(1, Math.round(r.ms || 1))} msec\n;; SERVER: ${srv}#53(${srv}) (UDP)`;
    }
    if (win) {
      if (r.err === "timeout" || r.err === "none") return `DNS request timed out.\n    timeout was 2 seconds.\nServer:  UnKnown\nAddress:  ${srv}\n\nDNS request timed out.\n    timeout was 2 seconds.\n*** Request to UnKnown timed-out`;
      const head = `Server:  UnKnown\nAddress:  ${srv}\n`;
      if (r.err) return `${head}\n*** UnKnown can't find ${name}: Non-existent domain`;
      return `${head}\nNon-authoritative answer:\nName:    ${name}\n${r.all.length > 1 ? "Addresses:  " + r.all.join("\n          ") : "Address:  " + r.ip}`;
    }
    if (r.err === "timeout" || r.err === "none") return ";; connection timed out; no servers could be reached";
    const head = `Server:\t\t${srv}\nAddress:\t${srv}#53\n`;
    if (r.err) return `${head}\n** server can't find ${name}: NXDOMAIN`;
    return `${head}\nNon-authoritative answer:\n${r.all.map((a) => `Name:\t${name}\nAddress: ${a}`).join("\n")}`;
  }

  if (c === "ping") {
    let count = 4, size = win ? 32 : 56, host = null;
    for (let i = 1; i < t.length; i++) { const a = t[i]; if (a === "-n" || a === "-c") count = Math.min(10, Number(t[++i]) || 4); else if (a === "-l" || a === "-s") size = Number(t[++i]) || size; else if (a === "-t") count = 6; else if (!a.startsWith("-")) host = a; }
    if (!host) return null;
    const ip = await target(host);
    if (!ip) return win ? `Ping request could not find host ${host}. Please check the name and try again.` : `ping: ${host}: Temporary failure in name resolution`;
    const out = await exec(call, ns, ["ping", "-c", String(count), "-W", "1", "-s", String(size), ip], count * 1500 + 3000);
    const { rep } = parsePing(out);
    if (!win) return out.replace(/seq=/g, "icmp_seq=").trim();
    const L = [`Pinging ${host !== ip ? `${host} [${ip}]` : ip} with ${size} bytes of data:`];
    for (let s = 0; s < count; s++) { const r = rep.find((x) => x.seq === s); L.push(r ? `Reply from ${ip}: bytes=${size} time${r.ms < 1 ? "<1" : "=" + Math.round(r.ms)}ms TTL=${r.ttl}` : "Request timed out."); }
    const ok = rep.length, ms = rep.map((r) => Math.round(r.ms));
    L.push("", `Ping statistics for ${ip}:`, `    Packets: Sent = ${count}, Received = ${ok}, Lost = ${count - ok} (${Math.round(((count - ok) / count) * 100)}% loss),`);
    if (ok) L.push("Approximate round trip times in milli-seconds:", `    Minimum = ${Math.min(...ms)}ms, Maximum = ${Math.max(...ms)}ms, Average = ${Math.round(ms.reduce((a, b) => a + b, 0) / ok)}ms`);
    return L.join("\n");
  }
  if (c === "tracert" || c === "traceroute" || c === "pathping") {
    const host = t.slice(1).find((a) => !a.startsWith("-"));
    if (!host) return null;
    const ip = await target(host);
    if (!ip) return win ? `Unable to resolve target system name ${host}.` : `${host}: Name or service not known`;
    const out = await exec(call, ns, ["traceroute", "-n", "-w", "1", "-q", "3", "-m", "12", ip], 45000);
    if (!out.trim()) return null; // no traceroute in this build: the simulator answers
    if (!win) return out.trim();
    const hops = [];
    for (const l of out.split("\n").slice(1)) {
      const m = /^\s*(\d+)\s+(.*)$/.exec(l);
      if (!m) continue;
      const addr = (/(\d+\.\d+\.\d+\.\d+)/.exec(m[2]) || [])[1];
      const times = [...m[2].matchAll(/([\d.]+) ms|\*/g)].map((x) => (x[0] === "*" ? "*" : Number(x[1]) < 1 ? "<1 ms" : `${Math.round(Number(x[1]))} ms`));
      while (times.length < 3) times.push("*");
      hops.push({ n: m[1], addr, times });
    }
    if (c === "pathping") {
      const L = [`Tracing route to ${host !== ip ? `${host} [${ip}]` : ip}`, "over a maximum of 30 hops:", ...hops.map((x) => `  ${x.n}  ${x.addr || "*"}`), "", "Computing statistics for 25 seconds...",
        "            Source to Here   This Node/Link", "Hop  RTT    Lost/Sent = Pct  Lost/Sent = Pct  Address"];
      for (const x of hops) { const lost = x.times.filter((v) => v === "*").length; L.push(`${pad(x.n, 4)} ${pad(x.times.find((v) => v !== "*") || "---", 7)}${pad(`${lost}/  3 = ${Math.round((lost / 3) * 100)}%`, 17)}${pad(`${lost}/  3 = ${Math.round((lost / 3) * 100)}%`, 17)}${x.addr || "[Request timed out]"}`); }
      return L.concat("", "Trace complete.").join("\n");
    }
    return [`Tracing route to ${host !== ip ? `${host} [${ip}]` : ip}`, "over a maximum of 30 hops:", "",
      ...hops.map((x) => `${String(x.n).padStart(3)}${x.times.map((v) => v.padStart(9)).join("")}  ${x.addr || "Request timed out."}`), "", "Trace complete."].join("\n");
  }
  if (win && c === "arp" && /^-a$/i.test(t[1] || "")) {
    const nb = JSON.parse((await exec(call, ns, ["ip", "-j", "neigh", "show"])) || "[]").filter((n) => n.lladdr);
    const me = JSON.parse((await exec(call, ns, ["ip", "-j", "-4", "addr", "show", "dev", h.port || "eth0"])) || "[]");
    const myIp = ((me[0] || {}).addr_info || [])[0];
    return [``, `Interface: ${myIp ? myIp.local : "0.0.0.0"} --- 0x5`, `  Internet Address      Physical Address      Type`,
      ...nb.map((n) => `  ${pad(n.dst, 22)}${pad(mac(n.lladdr, true), 22)}dynamic`), `  ${pad("255.255.255.255", 22)}${pad("ff-ff-ff-ff-ff-ff", 22)}static`].join("\n");
  }
  if (win && c === "route" && /^print$/i.test(t[1] || "")) {
    const rt = JSON.parse((await exec(call, ns, ["ip", "-j", "-4", "route", "show"])) || "[]");
    const rows = rt.map((r) => { const [net, len] = r.dst === "default" ? ["0.0.0.0", 0] : r.dst.includes("/") ? r.dst.split("/") : [r.dst, 32]; return `${pad(net, 18).padStart(18)}${pad(lenMask(Number(len)), 17).padStart(17)}${pad(r.gateway || "On-link", 17).padStart(17)}${pad(r.prefsrc || "", 16).padStart(16)}${String(r.gateway ? 25 : 281).padStart(6)}`; });
    return [`===========================================================================`, `Interface List`, `  5...${mac("00:50:56:" + h.id.length.toString(16).padStart(2, "0") + ":1a:2b", false).replace(/:/g, " ")} ......Intel(R) 82574L Gigabit Network Connection`, `  1...........................Software Loopback Interface 1`, `===========================================================================`, ``,
      `IPv4 Route Table`, `===========================================================================`, `Active Routes:`, `Network Destination        Netmask          Gateway       Interface  Metric`, ...rows, `===========================================================================`].join("\n");
  }
  if (win && c === "netstat") {
    const ss = await exec(call, ns, ["ss", "-tanu"]);
    if (!ss.trim()) return null;
    const L = ["", "Active Connections", "", "  Proto  Local Address          Foreign Address        State           PID"];
    for (const l of ss.split("\n").slice(1)) {
      const f = l.trim().split(/\s+/);
      if (f.length < 6) continue;
      const state = { LISTEN: "LISTENING", ESTAB: "ESTABLISHED", "TIME-WAIT": "TIME_WAIT", "SYN-SENT": "SYN_SENT", UNCONN: "" }[f[1]] ?? f[1];
      L.push(`  ${pad(f[0].toUpperCase(), 7)}${pad(f[4].replace("*", "0.0.0.0"), 23)}${pad(f[5].replace("*:*", "*:*").replace(/^\*/, "0.0.0.0"), 23)}${pad(state, 16)}${4 + (f[4].length % 7) * 100}`);
    }
    return L.join("\n");
  }
  if (!win && c === "uname") {
    // an Ubuntu server's kernel; only the machine type comes from FortiTatake OS (x86_64 on a PC, aarch64 on a phone)
    const m = (await exec(call, ns, ["uname", "-m"])).trim();
    if (!m) return null;
    const f = { s: "Linux", n: h.hostname.toLowerCase(), r: "6.8.0-48-generic", v: "#48-Ubuntu SMP PREEMPT_DYNAMIC Fri Sep 27 14:04:52 UTC 2024", m, p: m, i: m, o: "GNU/Linux" };
    const flags = t.slice(1).join("").replace(/-/g, "");
    if (!flags) return "Linux";
    if (flags.includes("a")) return "snrvmpio".split("").map((k) => f[k]).join(" ");
    return [..."snrvmpio"].filter((k) => flags.includes(k)).map((k) => f[k]).join(" ") || `uname: invalid option -- '${flags[0]}'`;
  }
  if (!win && c === "ip" && /^n(e(i(gh?)?)?)?$/.test(t[1] || "")) return (await exec(call, ns, ["ip", "neigh", "show"])).trim() || "";
  if (!win && c === "ip" && /^r(o(u(te?)?)?)?$/.test(t[1] || "")) return (await exec(call, ns, ["ip", "route", "show"])).trim();
  if (!win && (c === "ss" || c === "netstat")) return (await exec(call, ns, ["ss", ...(t.length > 1 ? t.slice(1) : ["-tuln"])])).trim() || null;
  return null;
}

// ---------------------------------------------------------------- ISP routers (Cisco IOS look)
// the kernel creates these in every namespace when the tunnel modules load; a router has none of them
const labIf = (i) => i.ifname !== "lo" && !/^(gre0|gretap0|erspan0|sit0|ip_vti0|ip6tnl0|ip6gre0|tunl0|ip6_vti0)$/.test(i.ifname);
const IOS_IF = (n) => (/^(gi|ge|eth|inet|wan|lan)/i.test(n) ? n : n);
export async function realRouterCmd(call, lab, r, line) {
  const t = line.trim().toLowerCase().replace(/\s+/g, " ");
  const ns = r.id;
  // IOS-style abbreviations: "sh ip int br" is "show ip interface brief"
  const words = t.split(" ");
  const is = (...forms) => forms.some((f) => { const fw = f.split(" "); return fw.length === words.length && fw.every((w, i) => w.startsWith(words[i])); });
  if (/^ping \S+/.test(t)) {
    const ip = t.split(" ")[1];
    if (!isIp(ip)) return "% Unrecognized host or address, or protocol not running.";
    const out = await exec(call, ns, ["ping", "-c", "5", "-W", "1", "-i", "0.2", "-s", "72", ip], 12000);
    const { rep, unreach } = parsePing(out);
    const marks = Array.from({ length: 5 }, (_, s) => (rep.some((x) => x.seq === s) ? "!" : unreach ? "U" : "."));
    const ms = rep.map((x) => Math.round(x.ms));
    return `Type escape sequence to abort.\nSending 5, 100-byte ICMP Echos to ${ip}, timeout is 2 seconds:\n${marks.join("")}\nSuccess rate is ${rep.length * 20} percent (${rep.length}/5)${rep.length ? `, round-trip min/avg/max = ${Math.min(...ms)}/${Math.round(ms.reduce((a, b) => a + b, 0) / ms.length)}/${Math.max(...ms)} ms` : ""}`;
  }
  if (/^tr(a(c(e(r(o(u(te?)?)?)?)?)?)?)? \S+/.test(t)) {
    const ip = t.split(" ")[1];
    if (!isIp(ip)) return "% Unrecognized host or address, or protocol not running.";
    const out = await exec(call, ns, ["traceroute", "-n", "-w", "1", "-q", "3", "-m", "12", ip], 45000);
    const L = ["Type escape sequence to abort.", `Tracing the route to ${ip}`, "VRF info: (vrf in name/id, vrf out name/id)"];
    for (const l of out.split("\n").slice(1)) { const m = /^\s*(\d+)\s+(.*)$/.exec(l); if (!m) continue; const addr = (/(\d+\.\d+\.\d+\.\d+)/.exec(m[2]) || [])[1]; const times = [...m[2].matchAll(/([\d.]+) ms|\*/g)].map((x) => (x[0] === "*" ? "*" : `${Math.max(1, Math.round(Number(x[1])))} msec`)); L.push(`  ${m[1]} ${addr || ""} ${times.join(" ")}`); }
    return L.join("\n");
  }
  if (is("show ip route")) {
    const rt = JSON.parse((await exec(call, ns, ["ip", "-j", "-4", "route", "show"])) || "[]");
    const L = ["Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP", "       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area", "       * - candidate default, U - per-user static route, o - ODR", "", `Gateway of last resort is ${(rt.find((x) => x.dst === "default") || {}).gateway || "not set"}${rt.some((x) => x.dst === "default") ? " to network 0.0.0.0" : ""}`, ""];
    const dyn = new Map((lab.routerDynamic(r) || []).map((x) => [`${x.dst.ip}/${x.dst.len}`, x.type]));
    for (const x of rt) {
      const dst = x.dst === "default" ? "0.0.0.0/0" : x.dst;
      if (x.protocol === "kernel" && x.scope === "link") { L.push(`C        ${dst} is directly connected, ${IOS_IF(x.dev)}`); if (x.prefsrc) L.push(`L        ${x.prefsrc}/32 is directly connected, ${IOS_IF(x.dev)}`); continue; }
      const code = x.dst === "default" ? "S*" : "S";
      L.push(`${pad(code, 9)}${dst} [1/0] via ${x.gateway || "0.0.0.0"}${x.dev ? `, ${IOS_IF(x.dev)}` : ""}`);
    }
    return L.join("\n");
  }
  if (is("show ip interface brief")) {
    const a = JSON.parse((await exec(call, ns, ["ip", "-j", "addr", "show"])) || "[]").filter(labIf);
    return [`Interface              IP-Address      OK? Method Status                Protocol`, ...a.map((i) => { const v4 = (i.addr_info || []).find((x) => x.family === "inet"); const up = (i.flags || []).includes("UP"); const lower = (i.flags || []).includes("LOWER_UP"); return `${pad(IOS_IF(i.ifname), 23)}${pad(v4 ? v4.local : "unassigned", 16)}YES ${pad(v4 ? "manual" : "unset", 7)}${pad(up ? "up" : "administratively down", 22)}${up && lower ? "up" : "down"}`; })].join("\n");
  }
  if (is("show interfaces")) {
    const a = JSON.parse((await exec(call, ns, ["ip", "-j", "-s", "addr", "show"])) || "[]").filter(labIf);
    return a.map((i) => { const v4 = (i.addr_info || []).find((x) => x.family === "inet"); const up = (i.flags || []).includes("UP") && (i.flags || []).includes("LOWER_UP"); const s = i.stats64 || {}; return `${IOS_IF(i.ifname)} is ${up ? "up" : "down"}, line protocol is ${up ? "up" : "down"}\n  Hardware is iGbE, address is ${(i.address || "").replace(/:/g, "").replace(/(.{4})(?!$)/g, "$1.")}\n  Internet address is ${v4 ? `${v4.local}/${v4.prefixlen}` : "unassigned"}\n  MTU ${i.mtu} bytes, BW 1000000 Kbit/sec, DLY 10 usec\n  Encapsulation ARPA, loopback not set\n     ${(s.rx || {}).packets || 0} packets input, ${(s.rx || {}).bytes || 0} bytes, 0 no buffer\n     ${(s.rx || {}).errors || 0} input errors, 0 CRC, 0 frame, 0 overrun, ${(s.rx || {}).dropped || 0} ignored\n     ${(s.tx || {}).packets || 0} packets output, ${(s.tx || {}).bytes || 0} bytes, 0 underruns\n     ${(s.tx || {}).errors || 0} output errors, 0 collisions, 0 interface resets`; }).join("\n");
  }
  if (is("show arp") || is("show ip arp")) {
    const nb = JSON.parse((await exec(call, ns, ["ip", "-j", "neigh", "show"])) || "[]").filter((n) => n.lladdr);
    const me = JSON.parse((await exec(call, ns, ["ip", "-j", "-4", "addr", "show"])) || "[]");
    const L = ["Protocol  Address          Age (min)  Hardware Addr   Type   Interface"];
    for (const i of me) for (const a of (i.addr_info || []).filter((x) => x.family === "inet" && i.ifname !== "lo")) L.push(`Internet  ${pad(a.local, 17)}-          ${pad((i.address || "").replace(/:/g, "").replace(/(.{4})(?!$)/g, "$1."), 16)}ARPA   ${IOS_IF(i.ifname)}`);
    for (const n of nb) L.push(`Internet  ${pad(n.dst, 17)}${pad("0", 11)}${pad(n.lladdr.replace(/:/g, "").replace(/(.{4})(?!$)/g, "$1."), 16)}ARPA   ${IOS_IF(n.dev)}`);
    return L.join("\n");
  }
  if (is("show access-lists") || is("show ip access-lists")) {
    const rs = await exec(call, ns, ["nft", "list", "ruleset"]);
    const drops = [...rs.matchAll(/ip (saddr|daddr) \{?\s*([^}\n]+?)\s*\}? drop/g)];
    if (!drops.length) return "";
    return [`Extended IP access list ISP-BOGON-FILTER`, ...drops.flatMap((m, i) => m[2].split(/,\s*/).map((p, j) => { const [n, l] = p.split("/"); const wild = lenMask(Number(l)).split(".").map((o) => 255 - Number(o)).join("."); return `    ${(i * 10 + j + 1) * 10} deny ip ${m[1] === "saddr" ? `${n} ${wild} any` : `any ${n} ${wild}`}`; })), `    1000 permit ip any any`].join("\n");
  }
  if (is("show version")) {
    const up = Number(((await exec(call, ns, ["cat", "/proc/uptime"])).split(" ")[0]) || 0);
    const ifs = JSON.parse((await exec(call, ns, ["ip", "-j", "link", "show"])) || "[]").filter(labIf).length;
    return `Cisco IOS XE Software, Version 17.09.05a\nCisco IOS Software [Cupertino], Virtual XE Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 17.9.5a, RELEASE SOFTWARE (fc3)\nTechnical Support: http://www.cisco.com/techsupport\n\nROM: IOS-XE ROMMON\n\n${r.id} uptime is ${Math.floor(up / 3600)} hours, ${Math.floor((up % 3600) / 60)} minutes\nSystem returned to ROM by reload\nSystem image file is "bootflash:packages.conf"\n\ncisco C8000V (VXE) processor (revision VXE) with 1984096K/3075K bytes of memory.\nProcessor board ID 9X${r.id.length}QW${(r.id.charCodeAt(0) * 7919) % 100000}\n${ifs} Gigabit Ethernet interfaces\n32768K bytes of non-volatile configuration memory.\n\nConfiguration register is 0x2102`;
  }
  if (is("show clock")) return `*${new Date(lab.clock - 5 * 3600000).toUTCString().replace("GMT", "COT")}`;
  return null;
}
