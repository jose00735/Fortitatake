// get / diagnose / execute on the FortiGate, and the consoles of PCs, servers and routers.
import { Lab, PROTO, bpf } from "./sim.js";
import { pick, tokenize } from "./fgt.js";
import { ipToInt, intToIp, prefixStr, maskStr, hex, inPrefix, parsePrefix } from "./net.js";
import { FortiGate } from "./fgt.js";

const NOT_SIM = "This command exists in FortiOS 8.0.2 but is not simulated in FortiTatake.";
const pad = (s, n) => (String(s).length >= n ? String(s) + " " : String(s) + " ".repeat(n - String(s).length));
const ms = (r) => (8 + Math.floor(r() * 9));

// ---------- FortiGate ----------
Lab.prototype.diagnose = function (fg, toks, line) {
  const w = toks.map((t) => t.toLowerCase());
  const head = pick(w[0], ["get", "diagnose", "execute"]);
  const rest = w.slice(1);
  const known = (prefix) => fg.schema.cmds.some((c) => c.startsWith(prefix));
  try {
    const raw = toks.slice(1);
    if (fg.kind !== "fortigate" && this.mgmtDiag) { const r = this.mgmtDiag(fg, head, rest); if (r !== null && r !== undefined) return r; }
    for (const fn of [this.vpnDiag, this.sdwanDiag]) {
      if (head !== "diagnose" || !fn) continue;
      const r = fn.call(this, fg, rest, raw);
      if (r !== null && r !== undefined) return r;
    }
    if (this.haDiag) { const r = this.haDiag(fg, rest, raw, head); if (r !== null && r !== undefined) return r; }
    if (this.switchDiag && fg.kind === "fortigate") { const r = this.switchDiag(fg, rest, head); if (r !== null && r !== undefined) return r; }
    if (this.routingDiag && fg.kind === "fortigate") { const r = this.routingDiag(fg, rest, head); if (r !== null && r !== undefined) return r; }
    if (this.authDiag && fg.kind === "fortigate") { const r = this.authDiag(fg, rest, raw, head); if (r !== null && r !== undefined) return r; }
    if (head === "get" && match(rest, ["vpn", "ipsec", "tunnel", "summary"]) && this.vpnSummary) return this.vpnSummary(fg);
    if (head === "get") return getCmd(this, fg, rest, toks.slice(1));
    if (head === "diagnose") return diagCmd(this, fg, rest, toks.slice(1));
    if (head === "execute") return execCmd(this, fg, rest, toks.slice(1));
  } catch (e) {
    return `Command fail. ${e.message}`;
  }
  return "Command fail. Return code -1";
};

function match(rest, words) {
  // every typed word must be a prefix of the expected word
  if (rest.length < words.length) return false;
  return words.every((x, i) => x.startsWith(rest[i]) && rest[i].length >= Math.min(2, x.length));
}

function getCmd(lab, fg, r, raw) {
  if (match(r, ["system", "status"])) {
    return [`Version: ${fg.model} ${fg.version},build0000,260115 (GA.F)`, `Firmware Signature: certified`, `Virus-DB: 93.01234(2026-11-23 18:22)`, `IPS-DB: 34.00123(2026-11-22 01:10)`,
      `Serial-Number: ${fg.serial}`, `License Status: Valid`, `VM Resources: 2 CPU/2 allowed, 3956 MB RAM`, `Log hard disk: Available`, `Hostname: ${fg.hostname()}`,
      `Private Encryption: Disable`, `Operation Mode: NAT`, `Current virtual domain: root`, `Max number of virtual domains: 1`, `Virtual domains status: 1 in NAT mode, 0 in TP mode`,
      `Virtual domain configuration: disable`, `FIPS-CC mode: disable`, `Current HA mode: ${haMode(fg)}`, `Branch point: 0000`, `Release Version Information: GA`, `System time: ${new Date(lab.clock).toUTCString()}`].join("\n");
  }
  if (match(r, ["system", "interface"])) {
    const phys = r[2] && "physical".startsWith(r[2]);
    return lab.fgtIntfs(fg).map((i) => phys
      ? `\t==[${i.name}]\n\t\tmode: ${i.mode || "static"}\n\t\tip: ${i.prefix ? `${intToIp(i.prefix.ip)} ${maskStr(i.prefix.len)}` : "0.0.0.0 0.0.0.0"}\n\t\tipv6: ::/0\n\t\tstatus: ${i.up ? "up" : "down"}\n\t\tspeed: ${i.up ? "1000Mbps (Duplex: full)" : "n/a"}`
      : `== [ ${i.name} ]\nname: ${i.name}   mode: ${i.mode || "static"}    ip: ${i.prefix ? `${intToIp(i.prefix.ip)} ${maskStr(i.prefix.len)}` : "0.0.0.0 0.0.0.0"}   status: ${i.admin ? "up" : "down"}    netbios-ns: disable   type: ${i.type}   ${i.vlan ? `vlanid: ${i.vlan}   ` : ""}mtu-override: disable   link-status: ${i.up ? "up" : "down"}`).join("\n");
  }
  if (match(r, ["router", "info", "routing-table"])) {
    const what = r[3] || "all";
    const { all, active, inactive = [] } = lab.fgtRoutes(fg);
    if ("details".startsWith(what) && r[4]) {
      const ip = ipToInt(r[4]);
      const rt = lab.fgtLookup(fg, ip);
      if (!rt) return `Network not in table`;
      return `Routing table for VRF=0\nRouting entry for ${prefixStr(rt.dst)}\n  Known via "${rt.type === "C" ? "connected" : rt.type === "B" ? "bgp" : rt.type.startsWith("O") ? "ospf" : "static"}", distance ${rt.distance}, metric ${rt.metric || 0}, best\n  * ${rt.type === "C" ? `directly connected, ${rt.dev}` : `vrf 0 ${intToIp(rt.gw)}, via ${rt.dev}`}`;
    }
    const list = "database".startsWith(what) ? [...all, ...inactive] : active;
    const lines = [`Codes: K - kernel, C - connected, S - static, R - RIP, B - BGP`, `       O - OSPF, IA - OSPF inter area`, `       N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2`, `       E1 - OSPF external type 1, E2 - OSPF external type 2`, `       i - IS-IS, L1 - IS-IS level-1, L2 - IS-IS level-2, ia - IS-IS inter area`, `       V - BGP VPNv4`, `       * - candidate default`, ``, `Routing table for VRF=0`];
    const sorted = [...list].sort((a, b) => (a.dst.ip - b.dst.ip) || (a.dst.len - b.dst.len));
    for (const x of sorted) {
      const isActive = active.includes(x);
      const code = (x.type + (x.dst.len === 0 ? "*" : "")).padEnd(8);
      const mark = "database".startsWith(what) ? (isActive ? "*> " : "   ") : "";
      if (x.type === "C") lines.push(`${code}${mark}${prefixStr(x.dst)} is directly connected, ${x.dev}`);
      else if (x.type === "B" && x.recursive) lines.push(`${code}${mark}${prefixStr(x.dst)} [${x.distance}/${x.metric || 0}] via ${intToIp(x.nh)} (recursive via ${intToIp(x.gw)}, ${x.dev}), 00:12:41`);
      else if (x.type.startsWith("O") || x.type === "B") lines.push(`${code}${mark}${prefixStr(x.dst)} [${x.distance}/${x.metric || 0}] via ${intToIp(x.gw)}, ${x.dev}, 00:12:41`);
      else if (x.inactive) lines.push(`${code}${mark}${prefixStr(x.dst)} [${x.distance}/0] via ${intToIp(x.gw)}, ${x.dev} inactive, [${x.priority}/0]`);
      else if (x.blackhole) lines.push(`${code}${mark}${prefixStr(x.dst)} [${x.distance}/0] is a summary, Null, [${x.priority}/0]`);
      else lines.push(`${code}${mark}${prefixStr(x.dst)} [${x.distance}/0] via ${intToIp(x.gw)}, ${x.dev}, [${x.priority}/0]`);
    }
    return lines.join("\n");
  }
  if (match(r, ["system", "arp"])) {
    const out = ["Address           Age(min)   Hardware Addr      Interface"];
    for (const i of lab.fgtIntfs(fg)) {
      if (!i.up || !i.seg) continue;
      for (const m of i.seg.members) {
        const d = lab.dev(m.dev);
        if (!d || d === fg) continue;
        const ip = d.ip ? d.ip() : d.ifaces ? (d.ifaces.find((x) => x.name === m.port) || {}).prefix?.ip : null;
        if (ip) out.push(`${pad(intToIp(ip), 18)}0          ${mac(d.id)}  ${i.name}`);
      }
    }
    return out.join("\n");
  }
  if (match(r, ["system", "performance", "status"])) return `CPU states: 2% user 1% system 0% nice 97% idle 0% iowait 0% irq 0% softirq\nMemory: 4050892k total, 1490212k used (36.8%), 2365400k free (58.4%), 195280k freeable (4.8%)\nAverage network usage: 412 / 380 kbps in 1 minute\nAverage sessions: ${(fg.sessList || []).length} sessions in 1 minute\nUptime: 12 days,  4 hours,  31 minutes`;
  if (match(r, ["system", "ha", "status"])) return `HA Health Status: OK\nModel: ${fg.model}\nMode: ${haMode(fg)}`;
  if (fg.schema.cmds.some((c) => c.startsWith("get " + r.join(" ")))) return NOT_SIM;
  // `get <config path>` works like show for objects
  const path = fg.matchPath(raw.slice(0, 3)) || fg.matchPath(raw.slice(0, 2));
  if (path) { const s = fg.P[path]; const n = fg.inst(path); return s.t === "table" ? n.list().map((e) => `== [ ${e.key} ]\n` + fg.getLines(s, e, true)).join("\n") : fg.getLines(s, n, false); }
  return `command parse error before '${raw[0] || ""}'\nCommand fail. Return code -61`;
}

function haMode(fg) { const h = fg.obj("system ha"); const m = fg.one("system ha", h, "mode"); return !m || m === "standalone" ? "standalone" : m === "a-p" ? "a-p" : m; }
function mac(id) { let h = 0; for (const c of id) h = (h * 31 + c.charCodeAt(0)) >>> 0; const x = hex(h); return `00:09:0f:${x.slice(0, 2)}:${x.slice(2, 4)}:${x.slice(4, 6)}`; }

function diagCmd(lab, fg, r, raw) {
  const d = fg.dbg;
  if (match(r, ["debug", "enable"])) { d.enabled = true; return ""; }
  if (match(r, ["debug", "disable"])) { d.enabled = false; return ""; }
  if (match(r, ["debug", "reset"])) { d.flowFilter = {}; d.flowCount = 0; d.enabled = false; return ""; }
  if (match(r, ["debug", "info"])) return `debug output:           ${d.enabled ? "enable" : "disable"}\nconsole timestamp:      disable\nconsole no user log message:    disable\nCLI debug level:        3`;
  if (match(r, ["debug", "console", "timestamp"])) return "";
  if (match(r, ["debug", "flow", "filter"])) {
    const k = r[3];
    if (!k) return Object.entries(d.flowFilter).map(([a, b]) => `${a}: ${typeof b === "number" && a.includes("addr") ? intToIp(b) : b}`).join("\n") || "vf: any\nproto: any\nHost addr: any\nHost saddr: any\nHost daddr: any\nport: any\nsport: any\ndport: any";
    if ("clear".startsWith(k)) { d.flowFilter = {}; return ""; }
    if ("addr".startsWith(k) && k.length >= 2) { d.flowFilter.addr = ipToInt(raw[4]); return ""; }
    if ("saddr".startsWith(k)) { d.flowFilter.saddr = ipToInt(raw[4]); return ""; }
    if ("daddr".startsWith(k)) { d.flowFilter.daddr = ipToInt(raw[4]); return ""; }
    if ("proto".startsWith(k)) { d.flowFilter.proto = Number(raw[4]); return ""; }
    if ("port".startsWith(k) || "dport".startsWith(k)) { d.flowFilter.port = Number(raw[4]); return ""; }
    if ("vd".startsWith(k) || "negate".startsWith(k)) return "";
    return NOT_SIM;
  }
  if (match(r, ["debug", "flow", "show"])) return "";
  if (match(r, ["debug", "flow", "trace", "start"])) { d.flowCount = Number(raw[4] || 1); d.traceId = 0; return ""; }
  if (match(r, ["debug", "flow", "trace", "stop"])) { d.flowCount = 0; return ""; }
  if (match(r, ["sniffer", "packet"])) {
    const intf = raw[2] || "any";
    const filter = raw[3] || "none";
    const verbose = Number(raw[4] || 1);
    const count = Number(raw[5] || 0) || 100;
    const known = intf === "any" || lab.fgtIntfs(fg).some((i) => i.name === intf);
    if (!known) return `Interface ${intf} not found.`;
    d.sniffer = { intf, filter, verbose, left: count, total: count, start: lab.clock };
    fg.async.push(`Using Original Sniffing Mode\ninterfaces=[${intf}]\nfilters=[${filter === "none" ? "" : filter}]`);
    return "(capturing: generate traffic from another console, press Ctrl+C here to stop)";
  }
  if (match(r, ["sys", "session", "filter"])) {
    d.sessFilter = d.sessFilter || {};
    const k = r[3];
    if (!k) return Object.entries(d.sessFilter).map(([a, b]) => `${a}: ${b}`).join("\n") || "session filter: any";
    if ("clear".startsWith(k)) { d.sessFilter = {}; return ""; }
    d.sessFilter[k] = raw[4];
    return "";
  }
  if (match(r, ["sys", "session", "clear"])) { fg.sessions.clear(); fg.sessList = []; return ""; }
  if (match(r, ["sys", "session", "list"])) return sessionList(lab, fg);
  if (match(r, ["firewall", "iprope", "lookup"])) {
    // diagnose firewall iprope lookup <src> <sport> <dst> <dport> <proto> <dev>
    const [src, sport, dst, dport, proto, dev] = raw.slice(3);
    if (!dev) return "Usage: diagnose firewall iprope lookup <src_ip> <src_port> <dst_ip> <dst_port> <protocol> <dev>";
    const p = PROTO[String(proto).toLowerCase()] || Number(proto);
    const pkt = { src: ipToInt(src), dst: ipToInt(dst), proto: p, sport: Number(sport), dport: Number(dport), icmpType: 8 };
    const vip = lab.vipFor(fg, pkt, dev);
    const rt = lab.fgtLookup(fg, vip ? vip.dst : pkt.dst);
    if (!rt) return `<src [${src}-${sport}] dst [${dst}-${dport}] proto ${proto} dev ${dev}> no route to destination`;
    const pol = lab.policyLookup(fg, pkt, dev, rt.dev, vip && lab.policyLookup(fg, pkt, dev, rt.dev, vip) ? vip : null);
    return `<src [${src}-${sport}] dst [${dst}-${dport}] proto ${proto} dev ${dev}> matches policy id: ${pol ? pol.id : 0}`;
  }
  if (match(r, ["ip", "arp", "list"])) return getCmd(lab, fg, ["system", "arp"], ["system", "arp"]);
  if (match(r, ["sys", "top"])) return `Run Time:  12 days, 4 hours and 31 minutes\n0U, 0N, 1S, 99I, 0WA, 0HI, 0SI, 0ST; 3956T, 2365F\n          newcli      301      R       0.9     0.4  0\n       ipsengine      201      S <     0.0     4.1  1\n         miglogd      176      S       0.0     1.2  0\n          httpsd      152      S       0.0     0.9  1`;
  if (match(r, ["autoupdate", "versions"])) return `AV Engine\n---------\nVersion: 7.00034 signed\nContract Expiry Date: Thu Nov 26 2027\n\nVirus Definitions\n---------\nVersion: 93.01234 signed\nContract Expiry Date: Thu Nov 26 2027`;
  if (fg.schema.cmds.some((c) => c.startsWith("diagnose " + r.slice(0, 2).join(" ")))) return NOT_SIM;
  return `command parse error before '${raw[0] || ""}'\nCommand fail. Return code -61`;
}

function sessionList(lab, fg) {
  const f = (fg.dbg.sessFilter) || {};
  const list = (fg.sessList || []).filter((s) => {
    if (f.src && intToIp(s.orig.src) !== f.src) return false;
    if (f.dst && intToIp(s.orig.dst) !== f.dst) return false;
    if (f.dport && String(s.orig.dport) !== f.dport) return false;
    if (f.policy && String(s.policy) !== f.policy) return false;
    return true;
  });
  const out = [];
  for (const s of list.slice(-20)) {
    const o = s.orig;
    out.push(`session info: proto=${s.proto} proto_state=${s.proto === 6 ? "01" : "00"} duration=${Math.max(1, Math.round((lab.clock - s.start) / 1000))} expire=${s.proto === 6 ? 3596 : 59} timeout=${s.proto === 6 ? 3600 : 0} flags=00000000 socktype=0 sockport=0 av_idx=0 use=3`);
    out.push(`origin-shaper=\nreply-shaper=\nper_ip_shaper=\nclass_id=0 ha_id=0 policy_dir=0 tunnel=/ vlan_cos=0/255`);
    out.push(`state=may_dirty\nstatistic(bytes/packets/allow_err): org=84/1/1 reply=84/1/1 tuples=2`);
    out.push(`tx speed(Bps/kbps): 0/0 rx speed(Bps/kbps): 0/0`);
    out.push(`orgin->sink: org pre->post, reply pre->post dev=${s.in}->${s.out}/${s.out}->${s.in} gwy=${intToIp(s.gw)}/${intToIp(o.src)}`);
    const showPort = (p) => (s.proto === 1 ? o.sport : p);
    const dstSeen = s.dnat ? s.dnat.ip : o.dst;
    if (s.snat) {
      out.push(`hook=post dir=org act=snat ${intToIp(o.src)}:${showPort(o.sport)}->${intToIp(dstSeen)}:${showPort(s.dnat ? s.dnat.port : o.dport)}(${intToIp(s.snat.ip)}:${s.snat.port})`);
      out.push(`hook=pre dir=reply act=dnat ${intToIp(dstSeen)}:${showPort(s.dnat ? s.dnat.port : o.dport)}->${intToIp(s.snat.ip)}:${s.snat.port}(${intToIp(o.src)}:${showPort(o.sport)})`);
    } else if (s.dnat) {
      out.push(`hook=pre dir=org act=dnat ${intToIp(o.src)}:${showPort(o.sport)}->${intToIp(o.dst)}:${showPort(o.dport)}(${intToIp(s.dnat.ip)}:${showPort(s.dnat.port)})`);
      out.push(`hook=post dir=reply act=snat ${intToIp(s.dnat.ip)}:${showPort(s.dnat.port)}->${intToIp(o.src)}:${showPort(o.sport)}(${intToIp(o.dst)}:${showPort(o.dport)})`);
    } else {
      out.push(`hook=pre dir=org act=noop ${intToIp(o.src)}:${showPort(o.sport)}->${intToIp(o.dst)}:${showPort(o.dport)}(0.0.0.0:0)`);
      out.push(`hook=post dir=reply act=noop ${intToIp(o.dst)}:${showPort(o.dport)}->${intToIp(o.src)}:${showPort(o.sport)}(0.0.0.0:0)`);
    }
    out.push(`pos/(before,after) 0/(0,0), 0/(0,0)\nmisc=0 policy_id=${s.policy} pol_uuid_idx=${15800 + Number(s.policy || 0)} auth_info=0 chk_client_info=0 vd=0`);
    out.push(`serial=${hex(s.id)} tos=ff/ff app_list=0 app=0 url_cat=0\nrpdb_link_id=00000000 ngfwid=n/a\nnpu_state=0x000001 no_offload\nno_ofld_reason:  disabled-by-policy\n`);
  }
  out.push(`total session ${list.length}`);
  return out.join("\n");
}

function execCmd(lab, fg, r0, raw) {
  let r = r0;
  if (r[0] === "ping" || r[0] === "pin") r = ["ping", ...r.slice(1)];
  if (r[0] !== "ping" && (match(r, ["ping-options", "source"]) || match(r, ["ping-options", "reset"]))) {
    if (r[1].startsWith("r")) { fg.dbg.pingSrc = null; return ""; }
    const ip = ipToInt(raw[2]);
    if (ip === null || !lab.isLocal(fg, ip)) return `${raw[2] || ""}: invalid source address\nCommand fail. Return code -1`;
    fg.dbg.pingSrc = ip;
    return "";
  }
  if (r[0] !== "ping" && match(r, ["ping-options"])) return "";
  if (r[0] === "ping") {
    const target = raw[1];
    if (!target) return "Command fail. Return code -1";
    const res = lab.resolve(fg.id, target);
    if (res.err) return `Unable to resolve hostname.\nCommand fail. Return code -1`;
    const ip = res.ip;
    const out = [`PING ${target} (${intToIp(ip)}): 56 data bytes`];
    let ok = 0;
    const times = [];
    for (let i = 0; i < 5; i++) {
      const p = lab.probe(fg.id, { dst: ip, proto: 1, seq: i + 1, icmpId: 4100 + (lab.clock % 50) });
      if (p.ok) { ok++; const t = ms(lab.rand) + Math.round(lab.rand() * 10) / 10; times.push(t); out.push(`64 bytes from ${intToIp(ip)}: icmp_seq=${i} ttl=${p.reached === "INTERNET" ? 117 : 255} time=${t.toFixed(1)} ms`); }
    }
    out.push("", `--- ${target} ping statistics ---`, `5 packets transmitted, ${ok} packets received, ${Math.round((5 - ok) * 20)}% packet loss`);
    if (ok) out.push(`round-trip min/avg/max = ${Math.min(...times).toFixed(1)}/${(times.reduce((a, b) => a + b, 0) / ok).toFixed(1)}/${Math.max(...times).toFixed(1)} ms`);
    return out.join("\n");
  }
  if (match(r, ["traceroute"])) {
    const res = lab.resolve(fg.id, raw[1] || "");
    if (res.err) return `traceroute: unknown host ${raw[1]}`;
    return traceroute(lab, fg.id, res.ip, raw[1], "linux");
  }
  if (match(r, ["backup", "config"])) {
    const kind = r[2] || "";
    if (kind.startsWith("tf") || kind.startsWith("ft")) {
      const server = raw[4];
      const ip = ipToInt(server || "");
      if (ip === null) return "Command fail. Return code -1";
      const p = lab.probe(fg.id, { dst: ip, proto: kind.startsWith("tf") ? 17 : 6, dport: kind.startsWith("tf") ? 69 : 21 });
      if (!p.ok) return `Please wait...\n\nConnect to ${kind.startsWith("tf") ? "tftp" : "ftp"} server ${server} ...\nFailed to send config file to ${kind.startsWith("tf") ? "tftp" : "ftp"} server ${server}.\nCommand fail. Return code -1`;
      fg.backups = (fg.backups || []).concat({ ts: lab.clock, file: raw[3] });
      return `Please wait...\n\nConnect to ${kind.startsWith("tf") ? "tftp" : "ftp"} server ${server} ...\n#\nSend config file to ${kind.startsWith("tf") ? "tftp" : "ftp"} server OK.`;
    }
    if (kind.startsWith("fl") || kind.startsWith("us") || kind.startsWith("ma")) {
      fg.backups = (fg.backups || []).concat({ ts: lab.clock, file: raw[3] || "flash" });
      return `Please wait...\n\nSend config file to ${kind} OK.`;
    }
    return "Usage: execute backup config {flash|ftp|tftp|usb|management-station} ...";
  }
  if (match(r, ["dhcp", "lease-list"])) {
    const out = [];
    for (const i of lab.fgtIntfs(fg)) {
      const leases = [...lab.devices.values()].filter((h) => h.lease && h.lease.fgt === fg.id && h.lease.intf === i.name);
      if (!leases.length) continue;
      out.push(i.name, "  IP\t\t\tMAC-Address\t\tHostname\t\tVCI\t\tSSID\t\tAP\t\tSERVER-ID\t\tExpiry");
      for (const h of leases) out.push(`  ${intToIp(h.lease.prefix.ip)}\t\t${mac(h.id)}\t${h.hostname}\t\tMSFT 5.0\t\t\t\t\t\t1\t\tWed Dec  2 10:${String(lab.clock % 60).padStart(2, "0")}:00 2026`);
    }
    return out.join("\n") || "";
  }
  if (match(r, ["reboot"]) || match(r, ["factoryreset"]) || match(r, ["shutdown"])) return "Rebooting or resetting is disabled in FortiTatake labs: it would wipe the scenario.";
  if (match(r, ["log", "display"])) return "0 logs found.\n0 logs returned.";
  if (fg.schema.cmds.some((c) => c.startsWith("execute " + r.slice(0, 1).join(" ")))) return NOT_SIM;
  return `command parse error before '${raw[0] || ""}'\nCommand fail. Return code -61`;
}

function traceroute(lab, fromId, ip, name, style) {
  const out = style === "windows" ? [`Tracing route to ${name} [${intToIp(ip)}]`, `over a maximum of 30 hops:`, ``] : [`traceroute to ${name} (${intToIp(ip)}), 32 hops max, 3 probe packets per hop, 72 byte packets`];
  for (let ttl = 1; ttl <= 12; ttl++) {
    const res = lab.send(fromId, { src: srcOf(lab, fromId, ip), dst: ip, proto: 1, icmpType: 8, icmpId: 77, seq: ttl, ttl });
    let hopIp = null, done = false;
    if (res.delivered) { hopIp = ip; done = true; }
    else if (res.drop && res.drop.ttl) { const d = lab.dev(res.drop.dev); hopIp = res.drop.hopIp ?? (d.ifaces ? hopAddr(lab, d, res) : null); }
    else if (res.drop && !res.drop.ttl) {
      // a FortiGate on the path consumes ttl too: approximate with the gateways seen
      hopIp = null;
    }
    // FortiGates on the way count as hops
    const t1 = ms(lab.rand), t2 = ms(lab.rand), t3 = ms(lab.rand);
    if (hopIp !== null) out.push(style === "windows" ? `${String(ttl).padStart(3)}    ${t1} ms    ${t2} ms    ${t3} ms  ${intToIp(hopIp)}` : ` ${ttl}  ${intToIp(hopIp)}  ${t1}.${t2}${t3}0 ms  ${t2}.${t1}00 ms  ${t3}.${t2}10 ms`);
    else out.push(style === "windows" ? `${String(ttl).padStart(3)}     *        *        *     Request timed out.` : ` ${ttl}  * * *`);
    if (done || (res.drop && !res.drop.ttl && ttl > 3)) break;
  }
  if (style === "windows") out.push("", "Trace complete.");
  return out.join("\n");
}
function hopAddr(lab, router, res) {
  // the interface the probe came in on: the router interface on the segment of the previous device
  const prev = res.path[res.path.length - 2];
  for (const i of router.ifaces) {
    const seg = lab.segOf(router.id, i.name);
    if (seg && seg.members.some((m) => m.dev === prev)) return i.prefix.ip;
  }
  return router.ifaces[0] && router.ifaces[0].prefix.ip;
}
function srcOf(lab, fromId, dst) {
  const d = lab.dev(fromId);
  if (d instanceof FortiGate) { const rt = lab.fgtLookup(d, dst); const i = rt && lab.fgtIntfs(d).find((x) => x.name === rt.dev); return d.dbg.pingSrc || (i && i.prefix ? i.prefix.ip : 0); }
  return d.ip ? d.ip() : 0;
}

// ---------- PCs and servers ----------
export function hostRun(lab, h, line) {
  h.history.push({ line, ts: lab.clock });
  const t = tokenize(line.trim());
  if (!t.length) return "";
  const c = t[0].toLowerCase();
  const win = h.os === "windows";
  if (c === "help" || c === "?") return win
    ? "Commands: ipconfig [/all|/renew|/release], ping [-n N] [-l size] [-f] <host>, tracert <host>, nslookup <name>, curl [-k] [-I] <url>, tnc <host> -port <n>, login <user> <password>, forticlient connect|status|disconnect, cls"
    : "Commands: ip a, ip route, ping [-c N] [-s size] [-M do] <host>, traceroute <host>, nslookup|dig <name>, curl [-k] [-I] <url>, nc -zv <host> <port>, login <user> <password>, clear";
  if (c === "ipconfig" || (c === "ip" && t[1] && "address".startsWith(t[1])) || c === "ifconfig") {
    if (t[1] && t[1].toLowerCase() === "/renew") { const ok = lab.renew(h); if (!ok) return "An error occurred while renewing interface Ethernet0 : unable to contact your DHCP server. Request has timed out."; }
    if (t[1] && t[1].toLowerCase() === "/release") { h.lease = null; return "Ethernet adapter Ethernet0:\n\n   Media State . . . . . . . . . . . : Media disconnected"; }
    const a = h.addr();
    const gw = h.gateway();
    if (!win) return `2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP\n    link/ether ${mac(h.id)} brd ff:ff:ff:ff:ff:ff\n    inet ${a ? `${intToIp(a.ip)}/${a.len}` : "(none)"} scope global eth0`;
    const ipStr = a ? intToIp(a.ip) : `169.254.${(h.id.length * 37) % 255}.${(h.id.length * 11) % 255}`;
    const lines = [`Windows IP Configuration`, ``, `Ethernet adapter Ethernet0:`, ``, `   Connection-specific DNS Suffix  . : ${h.dhcp && h.lease ? "lab.local" : ""}`,
      `   IPv4 Address. . . . . . . . . . . : ${ipStr}${a ? "" : " (autoconfiguration, DHCP did not answer)"}`, `   Subnet Mask . . . . . . . . . . . : ${a ? maskStr(a.len) : "255.255.0.0"}`, `   Default Gateway . . . . . . . . . : ${gw ? intToIp(gw) : ""}`];
    if (t[1] && t[1].toLowerCase() === "/all") lines.push(`   DHCP Enabled. . . . . . . . . . . : ${h.dhcp ? "Yes" : "No"}`, ...(h.lease ? [`   DHCP Server . . . . . . . . . . . : ${intToIp(h.lease.server)}`] : []), `   DNS Servers . . . . . . . . . . . : ${h.dnsServers().map(intToIp).join("\n                                       ") || ""}`);
    return lines.join("\n");
  }
  if (c === "ip" && t[1] && "route".startsWith(t[1])) {
    const a = h.addr(); const gw = h.gateway();
    return `${gw ? `default via ${intToIp(gw)} dev eth0\n` : ""}${a ? `${prefixStr(a)} dev eth0 proto kernel scope link src ${intToIp(a.ip)}` : ""}`;
  }
  if (c === "ping") return hostPing(lab, h, t.slice(1), win);
  if (c === "tracert" || c === "traceroute") {
    const target = t[t.length - 1];
    const r = lab.resolve(h.id, target);
    if (r.err) return win ? `Unable to resolve target system name ${target}.` : `${target}: Name or service not known`;
    return traceroute(lab, h.id, r.ip, target, win ? "windows" : "linux");
  }
  if (c === "nslookup" || c === "dig") {
    const name = t[1];
    if (!name) return "Usage: nslookup <name>";
    const r = lab.resolve(h.id, name);
    const srv = r.server !== undefined ? intToIp(r.server) : "(none)";
    if (r.err) return `Server:  UnKnown\nAddress:  ${srv}\n\n*** ${r.err.includes("timed out") ? `Request to UnKnown timed-out` : `UnKnown can't find ${name}: Non-existent domain`}`;
    return `Server:  UnKnown\nAddress:  ${srv}\n\nNon-authoritative answer:\nName:    ${name}\nAddress:  ${intToIp(r.ip)}`;
  }
  if (c === "curl" || c === "wget") return hostCurl(lab, h, t.slice(1));
  if (c === "tnc" || c === "test-netconnection" || c === "nc") {
    let host, port;
    if (c === "nc") { host = t[t.length - 2]; port = Number(t[t.length - 1]); }
    else { host = t[1]; const i = t.findIndex((x) => /^-port$/i.test(x)); port = Number(i > 0 ? t[i + 1] : 80); }
    const r = lab.resolve(h.id, host);
    if (r.err) return `Name resolution of ${host} failed`;
    const p = lab.probe(h.id, { dst: r.ip, proto: 6, dport: port });
    if (c === "nc") return p.ok ? `Connection to ${host} ${port} port [tcp/*] succeeded!` : `nc: connect to ${host} port ${port} (tcp) failed: ${p.drop && p.drop.refused ? "Connection refused" : "Connection timed out"}`;
    return `ComputerName     : ${host}\nRemoteAddress    : ${intToIp(r.ip)}\nRemotePort       : ${port}\nInterfaceAlias   : Ethernet0\nSourceAddress    : ${intToIp(h.ip() || 0)}\nTcpTestSucceeded : ${p.ok ? "True" : "False"}`;
  }
  if (c === "login") return lab.hostLogin ? lab.hostLogin(h, t.slice(1)) : "No authentication page here.";
  if (c === "forticlient" || c === "fortivpn") return lab.forticlient ? lab.forticlient(h, t.slice(1)) : "FortiClient is not installed.";
  if (c === "ss" || c === "netstat") return [...h.services].filter((s) => s.startsWith("tcp/")).map((s) => `LISTEN 0 511 0.0.0.0:${s.slice(4)} 0.0.0.0:*`).join("\n") || "(no listening ports)";
  if (c === "hostname") return h.hostname;
  return win ? `'${t[0]}' is not recognized as an internal or external command,\noperable program or batch file. Type help for the commands this lab PC knows.` : `bash: ${t[0]}: command not found (type help)`;
}

function hostPing(lab, h, args, win) {
  let count = 4, size = win ? 32 : 56, df = false, target = null;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "-n" || a === "-c") count = Math.min(10, Number(args[++i]) || 4);
    else if (a === "-l" || a === "-s") size = Number(args[++i]) || size;
    else if (a === "-f") df = true;
    else if (a === "-M") { df = args[++i] === "do"; }
    else if (a === "-t") count = 6;
    else target = a;
  }
  if (!target) return win ? "Usage: ping [-n count] [-l size] [-f] target_name" : "Usage: ping [-c count] [-s size] [-M do] destination";
  const r = lab.resolve(h.id, target);
  if (r.err) return win ? `Ping request could not find host ${target}. Please check the name and try again.` : `ping: ${target}: Temporary failure in name resolution`;
  const ip = r.ip;
  const named = target !== intToIp(ip) ? `${target} [${intToIp(ip)}]` : intToIp(ip);
  const out = win ? [`Pinging ${named} with ${size} bytes of data:`] : [`PING ${target} (${intToIp(ip)}) ${size}(${size + 28}) bytes of data.`];
  let ok = 0;
  const times = [];
  let last = null;
  for (let i = 0; i < count; i++) {
    const p = lab.probe(h.id, { dst: ip, proto: 1, seq: i + 1, icmpId: 1, size: size + 28, df });
    last = p;
    if (p.ok) { ok++; const tm = ms(lab.rand) + (p.reached && p.reached.startsWith("INTERNET") ? 6 : 0); times.push(tm); out.push(win ? `Reply from ${intToIp(ip)}: bytes=${size} time=${tm}ms TTL=${p.reached === "INTERNET" ? 117 : 64}` : `${size + 8} bytes from ${intToIp(ip)}: icmp_seq=${i + 1} ttl=${p.reached === "INTERNET" ? 117 : 64} time=${tm}.${i}2 ms`); }
    else if (p.drop && p.drop.mtu) out.push(win ? "Packet needs to be fragmented but DF set." : `ping: local error: message too long, mtu=${p.drop.mtu}`);
    else if (p.drop && p.drop.dev === h.id && /no IP|gateway|ARP/.test(p.drop.reason)) out.push(win ? (/no IP/.test(p.drop.reason) ? "PING: transmit failed. General failure." : `Reply from ${intToIp(h.ip())}: Destination host unreachable.`) : `From ${intToIp(h.ip() || 0)} icmp_seq=${i + 1} Destination Host Unreachable`);
    else if (win) out.push("Request timed out.");
  }
  if (win) {
    out.push("", `Ping statistics for ${intToIp(ip)}:`, `    Packets: Sent = ${count}, Received = ${ok}, Lost = ${count - ok} (${Math.round(((count - ok) / count) * 100)}% loss),`);
    if (ok) out.push(`Approximate round trip times in milli-seconds:`, `    Minimum = ${Math.min(...times)}ms, Maximum = ${Math.max(...times)}ms, Average = ${Math.round(times.reduce((a, b) => a + b, 0) / ok)}ms`);
  } else {
    out.push("", `--- ${target} ping statistics ---`, `${count} packets transmitted, ${ok} received, ${Math.round(((count - ok) / count) * 100)}% packet loss, time ${count * 1001}ms`);
  }
  return out.join("\n");
}

function hostCurl(lab, h, args) {
  const url = args.find((a) => !a.startsWith("-"));
  if (!url) return "curl: try 'curl --help' for more information";
  const head = args.includes("-I") || args.includes("--head");
  const m = url.match(/^(https?):\/\/([^/:]+)(?::(\d+))?(\/.*)?$/i) || [null, "http", url.split("/")[0], null, "/"];
  const scheme = (m[1] || "http").toLowerCase(), host = m[2], port = Number(m[3] || (scheme === "https" ? 443 : 80));
  const r = lab.resolve(h.id, host);
  if (r.err) return `curl: (6) Could not resolve host: ${host}`;
  const p = lab.probe(h.id, { dst: r.ip, proto: 6, dport: port });
  if (!p.ok && p.drop && p.drop.auth && (port === 80 || port === 443)) {
    // identity-based policy: the FortiGate answers with its authentication page
    h.authPending = { fg: p.drop.auth.fg, policy: p.drop.auth.policy };
    const portal = `${intToIp(p.drop.auth.portal)}:${scheme === "https" ? 1003 : 1000}`;
    return `HTTP/1.1 303 See Other\nLocation: ${scheme === "https" ? "https" : "http"}://${portal}/fgtauth?0a1b2c3d4e5f6789\n${head ? "" : `\n<html><head><title>Firewall Authentication</title></head><body><h2>Authentication Required</h2><p>Please enter your username and password to continue.</p><form>Username: ____  Password: ____  [Continue]</form></body></html>\n(Type: login <user> <password>)`}`;
  }
  if (!p.ok) {
    if (p.drop && p.drop.refused) return `curl: (7) Failed to connect to ${host} port ${port} after 23 ms: Couldn't connect to server`;
    return `curl: (28) Failed to connect to ${host} port ${port} after 21003 ms: Timeout was reached`;
  }
  const fortiAdmin = p.fwd && p.fwd.localAnswer;
  const path = (m[4] || "/");
  const cloud = [...lab.devices.values()].find((d) => d.kind === "cloud" && d.hosts.some((x) => x.ip === p.seenDst));
  const ch = cloud && cloud.hosts.find((x) => x.ip === p.seenDst);
  const w = lab.webInspect ? lab.webInspect(h.id, p, { scheme, host, path, file: ch && ch.files[path] }) : { verdict: "allowed" };
  if (w.verdict === "cert-error") return `curl: (60) SSL certificate problem: unable to get local issuer certificate\nMore details here: https://curl.se/docs/sslcerts.html\n(The FortiGate re-signs ${host} with its own CA, which this device doesn't trust.)`;
  if (w.verdict === "blocked") return head ? `HTTP/1.1 403 Forbidden\nContent-Type: text/html; charset=utf-8` : `HTTP/1.1 403 Forbidden\nContent-Type: text/html; charset=utf-8\n\n${w.body}`;
  if (ch && ch.files[path] === "eicar" && !head) return `HTTP/1.1 200 OK\nContent-Type: application/octet-stream\nContent-Length: 68\n\nX5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H* (saved ${path.split("/").pop()})`;
  const body = fortiAdmin ? `HTTP/1.1 200 OK\nServer: xxxxxxxx-xxxxx\nContent-Type: text/html\nX-Frame-Options: SAMEORIGIN\n\n<!DOCTYPE html><title>FortiGate</title> ... (FortiGate login page)` : `HTTP/1.1 200 OK\nServer: nginx\nContent-Type: text/html; charset=UTF-8\nContent-Length: 612\n${head ? "" : `\n<html><head><title>${host}</title></head><body>It works: ${host} answered from ${intToIp(p.seenDst)}${p.seenSrc ? ` and saw the client as ${intToIp(p.seenSrc)}` : ""}.</body></html>`}`;
  return head ? body.split("\n\n")[0] : body;
}

// ---------- routers (read-only) ----------
export function routerRun(lab, r, line) {
  const t = line.trim().toLowerCase();
  if (!t) return "";
  if (t === "help" || t === "?") return `Commands: show ip interface brief, show ip route, ping <ip>${r.spec && r.spec.ospf ? ", show ip ospf neighbor" : ""}${r.spec && r.spec.bgp ? ", show ip bgp summary, show ip bgp" : ""}`;
  if (t.startsWith("show ip int")) return r.ifaces.map((i) => `${pad(i.name, 16)}${pad(i.prefix ? intToIp(i.prefix.ip) + "/" + i.prefix.len : "unassigned", 20)}${i.up ? "up" : "down"}`).join("\n");
  if (t.startsWith("show ip route")) return r.ifaces.filter((i) => i.prefix).map((i) => `C    ${prefixStr(i.prefix)} is directly connected, ${i.name}`).concat(r.routes.map((x) => `S    ${prefixStr(x.dst)} [1/0] via ${x.via ? intToIp(x.via) : "Internet uplink"}`)).concat(lab.routerDynamic(r).map((x) => `${x.type.padEnd(5)}${prefixStr(x.dst)} [${x.distance}/${x.metric || 0}] via ${intToIp(x.gw)}`)).join("\n");
  { const d = lab.routerShow && lab.routerShow(r, t); if (d !== null && d !== undefined) return d; }
  if (t.startsWith("ping")) {
    const ip = ipToInt(t.split(/\s+/)[1] || "");
    if (ip === null) return "% Invalid input";
    let ok = 0;
    for (let i = 0; i < 5; i++) if (lab.probe(r.id, { dst: ip, proto: 1, src: r.ifaces.find((x) => x.prefix && inPrefix(ip, x.prefix))?.prefix.ip ?? r.ifaces[0].prefix.ip }).ok) ok++;
    return `Type escape sequence to abort.\nSending 5, 100-byte ICMP Echos to ${intToIp(ip)}, timeout is 2 seconds:\n${"!".repeat(ok)}${".".repeat(5 - ok)}\nSuccess rate is ${ok * 20} percent (${ok}/5)`;
  }
  return `This router is read-only for you. Try: show ip interface brief, show ip route, ping <ip>${r.spec && r.spec.ospf ? ", show ip ospf neighbor" : ""}${r.spec && r.spec.bgp ? ", show ip bgp summary, show ip bgp" : ""}`;
}
