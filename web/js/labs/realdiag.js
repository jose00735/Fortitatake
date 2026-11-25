// FortiOS-style output from the real network: `diagnose sniffer packet` from tcpdump and
// `execute ping` from ping, both run inside the FortiGate's namespace on FortiTatake OS.

const LINE = /^(\d+\.\d+)\s+(\S+)\s+(In|Out|M|B|P)\s+IP\s+(\S+) > (\S+): (.*)$/;
const splitPort = (a) => { const i = a.lastIndexOf("."); return [a.slice(0, i), a.slice(i + 1)]; };

// one tcpdump line -> { ts, intf, dir, text } in FortiOS sniffer terms, or null
export function parseTcpdump(line) {
  const m = LINE.exec(line.trim());
  if (!m) return null;
  const [, ts, intf, dir, from, to, rest] = m;
  let text;
  if (rest.startsWith("ICMP")) {
    const what = rest.replace(/^ICMP\s+/, "").replace(/, id \d+.*$/, "").replace(/, length \d+$/, "");
    text = `${from} -> ${to}: icmp: ${what}`;
  } else if (rest.startsWith("Flags [")) {
    const fl = (/Flags \[([^\]]*)\]/.exec(rest) || [])[1] || "";
    const seq = (/seq (\d+)(?::\d+)?/.exec(rest) || [])[1];
    const ack = (/ack (\d+)/.exec(rest) || [])[1];
    const len = Number((/length (\d+)/.exec(rest) || [])[1] || 0);
    const [fa, fp] = splitPort(from), [ta, tp] = splitPort(to);
    const words = [];
    if (fl.includes("S")) words.push("syn " + (seq || 0));
    if (fl.includes("F")) words.push("fin " + (seq || 0));
    if (fl.includes("R")) words.push("rst " + (seq || 0));
    if (fl.includes("P")) words.push("psh " + (seq || 0));
    if (fl.includes(".")) words.push("ack " + (ack || 0));
    text = `${fa}.${fp} -> ${ta}.${tp}: ${words.join(" ") || "tcp"}${len && !fl.includes("S") ? "" : ""}`;
  } else {
    const len = (/\((\d+)\)\s*$/.exec(rest) || /length (\d+)/.exec(rest) || [])[1] || 0;
    const [fa, fp] = splitPort(from), [ta, tp] = splitPort(to);
    text = /^\d+$/.test(fp) ? `${fa}.${fp} -> ${ta}.${tp}: udp ${len}` : `${from} -> ${to}: ${rest}`;
  }
  return { ts: Number(ts), intf, dir: dir === "Out" ? "out" : "in", text };
}

// parse "diagnose sniffer packet <intf> '<filter>' <verbose> <count> <a|l>"
export function parseSnifferCmd(line) {
  const m = /^\s*diag(?:n|no|nos|nose)?\s+sniffer\s+packet(?:\s+(\S+))?(?:\s+(?:'([^']*)'|"([^"]*)"|(\S+)))?(?:\s+(\d+))?(?:\s+(\d+))?(?:\s+([al]))?\s*$/i.exec(line);
  if (!m) return null;
  const filter = (m[2] ?? m[3] ?? m[4] ?? "none").trim();
  return { intf: m[1] || "any", filter: filter === "none" ? "" : filter, verbose: Number(m[5] || 1), count: Number(m[6] || 0), abs: m[7] === "a" };
}

export const safeFilter = (f) => /^[A-Za-z0-9 .:/()!&|<>=\-]*$/.test(f) ? f : null;

export function snifferHeader(s) {
  return `Using Original Sniffing Mode\ninterfaces=[${s.intf}]\nfilters=[${s.filter}]`;
}

export function snifferLine(s, p) {
  if (s.intf !== "any" && p.intf !== s.intf) return null;
  if (p.intf === "lo") return null;
  if (s.t0 === undefined) s.t0 = p.ts;
  let t;
  if (s.abs) { const d = new Date(p.ts * 1000); t = d.toISOString().replace("T", " ").replace("Z", "").slice(0, 26); }
  else t = (p.ts - s.t0).toFixed(6);
  return s.verbose >= 4 ? `${t} ${p.intf} ${p.dir} ${p.text}` : `${t} ${p.text}`;
}

// busybox/iputils ping output -> FortiOS execute ping wording
export function fortiPing(text) {
  return text.replace(/seq=(\d+)/g, "icmp_seq=$1").replace(/\bPING (\S+) \((\S+)\): (\d+) data bytes/, "PING $1 ($2): $3 data bytes");
}

// ---------------------------------------------------------------- diagnose debug flow

const hex8 = (n) => (n >>> 0).toString(16).padStart(8, "0");
const hash = (s) => { let h = 2166136261; for (const c of s) { h ^= c.charCodeAt(0); h = Math.imul(h, 16777619) >>> 0; } return h; };

// nftables rules that mark the packets FortiOS's flow filter selects (OR = several rules)
export function traceRules(f, ip) {
  let alts = [[]];
  const or = (opts) => { alts = alts.flatMap((a) => opts.map((o) => [...a, o])); };
  if (f.addr) or([`ip saddr ${ip(f.addr)}`, `ip daddr ${ip(f.addr)}`]);
  if (f.saddr) or([`ip saddr ${ip(f.saddr)}`]);
  if (f.daddr) or([`ip daddr ${ip(f.daddr)}`]);
  if (f.proto) or([`ip protocol ${f.proto}`]);
  if (f.port) or([`th sport ${f.port}`, `th dport ${f.port}`]);
  const rules = alts.map((a) => `  ${a.join(" ")} meta nftrace set 1`.replace(/^ {2} /, "  "));
  return `table ip ftktrace {\n chain p {\n  type filter hook prerouting priority -350; policy accept;\n${rules.join("\n")}\n }\n}\n`;
}

// nft monitor trace -> FortiOS debug flow lines. ctx: { routeGw(dst) -> "a.b.c.d", natIp(oif) -> ip, onTrace(lines) }
export class FlowTrace {
  constructor(ctx) { this.ctx = ctx; this.t = new Map(); this.order = []; this.n = 0; this.seen = new Set(); }
  feed(line) {
    const m = /^trace id (\w+) ip (\S+) (\S+) (packet: (.*)|rule (.*) \(verdict (\w+)\)|policy (\w+)|verdict (\w+))\s*$/.exec(line.trim());
    if (!m) return;
    const [, id, table, chain, , pkt, rule, rverdict, policy] = m;
    let t = this.t.get(id);
    if (!t) {
      if (!(table === "ftktrace" && pkt)) return;
      for (const old of this.order.splice(0)) this.finish(old); // a new packet: the previous one is done
      t = { id, facts: {} };
      this.t.set(id, t);
      this.order.push(id);
    }
    const f = t.facts;
    if (pkt) {
      const p = parsePkt(pkt);
      if (table === "ftktrace") f.pkt = p;
      else if (chain === "ftk_pre") f.newSess = true;
      else if (chain === "ftk_fwd") { f.fwd = true; f.oif = p.oif; }
      else if (chain === "ftk_in") f.local = true;
      return;
    }
    if (table !== "ftk") return;
    if (rule) {
      const mark = /ct mark set (0x[0-9a-f]+|\d+)/.exec(rule);
      if (chain === "ftk_pre" && /dnat/.test(rule)) f.dnat = (/dnat ip to (\S+)/.exec(rule) || [])[1];
      if (chain === "ftk_fwd") {
        if (/ct state established/.test(rule)) { f.est = true; this.finish(id); }
        else if (mark) { f.policy = Number(mark[1]); f.verdict = rverdict; if (rverdict !== "accept") this.finish(id); }
        else if (rverdict === "drop") { f.verdict = "drop"; this.finish(id); }
      }
      if (chain === "ftk_post") { if (/masquerade|snat/.test(rule)) f.snat = (/snat ip to (\S+)/.exec(rule) || [])[1] || "masq"; this.finish(id); }
      if (chain === "ftk_in") { f.inVerdict = rverdict; if (/established/.test(rule)) f.est = true; this.finish(id); }
    } else if (policy) {
      if (chain === "ftk_fwd" && policy === "drop") { f.verdict = "drop"; f.policy = 0; this.finish(id); }
      if (chain === "ftk_in") { f.inVerdict = policy; this.finish(id); }
      if (chain === "ftk_post") this.finish(id);
    }
  }
  finish(id) {
    const t = this.t.get(id);
    if (!t || t.done) return;
    t.done = true;
    this.t.delete(id);
    this.order = this.order.filter((x) => x !== id);
    const f = t.facts, p = f.pkt;
    if (!p) return;
    const L = [];
    const tid = ++this.n;
    const sid = hex8(hash([p.src, p.dst].sort().join() + [p.sport, p.dport].sort().join() + p.proto));
    const fwdKey = `${p.src}:${p.sport}>${p.dst}:${p.dport}`, revKey = `${p.dst}:${p.dport}>${p.src}:${p.sport}`;
    const shownDport = p.proto === 1 ? (p.icmpType || 0) * 256 : p.dport;
    L.push(["print_pkt_detail", 5939, `vd-root:0 received a packet(proto=${p.proto}, ${p.src}:${p.sport}->${p.dst}:${shownDport}) tun_id=0.0.0.0 from ${p.iif}.${p.proto === 1 ? ` type=${p.icmpType || 0}, code=0, id=${p.sport}, seq=${p.icmpSeq || 0}.` : p.proto === 6 ? ` flag [${p.flags}], win ${p.win || 0}` : ""}`]);
    if (f.est) L.push(["resolve_ip_tuple_fast", 5800, `Find an existing session, id-${sid}, ${this.seen.has(revKey) ? "reply" : "original"} direction`]);
    else if (f.newSess) {
      this.seen.add(fwdKey);
      L.push(["init_ip_session_common", 6120, `allocate a new session-${sid}, tun_id=0.0.0.0`]);
      L.push(["iprope_dnat_check", 5480, `in-[${p.iif}], out-[]`]);
      if (f.dnat) {
        L.push(["iprope_dnat_check", 5505, `result: skb_flags-02000000, vid-0, ret-matched, act-accept, flag-00000000`]);
        const [dip, dport] = f.dnat.split(":");
        L.push(["get_new_addr", 1219, `find DNAT: IP-${dip}, port-${dport || p.dport}(fixed port)`]);
      } else L.push(["iprope_dnat_check", 5505, `result: skb_flags-02000000, vid-0, ret-no-match, act-accept, flag-00000000`]);
    }
    const dst = f.dnat ? f.dnat.split(":")[0] : p.dst;
    if (f.local) {
      L.push(["__vf_ip_route_input_rcu", 1988, `find a route: flag=84000000 gw-${dst} via root`]);
      if (f.inVerdict === "drop") L.push(["iprope_in_check", 1029, `iprope_in_check() check failed on policy 0, drop`]);
    } else if (f.fwd) {
      L.push(["__vf_ip_route_input_rcu", 1988, `find a route: flag=04000000 gw-${this.ctx.routeGw(dst) || dst} via ${f.oif}`]);
      if (!f.est) {
        L.push(["__iprope_fwd_check", 810, `in-[${p.iif}], out-[${f.oif}], skb_flags-02000000, vid-0, app_id: 0, url_cat_id: 0`]);
        if (f.verdict === "accept") {
          L.push(["fw_forward_handler", 930, `Allowed by Policy-${f.policy}:${f.snat ? " SNAT" : ""}`]);
          if (f.snat) L.push(["__ip_session_run_tuple", 3500, `SNAT ${p.src}->${f.snat === "masq" ? this.ctx.natIp(f.oif) : f.snat.split("-")[0]}:${p.sport}`]);
          if (f.dnat) L.push(["__ip_session_run_tuple", 3500, `DNAT ${p.dst}:${p.dport}->${f.dnat.includes(":") ? f.dnat : f.dnat + ":" + p.dport}`]);
        } else L.push(["fw_forward_handler", 930, `Denied by forward policy check (policy ${f.policy || 0})`]);
      }
    } else if (!f.est) {
      L.push(["__vf_ip_route_input_rcu", 1988, `find a route: flag=00000000 gw-0.0.0.0 via root`]);
      L.push(["ip_route_input_slowpath", 2210, `no route to destination ${dst} or reverse path check fail, drop`]);
    }
    const idn = 20000 + (tid * 7) % 9000;
    this.ctx.onTrace(L.map(([fn, ln, msg]) => `id=${idn} trace_id=${tid} func=${fn} line=${ln} msg="${msg}"`));
  }
}

function parsePkt(s) {
  const g = (re) => (re.exec(s) || [])[1];
  const proto = /\bicmp type\b/.test(s) ? 1 : /\btcp sport\b/.test(s) ? 6 : /\budp sport\b/.test(s) ? 17 : Number(g(/ip protocol (\d+)/) || 0);
  const icmpTypes = { "echo-request": 8, "echo-reply": 0, "destination-unreachable": 3, "time-exceeded": 11 };
  const fl = g(/tcp flags == (\S+)/) || "";
  const flags = fl.split("|").map((x) => ({ syn: "S", ack: ".", fin: "F", rst: "R", psh: "P" }[x] || "")).join("") || "?";
  return {
    iif: g(/iif "([^"]+)"/), oif: g(/oif "([^"]+)"/), src: g(/ip saddr (\S+)/), dst: g(/ip daddr (\S+)/), proto,
    sport: Number(g(/(?:tcp|udp) sport (\d+)/) || g(/icmp id (\d+)/) || 0), dport: Number(g(/(?:tcp|udp) dport (\d+)/) || 0),
    icmpType: icmpTypes[g(/icmp type (\S+)/)] ?? Number(g(/icmp type (\d+)/) || 0), icmpSeq: Number(g(/icmp sequence (\d+)/) || 0),
    flags: flags.includes("S") && flags.includes(".") ? "S." : flags, win: g(/tcp window (\d+)/),
  };
}

// ---------------------------------------------------------------- diagnose sys session list

// conntrack -L (with accounting) -> sessions
export function parseConntrack(text) {
  const out = [];
  for (const line of text.split("\n")) {
    const m = /^(\w+)\s+(\d+)\s+(\d+)\s+(.*)$/.exec(line.trim());
    if (!m) continue;
    const [, , pnum, expire, rest] = m;
    const kv = [...rest.matchAll(/(\w+)=(\S+)/g)].map((x) => [x[1], x[2]]);
    const half = (n) => { const o = {}; let seen = 0; for (const [k, v] of kv) { if (k === "src") seen++; if (seen === n && ["src", "dst", "sport", "dport", "packets", "bytes", "id", "type", "code"].includes(k) && !(k in o)) o[k] = v; } return o; };
    const org = half(1), rep = half(2);
    const g = (k) => (kv.find((x) => x[0] === k) || [])[1];
    out.push({ proto: Number(pnum), expire: Number(expire), state: (/^[A-Z_]+/.exec(rest) || [""])[0], org, rep, mark: Number(g("mark") || 0), id: Number(g("id") || 0) });
  }
  return out;
}

export function formatSessions(list, ctx, filter = {}) {
  const sel = list.filter((s) => (!filter.src || s.org.src === filter.src) && (!filter.dst || s.org.dst === filter.dst) && (!filter.dport || s.org.dport === String(filter.dport)) && (!filter.policy || String(s.mark) === String(filter.policy)));
  const out = [];
  for (const s of sel) {
    const o = s.org, r = s.rep;
    const icmp = s.proto === 1;
    const sp = icmp ? (o.id || 0) : o.sport, dp = icmp ? (o.id || 0) : o.dport;
    const inIf = ctx.ifFor(o.src) || "?", outIf = ctx.ifFor(r.src) || "?";
    out.push(`session info: proto=${s.proto} proto_state=${s.proto === 6 ? (s.state === "ESTABLISHED" ? "01" : "00") : "00"} duration=${ctx.age(s)} expire=${s.expire} timeout=${s.proto === 6 ? 3600 : s.proto === 17 ? 180 : 60} flags=00000000 socktype=0 sockport=0 av_idx=0 use=3`);
    out.push(`origin-shaper=\nreply-shaper=\nper_ip_shaper=\nclass_id=0 ha_id=0 policy_dir=0 tunnel=/ vlan_cos=0/255`);
    out.push(`state=may_dirty\nstatistic(bytes/packets/allow_err): org=${o.bytes || 0}/${o.packets || 0}/1 reply=${r.bytes || 0}/${r.packets || 0}/1 tuples=2`);
    out.push(`tx speed(Bps/kbps): 0/0 rx speed(Bps/kbps): 0/0`);
    out.push(`orgin->sink: org pre->post, reply pre->post dev=${inIf}->${outIf}/${outIf}->${inIf} gwy=${ctx.routeGw(r.src) || r.src}/${o.src}`);
    const snat = r.dst !== o.src || (!icmp && r.dport !== o.sport), dnat = r.src !== o.dst || (!icmp && r.sport !== o.dport);
    if (snat) {
      out.push(`hook=post dir=org act=snat ${o.src}:${sp}->${r.src}:${icmp ? sp : r.sport}(${r.dst}:${icmp ? sp : r.dport})`);
      out.push(`hook=pre dir=reply act=dnat ${r.src}:${icmp ? sp : r.sport}->${r.dst}:${icmp ? sp : r.dport}(${o.src}:${sp})`);
    } else if (dnat) {
      out.push(`hook=pre dir=org act=dnat ${o.src}:${sp}->${o.dst}:${dp}(${r.src}:${icmp ? sp : r.sport})`);
      out.push(`hook=post dir=reply act=snat ${r.src}:${icmp ? sp : r.sport}->${o.src}:${sp}(${o.dst}:${dp})`);
    } else {
      out.push(`hook=pre dir=org act=noop ${o.src}:${sp}->${o.dst}:${dp}(0.0.0.0:0)`);
      out.push(`hook=post dir=reply act=noop ${o.dst}:${dp}->${o.src}:${sp}(0.0.0.0:0)`);
    }
    out.push(`pos/(before,after) 0/(0,0), 0/(0,0)\nmisc=0 policy_id=${s.mark} pol_uuid_idx=${15800 + s.mark} auth_info=0 chk_client_info=0 vd=0`);
    out.push(`serial=${hex8(s.id || hash(o.src + o.dst + sp + dp))} tos=ff/ff app_list=0 app=0 url_cat=0\nrpdb_link_id=00000000 ngfwid=n/a\nnpu_state=0x000001 no_offload\nno_ofld_reason:  disabled-by-policy\n`);
  }
  out.push(`total session ${sel.length}`);
  return out.join("\n");
}

// ---------------------------------------------------------------- get router info routing-table all

export function formatRoutes(kernel, simRoutes) {
  const head = [`Codes: K - kernel, C - connected, S - static, R - RIP, B - BGP`, `       O - OSPF, IA - OSPF inter area`, `       N1 - OSPF NSSA external type 1, N2 - OSPF NSSA external type 2`, `       E1 - OSPF external type 1, E2 - OSPF external type 2`, `       i - IS-IS, L1 - IS-IS level-1, L2 - IS-IS level-2, ia - IS-IS inter area`, `       V - BGP VPNv4`, `       * - candidate default`, ``, `Routing table for VRF=0`];
  const key = (d) => (d === "default" ? "0.0.0.0/0" : d.includes("/") ? d : d + "/32");
  const rows = kernel.filter((r) => !r.table || r.table === "main").map((r) => ({ ...r, k: key(r.dst) }));
  const ipn = (p) => p.split("/")[0].split(".").reduce((a, b) => a * 256 + Number(b), 0);
  rows.sort((a, b) => ipn(a.k) - ipn(b.k) || Number(a.k.split("/")[1]) - Number(b.k.split("/")[1]));
  const lines = [...head];
  for (const r of rows) {
    const sim = simRoutes.find((x) => x.k === r.k);
    if (r.type === "blackhole") { lines.push(`${("S" + (r.k === "0.0.0.0/0" ? "*" : "")).padEnd(8)}${r.k} [${sim ? sim.distance : 10}/0] is a summary, Null, [${sim ? sim.priority || 1 : 1}/0]`); continue; }
    if (r.protocol === "kernel" && r.scope === "link") { lines.push(`${"C".padEnd(8)}${r.k} is directly connected, ${r.dev}`); continue; }
    const type = sim ? sim.type : "S";
    const code = (type + (r.k === "0.0.0.0/0" ? "*" : "")).padEnd(8);
    const dist = sim ? sim.distance : 10;
    if (type.startsWith("O") || type === "B") lines.push(`${code}${r.k} [${dist}/${sim.metric || 0}] via ${r.gateway}, ${r.dev}, 00:12:41`);
    else if (r.gateway) lines.push(`${code}${r.k} [${dist}/0] via ${r.gateway}, ${r.dev}, [${sim ? sim.priority || 1 : 1}/0]`);
    else lines.push(`${code}${r.k} [${dist}/0] is directly connected, ${r.dev}, [${sim ? sim.priority || 1 : 1}/0]`);
  }
  return lines.join("\n");
}

// lookups over the compiled lab for one FortiGate (next hop, egress interface, interface IP)
export function routeHelpers(c, fgId) {
  const toN = (ip) => ip.split(".").reduce((a, b) => a * 256 + Number(b), 0);
  const inP = (ip, cidr) => { const [n, l] = cidr.split("/"); const len = Number(l); return len === 0 || Math.floor(toN(ip) / 2 ** (32 - len)) === Math.floor(toN(n) / 2 ** (32 - len)); };
  const addrs = c.topo.addrs.filter((a) => a.dev === fgId);
  const routes = c.topo.routes.filter((r) => r.dev === fgId).map((r) => ({ ...r, cidr: r.dst === "default" ? "0.0.0.0/0" : r.dst }));
  const best = (ip) => {
    let b = null;
    for (const a of addrs) { const [n, l] = a.cidr.split("/"); const net = `${n}/${l}`; if (Number(l) < 32 && inP(ip, net) && (!b || Number(l) > b.len)) b = { len: Number(l), dev: a.if, gw: ip }; }
    for (const r of routes) { const len = Number(r.cidr.split("/")[1]); if (inP(ip, r.cidr) && (!b || len > b.len)) b = { len, dev: r.if || (r.via && best0(r.via)), gw: r.via || ip }; }
    return b;
  };
  const best0 = (ip) => { for (const a of addrs) { const [n, l] = a.cidr.split("/"); if (Number(l) < 32 && inP(ip, `${n}/${l}`)) return a.if; } return null; };
  return {
    routeGw: (ip) => (best(ip) || {}).gw,
    ifFor: (ip) => (best(ip) || {}).dev,
    natIp: (oif) => ((addrs.find((a) => a.if === oif && !a.cidr.endsWith("/32")) || {}).cidr || "0.0.0.0/0").split("/")[0],
  };
}
