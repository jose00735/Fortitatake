// Real-network checks: the lab compiled onto FortiTatake OS, probes sent by the Linux kernel.
// The simulator still tells the story (which policy, which NAT); the kernel decides pass or fail.
// When the two disagree, the result says so, so simulator bugs show up instead of hiding.
import { compile, unsupported } from "./compile.js";
import { probeCheck, parseFrom, runChecks, checkOne } from "./grader.js";
import { ipToInt, intToIp } from "./net.js";

export class RealNet {
  // call(req, timeoutMs) sends one request to the agent and resolves with its reply
  constructor(call) { this.call = call; this.key = null; this.c = null; this.applyMs = 0; }

  stateKey(lab) {
    const cloud = [...lab.devices.values()].find((d) => d.kind === "cloud");
    // lab.ver misses some edits (policy moves), so the FortiGates' config text is part of the key
    let h = 2166136261;
    for (const d of lab.devices.values()) if (d.showAll) for (const ch of d.showAll(false)) { h ^= ch.charCodeAt(0); h = Math.imul(h, 16777619) >>> 0; }
    const leases = [...lab.devices.values()].map((d) => (d.lease ? d.lease.prefix.ip : "")).join(",");
    return `${lab.ver}|${cloud ? cloud.hosts.length : 0}|${Math.floor(lab.clock / 60000)}|${h}|${leases}`;
  }

  // Bring the VM's network in line with the lab. Only what changed is redone: a policy edit
  // reloads that FortiGate's nftables; addresses, routes or cabling rebuild the network
  // (which also ends any open Linux shells: `generation` goes up).
  async apply(lab) {
    while (this.busy) await this.busy;
    let done;
    this.busy = new Promise((r) => (done = r));
    try { return await this.applyNow(lab); } finally { this.busy = null; done(); }
  }

  async applyNow(lab) {
    const why = unsupported(lab);
    if (why.length) throw Object.assign(new Error(`stays on the simulator: ${why.join(", ")}`), { unsupported: true });
    const k = this.stateKey(lab);
    if (k === this.key && this.c) return this.c;
    const t = Date.now();
    if (this.agentVer === undefined) { const h = await this.call({ op: "hello" }, 5000).catch(() => ({})); this.agentVer = h.ver || "0"; this.agentIke = h.ike !== false; }
    lab.agentVer = this.agentVer;
    lab.agentIke = this.agentIke;
    const c = compile(lab);
    const prev = this.c;
    const topoSame = prev && JSON.stringify(prev.topo) === JSON.stringify(c.topo);
    if (!topoSame) {
      await this.call({ op: "topo.apply", topo: c.topo }, 60000);
      this.generation = (this.generation || 0) + 1;
    }
    this.nftReloaded = [];
    for (const [ns, ruleset] of Object.entries(c.nft)) if (!topoSame || prev.nft[ns] !== ruleset) { await this.call({ op: "ns.nft", ns, ruleset }, 15000); this.nftReloaded.push(ns); }
    // IPsec tunnels and routes through them (ip -force: "link del" of a tunnel that isn't there yet is fine)
    for (const [ns, lines] of Object.entries(c.extra || {})) {
      if (!lines.length || (topoSame && prev.extra && JSON.stringify(prev.extra[ns]) === JSON.stringify(lines))) continue;
      await this.call({ op: "ns.exec", ns, argv: ["ip", "-force", "-batch", "-"], input: lines.join("\n") + "\n" }, 15000);
    }
    for (const l of c.listen) {
      const old = topoSame && prev.listen.find((x) => x.ns === l.ns);
      if (!old || JSON.stringify(old) !== JSON.stringify(l)) await this.call({ op: "listen.start", ...l }, 10000);
    }
    // the IPS engine reads the queues the ruleset just made (a reload of the ruleset drops its block set)
    for (const [ns, rq] of Object.entries(c.ips || {})) {
      if (!this.nftReloaded.includes(ns) && prev && prev.ips && JSON.stringify(prev.ips[ns]) === JSON.stringify(rq)) continue;
      try { await this.call(rq, 10000); this.ipsErr = null; } catch (e) { this.ipsErr = `${ns}: ${e.message}`; }
    }
    // FRR (stage 4): OSPF and BGP for real; a config change restarts that device's FRR, sessions come back in seconds
    this.frrErr = null;
    for (const [ns, f] of Object.entries(c.frr || {})) {
      if (topoSame && prev.frr && prev.frr[ns] && prev.frr[ns].conf === f.conf) continue;
      try { const r = await this.call({ op: "frr.apply", ns, conf: f.conf, daemons: f.daemons }, 30000); if (r.error) this.frrErr = `${ns}: ${r.error}`; } catch (e) { this.frrErr = `${ns}: ${e.message}`; }
      this.frrPending = Date.now();
    }
    if (topoSame && prev.frr) for (const ns of Object.keys(prev.frr)) if (!(c.frr || {})[ns]) await this.call({ op: "frr.apply", ns, conf: "" }, 15000).catch(() => {});
    // strongSwan (stage 6): any IKE change restarts every charon in the lab, so both ends start from a clean slate
    this.ikeErr = null;
    const ikeKey = JSON.stringify(Object.entries(c.ike || {}).map(([ns, x]) => [ns, x.conf]));
    const prevKey = topoSame && prev.ike ? JSON.stringify(Object.entries(prev.ike).map(([ns, x]) => [ns, x.conf])) : null;
    if (ikeKey !== prevKey) {
      if (topoSame && prev.ike) for (const ns of Object.keys(prev.ike)) if (!(c.ike || {})[ns]) await this.call({ op: "ipsec.apply", ns, conf: "" }, 15000).catch(() => {});
      for (const [ns, x] of Object.entries(c.ike || {})) {
        try { const r = await this.call({ op: "ipsec.apply", ns, conf: x.conf }, 25000); if (r.error) this.ikeErr = `${ns}: ${r.error}`; } catch (e) { this.ikeErr = `${ns}: ${e.message}`; }
      }
      if (Object.keys(c.ike || {}).length) this.ikePending = Date.now();
    }
    this.c = c;
    this.key = k;
    this.applyMs = Date.now() - t;
    this.lastFull = !topoSame;
    return c;
  }

  // one probe from a device; returns {pass, error, reached, seenSrc, seenDst}
  // FRR needs a moment after a (re)start: OSPF waits a dead interval before electing a DR, BGP
  // retries every few seconds. Wait until every route the simulator expects is in the kernel (60 s at most).
  async frrSettle(lab, maxMs = 60000) {
    if (!this.frrPending || !this.c || !this.c.frr) return;
    const expect = {};
    for (const ns of Object.keys(this.c.frr)) {
      const d = lab.dev(ns);
      const dyn = d && d.kind === "router" ? lab.routerDynamic(d) : d ? lab.fgtRoutes(d).active.filter((r) => /^(O|B)/.test(r.type) && !r.inactive) : [];
      expect[ns] = [...new Set(dyn.map((r) => (r.dst.len === 0 ? "default" : `${intToIp(r.dst.ip)}/${r.dst.len}`).replace(/\/32$/, "")))];
    }
    const until = this.frrPending + maxMs;
    while (Date.now() < until) {
      let missing = 0;
      for (const [ns, want] of Object.entries(expect)) {
        if (!want.length) continue;
        const r = await this.call({ op: "ns.exec", ns, argv: ["ip", "-4", "route", "show"] }, 8000).catch(() => ({ stdout: "" }));
        const have = new Set((r.stdout || "").split("\n").map((l) => l.split(" ")[0]));
        missing += want.filter((p) => !have.has(p)).length;
      }
      if (!missing) break;
      await new Promise((res) => setTimeout(res, 1500));
    }
    this.frrPending = 0;
  }

  // IKE needs a moment too: wait until every child SA the simulator expects up is installed (15 s at most)
  async ikeSettle(maxMs = 15000) {
    if (!this.ikePending || !this.c || !this.c.ike) return;
    const until = this.ikePending + maxMs;
    while (Date.now() < until) {
      let missing = 0;
      for (const [ns, x] of Object.entries(this.c.ike)) {
        const want = Object.entries(x.up || {}).filter(([, ch]) => ch.length);
        if (!want.length) continue;
        const r = await this.call({ op: "ipsec.show", ns }, 8000).catch(() => ({ sas: {} }));
        for (const [conn, ch] of want) for (const n of ch) if (!(r.sas && r.sas[conn] && r.sas[conn].children && r.sas[conn].children[n] === "INSTALLED")) missing++;
      }
      if (!missing) break;
      await new Promise((res) => setTimeout(res, 500));
    }
    this.ikePending = 0;
  }

  async probe(lab, from, dst, proto, port) {
    const c = await this.apply(lab);
    await this.frrSettle(lab);
    await this.ikeSettle();
    const since = proto === "icmp" ? 0 : (await this.call({ op: "listen.log", ns: "-" }, 3000)).seq;
    const base = { op: "probe", ns: from, dst: intToIp(dst), timeout_ms: 1500 };
    let r;
    if (proto === "icmp") r = await this.call({ ...base, proto: "icmp", count: 1 }, 8000);
    else r = await this.call({ ...base, proto, port }, 8000);
    // who saw it: the device that owns the address, or (through a VIP) whoever logged the connection
    let seen = null, target = c.where[dst] || null;
    if (proto !== "icmp") {
      const owners = [...new Set(Object.values(c.where))];
      const deadline = Date.now() + (proto === "udp" ? 800 : 400);
      while (!seen) {
        for (const ns of owners) {
          const lg = await this.call({ op: "listen.log", ns, since_seq: since }, 3000).catch(() => null);
          const h = lg && (lg.hits || []).filter((x) => x.proto === proto && x.src !== "127.0.0.1").pop();
          if (h && (!seen || h.seq > seen.seq)) seen = { ...h, ns };
        }
        if (seen || Date.now() > deadline) break;
        await new Promise((res) => setTimeout(res, 60));
      }
      if (seen) target = seen.ns;
    }
    const pass = proto === "udp" ? !!seen : !!r.pass;
    return { pass, error: r.error || (pass ? null : proto === "udp" ? "no answer" : "timeout"), detail: r.detail, reached: target, seenSrc: seen ? ipToInt(seen.src) : undefined, seenDst: seen ? ipToInt(seen.dst) : undefined, ms: r.ms };
  }
}

const sentence = (r) => ({
  refused: "the destination answered with a TCP reset (nothing listening there, or the FortiGate itself refused it)",
  timeout: "the packets were dropped on the way (no answer before the timeout)",
  unreachable: "the network sent back \"unreachable\" (no route)",
  reset: "the connection was reset",
  "no answer": "nothing arrived at a server",
}[r.error] || r.error || "it failed");

// A probe check on the real network; the simulator's result is used for the explanation.
export async function realProbeCheck(lab, real, pr) {
  const sim = probeCheck(lab, pr);
  const { id, src } = parseFrom(lab, pr.from);
  if (src !== undefined || pr.as || pr.at || pr.fresh || pr.on) return { ...sim, engine: "sim" }; // not compiled yet
  let dst = pr.to;
  if (String(dst).startsWith("@")) { const d = lab.dev(dst.slice(1)); dst = d && d.ip ? d.ip() : null; }
  else if (!/^\d+\.\d+\.\d+\.\d+$/.test(dst)) { const r = lab.resolve(id, dst); dst = r.ip || null; }
  else dst = ipToInt(dst);
  if (!dst) return { ...sim, engine: "sim" };
  const proto = pr.proto || "icmp";
  const r = await real.probe(lab, id, dst, proto, pr.port || 0);
  const what = `${pr.proto ? pr.proto.toUpperCase() : "ping"}${pr.port ? " " + pr.port : ""} from ${id} to ${pr.to}`;
  const want = (pr.expect || "ok") !== "fail";
  let pass, detail;
  if (!want) {
    pass = !r.pass;
    detail = pass ? `${what} is blocked on the real network: ${sentence(r)}.` : `${what} still gets through on the real network${r.reached ? ` (answered by ${r.reached})` : ""}. It should be blocked.`;
  } else if (!r.pass) {
    pass = false;
    detail = `${what} fails on the real network: ${sentence(r)}.`;
  } else {
    const probs = [];
    if ((pr.snat || pr.dnat || pr.seen_src || pr.no_snat) && r.seenSrc === undefined) probs.push("no lab server logged the connection, so the NAT can't be confirmed");
    if (pr.snat && r.seenSrc !== undefined && r.seenSrc !== ipToInt(pr.snat)) probs.push(`the server saw source ${intToIp(r.seenSrc)} instead of ${pr.snat}`);
    if (pr.no_snat && r.seenSrc !== undefined) { const fromIp = (lab.dev(id) || {}).ip ? lab.dev(id).ip() : null; if (fromIp && r.seenSrc !== fromIp) probs.push(`it was source-NATed to ${intToIp(r.seenSrc)}, but the server must see the real client IP`); }
    if (pr.seen_src && r.seenSrc !== undefined && r.seenSrc !== ipToInt(pr.seen_src)) probs.push(`the server saw the client as ${intToIp(r.seenSrc)} instead of ${pr.seen_src}`);
    if (pr.dnat && r.seenDst !== undefined && r.seenDst !== ipToInt(pr.dnat)) probs.push(`it reached ${intToIp(r.seenDst)} instead of ${pr.dnat}`);
    if (pr.reach && r.reached && r.reached !== pr.reach) probs.push(`it was answered by ${r.reached}, not ${pr.reach}`);
    pass = !probs.length;
    detail = pass ? `${what} works on the real network${r.seenSrc !== undefined && proto !== "icmp" ? ` (the server saw ${intToIp(r.seenSrc)})` : ""}.` : `${what} works, but ${probs.join("; ")}.`;
    // policy and egress come from the simulator's walk; keep its verdict on those
    if (pass && !sim.pass && (pr.policy !== undefined || pr.egress)) { pass = false; detail = sim.detail; }
  }
  const out = { pass, detail, engine: "linux", sim: sim.pass };
  if (sim.pass !== pass) { out.disagree = true; out.simDetail = sim.detail; }
  else if (!pass && sim.detail) out.detail += ` ${sim.detail.replace(/^.*? (fails|is blocked|still gets through)[^.]*\.\s*/, "")}`.trimEnd();
  return out;
}

// Same as runChecks, with probe checks on the real network.
export async function runChecksReal(lab, checks, answers, real) {
  const simRes = runChecks(lab, checks, answers);
  const out = [];
  for (let i = 0; i < checks.length; i++) {
    const c = checks[i];
    if (!c.probe && !c.all) { out.push(lab.realLog && isLogCheck(c) ? { id: c.id, text: c.text, ...(await waitLogs(lab, real, c, answers)) } : simRes[i]); continue; }
    try { out.push({ id: c.id, text: c.text, ...(await realOne(lab, real, c, answers)) }); }
    catch (e) { out.push({ ...simRes[i], engine: "sim", ...(e.unsupported ? { simOnly: e.message } : { engineError: e.message }) }); }
  }
  return out;
}

// checks that read what FortiAnalyzer/FortiSIEM/FortiEDR received: on the real network logs take a moment
const isLogCheck = (c) => !!(c.faz || c.siem || c.fazinc || c.edr);
async function waitLogs(lab, real, c, answers) {
  let r = checkOne(lab, c, answers);
  // sessions are logged when they close; give the pipeline up to 12 s to carry them
  for (let t = Date.now(); !r.pass && Date.now() - t < 12000;) {
    await new Promise((res) => setTimeout(res, 700));
    await lab.realLog.tick(real.c, real.generation);
    r = checkOne(lab, c, answers);
  }
  return { ...r, engine: "linux" };
}
async function realOne(lab, real, c, answers) {
  if (c.probe) return realProbeCheck(lab, real, c.probe);
  if (c.all) {
    const r = [];
    for (const x of c.all) r.push(await realOne(lab, real, x, answers));
    return { pass: r.every((x) => x.pass), detail: r.filter((x) => !x.pass).map((x) => x.detail).join(" ") || r[0].detail, engine: r.some((x) => x.engine === "linux") ? "linux" : "sim" };
  }
  if (lab.realLog && isLogCheck(c)) return waitLogs(lab, real, c, answers);
  return checkOne(lab, c, answers);
}

export { unsupported };
