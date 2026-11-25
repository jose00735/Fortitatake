// Real-network checks: the lab compiled onto FortiTatake OS, probes sent by the Linux kernel.
// The simulator still tells the story (which policy, which NAT); the kernel decides pass or fail.
// When the two disagree, the result says so, so simulator bugs show up instead of hiding.
import { compile, unsupported } from "./compile.js";
import { probeCheck, parseFrom, runChecks } from "./grader.js";
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

  async apply(lab) {
    const why = unsupported(lab);
    if (why.length) throw Object.assign(new Error(`stays on the simulator: ${why.join(", ")}`), { unsupported: true });
    const k = this.stateKey(lab);
    if (k === this.key && this.c) return this.c;
    const t = Date.now();
    const c = compile(lab);
    await this.call({ op: "topo.apply", topo: c.topo }, 30000);
    for (const [ns, ruleset] of Object.entries(c.nft)) await this.call({ op: "ns.nft", ns, ruleset }, 15000);
    for (const l of c.listen) await this.call({ op: "listen.start", ...l }, 10000);
    this.c = c;
    this.key = k;
    this.applyMs = Date.now() - t;
    return c;
  }

  // one probe from a device; returns {pass, error, reached, seenSrc, seenDst}
  async probe(lab, from, dst, proto, port) {
    const c = await this.apply(lab);
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
    if (!c.probe) { out.push(simRes[i]); continue; }
    try { out.push({ id: c.id, text: c.text, ...(await realProbeCheck(lab, real, c.probe)) }); }
    catch (e) { out.push({ ...simRes[i], engine: "sim", ...(e.unsupported ? { simOnly: e.message } : { engineError: e.message }) }); }
  }
  return out;
}

export { unsupported };
