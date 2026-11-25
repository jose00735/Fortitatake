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
