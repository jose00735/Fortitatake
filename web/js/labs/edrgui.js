// A FortiEDR-style management console for the lab's EDR manager: the same screens and workflow
// (Dashboard, Event Viewer with raw data and the process tree, Forensics, Inventory, Security
// Settings), drawn in FortiTatake's own style and laid out for phones too. Every action runs as
// the console command it stands for, so it's recorded, replayed and graded like typed ones.
import { h, $, $$, esc } from "../core.js";
import { intToIp } from "./net.js";
import { EDR_RULES } from "./edrlive.js";

const CLS = ["Malicious", "Suspicious", "PUP", "Likely Safe", "Safe"];
const clsKey = (c) => String(c || "").toLowerCase().replace(/\s+/g, "-");
const POLICIES = ["Execution Prevention", "Exfiltration Prevention", "Ransomware Prevention", "Device Control"];

export function openEdrGui({ run, edrId, exec, onClose }) {
  const lab = run.lab;
  const mgr = lab.dev(edrId);
  let tab = "events", sel = null, filter = "";
  const el = h(`<section class="edr-gui" role="dialog" aria-label="FortiEDR console on ${esc(edrId)}" tabindex="-1">
    <header class="edr-top"><span class="edr-brand">EDR Central Manager</span><span class="edr-host">${esc(mgr.hostname || edrId)} · ${esc(intToIp(mgr.ip() || 0))}</span><button class="edr-x" aria-label="Close the console">✕</button></header>
    <nav class="edr-nav" role="tablist">
      ${[["dash", "Dashboard"], ["events", "Event Viewer"], ["forensics", "Forensics"], ["inventory", "Inventory"], ["settings", "Security Settings"]].map(([k, l]) => `<button role="tab" data-t="${k}">${l}</button>`).join("")}
    </nav>
    <main class="edr-main"></main>
  </section>`);
  document.body.appendChild(el);
  const main = $(".edr-main", el);
  const act = (cmd) => { const out = exec(edrId, cmd); render(); return out; };
  const evs = () => lab.edrEvents(mgr);
  const badge = (c) => `<span class="edr-cls edr-${clsKey(c)}">${esc(c)}</span>`;
  const tree = (e) => {
    const chain = e.chain && e.chain.length ? e.chain : [e.parent, e.process].filter(Boolean);
    return `<ol class="edr-tree">${chain.map((p, i) => `<li style="--d:${i}"><span class="edr-node${i === chain.length - 1 ? " hot" : ""}">${esc(p)}</span>${i === chain.length - 1 && e.cmd ? `<code>${esc(e.cmd)}</code>` : ""}</li>`).join("")}${e.dst ? `<li style="--d:${chain.length}"><span class="edr-node net">→ ${esc(e.dst)}</span></li>` : ""}${e.target ? `<li style="--d:${chain.length}"><span class="edr-node file">✎ ${esc(e.target)}</span></li>` : ""}</ol>`;
  };
  const detail = (e) => `<div class="edr-detail">
      <div class="edr-dhead">${badge(e.classification)}<b>${esc(e.process)}</b><span>${esc(e.hostname)} · ${esc(e.date)} ${esc(e.time)}</span></div>
      <dl class="edr-raw">
        <dt>Rule</dt><dd>${esc(e.rule)}${e.attack ? ` <small>${esc(e.attack)}</small>` : ""}</dd>
        <dt>Policy</dt><dd>${esc(e.policy || "-")} · ${esc(e.mode || "")}</dd>
        <dt>Action</dt><dd>${esc(e.action)}${e.prevented ? ` · ${esc(e.prevented)}` : ""}${e.handled ? ` · ${esc(e.handled)}` : ""}</dd>
        ${e.detail ? `<dt>Why</dt><dd>${esc(e.detail)}</dd>` : ""}
        <dt>Process</dt><dd>${esc(e.path || e.process)}${e.pid ? ` · PID ${e.pid}` : ""}${e.user ? ` · ${esc(e.user)}` : ""}</dd>
        <dt>Command line</dt><dd><code>${esc(e.cmd || "-")}</code></dd>
        ${e.dst ? `<dt>Destination</dt><dd>${esc(e.dst)}</dd>` : ""}
        ${e.target ? `<dt>Target</dt><dd>${esc(e.target)}</dd>` : ""}
        <dt>Hash</dt><dd><code>${esc(e.hash || "-")}</code> · signed: ${esc(e.signed || "no")}</dd>
        <dt>Source</dt><dd>${e.real ? "real telemetry from the collector" : "scenario event"}</dd>
      </dl>
      <h4>Process tree</h4>${tree(e)}
      <div class="edr-acts">
        <label>Classify <select data-cls>${CLS.map((c) => `<option${c === e.classification ? " selected" : ""}>${c}</option>`).join("")}</select></label>
        <button data-a="exception">Exception (all collectors)</button><button data-a="exception-host">Exception (this device)</button>
        <button data-a="kill">Remediate: kill process</button><button data-a="delete">Remediate: delete file</button>
        <button data-a="isolate">Isolate device</button>
      </div></div>`;
  const views = {
    dash() {
      const list = evs(), cols = lab.edrCollectors(mgr);
      const by = (k) => list.filter((e) => e.classification === k).length;
      return `<div class="edr-cards">
        ${CLS.slice(0, 3).map((c) => `<div class="edr-card"><span class="edr-n">${by(c)}</span>${badge(c)}</div>`).join("")}
        <div class="edr-card"><span class="edr-n">${list.filter((e) => !e.handled).length}</span><span>unhandled events</span></div>
        <div class="edr-card"><span class="edr-n">${cols.filter((c) => c.connected).length}/${cols.length}</span><span>collectors running</span></div>
        <div class="edr-card"><span class="edr-n">${cols.filter((c) => c.isolated).length}</span><span>isolated devices</span></div></div>
        <h4>Most recent</h4>${list.slice(-6).reverse().map((e) => `<button class="edr-row" data-ev="${e.id}">${badge(e.classification)}<b>${esc(e.process)}</b><span>${esc(e.hostname)}</span><span>${esc(e.rule)}</span><time>${esc(e.time)}</time></button>`).join("") || "<p>No security events yet.</p>"}`;
    },
    events() {
      const list = evs().filter((e) => !filter || [e.hostname, e.process, e.rule, e.classification].join(" ").toLowerCase().includes(filter)).reverse();
      return `<div class="edr-bar"><input type="search" placeholder="Filter by device, process, rule, classification" value="${esc(filter)}" data-filter aria-label="Filter events"></div>
        <div class="edr-list" role="list">${list.map((e) => `<div role="listitem" class="edr-item${sel === e.id ? " open" : ""}"><button class="edr-row" data-ev="${e.id}" aria-expanded="${sel === e.id}">${badge(e.classification)}<b>${esc(e.process)}</b><span>${esc(e.hostname)}</span><span class="edr-rule">${esc(e.rule)}</span><span class="edr-act">${esc(e.action)}${e.handled ? " · handled" : ""}</span><time>${esc(e.time)}</time></button>${sel === e.id ? detail(e) : ""}</div>`).join("") || "<p>No security events.</p>"}</div>`;
    },
    forensics() {
      const e = evs().find((x) => x.id === sel) || evs().slice(-1)[0];
      if (!e) return "<p>Pick an event in the Event Viewer first.</p>";
      const raw = (mgr.tel && mgr.tel.raw.filter((r) => r.host === e.host).slice(-25)) || [];
      return `<h4>Flow analyzer · event ${e.id}</h4>${tree(e)}<h4>Raw telemetry from ${esc(e.hostname)}</h4><pre class="edr-pre">${raw.length ? raw.map((r) => `${new Date(r.t).toLocaleTimeString()} ${r.kind.padEnd(5)} ${r.kind === "perf" ? `cpu ${r.cpu} % mem ${r.mem_mb} MB${r.top ? ` top ${r.top.name}(${r.top.pid})` : ""}` : r.kind === "proc" ? `${r.parent || "?"} → ${r.name} (${r.pid}) ${r.cmd || ""}` : r.kind === "net" ? `${r.process || "?"} ${r.src}:${r.sport} → ${r.dst}:${r.dport}` : JSON.stringify(r)}`).map(esc).join("\n") : "Scenario event: no raw telemetry (the real network is off or the collector hasn't reported)."}</pre>`;
    },
    inventory() {
      const cols = lab.edrCollectors(mgr);
      const raw = (id) => mgr.tel && mgr.tel.hosts.get(id);
      return `<div class="edr-list">${cols.map((c) => { const t = raw(c.h.id); const p = t && t.perf.slice(-1)[0]; return `<div class="edr-coll"><b>${esc(c.h.hostname || c.h.id)}</b><span>${esc(intToIp(c.h.ip() || 0))} · ${c.h.os === "windows" ? "Windows" : "Linux"}</span><span class="edr-state ${c.isolated ? "iso" : c.connected ? "ok" : "off"}">${c.isolated ? "Isolated" : c.connected ? "Running" : "Disconnected"}</span>${p ? `<span>CPU ${p.cpu} % · ${p.mem} MB</span>` : ""}<button data-iso="${esc(c.h.id)}">${c.isolated ? "Release" : "Isolate"}</button></div>`; }).join("") || "<p>No collectors registered.</p>"}</div>`;
    },
    settings() {
      const st = lab.edrStateOf(mgr);
      return `<h4>Security policies (group Default)</h4><div class="edr-list">${POLICIES.map((p) => `<div class="edr-pol"><b>${p}</b><div class="edr-seg" role="radiogroup" aria-label="${p}"><button data-pol="${p}" data-m="simulation" aria-pressed="${st.modes[p] !== "Prevention"}">Simulation</button><button data-pol="${p}" data-m="prevention" aria-pressed="${st.modes[p] === "Prevention"}">Prevention</button></div></div>`).join("")}</div>
        <h4>Rules on live telemetry</h4><div class="edr-list">${EDR_RULES.map((r) => `<div class="edr-rulerow"><b>${esc(r.rule)}</b><span>${esc(r.policy)} · ${badge(r.cls)} · ${esc(r.attack)}</span><small>${esc(r.desc)}</small></div>`).join("")}</div>
        <h4>Syslog export</h4><div class="edr-bar"><input data-syslog placeholder="FortiSIEM IP, or off" value="${esc(st.syslog || "")}" aria-label="Syslog destination"><button data-a="syslog">Save</button></div>
        <h4>Exceptions</h4>${st.exceptions.length ? `<ul>${st.exceptions.map((x) => `<li>${esc(x.process)} · ${esc(x.rule)} · ${x.host === "*" ? "all collectors" : esc(x.host)}</li>`).join("")}</ul>` : "<p>None.</p>"}`;
    },
  };
  const render = () => {
    $$(".edr-nav button", el).forEach((b) => b.setAttribute("aria-selected", b.dataset.t === tab));
    const keepFocus = document.activeElement && document.activeElement.dataset && document.activeElement.dataset.filter !== undefined;
    main.innerHTML = views[tab]();
    if (keepFocus) { const f = $("[data-filter]", main); f.focus(); f.setSelectionRange(f.value.length, f.value.length); }
    $$("[data-ev]", main).forEach((b) => (b.onclick = () => { const id = Number(b.dataset.ev); sel = sel === id && tab === "events" ? null : id; tab = "events"; render(); }));
    const f = $("[data-filter]", main); if (f) f.oninput = () => { filter = f.value.toLowerCase(); render(); };
    const cs = $("[data-cls]", main); if (cs) cs.onchange = () => act(`classify ${sel} ${clsKey(cs.value)}`);
    $$("[data-a]", main).forEach((b) => (b.onclick = () => {
      const e = evs().find((x) => x.id === sel);
      const a = b.dataset.a;
      if (a === "syslog") { act(`syslog ${$("[data-syslog]", main).value.trim() || "off"}`); return; }
      if (!e) return;
      if (a === "exception") act(`exception ${e.id} all`);
      else if (a === "exception-host") act(`exception ${e.id} host`);
      else if (a === "kill" || a === "delete") { act(`remediate ${e.id} ${a}`); if (a === "kill" && e.real && e.pid) (lab.edrActions = lab.edrActions || []).push({ host: e.host, kind: "kill", pid: e.pid, event: e.id }); }
      else if (a === "isolate") act(`isolate ${e.host}`);
    }));
    $$("[data-iso]", main).forEach((b) => (b.onclick = () => act(`${b.textContent === "Release" ? "unisolate" : "isolate"} ${b.dataset.iso}`)));
    $$("[data-pol]", main).forEach((b) => (b.onclick = () => act(`policy "${b.dataset.pol}" ${b.dataset.m}`)));
  };
  $$(".edr-nav button", el).forEach((b) => (b.onclick = () => { tab = b.dataset.t; render(); }));
  const close = () => { clearInterval(timer); el.remove(); onClose && onClose(); };
  $(".edr-x", el).onclick = close;
  el.addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });
  const timer = setInterval(() => { if (!document.body.contains(el)) { clearInterval(timer); return; } const a = document.activeElement; if (!(el.contains(a) && /^(SELECT|INPUT)$/.test(a.tagName))) render(); }, 2500);
  window.addEventListener("hashchange", close, { once: true });
  render();
  el.focus();
  return { close };
}
