// Labs screens: the catalogue and the lab runner (ticket, topology, consoles, checks).
import { ipsLogRec, ATTACKER_IP, attackSource, attackTarget, attackRequests, attackPort } from "./ips.js";
import { trafficPlan, BASELINE_RATE, BASELINE_HOURS, virtualTime, summarize, fmtBytes } from "./traffic.js";
import { h, $, $$, esc, md, inline, icon } from "../core.js";
import { S, record } from "../state.js";
import { LabRun } from "./runtime.js";
import { RealNet } from "./real.js";
import { RealLogs } from "./reallog.js";
import { realHostCmd, realRouterCmd, realResolve } from "./realcli.js";
import { parseRemoteCmd, connectError, connectedLines, passPrompt, closedLine, ServerSession } from "./remote.js";
import { parseTcpdump, parseSnifferCmd, safeFilter, snifferHeader, snifferLine, localStamp, fortiPing, traceRules, FlowTrace, parseConntrack, formatSessions, formatRoutes, routeHelpers } from "./realdiag.js";
import { intToIp, ipToInt, isIp } from "./net.js";
import { api } from "../core.js";
import { drawTopology } from "./topo.js";
import { FortiGate } from "./fgt.js";
import { isConfigLine, hostsEntry } from "./netcfg.js";

const TIERS = ["Console", "Fundamentals", "Core PS", "Advanced", "Break-fix", "SecOps", "Capstones"];
const TRACK = { fortigate: "FortiGate", routing: "Routing", identity: "Identity", fortimanager: "FortiManager", fortianalyzer: "FortiAnalyzer", fortiswitch: "FortiSwitch", fortisiem: "FortiSIEM", fortiedr: "FortiEDR", secops: "SecOps", integration: "Multi-product", sdwan: "SD-WAN", vpn: "VPN", ha: "HA" };
const KIND = { project: "Project", ticket: "Ticket", drill: "Drill", capstone: "Capstone", investigation: "Investigation" };

let catalog = null, schemas = null;
async function loadCatalog() {
  if (!catalog) catalog = fetch("content/labs.json", { cache: "no-store" }).then((r) => r.json());
  return catalog;
}
async function loadSchemas() {
  if (!schemas) schemas = Promise.all([...["fortios", "fortianalyzer", "fortimanager"].map((p) => fetch(`schema/${p}-8.0.2.json`).then((r) => r.json())), fetch("content/threats.json").then((r) => r.json()).catch(() => ({ packs: [] }))]).then(([fortios, fortianalyzer, fortimanager, th]) => ({ fortios, fortianalyzer, fortimanager, threats: th.packs || [] }));
  return schemas;
}
const key = (id) => "ft-lab-" + id;
function saved(id, k = key(id)) { try { return JSON.parse(localStorage.getItem(k) || "null"); } catch (e) { return null; } }
function store(run, k = key(run.def.id)) { try { localStorage.setItem(k, JSON.stringify(run.save())); } catch (e) { /* storage off: progress lives for this session only */ } }
function forget(id, k = key(id)) { try { localStorage.removeItem(k); } catch (e) { /* ignore */ } }

// lab parts are review items too: LAB.<lab>.<part>
export const partItemId = (lab, part) => `LAB.${lab}.${part}`;
export async function labIndex() {
  const cat = await loadCatalog();
  return cat.labs;
}

// A single lab part inside a sortie block or a review. The run is separate from the
// catalogue run (its own save slot), so practising part c here never disturbs the lab.
// opts: { label, exam, slot } · done(result|null), result = { passed, hints, revealed, ms }
export async function labPart(stage, labId, partId, opts, done) {
  stage.replaceChildren(h(`<div class="panel"><p class="muted">Booting the lab…</p></div>`));
  const [cat, sch] = await Promise.all([loadCatalog(), loadSchemas()]);
  const def = cat.labs.find((l) => l.id === labId);
  const idx = def ? def.parts.findIndex((p) => p.id === partId) : -1;
  if (idx < 0) return done(null);
  const k = `ft-lab-s-${opts.slot || "x"}-${labId}-${partId}`;
  const boot = (fresh) => {
    if (fresh) forget(labId, k);
    const prev = saved(labId, k);
    const run = new LabRun(def, sch, prev);
    if (!prev) { run.jumpTo(idx); store(run, k); }
    run.exam = !!opts.exam;
    mount(stage, run, { embedded: true, only: idx, key: k, label: opts.label, exam: !!opts.exam,
      reset: () => boot(true),
      finish: (r) => { if (r) forget(labId, k); done(r); } });
  };
  boot(false);
}

// ---------- catalogue ----------
export async function labsHome(main, filter = "all") {
  main.replaceChildren(h(`<div class="wrap"><p class="muted">Loading labs…</p></div>`));
  let cat;
  try { cat = await loadCatalog(); } catch (e) { main.replaceChildren(h(`<div class="wrap"><h1>Labs</h1><p>The lab catalogue didn't load: ${esc(e.message)}</p></div>`)); return; }
  const done = S.p.labDone || new Map();
  const tracks = [...new Set(cat.labs.map((l) => l.track))];
  const labs = cat.labs.filter((l) => filter === "all" || l.track === filter || String(l.tier) === filter);
  const tiers = [...new Set(labs.map((l) => l.tier))].sort();
  const el = h(`<div class="wrap labs-home">
    <h1>Labs</h1>
    <p class="muted read">Real PS projects and tickets on emulated FortiOS 8.0.2. Configure from the CLI, test from the PCs, and press <b>Check</b>: the grader tests what the network actually does, so any valid configuration passes.</p>
    <div class="chips" role="toolbar" aria-label="Filter labs">
      <button data-f="all" class="${filter === "all" ? "on" : ""}">All ${cat.labs.length}</button>
      ${tracks.map((t) => `<button data-f="${t}" class="${filter === t ? "on" : ""}">${esc(TRACK[t] || t)}</button>`).join("")}
      ${[...new Set(cat.labs.map((l) => l.tier))].sort().map((t) => `<button data-f="${t}" class="${filter === String(t) ? "on" : ""}">${t}. ${TIERS[t]}</button>`).join("")}
    </div>
    ${tiers.map((t) => `<h2>${t}. ${TIERS[t]}</h2><div class="lab-list">${labs.filter((l) => l.tier === t).map((l) => card(l, done.get(l.id), saved(l.id))).join("")}</div>`).join("")}
  </div>`);
  main.replaceChildren(el);
  $$("[data-f]", el).forEach((b) => (b.onclick = () => labsHome(main, b.dataset.f)));
}
function card(l, d, s) {
  const parts = l.parts.length;
  const prog = d ? `<span class="lab-state done">Done · ${d.score} pts</span>` : s ? `<span class="lab-state wip">In progress · part ${Math.min((s.passed || []).length + 1, parts)} of ${parts}</span>` : "";
  return `<a class="lab-card" href="#/lab/${esc(l.id)}">
    <div class="row spread"><span class="tag">${esc(KIND[l.kind] || l.kind)}</span><span class="tiny">${esc(l.id)} · ${esc(TRACK[l.track] || l.track)} · ~${l.par || 30} min${parts > 1 ? ` · ${parts} parts` : ""}</span></div>
    <b>${esc(l.title)}</b>
    <span class="small muted">${esc(l.customer || "")}</span>
    ${prog}
  </a>`;
}

// ---------- runner ----------
export async function labView(main, id) {
  main.replaceChildren(h(`<div class="wrap"><p class="muted">Booting the lab…</p></div>`));
  const [cat, sch] = await Promise.all([loadCatalog(), loadSchemas()]);
  const def = cat.labs.find((l) => l.id === id);
  if (!def) { main.replaceChildren(h(`<div class="wrap"><p>Lab ${esc(id)} not found. <a href="#/labs">Back to labs</a></p></div>`)); return; }
  const run = new LabRun(def, sch, saved(id));
  const s0 = saved(id);
  run.exam = !!(s0 && s0.exam);
  mount(main, run);
}

function mount(main, run, opts = {}) {
  const def = run.def;
  const k = opts.key || key(def.id);
  const emb = !!opts.embedded;
  const devs = run.consoleDevices();
  const firstFgt = devs.find((d) => d instanceof FortiGate) || devs[0];
  const ui = { dev: firstFgt.id, buf: {}, hist: {}, hi: {}, unread: new Set(), view: "ticket", sh: {}, cap: {}, trace: {}, pcap: {}, rem: {}, known: new Set(), hub: {} };
  const shOn = (id) => !!(ui.sh[id] && ui.sh[id].on);
  for (const d of devs) { ui.buf[d.id] = []; ui.hist[d.id] = []; }
  // what a real console shows when it opens
  for (const d of devs) {
    if (d.os === "windows" && (d.kind === "host" || d.kind === "server")) ui.buf[d.id].push("Microsoft Windows [Version 10.0.19045.6466]", "(c) Microsoft Corporation. All rights reserved.", "");
    else if (d.kind === "host" || d.kind === "server") ui.buf[d.id].push(`Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-48-generic x86_64)`, "");
    else if (d.kind === "router") ui.buf[d.id].push("", `User Access Verification`, "", `${d.id} line 0 is now available`, "");
  }
  for (const d of devs) if (d instanceof FortiGate) ui.buf[d.id].push(`${{ fortianalyzer: "FortiAnalyzer", fortimanager: "FortiManager" }[d.product] || "FortiOS"} v8.0.2 emulated by FortiTatake · ${d.model} · type ? for help, Tab to complete`, "");
  else ui.buf[d.id].push(d.kind === "router" ? `${d.id}: ${d.label || "router"}, IOS-style CLI (enable, configure terminal). Type help for its commands.` : `${d.id} (${d.os}) · type help`, "");

  const el = h(`<div class="labrun${emb ? " embedded" : ""}" data-view="ticket">
    <header class="lr-head">
      ${emb ? `<span class="tag acc">${esc(opts.label || "Lab")}</span>` : `<a href="#/labs" class="ghost btn small">← Labs</a>`}
      <div class="lr-title"><span class="tiny">${esc(def.id)} · ${esc(KIND[def.kind] || def.kind)} · ${esc(def.customer || "")}</span><b>${esc(def.title)}</b></div>
      <div class="row lr-meta"><span class="kbd num" data-timer>0:00</span>${emb ? (opts.exam ? `<span class="tag">Exam mode: no hints</span>` : "") : `<label class="small row" style="gap:6px"><input type="checkbox" data-exam ${run.exam ? "checked" : ""}> Exam mode</label>`}<span class="small row lr-real" style="gap:6px" hidden title="This lab runs on FortiTatake OS: a real Linux network built from it">Real network <span class="lr-live" data-live></span></span><button class="ghost small" data-reset>Reset</button>${emb ? `<button class="ghost small" data-leave>Skip this lab</button>` : ""}</div>
    </header>
    <nav class="lr-tabs" aria-label="Lab panels"><button data-v="ticket" class="on">Ticket</button><button data-v="net">Network</button><button data-v="term">Console</button></nav>
    <div class="lr-grid">
      <aside class="lr-side" data-pane="ticket"></aside>
      <section class="lr-main">
        <div class="lr-topo" data-pane="net"></div>
        <div class="lr-term" data-pane="term">
          <div class="lr-devtabs" role="tablist"></div>
          <div class="lr-out" tabindex="0" aria-live="polite"></div>
          <div class="lr-line"><span class="lr-prompt"></span><input class="lr-in" autocomplete="off" autocapitalize="off" spellcheck="false" aria-label="Console input"></div>
          <div class="lr-keys"><button data-k="Tab">Tab</button><button data-k="?">?</button><button data-k="Up">↑</button><button data-k="Down">↓</button><button data-k="C">Ctrl+C</button><button data-k="end">end</button><button data-k="next">next</button></div>
        </div>
      </section>
    </div>
  </div>`);
  main.replaceChildren(el);
  const out = $(".lr-out", el), inp = $(".lr-in", el), prompt = $(".lr-prompt", el);

  const setView = (v) => { ui.view = v; el.dataset.view = v; $$(".lr-tabs button", el).forEach((b) => b.classList.toggle("on", b.dataset.v === v)); if (v === "term") inp.focus(); };
  $$(".lr-tabs button", el).forEach((b) => (b.onclick = () => setView(b.dataset.v)));

  // ----- consoles -----
  const devTabs = () => {
    const liveOn = typeof live !== "undefined" && (live.state === "live" || live.state === "apply");
    $(".lr-devtabs", el).innerHTML = devs.map((d) => `<button role="tab" aria-selected="${d.id === ui.dev}" data-dev="${esc(d.id)}" class="${d.id === ui.dev ? "on" : ""}">${esc(d.id)}${shOn(d.id) ? " $" : ""}${ui.unread.has(d.id) ? ' <i class="dot" aria-label="new output"></i>' : ""}</button>`).join("") +
      `<span class="lr-tools">` + (ui.pcap[ui.dev] && liveOn ? `<button class="lr-shellbtn" data-pcap title="The last diagnose sniffer packet capture on this FortiGate, for Wireshark">Download .pcap</button>` : "") +
      `<button class="lr-shellbtn" data-attack ${(run.lab.threats || []).length ? "" : "hidden"} title="Send a threat pack's attack traffic at a lab server and see what your IPS does">Attacks</button>` +
      `<button class="lr-shellbtn${ui.traffic && ui.traffic.on ? " on" : ""}" data-traffic ${liveOn ? "" : "hidden"} title="Everyday office traffic on the real lab network: browsing, DNS, file share, mail, voice">Office traffic</button>` +
      `<button class="lr-shellbtn${shOn(ui.dev) ? " on" : ""}" data-shell ${liveOn ? "" : "hidden"} title="A real Linux shell inside this device, on the real lab network">${shOn(ui.dev) ? "Back to the console" : "Linux shell"}</button></span>`;
    $$(".lr-devtabs [data-dev]", el).forEach((b) => (b.onclick = () => selectDev(b.dataset.dev)));
    const sb = $(".lr-devtabs [data-shell]", el); if (sb) sb.onclick = () => { toggleShell(ui.dev); devTabs(); };
    const pb = $(".lr-devtabs [data-pcap]", el); if (pb) pb.onclick = () => downloadPcap(ui.dev);
    const tb = $(".lr-devtabs [data-traffic]", el); if (tb) tb.onclick = () => openTraffic();
    const ab = $(".lr-devtabs [data-attack]", el); if (ab) ab.onclick = () => openAttacks();
  };
  const paint = () => {
    const sh = ui.sh[ui.dev];
    out.textContent = shOn(ui.dev) ? sh.text : ui.buf[ui.dev].join("\n");
    out.scrollTop = out.scrollHeight;
    const rs = ui.rem[ui.dev];
    prompt.textContent = rs ? rs.pending : shOn(ui.dev) ? `${ui.dev} (Linux) # ` : run.prompt(ui.dev);
    const masked = !!rs && (rs.stage === "pass" || /password: ?$/i.test(rs.pending));
    if (inp.type !== (masked ? "password" : "text")) inp.type = masked ? "password" : "text";
  };
  const print = (dev, text) => {
    const b = ui.buf[dev];
    b.push(...String(text).split("\n"));
    if (b.length > 1500) b.splice(0, b.length - 1500);
    if (dev !== ui.dev) { ui.unread.add(dev); devTabs(); }
  };
  const selectDev = (id) => { if (!ui.buf[id]) return; ui.dev = id; ui.unread.delete(id); devTabs(); paint(); topo(); inp.focus(); };
  const pump = () => {
    const a = run.drain();
    for (const [dev, lines] of Object.entries(a)) print(dev, lines.join("\n"));
  };
  const topo = () => {
    $(".lr-topo", el).innerHTML = drawTopology(run, ui.dev);
    $$(".lr-topo .tp-wire", el).forEach((w) => {
      const go = (e) => { e.stopPropagation(); openWire({ seg: w.dataset.seg, cap: w.dataset.cap, port: w.dataset.port, peer: w.dataset.peer, hub: w.dataset.hub === "1" }); };
      w.onclick = go;
      w.onkeydown = (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); go(e); } };
    });
    $$(".lr-topo [data-dev].click", el).forEach((g) => {
      const go = () => { selectDev(g.dataset.dev); if (window.matchMedia("(max-width: 900px)").matches) setView("term"); };
      g.onclick = go;
      g.onkeydown = (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); go(); } };
    });
  };
  const exec = (line) => {
    const dev = ui.dev;
    if (ui.rem[dev]) { remLine(dev, line); return; }
    if (shOn(dev)) { shellLine(dev, line); return; }
    if (remoteCmd(dev, line)) return;
    if (realDiag(dev, line)) return;
    if (realDevCmd(dev, line)) return;
    print(dev, run.prompt(dev) + line);
    if (line.trim() === "clear" || line.trim() === "cls") { ui.buf[dev] = []; paint(); return; }
    const r = run.exec(dev, line);
    if (r) print(dev, r);
    pump();
    if (run.lab.pendingEdit) { const pe = run.lab.pendingEdit; run.lab.pendingEdit = null; if (line.trim()) { ui.hist[dev].push(line); ui.hi[dev] = ui.hist[dev].length; } store(run, k); paint(); openEditor(pe); return; }
    if (line.trim()) { ui.hist[dev].push(line); ui.hi[dev] = ui.hist[dev].length; }
    store(run, k);
    paint(); topo();
  };
  inp.addEventListener("keydown", (e) => {
    const dev = run.device(ui.dev);
    const isFgt = dev instanceof FortiGate && !shOn(ui.dev) && !ui.rem[ui.dev];
    if (e.key === "Enter") { e.preventDefault(); const v = inp.value; inp.value = ""; exec(v); }
    else if (e.key === "Tab") {
      e.preventDefault();
      if (!isFgt) return;
      const r = dev.complete(inp.value);
      if (r.choices.length > 1) { print(ui.dev, run.prompt(ui.dev) + inp.value); print(ui.dev, columns(r.choices)); paint(); }
      inp.value = r.line;
    } else if (e.key === "?" && isFgt) {
      e.preventDefault();
      print(ui.dev, run.prompt(ui.dev) + inp.value + "?");
      print(ui.dev, dev.help(inp.value + "?"));
      paint();
    } else if (e.key === "ArrowUp" || e.key === "ArrowDown") {
      e.preventDefault();
      const hs = ui.hist[ui.dev];
      if (!hs.length) return;
      ui.hi[ui.dev] = Math.max(0, Math.min(hs.length, (ui.hi[ui.dev] ?? hs.length) + (e.key === "ArrowUp" ? -1 : 1)));
      inp.value = hs[ui.hi[ui.dev]] || "";
    } else if ((e.key === "c" || e.key === "C") && e.ctrlKey) {
      e.preventDefault();
      if (ui.rem[ui.dev]) { const rs = ui.rem[ui.dev]; print(ui.dev, rs.pending + (rs.stage === "pass" ? "" : inp.value) + "^C"); inp.value = ""; if (rs.stage !== "open") { rs.pending = ""; remEnd(ui.dev, true); } paint(); return; }
      if (ui.cap[ui.dev]) { const c = ui.cap[ui.dev]; print(ui.dev, inp.value + "^C"); inp.value = ""; c.stopping = true; realCall({ op: "shell.signal", shell: c.id }).catch(() => {}); paint(); return; }
      if (shOn(ui.dev)) { const sh = ui.sh[ui.dev]; sh.text += inp.value + "^C\n"; inp.value = ""; if (sh.id) realCall({ op: "shell.signal", shell: sh.id }).catch(() => {}); paint(); return; }
      print(ui.dev, run.prompt(ui.dev) + inp.value + "^C" + run.stopCapture(ui.dev));
      inp.value = "";
      paint();
    } else if ((e.key === "l" || e.key === "L") && e.ctrlKey) { e.preventDefault(); ui.buf[ui.dev] = []; paint(); }
  });
  $$(".lr-keys [data-k]", el).forEach((b) => (b.onclick = () => {
    const k = b.dataset.k;
    inp.focus();
    if (k === "end" || k === "next") { exec(k); return; }
    const map = { Tab: { key: "Tab" }, "?": { key: "?" }, Up: { key: "ArrowUp" }, Down: { key: "ArrowDown" }, C: { key: "c", ctrlKey: true } };
    inp.dispatchEvent(new KeyboardEvent("keydown", { ...map[k], bubbles: true, cancelable: true }));
  }));
  out.addEventListener("click", () => { if (!window.getSelection().toString()) inp.focus(); });

  // ----- ticket side -----
  const side = $(".lr-side", el);
  const renderSide = (results, note) => {
    const p = run.current;
    const res = results || run.results[p.id] || null;
    const shown = run.hints[p.id] || 0;
    const answers = (p.checks || []).filter((c) => c.answer);
    side.innerHTML = `
      ${(run.part === 0 && !run.passed.size) || (emb && run.part > 0) ? `${emb && run.part > 0 ? `<p class="tiny">The earlier parts are already configured with their reference solutions. Start from part ${run.part + 1}.</p>` : ""}<details class="panel md lr-brief" open><summary><b>The brief</b></summary>${md(def.brief)}</details>` : `<details class="panel md lr-brief"><summary><b>The brief</b></summary>${md(def.brief)}</details>`}
      ${run.parts.length > 1 ? `<ol class="lr-parts">${run.parts.map((q, i) => `<li class="${run.passed.has(q.id) ? "done" : i === run.part ? "on" : ""}">${run.passed.has(q.id) ? "✓ " : ""}${esc(q.title || "Part " + (i + 1))}</li>`).join("")}</ol>` : ""}
      <section class="panel lr-part">
        ${run.parts.length > 1 ? `<div class="tiny">Part ${run.part + 1} of ${run.parts.length}</div><h3 style="margin-top:2px">${esc(p.title || "")}</h3>` : ""}
        ${p.brief ? `<div class="md small">${md(p.brief)}</div>` : ""}
        <b class="small">Tasks</b>
        <ul class="small lr-tasks">${(p.tasks || []).map((t) => `<li>${inline(t)}</li>`).join("")}</ul>
        ${answers.length ? `<div class="stack">${answers.map((c) => `<label class="field small">${inline(c.text)}<input data-ans="${esc(c.id)}" value="${esc(run.answers[c.id] || "")}" autocomplete="off"></label>`).join("")}</div>` : ""}
        <div class="row" style="margin-top:12px">
          <button class="primary" data-check>Check</button>
          ${run.exam ? "" : `<button data-hint ${shown >= (p.hints || []).length ? "disabled" : ""}>Hint (${(p.hints || []).length - shown} left)</button>`}
          ${run.exam ? "" : `<button class="ghost" data-reveal>${run.revealed[p.id] ? "Solution" : "Reveal solution"}</button>`}
        </div>
        ${shown ? `<ol class="small lr-hints">${(p.hints || []).slice(0, shown).map((x) => `<li>${inline(x)}</li>`).join("")}</ol>` : ""}
        ${note || ""}
        ${res ? `<ul class="lr-checks">${res.map((r) => `<li class="${r.pass ? "ok" : "no"}"><b>${r.pass ? "✓" : "✗"}</b><div><span class="small">${inline(r.text)}${r.engine === "linux" ? ` <span class="lr-eng" title="Sent through FortiTatake OS">real network</span>` : ""}</span><span class="tiny">${esc(r.detail || "")}</span>${r.disagree ? `<span class="tiny lr-dis">The simulator predicted the opposite (${esc(r.simDetail || "")}). The real network decides; this is worth reporting.</span>` : ""}${r.engineError ? `<span class="tiny lr-dis">FortiTatake OS didn't answer (${esc(r.engineError)}), so the simulator checked this one.</span>` : ""}</div></li>`).join("")}</ul>` : `<p class="tiny">The checklist stays hidden until you press Check. It tests what the network does, not what you typed.</p>`}
        ${run.revealed[p.id] ? solutionHtml(p) : ""}
        ${run.passed.has(p.id) ? `<div class="call why md"><b>Why it works</b>${md(p.explain || "")}</div>${emb ? `<button class="primary" data-cont>Continue</button>` : run.part < run.parts.length - 1 ? `<button class="primary" data-next>Next part →</button>` : ""}` : ""}
      </section>`;
    $$("[data-ans]", side).forEach((i) => (i.oninput = () => { run.answers[i.dataset.ans] = i.value; store(run, k); }));
    $("[data-check]", side).onclick = doCheck;
    const hb = $("[data-hint]", side); if (hb) hb.onclick = () => { run.hint(p.id); store(run, k); renderSide(); };
    const rv = $("[data-reveal]", side);
    if (rv) rv.onclick = () => { if (run.revealed[p.id] || confirm("Reveal the reference solution? This part's score drops to 20 points.")) { run.revealed[p.id] = true; store(run, k); renderSide(); } };
    $$("[data-apply]", side).forEach((b) => (b.onclick = () => {
      const dev = b.dataset.apply;
      for (const line of String(p.solution[dev]).split("\n")) if (line.trim()) { selectDev(dev); exec(line.trim()); }
    }));
    const nx = $("[data-next]", side); if (nx) nx.onclick = () => { run.advance(); store(run, k); renderSide(); };
    const ct = $("[data-cont]", side); if (ct) ct.onclick = () => opts.finish({ passed: true, hints: run.hints[p.id] || 0, revealed: !!run.revealed[p.id], ms: run.elapsed });
  };
  // FortiTatake OS: offered when this device has a build and QEMU; the choice is remembered
  const real = { on: false, net: null, busy: false };
  api("engine/status").then((st) => {
    if (!st || !st.runner || !st.runner.qemu || !st.runner.build) return;
    const box = $(".lr-real", el); if (!box) return;
    box.hidden = false;
    real.on = true; // always the real network when this device can run it; the simulator is only the fallback
    startLive();
  }).catch(() => {});
  try { window.ftkLab = { run, real }; } catch { /* no window */ }
  const realCall = async (req, ms) => {
    const r = await api("engine/lab/call", { method: "POST", body: req });
    if (!r.ok) throw new Error(r.err || "engine error");
    return r;
  };
  // ----- live: the VM follows the lab, and devices get real Linux shells -----
  const live = { state: "", timer: null, gen: 0, err: "" };
  const setLive = (st, msg) => {
    live.state = st;
    const l = $("[data-live]", el);
    if (l) { l.textContent = { boot: "starting…", apply: "applying…", live: "live", sim: "simulator only", off: "", err: "offline (hover for why; retrying in 30 s)" }[st] || ""; l.dataset.st = st; l.title = msg || ""; }
    const was = live.shown;
    live.shown = st === "live" || st === "apply";
    if (!live.shown && run.lab.realLog) { run.lab.realLog.stop(); run.lab.realLog = null; }
    if (!live.shown) for (const d of Object.keys(ui.sh)) ui.sh[d].on = false;
    if (!live.shown) for (const [d, rs] of Object.entries(ui.rem)) if (rs.session) remEnd(d);
    if (was !== live.shown) { devTabs(); paint(); }
  };
  const liveTick = async () => {
    if (!real.on || real.busy || live.ticking) return;
    if (live.retryAt && Date.now() < live.retryAt) return; // don't hammer a VM that won't start
    live.retryAt = 0;
    live.ticking = true;
    try {
      real.net = real.net || new RealNet(realCall);
      if (real.net.stateKey(run.lab) !== real.net.key) {
        setLive(real.net.c ? "apply" : "boot");
        await real.net.apply(run.lab);
        if (Object.keys(ui.trace).length) await retrace();
        if (run.lab.realLog && real.net.nftReloaded) run.lab.realLog.reloaded = [...(run.lab.realLog.reloaded || []), ...real.net.nftReloaded];
        if (real.net.generation !== live.gen) {
          live.gen = real.net.generation;
          for (const sh of Object.values(ui.sh)) if (sh.id) { sh.id = null; sh.text += "\n[the lab network was rebuilt; a new shell starts with your next command]\n"; }
          // traces and captures were running in the old namespaces
          for (const [d, t] of Object.entries(ui.trace)) { realCall({ op: "shell.close", shell: t.id }).catch(() => {}); delete ui.trace[d]; }
          for (const [d, cp] of Object.entries(ui.cap)) { realCall({ op: "shell.close", shell: cp.id }).catch(() => {}); delete ui.cap[d]; print(d, "[the lab network was rebuilt; run the command again]"); }
          for (const [d, rs] of Object.entries(ui.rem)) if (rs.session) remEnd(d);
          for (const k of Object.keys(ui.hub)) if (ui.hub[k] instanceof ServerSession) delete ui.hub[k];
        }
      }
      setLive("live");
      // sessions that arrive from a Linux shell (busybox telnet), or any open one
      if (Date.now() - (live.conAt || 0) > 1500) { live.conAt = Date.now(); await remPoll(); if (Object.keys(ui.hub).some((x) => ui.hub[x] instanceof ServerSession)) remFast(); }
      await syncTracers();
      await pollWires();
      await trafficTick();
      await ipsTick();
      // SecOps: logs from the kernel, shipped over the lab network, collected where they arrive
      if (!run.lab.realLog) run.lab.realLog = new RealLogs(run.lab, realCall);
      if (Date.now() - (live.logAt || 0) > 1500) { live.logAt = Date.now(); await run.lab.realLog.tick(real.net.c, real.net.generation); }
      for (const [dev, c] of Object.entries(ui.cap)) {
        const r = await realCall({ op: "shell.read", shell: c.id, since: c.next });
        c.next = r.next;
        const lines = (c.partial + (r.data || "")).split("\n");
        c.partial = lines.pop();
        for (const l of lines) {
          if (c.kind === "ping") { print(dev, fortiPing(l)); continue; }
          const pk = parseTcpdump(l);
          const txt = pk && !c.full && snifferLine(c.s, pk);
          if (!txt) continue;
          print(dev, txt);
          if (++c.n >= (c.s.count || Infinity)) { c.full = true; realCall({ op: "shell.signal", shell: c.id }).catch(() => {}); }
        }
        if (!r.alive) {
          if (c.kind === "sniffer") { print(dev, `\n${c.n} packets received by filter\n0 packets dropped by kernel`); ui.pcap[dev] = true; devTabs(); }
          delete ui.cap[dev];
          realCall({ op: "shell.close", shell: c.id }).catch(() => {});
        }
        if (dev === ui.dev) paint();
      }
      for (const [dev, sh] of Object.entries(ui.sh)) {
        if (!sh.id) continue;
        const r = await realCall({ op: "shell.read", shell: sh.id, since: sh.next });
        if (r.data) { sh.text = (sh.text + r.data).slice(-200000); if (dev === ui.dev) paint(); else { ui.unread.add(dev); devTabs(); } }
        sh.next = r.next;
        if (!r.alive) { sh.id = null; sh.text += "\n[shell ended]\n"; if (dev === ui.dev) paint(); }
      }
    } catch (e) {
      setLive(e.unsupported ? "sim" : "err", e.message);
      if (!e.unsupported) { live.retryAt = Date.now() + 30000; real.net = null; }
      else live.retryAt = Date.now() + 5000;
    }
    finally { live.ticking = false; }
  };
  const startLive = () => { if (!live.timer) { live.timer = setInterval(() => { if (!document.body.contains(el)) { clearInterval(live.timer); return; } if (!document.hidden) liveTick(); }, 700); liveTick(); } };
  const toggleShell = (dev) => {
    const sh = ui.sh[dev] || (ui.sh[dev] = { on: false, id: null, text: "", next: 0 });
    sh.on = !sh.on;
    if (sh.on && !sh.text) sh.text = `Linux shell inside ${dev}, on the real lab network. Try: ip -br addr, ip route, ping -c 3 <ip>, traceroute <ip>, nslookup <name>, curl -sk https://<ip>, tcpdump -ni any -c 5\nType exit or press the button again to go back.\n\n`;
    paint(); inp.focus();
  };
  // diagnose debug flow on the real packets: nftables tracing in the FortiGate, in FortiOS words
  const syncTracers = async () => {
    for (const fg of run.lab.devices.values()) {
      if (!(fg instanceof FortiGate) || !fg.dbg || fg.kind !== "fortigate") continue;
      fg.dbg.real = live.state === "live";
      const want = fg.dbg.real && fg.dbg.enabled && fg.dbg.flowCount > 0;
      const key = JSON.stringify(fg.dbg.flowFilter || {});
      const t = ui.trace[fg.id];
      if (t && (!want || t.key !== key) && !t.stopping) { t.stopping = true; realCall({ op: "shell.signal", shell: t.id }).catch(() => {}); }
      if (want && !t) {
        const rules = traceRules(fg.dbg.flowFilter || {}, intToIp);
        const file = `/run/ftk/trace-${fg.id}.nft`;
        const r = await realCall({ op: "shell.open", ns: fg.id });
        const h = routeHelpers(real.net.c, fg.id);
        const nt = { id: r.shell, next: 0, partial: "", key, file };
        nt.ft = new FlowTrace({ ...h, onTrace: (lines) => {
          if (fg.dbg.flowCount <= 0) return;
          fg.dbg.flowCount--;
          for (const l of lines) print(fg.id, l);
          if (fg.id === ui.dev) paint(); else { ui.unread.add(fg.id); devTabs(); }
        } });
        ui.trace[fg.id] = nt;
        await realCall({ op: "shell.write", shell: r.shell, data: `mkdir -p /run/ftk\ncat > ${file} <<'FTKEOF'\n${rules}FTKEOF\nnft delete table ip ftktrace 2>/dev/null; nft -f ${file} && nft monitor trace; nft delete table ip ftktrace 2>/dev/null; exit\n` });
      }
    }
    for (const [dev, t] of Object.entries(ui.trace)) {
      const r = await realCall({ op: "shell.read", shell: t.id, since: t.next });
      t.next = r.next;
      const lines = (t.partial + (r.data || "")).split("\n");
      t.partial = lines.pop();
      for (const l of lines) t.ft.feed(l);
      if (!r.alive) { delete ui.trace[dev]; realCall({ op: "shell.close", shell: t.id }).catch(() => {}); }
    }
  };
  // a FortiGate's nftables reload wipes the trace table: put it back
  const retrace = async () => { for (const [dev, t] of Object.entries(ui.trace)) await realCall({ op: "ns.exec", ns: dev, argv: ["nft", "-f", t.file] }).catch(() => {}); };
  const downloadPcap = async (dev) => {
    try {
      const r = await realCall({ op: "ns.exec", ns: dev, argv: ["base64", `/run/ftk/cap-${dev}.pcap`] });
      const b64 = (r.stdout || "").replace(/\s+/g, "");
      const name = `${dev}-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.pcap`;
      if (window.FTAndroid && window.FTAndroid.saveFileBase64) { window.FTAndroid.saveFileBase64(name, "application/vnd.tcpdump.pcap", b64); return; }
      const bin = Uint8Array.from(atob(b64), (ch) => ch.charCodeAt(0));
      const a = document.createElement("a");
      a.href = URL.createObjectURL(new Blob([bin], { type: "application/vnd.tcpdump.pcap" }));
      a.download = name; document.body.appendChild(a); a.click();
      setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
    } catch (e) { print(dev, `[FortiTatake OS: couldn't read the capture: ${e.message}]`); paint(); }
  };
  // ----- SSH and Telnet between lab devices -----
  const REALCMD = /^(ping|tracert|traceroute|tr|pathping|arp|route|netstat|ss|uname|ip|sh|show|nslookup|dig)\b/i;
  // simulator commands that use a name: on the real network the name is looked up for real first
  const PRERESOLVE = /^(curl|wget|tnc|test-netconnection|nc)\b/i;
  const nameArg = (line) => {
    for (const a of line.trim().split(/\s+/).slice(1)) {
      if (a.startsWith("-")) continue;
      const m = a.match(/^[a-z]+:\/\/([^/:]+)/i);
      return m ? m[1] : a.split(/[/:]/)[0];
    }
    return null;
  };
  // curl / wget / Test-NetConnection / nc -> one real probe { proto, dst, port, host, path }
  const realProbe = (line, name, ip) => {
    if (!ip) return null;
    const t = line.trim(), w = t.split(/\s+/), c = w[0].toLowerCase();
    if (c === "curl" || c === "wget") {
      const u = w.slice(1).find((a) => !a.startsWith("-") && /[.:]/.test(a)) || "";
      const m = u.match(/^(?:(https?):\/\/)?([^/:]+)(?::(\d+))?(\/\S*)?/i);
      if (!m) return null;
      const proto = (m[1] || "http").toLowerCase();
      return { proto, dst: ip, port: Number(m[3] || (proto === "https" ? 443 : 80)), host: name && !isIp(name) ? name : "", path: m[4] || "/" };
    }
    if (c === "tnc" || c === "test-netconnection") {
      const pi = w.findIndex((a) => /^-port$/i.test(a));
      const port = pi >= 0 ? Number(w[pi + 1]) : 0;
      return port ? { proto: "tcp", dst: ip, port } : { proto: "icmp", dst: ip, count: 1 };
    }
    if (c === "nc") {
      const args = w.slice(1).filter((a) => !a.startsWith("-"));
      const port = Number(args[1]);
      return port ? { proto: w.some((a) => /^-\w*u/.test(a)) ? "udp" : "tcp", dst: ip, port } : null;
    }
    return null;
  };
  const localUser = (d) => (d.spec && d.spec.user) || (d.os === "windows" ? "User" : "admin");
  // the prompt a remote user gets on a device
  const remotePrompt = (devId, user) => {
    const d = run.device(devId);
    if (d.kind === "host" || d.kind === "server") return d.os === "windows" ? `C:\\Users\\${user}>` : `${user}@${d.hostname.toLowerCase()}:~$ `;
    return run.prompt(devId);
  };
  // a command typed in a remote session, answered by the device it arrived at
  const remoteAnswer = async (devId, line) => {
    const d = run.device(devId);
    if (live.state === "live" && ["host", "server", "router"].includes(d.kind) && REALCMD.test(line.trim()) && !isConfigLine(d, line)) {
      await catchUp();
      try { const o = d.kind === "router" ? await realRouterCmd(realCall, run.lab, d, line) : await realHostCmd(realCall, run.lab, d, line); if (o !== null) { run.log.push({ dev: devId, line }); return o; } } catch (e) { /* the simulator answers */ }
    }
    const o = run.exec(devId, line);
    pump();
    if (run.lab.pendingEdit) { const pe = run.lab.pendingEdit; run.lab.pendingEdit = null; openEditor(pe); }
    return o;
  };
  const remData = (dev, text) => {
    const rs = ui.rem[dev];
    if (!rs) return;
    const parts = (rs.pending + String(text).replace(/\r/g, "")).split("\n");
    rs.pending = parts.pop();
    if (parts.length) print(dev, parts.join("\n"));
    if (dev === ui.dev) paint(); else { ui.unread.add(dev); devTabs(); }
  };
  const remEnd = (dev, quiet) => {
    const rs = ui.rem[dev];
    if (!rs) return;
    delete ui.rem[dev];
    if (rs.session) realCall({ op: "remote.close", session: rs.session }).catch(() => {});
    if (rs.pending) print(dev, rs.pending);
    if (!quiet) print(dev, closedLine(run.device(dev), rs));
    if (dev === ui.dev) paint(); else { ui.unread.add(dev); devTabs(); }
  };
  const remConnected = (dev, rs, info) => {
    const d = run.device(dev);
    const L = connectedLines(d, rs, info || {}, ui.known.has(`${dev}>${rs.dst}`));
    if (L.length) print(dev, L.join("\n"));
    ui.known.add(`${dev}>${rs.dst}`);
    if (rs.proto === "ssh") { rs.stage = "pass"; rs.pending = passPrompt(d, rs); rs.tries = 0; }
    else { rs.stage = "open"; if (rs.server) rs.server.start(); }
    if (dev === ui.dev) paint();
  };
  const remoteCmd = (dev, line) => {
    const d = run.device(dev);
    if (!d || d.kind === "cloud") return false;
    const r = parseRemoteCmd(d, line, localUser(d).toLowerCase());
    if (!r) return false;
    print(dev, run.prompt(dev) + line);
    run.log.push({ dev, line });
    ui.hist[dev].push(line); ui.hi[dev] = ui.hist[dev].length;
    if (r.error) { print(dev, r.error); paint(); return true; }
    let dst = r.host;
    if (!isIp(dst)) {
      const ip = run.lab.lookupName(dst);
      if (!ip) {
        print(dev, d.kind === "router" ? "% Unknown command or computer name, or unable to find computer address" : r.proto === "ssh" ? `ssh: Could not resolve hostname ${dst}: ${d.os === "windows" ? "No such host is known." : "Name or service not known"}` : d.os === "windows" ? `Connecting To ${dst}...Could not open connection to the host, on port ${r.port}: Connect failed` : `telnet: could not resolve ${dst}/${r.port}: Name or service not known`);
        paint(); return true;
      }
      dst = intToIp(ip);
    }
    const rs = { ...r, dst, stage: "connecting", pending: "" };
    ui.rem[dev] = rs;
    paint();
    if (live.state === "live") {
      (async () => {
        try {
          const o = await realCall({ op: "remote.open", ns: dev, dst, port: r.port, proto: r.proto, user: r.user }, 15000);
          if (ui.rem[dev] !== rs) { if (o.session) realCall({ op: "remote.close", session: o.session }).catch(() => {}); return; }
          if (o.error) { delete ui.rem[dev]; print(dev, connectError(d, rs, o.error)); paint(); return; }
          rs.session = o.session;
          remConnected(dev, rs, o.info);
          remFast();
        } catch (e) {
          // an OS build from before v0.8.12 has no remote.* ops: the session runs in the simulator
          if (/unknown op/i.test(e.message) && ui.rem[dev] === rs) { if (!ui.oldOs) { ui.oldOs = true; print(dev, "[FortiTatake OS: this build is older than v0.8.12, so SSH and Telnet run in the simulator. Rebuild the OS to carry them on the real network.]"); } simOpen(dev, d, r, rs, dst); return; }
          delete ui.rem[dev]; print(dev, `[FortiTatake OS: ${e.message}]`); paint();
        }
      })();
      return true;
    }
    simOpen(dev, d, r, rs, dst);
    return true;
  };
  // simulator: a TCP probe decides whether the port answers, then the session runs in the app
  const simOpen = (dev, d, r, rs, dst) => {
    const req = { dst: ipToInt(dst), proto: 6, dport: r.port };
    if (d.kind === "router") { const i = d.ifaces.find((x) => x.prefix && (ipToInt(dst) >>> (32 - x.prefix.len)) === (x.prefix.ip >>> (32 - x.prefix.len))) || d.ifaces.find((x) => x.prefix); if (i) req.src = i.prefix.ip; }
    const res = run.lab.probe(dev, req);
    pump();
    if (!res.ok) {
      delete ui.rem[dev];
      const why = res.drop && res.drop.refused ? "refused" : res.drop && /route/i.test(res.drop.reason || "") ? "no route" : "timeout";
      setTimeout(() => { print(dev, connectError(d, rs, why)); paint(); }, why === "timeout" ? 1500 : 150);
      return true;
    }
    const target = run.device(res.reached);
    if (!target || target.kind === "cloud") { delete ui.rem[dev]; print(dev, r.proto === "ssh" ? "kex_exchange_identification: Connection closed by remote host" : "Connection closed by foreign host."); paint(); return true; }
    rs.server = new ServerSession({ dev: target, proto: r.proto, user: r.user, from: res.seenSrc !== undefined ? intToIp(res.seenSrc) : "", prompt: (u) => remotePrompt(target.id, u), answer: (l) => remoteAnswer(target.id, l), write: (t) => remData(dev, t), close: () => setTimeout(() => remEnd(dev), 0) });
    const fp = "SHA256:" + btoa(String.fromCharCode(...Array.from(target.id + dst, (c) => c.charCodeAt(0) & 255).concat(Array(32).fill(0)).slice(0, 32))).replace(/=+$/, "");
    setTimeout(() => ui.rem[dev] === rs && remConnected(dev, rs, { server: { windows: "SSH-2.0-OpenSSH_for_Windows_9.5", linux: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5", ios: "SSH-2.0-Cisco-1.25", fortios: "SSH-2.0-FortiSSH_7.4" }[rs.server.kind], kex: "curve25519-sha256", hostkey: "ssh-ed25519", cipher: "chacha20-poly1305@openssh.com", fingerprint: fp }), 120);
    return true;
  };
  const remLine = (dev, line) => {
    const rs = ui.rem[dev];
    if (rs.stage === "connecting") return;
    if (line.trim() === "~.") { print(dev, rs.pending + line); rs.pending = ""; remEnd(dev); return; }
    const masked = rs.stage === "pass" || /password: ?$/i.test(rs.pending);
    print(dev, rs.pending + (masked ? "" : line));
    rs.pending = "";
    if (!masked && line.trim()) { ui.hist[dev].push(line); ui.hi[dev] = ui.hist[dev].length; }
    if (rs.stage === "pass") {
      if (!line) {
        const d = run.device(dev);
        if (++rs.tries >= 3) { print(dev, d.kind === "router" ? "% Authentication failed." : `${rs.user}@${rs.host}: Permission denied (publickey,password,keyboard-interactive).`); rs.pending = ""; remEnd(dev, true); paint(); return; }
        print(dev, d.kind === "router" ? "% Authentication failed." : "Permission denied, please try again.");
        rs.pending = passPrompt(d, rs); paint(); return;
      }
      rs.stage = "open";
      if (rs.server) { rs.server.start(); paint(); return; }
    }
    paint();
    if (rs.server) { rs.server.line(line); return; }
    realCall({ op: "remote.send", session: rs.session, line }).then((w) => { if (!w.alive) remEnd(dev); }).catch(() => remEnd(dev));
  };
  // client sessions are read and arriving sessions answered every 250 ms while any is open
  const remPoll = async () => {
    if (ui.hub.busy || live.state !== "live") return;
    ui.hub.busy = true;
    try {
      for (const [dev, rs] of Object.entries(ui.rem)) {
        if (!rs.session) continue;
        const r = await realCall({ op: "remote.read", session: rs.session }).catch(() => ({ alive: false, data: "" }));
        if (ui.rem[dev] !== rs) continue;
        if (r.data) remData(dev, r.data);
        if (!r.alive) remEnd(dev);
      }
      const p = await realCall({ op: "console.poll" }).catch(() => ({ events: [] }));
      for (const ev of p.events || []) {
        if (ev.kind === "open") {
          const d = run.device(ev.ns);
          if (!d) { realCall({ op: "console.reply", sid: ev.sid, close: "1" }).catch(() => {}); continue; }
          const s = new ServerSession({ dev: d, proto: ev.proto, user: ev.user || "", from: ev.from, prompt: (u) => remotePrompt(d.id, u), answer: (l) => remoteAnswer(d.id, l),
            write: (t) => realCall({ op: "console.reply", sid: ev.sid, text: t }).catch(() => {}), close: () => { realCall({ op: "console.reply", sid: ev.sid, close: "1" }).catch(() => {}); delete ui.hub[ev.sid]; } });
          ui.hub[ev.sid] = s;
          s.start();
        } else if (ev.kind === "line" && ui.hub[ev.sid]) ui.hub[ev.sid].line(ev.line);
        else if (ev.kind === "close") delete ui.hub[ev.sid];
      }
    } finally { ui.hub.busy = false; }
  };
  const remFast = () => {
    if (ui.hub.timer) return;
    ui.hub.timer = setInterval(() => {
      const active = Object.values(ui.rem).some((x) => x.session) || Object.keys(ui.hub).some((k) => ui.hub[k] instanceof ServerSession);
      if (!document.body.contains(el) || !active) { clearInterval(ui.hub.timer); ui.hub.timer = null; return; }
      remPoll();
    }, 250);
  };

  // ----- click a wire: a live sniffer in a square picture-in-picture window -----
  ui.wires = ui.wires || {};
  const dragBy = (head, pip) => head.addEventListener("pointerdown", (e) => {
    if (e.target.closest("button, select, label")) return;
    const r = pip.getBoundingClientRect(), dx = e.clientX - r.left, dy = e.clientY - r.top;
    head.setPointerCapture(e.pointerId);
    const mv = (ev) => { pip.style.left = Math.max(0, Math.min(window.innerWidth - r.width, ev.clientX - dx)) + "px"; pip.style.top = Math.max(0, Math.min(window.innerHeight - 40, ev.clientY - dy)) + "px"; pip.style.right = "auto"; pip.style.bottom = "auto"; };
    const up = () => { head.removeEventListener("pointermove", mv); head.removeEventListener("pointerup", up); };
    head.addEventListener("pointermove", mv); head.addEventListener("pointerup", up);
  });
  const openWire = (w) => {
    const key = `${w.cap}|${w.port}|${w.seg}`;
    if (ui.wires[key]) { ui.wires[key].pip.focus(); return; }
    const n = Object.keys(ui.wires).length;
    const pip = h(`<section class="lr-pip" role="dialog" aria-label="Sniffer on ${esc(w.cap)} ${esc(w.port)}" tabindex="-1" style="right:${16 + n * 28}px;bottom:${16 + n * 28}px">
      <header class="pip-head"><span class="pip-title">${esc(w.cap)} ${esc(w.port)} \u2194 ${esc(w.peer)}</span><span class="pip-state"></span>
        <button data-a="pause" aria-label="Pause">Pause</button><button data-a="clear" aria-label="Clear">Clear</button><button data-a="close" aria-label="Close">\u2715</button></header>
      <div class="pip-cmd">${esc(run.device(w.cap) instanceof FortiGate ? run.prompt(w.cap) : w.cap + " # ")}diagnose sniffer packet ${esc(w.port)} 'none' 4 0 l</div>
      <pre class="pip-out" aria-live="off"></pre>
    </section>`);
    document.body.appendChild(pip);
    const out = $(".pip-out", pip), st = $(".pip-state", pip);
    const wd = { ...w, pip, lines: [], paused: false, n: 0, s: { intf: w.port, verbose: 4, count: 0, local: true } };
    ui.wires[key] = wd;
    if (!ui.wireNav) { ui.wireNav = true; window.addEventListener("hashchange", () => { ui.wireNav = false; for (const x of Object.values(ui.wires)) x.close(); }, { once: true }); }
    const render = () => { out.textContent = wd.lines.join("\n"); out.scrollTop = out.scrollHeight; };
    wd.add = (line) => { wd.n++; if (wd.paused) return; wd.lines.push(line); if (wd.lines.length > 400) wd.lines.splice(0, wd.lines.length - 400); render(); };
    const close = () => {
      pip.remove(); delete ui.wires[key];
      if (run.lab.taps) run.lab.taps.delete(key);
      if (wd.shell) { realCall({ op: "shell.signal", shell: wd.shell }).catch(() => {}); realCall({ op: "shell.close", shell: wd.shell }).catch(() => {}); }
    };
    wd.close = close;
    $$(".pip-head [data-a]", pip).forEach((b) => (b.onclick = () => {
      if (b.dataset.a === "close") close();
      else if (b.dataset.a === "clear") { wd.lines = []; render(); }
      else { wd.paused = !wd.paused; b.textContent = wd.paused ? "Resume" : "Pause"; }
    }));
    pip.addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });
    dragBy($(".pip-head", pip), pip);
    if (live.state === "live" && real.on) {
      st.textContent = "real network";
      (async () => {
        try {
          const r = await realCall({ op: "shell.open", ns: w.cap });
          if (!ui.wires[key]) { realCall({ op: "shell.close", shell: r.shell }).catch(() => {}); return; }
          wd.shell = r.shell; wd.next = 0; wd.partial = "";
          await realCall({ op: "shell.write", shell: r.shell, data: `tcpdump -Z root -l -n -S -tt -i any 2>/dev/null; exit\n` });
        } catch (e) { wd.add(`[FortiTatake OS: ${e.message}]`); }
      })();
    } else {
      st.textContent = "simulator";
      run.lab.taps = run.lab.taps || new Map();
      run.lab.taps.set(key, { seg: w.seg, cap: w.cap, hub: w.hub, push: (e) => wd.add(`${localStamp(Date.now())} ${w.port} ${e.dir} ${e.text}`) });
    }
    wd.add(`Using Original Sniffing Mode\ninterfaces=[${w.port}]\nfilters=[none]`);
    pip.focus();
  };
  const pollWires = async () => {
    for (const wd of Object.values(ui.wires)) {
      if (!wd.shell) continue;
      const r = await realCall({ op: "shell.read", shell: wd.shell, since: wd.next }).catch(() => null);
      if (!r) continue;
      wd.next = r.next;
      const lines = (wd.partial + (r.data || "")).split("\n");
      wd.partial = lines.pop();
      for (const l of lines) { const pk = parseTcpdump(l); const txt = pk && snifferLine(wd.s, pk); if (txt) wd.add(txt); }
      if (!r.alive) { wd.add(`\n${wd.n} packets received by filter\n0 packets dropped by kernel`); wd.shell = null; }
    }
  };

  // ----- office traffic: the five generators, run by the agent in each client's namespace -----
  ui.traffic = ui.traffic || { on: false, rate: 1, next: 0, events: [], running: [], gen: -1, rec: null, pollAt: 0 };
  const trafficStop = async () => { await realCall({ op: "gen.stop" }).catch(() => {}); };
  const trafficSet = async (on) => {
    const T = ui.traffic;
    T.on = on; T.gen = -1;
    run.lab.traffic = { on };
    run.lab.dirty();
    if (!on) { T.rec = null; await trafficStop(); }
    devTabs(); renderTraffic();
  };
  const trafficTick = async () => {
    const T = ui.traffic;
    if (!T.on || !real.net) return;
    if (T.gen !== real.net.generation || T.rateSent !== T.rate) {
      await trafficStop();
      const plan = trafficPlan(run.lab, T.rec ? BASELINE_RATE : T.rate);
      T.planned = plan.length; T.failed = [];
      for (const g of plan) {
        const r = await realCall({ op: "gen.start", ...g }).catch((e) => ({ err: e.message }));
        if (r && r.err) { if (/unknown op|not allowed/.test(r.err)) { T.failed = ["This FortiTatake OS image is older than office traffic (agent 0.11). Rebuild it on the OS screen."]; break; } T.failed.push(`${g.id}: ${r.err}`); }
      }
      T.gen = real.net.generation; T.rateSent = T.rate;
      renderTraffic();
    }
    if (Date.now() - T.pollAt < 1500) return;
    T.pollAt = Date.now();
    const r = await realCall({ op: "gen.stats", since: T.next }).catch(() => null);
    if (!r) return;
    T.next = r.next; T.running = r.running || [];
    for (const e of r.events || []) {
      T.events.push(e);
      if (T.rec) T.rec.events.push({ ...e, vt: virtualTime(T.rec.start, e.t) });
    }
    if (T.events.length > 400) T.events.splice(0, T.events.length - 400);
    if (T.rec && Date.now() - T.rec.start >= T.rec.ms) finishBaseline();
    renderTraffic();
  };
  const blKey = () => `ftk-baseline-${run.def.id}`;
  const loadBaseline = () => { try { return JSON.parse(localStorage.getItem(blKey()) || "null"); } catch (e) { return null; } };
  const finishBaseline = () => {
    const T = ui.traffic, rec = T.rec;
    T.rec = null; T.rateSent = -1; // back to the chosen rate
    const bl = { lab: run.def.id, recorded: new Date().toISOString(), rate: BASELINE_RATE, hours: BASELINE_HOURS, events: rec.events.map(({ vt, ns, kind, what, dst, port, proto, bytes, ok }) => ({ vt, ns, kind, what, dst, port, proto, bytes, ok })) };
    try { localStorage.setItem(blKey(), JSON.stringify(bl)); } catch (e) { /* too big for this browser: still offered as a download */ }
    T.baseline = bl;
  };
  const downloadBaseline = () => {
    const bl = ui.traffic.baseline || loadBaseline();
    if (!bl) return;
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([JSON.stringify(bl, null, 1)], { type: "application/json" }));
    a.download = `baseline-${run.def.id}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  };
  const renderTraffic = () => {
    const T = ui.traffic, pip = T.pip;
    if (!pip) return;
    $("[data-a=toggle]", pip).textContent = T.on ? "Stop" : "Start";
    $("[data-a=rec]", pip).disabled = !T.on || !!T.rec;
    $(".pip-state", pip).textContent = T.rec ? `recording a workday: ${Math.min(100, Math.round((Date.now() - T.rec.start) / T.rec.ms * 100))} %` : T.on ? `${T.running.length} generators` : "stopped";
    const rows = T.running.slice().sort((a, b) => a.id.localeCompare(b.id)).map((g) => `${g.ns.padEnd(12)} ${g.kind.padEnd(6)} ${String(g.flows).padStart(5)} flows ${String(g.errors).padStart(4)} failed ${fmtBytes(g.bytes).padStart(9)}`);
    const bl = T.baseline || loadBaseline();
    const sum = bl ? Object.entries(summarize(bl.events)).map(([k, v]) => `  ${k.padEnd(6)} ${String(v.flows).padStart(5)} flows, ${v.ok} ok, ${fmtBytes(v.bytes)}`).join("\n") : "";
    const evs = T.events.slice(-120).map((e) => `${localStamp(e.t).slice(11, 19)} ${e.ns} ${e.kind} ${e.what} -> ${e.dst}:${e.port}/${e.proto} ${e.ok ? fmtBytes(e.bytes) : "FAILED " + (e.err || "")}`);
    $(".pip-sum", pip).textContent = [
      T.on ? "" : "Stopped. Start runs browsing, DNS, file share, mail and voice from the lab PCs, for real: the flows cross your policies, NAT, the session list, the sniffer and the logs.",
      ...(T.failed && T.failed.length ? ["Could not start:", ...T.failed.map((f) => "  " + f)] : []),
      ...(rows.length ? ["Device       Gen    Flows", ...rows] : []),
      ...(bl ? [`Baseline workday recorded ${bl.recorded.slice(0, 16).replace("T", " ")} (${bl.events.length} flows):`, sum] : []),
    ].filter((x) => x).join("\n");
    $(".pip-out", pip).textContent = evs.join("\n");
    const o = $(".pip-out", pip); o.scrollTop = o.scrollHeight;
  };
  const openTraffic = () => {
    const T = ui.traffic;
    if (T.pip) { T.pip.focus(); return; }
    const pip = h(`<section class="lr-pip lr-traffic" role="dialog" aria-label="Office traffic" tabindex="-1" style="right:16px;bottom:16px">
      <header class="pip-head"><span class="pip-title">Office traffic</span><span class="pip-state"></span><button data-a="close" aria-label="Close">\u2715</button></header>
      <div class="pip-cmd pip-ctl"><button data-a="toggle">Start</button>
        <label>Speed <select data-a="rate"><option value="1">1\u00d7 (real time)</option><option value="10">10\u00d7</option><option value="60">60\u00d7</option></select></label>
        <button data-a="rec" title="Run a 9-hour office day at ${BASELINE_RATE}\u00d7 (about 4.5 minutes) and keep its flows as this lab's baseline">Record a workday</button>
        <button data-a="dl" title="The recorded baseline as JSON">Baseline .json</button></div>
      <pre class="pip-sum"></pre>
      <pre class="pip-out" aria-live="off"></pre>
    </section>`);
    document.body.appendChild(pip);
    T.pip = pip;
    $("[data-a=rate]", pip).value = String(T.rate);
    $("[data-a=rate]", pip).onchange = (e) => { T.rate = Number(e.target.value); renderTraffic(); };
    $("[data-a=toggle]", pip).onclick = () => trafficSet(!T.on);
    $("[data-a=rec]", pip).onclick = () => { T.rec = { start: Date.now(), ms: (BASELINE_HOURS * 3600000) / BASELINE_RATE, events: [] }; T.rateSent = -1; renderTraffic(); };
    $("[data-a=dl]", pip).onclick = downloadBaseline;
    const close = () => { pip.remove(); T.pip = null; };
    $("[data-a=close]", pip).onclick = close;
    pip.addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });
    dragBy($(".pip-head", pip), pip);
    if (!ui.trafficNav) { ui.trafficNav = true; window.addEventListener("hashchange", () => { ui.trafficNav = false; if (T.pip) close(); if (T.on) { T.on = false; trafficStop(); } }, { once: true }); }
    renderTraffic();
    pip.focus();
  };

  // ----- IPS hits from the real engine become FortiGate utm/ips logs -----
  const ipsTick = async () => {
    if (!real.net || !real.net.c || !Object.keys(real.net.c.ips || {}).length) return;
    if (Date.now() - (live.ipsAt || 0) < 1200) return;
    live.ipsAt = Date.now();
    const r = await realCall({ op: "ips.log", since: ui.ipsNext === undefined ? 1e12 : ui.ipsNext }).catch(() => null);
    if (!r) return;
    ui.ipsNext = r.next;
    for (const h of r.hits || []) {
      const fg = run.lab.dev(h.ns);
      const rec = fg && ipsLogRec(run.lab, fg, h);
      if (rec) run.lab.storeLog(fg, { ...run.lab.ipsStamp(), devname: fg.hostname(), devid: fg.serial, vd: "root", ...rec, seq: h.seq });
      ui.ipsHits = [...(ui.ipsHits || []), h].slice(-200);
    }
  };

  // ----- attacks: a threat pack's requests from the lab Internet (or a lab device) at a target -----
  const openAttacks = () => {
    if (ui.atkPip) { ui.atkPip.focus(); return; }
    const packs = run.lab.threats || [];
    const srcs = [{ v: "@attacker", l: `Internet attacker (${ATTACKER_IP})` }, ...devs.filter((d) => ["host", "server"].includes(d.kind) && d.ip && d.ip()).map((d) => ({ v: d.id, l: `${d.id} (${intToIp(d.ip())})` }))];
    const tg = [...new Set([...run.lab.names.keys()].filter((n) => !/^(dns\.google|one\.one|www\.google|update\.microsoft)/.test(n)))];
    const tgts = [...tg.map((n) => ({ v: n, l: n })), ...devs.filter((d) => d.kind === "server" && d.ip && d.ip()).map((d) => ({ v: d.id, l: `${d.id} (${intToIp(d.ip())})` }))];
    const opt = (xs) => xs.map((x) => `<option value="${esc(x.v)}">${esc(x.l)}</option>`).join("");
    const pip = h(`<section class="lr-pip lr-traffic lr-attack" role="dialog" aria-label="Attacks" tabindex="-1" style="left:16px;bottom:16px">
      <header class="pip-head"><span class="pip-title">Attacks (threat packs)</span><span class="pip-state"></span><button data-a="close" aria-label="Close">\u2715</button></header>
      <div class="pip-cmd pip-ctl">
        <label>Pack <select data-a="pack">${packs.map((p) => `<option value="${esc(p.id)}">${esc(p.id)} ${esc(p.name)}</option>`).join("")}</select></label>
        <label>From <select data-a="src">${opt(srcs)}</select></label>
        <label>At <select data-a="dst">${opt(tgts)}</select></label>
        <label>Port <select data-a="port"><option value="">pack default</option><option>80</option><option>443</option><option>8443</option><option>10443</option></select></label>
        <button data-a="go">Launch</button></div>
      <pre class="pip-sum"></pre>
      <pre class="pip-out" aria-live="polite"></pre>
    </section>`);
    document.body.appendChild(pip);
    ui.atkPip = pip;
    const sumEl = $(".pip-sum", pip), outEl = $(".pip-out", pip);
    const showPack = () => { const p = packs.find((x) => x.id === $("[data-a=pack]", pip).value); sumEl.textContent = p ? `${p.cve.join(", ")} \u00b7 ${p.severity} \u00b7 port ${p.generator.port}${p.generator.tls ? " (HTTPS)" : ""}\n${p.summary}\nLesson: ${p.lesson}` : ""; };
    $("[data-a=pack]", pip).onchange = showPack;
    showPack();
    const say = (t) => { outEl.textContent += t + "\n"; outEl.scrollTop = outEl.scrollHeight; };
    $("[data-a=go]", pip).onclick = async () => {
      const packId = $("[data-a=pack]", pip).value, from = $("[data-a=src]", pip).value, to = $("[data-a=dst]", pip).value, portSel = $("[data-a=port]", pip).value;
      const pack = packs.find((x) => x.id === packId);
      const src = attackSource(run.lab, from), dst = attackTarget(run.lab, to);
      if (!pack || !src || !dst) { say("Pick a pack, a source with an address and a target."); return; }
      const { port, tls } = attackPort(pack, portSel);
      say(`\n${localStamp(Date.now()).slice(11, 19)} ${pack.id} from ${src.label} at ${dst.host} (${dst.ip}:${port}${tls ? ", HTTPS" : ""})`);
      if (live.state === "live" && real.on) {
        try {
          await catchUp();
          const since = (await realCall({ op: "ips.log", since: 1e12 })).next;
          const reqs = attackRequests(pack, dst.host, "ftk-" + Math.random().toString(36).slice(2, 8));
          const r = await realCall({ op: "attack.run", ns: src.id, src: src.ip, dst: dst.ip, port, tls, sni: dst.host, ...(reqs[0].hex ? { requests_hex: reqs.map((x) => x.hex) } : { requests: reqs.map((x) => x.raw) }), timeout_ms: 2500 }, 30000);
          await new Promise((x) => setTimeout(x, 400));
          const hits = (await realCall({ op: "ips.log", since })).hits || [];
          await ipsTick();
          r.results.forEach((x, i) => {
            const hh = hits.find((y) => x.local && x.local.endsWith(":" + y.sport));
            const ips = hh ? ` \u2190 IPS ${hh.action} on ${hh.ns} policy ${hh.policy}, signature ${hh.sig}${hh.tls ? " (decrypted)" : ""}` : "";
            say(`  ${reqs[i].name.padEnd(22)} ${x.status ? "answered: " + x.status : x.kind === "timeout" ? "no answer (dropped)" : x.kind === "reset" ? "connection reset" : x.kind || "failed"}${ips}${x.error && !x.status && x.kind !== "timeout" && x.kind !== "reset" ? " (" + x.error + ")" : ""}`);
          });
          if (real.net && real.net.ipsErr) say(`  [FortiTatake OS: the IPS engine didn't start: ${real.net.ipsErr}]`);
          else if (real.net && !Object.keys(real.net.c.ips || {}).length && real.net.agentVer && !/^0\.(1[2-9]|[2-9]\d)/.test(real.net.agentVer)) say("  [This FortiTatake OS image predates the IPS engine (agent 0.12). Rebuild it on the OS screen.]");
        } catch (e) { say(`  [real network: ${e.message}]`); }
      } else {
        const r = run.lab.attackSim(from, to, packId, port);
        if (r.error) { say("  " + r.error); return; }
        for (const x of r.results) say(`  ${x.variant.padEnd(22)} ${x.outcome}: ${x.detail}`);
        pump();
      }
      run.log.push({ dev: "@attack", line: `${packId} ${from} ${to} ${port}` });
      store(run, k);
    };
    const close = () => { pip.remove(); ui.atkPip = null; };
    $("[data-a=close]", pip).onclick = close;
    pip.addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });
    dragBy($(".pip-head", pip), pip);
    window.addEventListener("hashchange", () => { if (ui.atkPip) close(); }, { once: true });
    pip.focus();
  };

  // wait until the real network matches the lab (after an address or route change)
  const catchUp = async () => {
    for (let i = 0; i < 60 && real.on && real.net && real.net.stateKey(run.lab) !== real.net.key; i++) {
      await liveTick();
      if (real.net.stateKey(run.lab) !== real.net.key) await new Promise((r) => setTimeout(r, 250));
    }
  };

  // ----- a small nano-style editor (Notepad on Windows) for config files -----
  const openEditor = (pe) => {
    const old = $(".lr-editor", el); if (old) old.remove();
    const win = pe.app === "notepad";
    const name = pe.path.split(/[\\/]/).pop();
    const ed = h(`<div class="lr-editor${win ? " notepad" : ""}" role="dialog" aria-label="Editing ${esc(pe.path)}">
      <div class="ed-title">${win ? `<span>${esc(name)} - Notepad</span>` : `<span>GNU nano 7.2</span><span class="ed-path">${esc(pe.path)}</span><span class="ed-mod"></span>`}</div>
      <textarea class="ed-text" spellcheck="false" autocapitalize="off" autocomplete="off" aria-label="File contents"></textarea>
      <div class="ed-status" aria-live="polite"></div>
      <div class="ed-keys">${win
        ? `<button data-a="save">Save <span class="kbd">Ctrl+S</span></button><button data-a="exit">Close <span class="kbd">Esc</span></button>`
        : `<button data-a="save"><b>^O</b> Write Out</button><button data-a="exit"><b>^X</b> Exit</button><button data-a="find"><b>^W</b> Where Is</button><button data-a="cut"><b>^K</b> Cut</button><button data-a="paste"><b>^U</b> Paste</button>`}</div>
    </div>`);
    const ta = $(".ed-text", ed), st = $(".ed-status", ed), mod = $(".ed-mod", ed);
    ta.value = pe.text;
    let saved = pe.text, clip = "", ask = null;
    const lines = (s) => (s.match(/\n/g) || []).length + (s && !s.endsWith("\n") ? 1 : 0);
    const status = (msg) => { st.textContent = msg || ""; };
    const dirty = () => ta.value !== saved;
    const markMod = () => { if (mod) mod.textContent = dirty() ? "Modified" : ""; };
    status(pe.note || (pe.readOnly ? `[ ${pe.path} is owned by root: open it with sudo to save changes ]` : win ? "" : `[ Read ${lines(pe.text)} lines ]`));
    const save = () => {
      if (pe.readOnly) { status(`[ Error writing ${pe.path}: Permission denied ]`); return false; }
      const msg = run.exec(pe.dev, "\u0001write " + pe.path + "\n" + ta.value);
      saved = ta.value; markMod(); store(run, k);
      status(win ? `Saved ${name}` : `[ Wrote ${lines(ta.value)} lines ]`);
      if (msg) print(pe.dev, msg);
      return true;
    };
    const close = () => { ed.remove(); delete el.dataset.edit; paint(); topo(); inp.focus(); };
    const exit = () => {
      if (!dirty()) return close();
      ask = "save"; status(win ? "Do you want to save changes to " + name + "?" : "Save modified buffer?");
      // buttons too, for phones without Ctrl or Y/N keys handy
      st.insertAdjacentHTML("beforeend", ` <button data-yn="y">${win ? "Save" : "Y Yes"}</button> <button data-yn="n">${win ? "Don't save" : "N No"}</button> <button data-yn="c">${win ? "Cancel" : "^C Cancel"}</button>`);
      $$("[data-yn]", st).forEach((b) => (b.onclick = () => answer(b.dataset.yn)));
    };
    const answer = (k) => {
      if (k === "y") { if (save()) close(); else ask = null; }
      else if (k === "n") close();
      else { ask = null; status("[ Cancelled ]"); ta.focus(); }
    };
    const find = () => { ask = "find"; status(win ? "" : "Search: "); };
    const act = (a) => {
      if (a === "save") save();
      else if (a === "exit") exit();
      else if (a === "find") find();
      else if (a === "cut") { const v = ta.value, p = ta.selectionStart; const s0 = v.lastIndexOf("\n", p - 1) + 1; let e0 = v.indexOf("\n", p); e0 = e0 < 0 ? v.length : e0 + 1; clip = v.slice(s0, e0); ta.value = v.slice(0, s0) + v.slice(e0); ta.selectionStart = ta.selectionEnd = s0; markMod(); }
      else if (a === "paste") { const v = ta.value, p = ta.selectionStart; ta.value = v.slice(0, p) + clip + v.slice(p); ta.selectionStart = ta.selectionEnd = p + clip.length; markMod(); }
      ta.focus();
    };
    let query = "";
    ed.addEventListener("keydown", (e) => {
      if (ask === "save") {
        e.preventDefault();
        const kk = e.key.toLowerCase();
        if (kk === "y" || kk === "n") answer(kk);
        else if (kk === "escape" || (kk === "c" && e.ctrlKey)) answer("c");
        return;
      }
      if (ask === "find") {
        e.preventDefault();
        if (e.key === "Enter") { ask = null; const i = ta.value.indexOf(query, ta.selectionEnd) >= 0 ? ta.value.indexOf(query, ta.selectionEnd) : ta.value.indexOf(query); if (query && i >= 0) { ta.setSelectionRange(i, i + query.length); status(""); } else status(`[ "${query}" not found ]`); query = ""; }
        else if (e.key === "Escape" || (e.key === "c" && e.ctrlKey)) { ask = null; query = ""; status("[ Cancelled ]"); }
        else if (e.key === "Backspace") { query = query.slice(0, -1); status("Search: " + query); }
        else if (e.key.length === 1) { query += e.key; status("Search: " + query); }
        return;
      }
      const kk = e.key.toLowerCase();
      if (e.ctrlKey && (kk === "o" || kk === "s")) { e.preventDefault(); act("save"); }
      else if ((e.ctrlKey && kk === "x") || (win && kk === "escape")) { e.preventDefault(); act("exit"); }
      else if (e.ctrlKey && kk === "w" && !win) { e.preventDefault(); act("find"); }
      else if (e.ctrlKey && kk === "k" && !win) { e.preventDefault(); act("cut"); }
      else if (e.ctrlKey && kk === "u" && !win) { e.preventDefault(); act("paste"); }
      e.stopPropagation();
    });
    ta.addEventListener("input", markMod);
    $$(".ed-keys [data-a]", ed).forEach((b) => (b.onclick = () => act(b.dataset.a)));
    $(".lr-devtabs", el).after(ed);
    el.dataset.edit = "1";
    if (ui.view !== "term") setView("term");
    ta.focus(); ta.setSelectionRange(0, 0); ta.scrollTop = 0;
  };

  // PCs, servers and ISP routers: troubleshooting commands answered from the real network
  const realDevCmd = (dev, line) => {
    const d = run.device(dev);
    if (live.state !== "live" || !d || !["host", "server", "router"].includes(d.kind) || !line.trim() || /^(cls|clear)$/i.test(line.trim())) return false;
    if (PRERESOLVE.test(line.trim()) && d.kind !== "router") {
      print(dev, run.prompt(dev) + line);
      ui.hist[dev].push(line); ui.hi[dev] = ui.hist[dev].length;
      paint();
      (async () => {
        const name = nameArg(line);
        let ip = name && isIp(name) ? name : null;
        if (name && !ip) { const he = hostsEntry(d, name); if (he !== null) ip = intToIp(he); else { const r = await realResolve(realCall, run.lab, d, name).catch(() => null); if (r && !r.err) ip = r.ip; } }
        const simOut = run.exec(dev, line);
        run.drain();
        // the same connection on the real network, so the FortiGate's session table, logs and sniffer see it
        const pr = realProbe(line, name, ip);
        let note = "";
        if (pr) {
          await catchUp();
          try {
            const r = await realCall({ op: "probe", ns: dev, ...pr, timeout_ms: 4000, hold_ms: 60000 }, 8000);
            const simOk = !/fail|refused|timed out|could not|unable|not recognized|no route|denied|unreachable|reset/i.test(simOut || "");
            if (r && r.pass === false && simOk) note = `\n[real network: ${pr.proto.toUpperCase()} to ${pr.dst}:${pr.port} ${r.error || "failed"}${r.detail ? ` (${r.detail})` : ""}]`;
          } catch (e) { /* the simulator's answer stands */ }
        }
        print(dev, (simOut || "") + note);
        if (dev === ui.dev) paint(); else { ui.unread.add(dev); devTabs(); }
      })();
      return true;
    }
    if (!REALCMD.test(line.trim()) || isConfigLine(d, line)) return false;
    print(dev, run.prompt(dev) + line);
    ui.hist[dev].push(line); ui.hi[dev] = ui.hist[dev].length;
    paint();
    (async () => {
      // a name is looked up for real before the simulator sees it, so both use the real answer
      const name = d.kind !== "router" && /^(ping|tracert|traceroute|pathping|nslookup|dig)\b/i.test(line.trim()) ? nameArg(line.replace(/\s-[a-z]+\s+\d+/gi, " ")) : null;
      if (name && !isIp(name)) await realResolve(realCall, run.lab, d, name).catch(() => null);
      const simOut = run.exec(dev, line); // history and checks; also the answer if the OS can't give one
      run.drain();
      await catchUp(); // an address change made just before must be on the real network first
      let out = null;
      try { out = d.kind === "router" ? await realRouterCmd(realCall, run.lab, d, line) : await realHostCmd(realCall, run.lab, d, line); }
      catch (e) { out = null; }
      print(dev, out !== null ? out : simOut);
      if (dev === ui.dev) paint(); else { ui.unread.add(dev); devTabs(); }
    })();
    return true;
  };
  // FortiGate commands that read the real network when it's live
  const realDiag = (dev, line) => {
    const fg = run.device(dev);
    if (!(fg instanceof FortiGate) || live.state !== "live" || fg.kind !== "fortigate") return false;
    const sn = parseSnifferCmd(line);
    const pg = /^\s*exec(?:u|ut|ute)?\s+ping\s+(\S+)\s*$/i.exec(line);
    const sl = /^\s*diag(?:n|no|nos|nose)?\s+sys(?:t|te|tem)?\s+session\s+(list|clear)\s*$/i.exec(line);
    const rt = /^\s*get\s+router\s+info\s+routing-table(?:\s+all)?\s*$/i.exec(line);
    if (sl || rt) {
      print(dev, run.prompt(dev) + line);
      run.exec(dev, line); // history for the checks; the output below comes from the kernel
      run.drain();
      ui.hist[dev].push(line); ui.hi[dev] = ui.hist[dev].length;
      paint();
      const h = routeHelpers(real.net.c, dev);
      (async () => {
        try {
          if (sl && sl[1].toLowerCase() === "clear") { await realCall({ op: "ns.exec", ns: dev, argv: ["conntrack", "-F"] }); }
          else if (sl) {
            const r = await realCall({ op: "ns.exec", ns: dev, argv: ["conntrack", "-L", "-o", "id"] });
            const f = (fg.dbg && fg.dbg.sessFilter) || {};
            print(dev, formatSessions(parseConntrack(r.stdout || ""), { ...h, age: (x) => Math.max(1, (x.proto === 6 ? 3600 : x.proto === 17 ? 180 : 10) - x.expire) }, f));
          } else {
            const r = await realCall({ op: "ns.exec", ns: dev, argv: ["ip", "-j", "route", "show"] });
            const { active } = run.lab.fgtRoutes(fg);
            const sim = active.map((x) => ({ k: `${intToIp(x.dst.ip)}/${x.dst.len}`, type: x.type, distance: x.distance, priority: x.priority, metric: x.metric }));
            print(dev, formatRoutes(JSON.parse(r.stdout || "[]"), sim));
          }
        } catch (e) { print(dev, `[FortiTatake OS: ${e.message}]`); }
        paint();
      })();
      return true;
    }
    if (!sn && !pg) return false;
    if (ui.cap[dev]) { print(dev, run.prompt(dev) + line); print(dev, "A capture or ping is still running here: press Ctrl+C first."); paint(); return true; }
    print(dev, run.prompt(dev) + line);
    run.exec(dev, line); // keeps the command in the history the checks look at
    run.drain();
    if (fg.dbg) fg.dbg.sniffer = null;
    let cmd, cap;
    if (sn) {
      const known = sn.intf === "any" || run.lab.fgtIntfs(fg).some((i) => i.name === sn.intf);
      if (!known) { print(dev, `Interface ${sn.intf} not found.`); paint(); return true; }
      const f = safeFilter(sn.filter);
      if (f === null) { print(dev, "Invalid filter."); paint(); return true; }
      print(dev, snifferHeader(sn));
      // --print with -w: FortiOS-style lines now, and a .pcap to download afterwards
      cmd = `mkdir -p /run/ftk; tcpdump -Z root -l -n -S -tt -i any -U -w /run/ftk/cap-${dev}.pcap --print ${f ? `'${f}'` : ""} 2>/dev/null; exit`;
      cap = { kind: "sniffer", s: sn, n: 0 };
    } else {
      let dst = pg[1];
      if (!isIp(dst)) { const ip = run.lab.lookupName(dst); if (!ip) { print(dev, `Unable to resolve hostname.`); paint(); return true; } dst = intToIp(ip); }
      const src = fg.dbg && fg.dbg.pingSrc ? ` -I ${intToIp(fg.dbg.pingSrc)}` : "";
      cmd = `ping -c 5 -W 2${src} ${dst} 2>&1; exit`;
      cap = { kind: "ping" };
    }
    ui.hist[dev].push(line); ui.hi[dev] = ui.hist[dev].length;
    paint();
    (async () => {
      try {
        const r = await realCall({ op: "shell.open", ns: dev });
        ui.cap[dev] = { ...cap, id: r.shell, next: 0, partial: "" };
        await realCall({ op: "shell.write", shell: r.shell, data: cmd + "\n" });
      } catch (e) { print(dev, `[FortiTatake OS: ${e.message}]`); delete ui.cap[dev]; paint(); }
    })();
    return true;
  };
  const shellLine = async (dev, line) => {
    const sh = ui.sh[dev];
    if (line.trim() === "clear") { sh.text = ""; paint(); return; }
    if (line.trim() === "exit") { sh.on = false; devTabs(); paint(); return; }
    sh.text += `${dev} (Linux) # ${line}\n`;
    if (line.trim()) { ui.hist[dev].push(line); ui.hi[dev] = ui.hist[dev].length; }
    paint();
    try {
      if (!sh.id) { const r = await realCall({ op: "shell.open", ns: dev }); sh.id = r.shell; sh.next = 0; }
      const w = await realCall({ op: "shell.write", shell: sh.id, data: line + "\n" });
      if (!w.alive) { sh.id = null; sh.text += "[shell ended; press Enter to start a new one]\n"; paint(); }
    } catch (e) { sh.text += `[FortiTatake OS: ${e.message}]\n`; paint(); }
  };

  const doCheck = async () => {
    if (real.busy) return;
    const was = new Set(run.passed);
    let res;
    if (real.on) {
      real.busy = true;
      const b = $("[data-check]", side); if (b) { b.disabled = true; b.textContent = "Checking on the real network…"; }
      try { real.net = real.net || new RealNet(realCall); res = await run.checkReal(real.net); }
      catch (e) { res = run.check(); }
      finally { real.busy = false; }
    } else res = run.check();
    const p = run.current;
    let note = "";
    if (run.passed.has(p.id) && !was.has(p.id)) {
      const hints = run.hints[p.id] || 0, revealed = !!run.revealed[p.id];
      record("lab_part", { lab: def.id, part: p.id, hints, revealed, ...(emb ? { sortie: true, exam: !!opts.exam, ms: run.elapsed } : {}) });
      // the part becomes a review item: revealed = Again, hints = Hard, clean = Good
      record("review", { item: partItemId(def.id, p.id), kind: "labpart", module: (def.modules || [])[0], rating: revealed ? 1 : hints ? 2 : 3 });
      if (emb) note = `<div class="verdict ok">Part complete.</div>`;
      else if (run.finished()) {
        const score = run.score();
        record("lab_done", { lab: def.id, kind: def.kind, track: def.track, tier: def.tier, score, elapsed: run.elapsed, exam: !!run.exam });
        note = `<div class="verdict ok"><b>Lab complete: ${score} points.</b> ${run.exam ? "Exam mode bonus applied." : ""}</div>`;
      } else note = `<div class="verdict ok">Part complete.</div>`;
    }
    store(run, k);
    renderSide(res, note);
    topo();
  };

  const tick = setInterval(() => {
    if (!document.body.contains(el)) { clearInterval(tick); return; }
    if (!document.hidden && !run.finished()) run.elapsed += 1000;
    const t = $("[data-timer]", el); if (t) t.textContent = mmss(run.elapsed) + ` / ${def.par || 30}:00`;
    if (run.elapsed % 15000 === 0) store(run, k);
  }, 1000);
  const ex = $("[data-exam]", el); if (ex) ex.onchange = (e) => { run.exam = e.target.checked; store(run, k); renderSide(); };
  $("[data-reset]", el).onclick = () => { if (confirm("Reset this lab to its starting state? Your configuration and progress in it are lost.")) { if (emb) opts.reset(); else { forget(def.id); labView(main, def.id); } } };
  const lv = $("[data-leave]", el); if (lv) lv.onclick = () => opts.finish(null);

  devTabs(); paint(); topo(); renderSide();
}

function solutionHtml(p) {
  return `<div class="call md"><b>Reference solution</b><p class="tiny">One valid way. Others pass too: the checks test behaviour.</p>${Object.entries(p.solution || {}).map(([dev, s]) => `<div class="row spread"><b class="small">${esc(dev)}</b><button class="small" data-apply="${esc(dev)}">Type it into ${esc(dev)}</button></div><pre><code>${esc(String(s).trim())}</code></pre>`).join("")}</div>`;
}
function columns(list) {
  const w = Math.max(...list.map((x) => x.length)) + 2;
  const per = Math.max(1, Math.floor(78 / w));
  const rows = [];
  for (let i = 0; i < list.length; i += per) rows.push(list.slice(i, i + per).map((x) => x.padEnd(w)).join(""));
  return rows.join("\n");
}
const mmss = (ms) => `${Math.floor(ms / 60000)}:${String(Math.floor(ms / 1000) % 60).padStart(2, "0")}`;
