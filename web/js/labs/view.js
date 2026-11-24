// Labs screens: the catalogue and the lab runner (ticket, topology, consoles, checks).
import { h, $, $$, esc, md, inline, icon } from "../core.js";
import { S, record } from "../state.js";
import { LabRun } from "./runtime.js";
import { drawTopology } from "./topo.js";
import { FortiGate } from "./fgt.js";

const TIERS = ["Console", "Fundamentals", "Core PS", "Advanced", "Break-fix", "SecOps", "Capstones"];
const TRACK = { fortigate: "FortiGate", fortimanager: "FortiManager", fortianalyzer: "FortiAnalyzer", fortiswitch: "FortiSwitch", fortisiem: "FortiSIEM", fortiedr: "FortiEDR", secops: "SecOps", integration: "Multi-product", sdwan: "SD-WAN", vpn: "VPN", ha: "HA" };
const KIND = { project: "Project", ticket: "Ticket", drill: "Drill", capstone: "Capstone", investigation: "Investigation" };

let catalog = null, schemas = null;
async function loadCatalog() {
  if (!catalog) catalog = fetch("content/labs.json", { cache: "no-store" }).then((r) => r.json());
  return catalog;
}
async function loadSchemas() {
  if (!schemas) schemas = Promise.all(["fortios", "fortianalyzer", "fortimanager"].map((p) => fetch(`schema/${p}-8.0.2.json`).then((r) => r.json()))).then(([fortios, fortianalyzer, fortimanager]) => ({ fortios, fortianalyzer, fortimanager }));
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
  const ui = { dev: firstFgt.id, buf: {}, hist: {}, hi: {}, unread: new Set(), view: "ticket" };
  for (const d of devs) { ui.buf[d.id] = []; ui.hist[d.id] = []; }
  for (const d of devs) if (d instanceof FortiGate) ui.buf[d.id].push(`${{ fortianalyzer: "FortiAnalyzer", fortimanager: "FortiManager" }[d.product] || "FortiOS"} v8.0.2 emulated by FortiTatake · ${d.model} · type ? for help, Tab to complete`, "");
  else ui.buf[d.id].push(d.kind === "router" ? `${d.id}: read-only ISP router. Try: show ip interface brief` : `${d.id} (${d.os}) · type help`, "");

  const el = h(`<div class="labrun${emb ? " embedded" : ""}" data-view="ticket">
    <header class="lr-head">
      ${emb ? `<span class="tag acc">${esc(opts.label || "Lab")}</span>` : `<a href="#/labs" class="ghost btn small">← Labs</a>`}
      <div class="lr-title"><span class="tiny">${esc(def.id)} · ${esc(KIND[def.kind] || def.kind)} · ${esc(def.customer || "")}</span><b>${esc(def.title)}</b></div>
      <div class="row lr-meta"><span class="kbd num" data-timer>0:00</span>${emb ? (opts.exam ? `<span class="tag">Exam mode: no hints</span>` : "") : `<label class="small row" style="gap:6px"><input type="checkbox" data-exam ${run.exam ? "checked" : ""}> Exam mode</label>`}<button class="ghost small" data-reset>Reset</button>${emb ? `<button class="ghost small" data-leave>Skip this lab</button>` : ""}</div>
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
    $(".lr-devtabs", el).innerHTML = devs.map((d) => `<button role="tab" aria-selected="${d.id === ui.dev}" data-dev="${esc(d.id)}" class="${d.id === ui.dev ? "on" : ""}">${esc(d.id)}${ui.unread.has(d.id) ? ' <i class="dot" aria-label="new output"></i>' : ""}</button>`).join("");
    $$(".lr-devtabs [data-dev]", el).forEach((b) => (b.onclick = () => selectDev(b.dataset.dev)));
  };
  const paint = () => {
    out.textContent = ui.buf[ui.dev].join("\n");
    out.scrollTop = out.scrollHeight;
    prompt.textContent = run.prompt(ui.dev);
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
    $$(".lr-topo [data-dev].click", el).forEach((g) => {
      const go = () => { selectDev(g.dataset.dev); if (window.matchMedia("(max-width: 900px)").matches) setView("term"); };
      g.onclick = go;
      g.onkeydown = (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); go(); } };
    });
  };
  const exec = (line) => {
    const dev = ui.dev;
    print(dev, run.prompt(dev) + line);
    if (line.trim() === "clear" || line.trim() === "cls") { ui.buf[dev] = []; paint(); return; }
    const r = run.exec(dev, line);
    if (r) print(dev, r);
    pump();
    if (line.trim()) { ui.hist[dev].push(line); ui.hi[dev] = ui.hist[dev].length; }
    store(run, k);
    paint(); topo();
  };
  inp.addEventListener("keydown", (e) => {
    const dev = run.device(ui.dev);
    const isFgt = dev instanceof FortiGate;
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
        ${res ? `<ul class="lr-checks">${res.map((r) => `<li class="${r.pass ? "ok" : "no"}"><b>${r.pass ? "✓" : "✗"}</b><div><span class="small">${inline(r.text)}</span><span class="tiny">${esc(r.detail || "")}</span></div></li>`).join("")}</ul>` : `<p class="tiny">The checklist stays hidden until you press Check. It tests what the network does, not what you typed.</p>`}
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
  const doCheck = () => {
    const was = new Set(run.passed);
    const res = run.check();
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
