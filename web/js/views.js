// Screens: Command (home), Review, Library, Interview Studio, Progress, Settings.
import { h, $, $$, esc, inline, md, shuffle, icon, tokenValue, download, api } from "./core.js";
import { S, record, setting, dueItems, moduleOrder, nextModule, openSession, MEDALS, xpForNext } from "./state.js";
import { anyItem, flashcard, quiz, lab, scenario, drill, telecyborg, setKeys } from "./widgets.js";
import { newSession, BLOCKS } from "./session.js";
import { syncPanel } from "./sync.js";

const lv = (n) => `<span class="levels" title="Mastery L${Math.floor(n)}">${[1, 2, 3, 4, 5].map((i) => `<i class="${n >= i ? "on" : ""}"></i>`).join("")}</span>`;
const daysTo = (d) => Math.ceil((new Date(d + "T09:00:00") - Date.now()) / 86400000);

// ---------- Command ----------
export function home(main) {
  const p = S.p;
  const open = openSession();
  const nm = nextModule();
  const due = dueItems().length;
  const iv = [["Recruiter", "date_recruiter"], ["Hiring manager", "date_hm"], ["Technical", "date_technical"]]
    .map(([n, k]) => [n, setting(k, "")]).filter(([, d]) => d);
  const openMod = open ? S.mods.get(open.module) : null;
  const doneBlocks = open ? open.blocks.size : 0;
  const el = h(`<div class="wrap">
    <div class="panel hero">
      <div>
        <div class="tiny">${esc(p.rank)} · level ${p.level}</div>
        <h1>${open ? "Resume your sortie" : "Next sortie"}</h1>
        <p class="muted" style="margin:0">${open ? `${esc(openMod.id)} · ${esc(openMod.title)} · block ${doneBlocks + 1} of ${BLOCKS.length}` : `${esc(nm.id)} · ${esc(nm.title)} · 4 hours, ten blocks`}</p>
        ${!open ? `<div class="row" style="margin-top:12px"><label class="small muted" for="pick">Or choose</label><select id="pick" style="width:auto">${moduleOrder().map((m) => `<option value="${esc(m.id)}" ${m.id === nm.id ? "selected" : ""}>${esc(m.id)} · ${esc(m.title)}</option>`).join("")}</select></div>` : ""}
      </div>
      <div class="row">${open ? `<button class="primary big" data-resume>${icon("play")} Resume</button><button data-abandon class="ghost">End it</button>` : `<button class="primary big" data-start>${icon("play")} Start sortie</button>`}</div>
    </div>
    <div class="panel" style="padding:0"><div class="stats">
      <div><b class="num">${due}</b><span>reviews due now</span></div>
      <div><b class="num">${p.streak}</b><span>day streak</span></div>
      <div><b class="num">${p.xp}</b><span>XP · ${p.levelXP}/${p.levelNeed} to next</span></div>
      <div><b class="num">${[...p.sessions.values()].filter((s) => s.end).length}</b><span>sorties finished</span></div>
    </div></div>
    <div class="grid2" style="margin-top:14px">
      <div class="panel"><div class="row spread"><h3 style="margin:0">Modules</h3><a href="#/library" class="small">Library</a></div>
        <div class="modlist">${moduleOrder().map((m) => { const ms = p.mastery.get(m.id) || { level: 0 }; return `<div class="modrow"><span class="id">${esc(m.id)}</span><a href="#/module/${esc(m.id)}">${esc(m.title)}</a>${lv(ms.level)}<span class="tiny">L${Math.floor(ms.level)}</span></div>`; }).join("")}</div></div>
      <div>
        <div class="panel"><h3 style="margin-top:0">Interviews</h3>${iv.length ? iv.map(([n, d]) => `<div class="row spread"><span>${esc(n)}</span><b class="num">${daysTo(d) >= 0 ? daysTo(d) + " days" : "done"}</b></div>`).join("") : `<p class="small muted" style="margin:0">Add your interview dates in <a href="#/settings">Settings</a> to see countdowns.</p>`}</div>
        <div class="panel"><h3 style="margin-top:0">Quick actions</h3><div class="row"><a class="btn" href="#/review">${icon("cards")} Review ${due}</a><a class="btn" href="#/interview">${icon("mic")} Drill interviews</a></div></div>
      </div>
    </div></div>`);
  main.replaceChildren(el);
  const st = $("[data-start]", el);
  if (st) st.onclick = () => { const id = $("#pick", el).value; const sid = newSession(id); location.hash = "#/session/" + sid; };
  const rs = $("[data-resume]", el);
  if (rs) rs.onclick = () => (location.hash = "#/session/" + open.sid);
  const ab = $("[data-abandon]", el);
  if (ab) ab.onclick = () => { if (confirm("End this sortie now? Finished blocks stay counted.")) { record("session_end", { sid: open.sid, module: open.module, abandoned: true }); home(main); } };
}

// ---------- Review ----------
export function review(main) {
  const items = dueItems().map((x) => x.id);
  const el = h(`<div class="wrap"><h1>Review</h1><p class="muted">Everything the scheduler says is due now: cards, missed questions and interview answers. Spacing does the work.</p><div data-stage></div></div>`);
  main.replaceChildren(el);
  const stage = $("[data-stage]", el);
  let i = 0;
  const step = () => {
    if (i >= items.length) {
      setKeys(null);
      stage.replaceChildren(h(`<div class="panel"><p>${items.length ? `Done: ${items.length} reviews.` : "Nothing is due right now."} Come back later or start a sortie.</p><a class="btn primary" href="#/home">Back to command</a></div>`));
      return;
    }
    anyItem(stage, items[i], () => { i++; step(); }, { label: `${i + 1} of ${items.length}` });
  };
  step();
}

// ---------- Library ----------
export function library(main) {
  const p = S.p;
  const stages = new Map();
  for (const m of moduleOrder()) {
    const k = m.stage_title || m.stage;
    if (!stages.has(k)) stages.set(k, []);
    stages.get(k).push(m);
  }
  const el = h(`<div class="wrap"><h1>Library</h1>${[...stages.entries()].map(([st, ms]) => `<div class="panel"><h3 style="margin-top:0">${esc(st)}</h3><div class="modlist">${ms.map((m) => { const x = p.mastery.get(m.id) || { level: 0 }; return `<div class="modrow"><span class="id">${esc(m.id)}</span><div><a href="#/module/${esc(m.id)}">${esc(m.title)}</a><div class="tiny">${(m.units || []).length} units · ${(m.cards || []).length} cards · ${(m.quiz || []).length} questions · ${(m.labs || []).length} labs · ${(m.scenarios || []).length} situations · ${(m.interview || []).length} drills</div></div>${lv(x.level)}<span class="tiny">L${Math.floor(x.level)}</span></div>`; }).join("")}</div></div>`).join("")}</div>`);
  main.replaceChildren(el);
}

export function moduleView(main, id, tab = "overview") {
  const m = S.mods.get(id);
  if (!m) { main.replaceChildren(h(`<div class="wrap"><p>Module not found.</p></div>`)); return; }
  const ms = S.p.mastery.get(id) || { level: 0, note: "" };
  const tabs = [["overview", "Overview"], ["read", "Read"], ["cards", "Cards"], ["practice", "Practice"], ["labs", "Labs"], ["situations", "Situations"], ["interview", "Interview"]];
  const el = h(`<div class="wrap"><div class="tiny">${esc(m.stage_title || m.stage)} · ${esc(m.id)}</div><h1>${esc(m.title)}</h1>
    <div class="tabs">${tabs.map(([k, n]) => `<button data-tab="${k}" class="${k === tab ? "on" : ""}">${n}</button>`).join("")}</div><div data-body></div></div>`);
  main.replaceChildren(el);
  $$("[data-tab]", el).forEach((b) => (b.onclick = () => (location.hash = `#/module/${id}/${b.dataset.tab}`)));
  const body = $("[data-body]", el);
  setKeys(null);
  const list = (a) => (a && a.length ? `<ul>${a.map((x) => `<li>${inline(x)}</li>`).join("")}</ul>` : "");
  if (tab === "overview") {
    body.replaceChildren(h(`<div class="grid2"><div class="panel md"><h3 style="margin-top:0">Objectives</h3>${list(m.objectives)}<h3>Sources</h3>${list(m.sources)}</div>
      <div class="panel"><h3 style="margin-top:0">Mastery L${Math.floor(ms.level)}</h3>${lv(ms.level)}<p class="small muted" style="margin-top:8px">${esc(ms.note)}</p>
      <p class="small">Estimated ${m.est_sessions || 1} sortie(s) of 4 hours.</p><button class="primary" data-start>${icon("play")} Start a sortie on this module</button></div></div>`));
    $("[data-start]", body).onclick = () => { const sid = newSession(id); location.hash = "#/session/" + sid; };
  } else if (tab === "read") {
    body.replaceChildren(h(`<div class="stack">${(m.units || []).map((u, i) => `<details class="panel md read" ${i === 0 ? "open" : ""}><summary><b>${i + 1}. ${esc(u.title)}</b> <span class="tiny">D${u.tier || 1} · ~${u.est_min || 10} min ${S.p.unitsDone.has(u.id) ? "· read" : ""}</span></summary>${md(u.body)}${u.source ? `<div class="tiny">Source: ${esc(u.source)}</div>` : ""}</details>`).join("")}</div>`));
  } else if (tab === "cards") {
    const cards = [...(m.cards || []), ...S.p.userCards.filter((c) => c.module === id)];
    body.replaceChildren(h(`<div class="panel"><table class="md" style="width:100%"><thead><tr><th>Front</th><th>Back</th><th>Due</th></tr></thead><tbody>${cards.map((c) => { const st = S.p.items.get(c.id); return `<tr><td>${inline(c.front)}${c.user ? ' <span class="tag">yours</span>' : ""}</td><td>${inline(c.back)}</td><td class="tiny num">${st ? new Date(st.due).toLocaleDateString() : "new"}</td></tr>`; }).join("")}</tbody></table></div>`));
  } else if (tab === "practice") {
    const qs = shuffle(m.quiz || []);
    let i = 0;
    const st = h(`<div></div>`);
    body.replaceChildren(st);
    const step = () => (i < qs.length ? quiz(st, qs[i], id, () => { i++; step(); }, { mode: "practice", label: `Practice ${i + 1} of ${qs.length}` }) : st.replaceChildren(h(`<div class="panel"><p>Practice round complete.</p></div>`)));
    step();
  } else if (tab === "labs") {
    body.replaceChildren(h(`<div class="stack">${(m.labs || []).map((l, i) => `<div class="panel row spread"><div><b>${esc(l.title)}</b><div class="small muted">${inline(l.goal)}</div></div><button data-lab="${i}">Open</button></div>`).join("") || `<p class="muted">No labs in this module.</p>`}</div>`));
    $$("[data-lab]", body).forEach((b) => (b.onclick = () => lab(body, m.labs[+b.dataset.lab], id, () => moduleView(main, id, "labs"))));
  } else if (tab === "situations") {
    body.replaceChildren(h(`<div class="stack">${(m.scenarios || []).map((s, i) => `<div class="panel row spread"><div><span class="tag">${s.kind === "raid" ? "Raid" : "Situation"}</span> <b>${esc(s.title)}</b></div><button data-sc="${i}">Open</button></div>`).join("") || `<p class="muted">No situations in this module.</p>`}</div>`));
    $$("[data-sc]", body).forEach((b) => (b.onclick = () => scenario(body, m.scenarios[+b.dataset.sc], id, () => moduleView(main, id, "situations"))));
  } else if (tab === "interview") {
    body.replaceChildren(h(`<div class="stack"><div class="row"><button data-tcall>Export all ${(m.interview || []).length} to TeleCyborg</button></div>${(m.interview || []).map((q, i) => { const d = S.p.drills.get(q.id); return `<div class="panel row spread"><div><span class="tag">${esc(q.stage)}</span> ${inline(q.question)}</div><div class="row"><span class="tiny">${d ? "last " + d.score + "/5" : "new"}</span><button data-q="${i}">Drill</button></div></div>`; }).join("")}</div>`));
    $("[data-tcall]", body).onclick = () => download(`${id}-interview.md`, telecyborg(m.interview || [], `${m.title} · interview answers`));
    $$("[data-q]", body).forEach((b) => (b.onclick = () => drill(body, m.interview[+b.dataset.q], id, () => moduleView(main, id, "interview"))));
  }
}

// ---------- Interview Studio ----------
export function interview(main, stage = "recruiter") {
  const all = S.content.modules.flatMap((m) => (m.interview || []).map((q) => ({ q, mod: m.id })));
  const names = { recruiter: "Recruiter", hm: "Hiring manager", technical: "Technical" };
  const list = all.filter((x) => x.q.stage === stage);
  const scored = list.filter((x) => S.p.drills.has(x.q.id));
  const avg = scored.length ? (scored.reduce((a, x) => a + S.p.drills.get(x.q.id).score, 0) / scored.length).toFixed(1) : "–";
  const el = h(`<div class="wrap"><h1>Interview Studio</h1>
    <div class="tabs">${Object.entries(names).map(([k, n]) => `<button data-st="${k}" class="${k === stage ? "on" : ""}">${n} <span class="tiny">${all.filter((x) => x.q.stage === k).length}</span></button>`).join("")}</div>
    <div class="panel row spread"><div class="count"><div><b class="num">${list.length}</b><span class="small muted">questions</span></div><div><b class="num">${scored.length}</b><span class="small muted">drilled</span></div><div><b class="num">${avg}</b><span class="small muted">average score</span></div></div>
      <div class="row"><button class="primary" data-run>${icon("mic")} Drill 5 (weakest first)</button><button data-tc>Export all to TeleCyborg</button></div></div>
    <div data-body class="stack" style="margin-top:14px">${list.map((x, i) => { const d = S.p.drills.get(x.q.id); return `<div class="panel row spread"><div style="flex:1;min-width:240px">${inline(x.q.question)}<div class="tiny">${esc(x.mod)}</div></div><div class="row"><span class="tiny">${d ? "last " + d.score + "/5" : "new"}</span><button data-q="${i}">Drill</button></div></div>`; }).join("")}</div></div>`);
  main.replaceChildren(el);
  setKeys(null);
  $$("[data-st]", el).forEach((b) => (b.onclick = () => (location.hash = "#/interview/" + b.dataset.st)));
  const body = $("[data-body]", el);
  $$("[data-q]", el).forEach((b) => (b.onclick = () => { const x = list[+b.dataset.q]; drill(body, x.q, x.mod, () => interview(main, stage)); window.scrollTo(0, 0); }));
  $("[data-tc]", el).onclick = () => download(`fortitatake-${stage}.md`, telecyborg(list.map((x) => x.q), `${names[stage]} answers`));
  $("[data-run]", el).onclick = () => {
    const sc = (x) => (S.p.drills.get(x.q.id) ? S.p.drills.get(x.q.id).score : 0);
    const picks = shuffle(list).sort((a, b) => sc(a) - sc(b)).slice(0, 5);
    let i = 0;
    const step = () => (i < picks.length ? drill(body, picks[i].q, picks[i].mod, () => { i++; step(); }, { label: `Drill ${i + 1} of ${picks.length}` }) : interview(main, stage));
    window.scrollTo(0, 0);
    step();
  };
}

// ---------- Progress ----------
export function progress(main) {
  const p = S.p;
  const got = new Set(p.medals.map((m) => m.id));
  const medalSvg = (on) => `<svg viewBox="0 0 40 40"><circle cx="20" cy="22" r="13" fill="${on ? "var(--accent)" : "var(--surface-3)"}"/><path d="M14 4h12l-3 9h-6z" fill="${on ? "var(--warn)" : "var(--line)"}"/><path d="M20 15l2.4 4.9 5.4.8-3.9 3.8.9 5.4-4.8-2.5-4.8 2.5.9-5.4-3.9-3.8 5.4-.8z" fill="${on ? "var(--accent-ink)" : "var(--surface)"}"/></svg>`;
  const sessions = [...p.sessions.values()].sort((a, b) => b.start - a.start).slice(0, 10);
  const el = h(`<div class="wrap"><h1>Progress</h1>
    <div class="panel"><div class="row spread"><div><div class="tiny">Rank</div><h2 style="margin:0">${esc(p.rank)} · level ${p.level}</h2></div><div class="num">${p.levelXP} / ${p.levelNeed} XP</div></div>
      <div class="meter" style="margin-top:10px"><i style="width:${Math.round((p.levelXP / p.levelNeed) * 100)}%"></i></div>
      <div class="count" style="margin-top:14px"><div><b class="num">${p.xp}</b><span class="small muted">total XP</span></div><div><b class="num">${p.reviews}</b><span class="small muted">reviews</span></div><div><b class="num">${p.quizFirst.size}</b><span class="small muted">questions answered</span></div><div><b class="num">${p.scenarios.length}</b><span class="small muted">situations</span></div><div><b class="num">${p.drills.size}</b><span class="small muted">drills</span></div><div><b class="num">${p.streak}</b><span class="small muted">day streak</span></div></div></div>
    <div class="panel"><h3 style="margin-top:0">Mastery</h3><div class="modlist">${moduleOrder().map((m) => { const x = p.mastery.get(m.id) || { level: 0, note: "" }; return `<div class="modrow"><span class="id">${esc(m.id)}</span><div>${esc(m.title)}<div class="tiny">${esc(x.note)}</div></div>${lv(x.level)}<span class="tiny">L${Math.floor(x.level)}</span></div>`; }).join("")}</div>
      <p class="tiny" style="margin:10px 0 0">L1 read · L2 70 % of cards consolidated (stability ≥ 7 days) · L3 75 % on D3 · L4 75 % on D4 and situations ≥ 3.5 · L5 boss ≥ 85 %</p></div>
    <div class="panel"><h3 style="margin-top:0">Medals <span class="tiny">${got.size} / ${MEDALS.length}</span></h3><div class="medals">${MEDALS.map((m) => `<div class="medal ${got.has(m.id) ? "" : "locked"}">${medalSvg(got.has(m.id))}<div><b>${esc(m.name)}</b><span>${esc(m.desc)}</span></div></div>`).join("")}</div></div>
    <div class="panel"><h3 style="margin-top:0">Recent sorties</h3>${sessions.length ? sessions.map((s) => `<div class="row spread small"><span>${new Date(s.start).toLocaleString()} · ${esc(s.module)}</span><span class="num">${s.blocks.size}/${BLOCKS.length} blocks${s.end ? " · done" : ""}</span></div>`).join("") : `<p class="small muted">No sorties yet.</p>`}</div></div>`);
  main.replaceChildren(el);
}

// ---------- Settings ----------
export function settings(main, info) {
  const skin = setting("skin", "fabric");
  const el = h(`<div class="wrap"><h1>Settings</h1>
    <div class="panel stack">
      <h3 style="margin-top:0">Skin</h3>
      <div class="row"><label class="opt"><input type="radio" name="skin" value="fabric" ${skin === "fabric" ? "checked" : ""}><span><b>Fabric</b><span class="why">Enterprise, calm, light</span></span></label>
      <label class="opt"><input type="radio" name="skin" value="hellforge" ${skin === "hellforge" ? "checked" : ""}><span><b>Hellforge</b><span class="why">Molten, loud on the big moments</span></span></label></div>
      <h3>Study plan</h3>
      <label class="field">Sorties per day<select data-k="sessions_per_day">${[1, 2, 3].map((n) => `<option ${+setting("sessions_per_day", 2) === n ? "selected" : ""}>${n}</option>`).join("")}</select></label>
      <label class="field">Target retention<select data-k="retention">${[0.85, 0.9, 0.93].map((n) => `<option value="${n}" ${+setting("retention", 0.9) === n ? "selected" : ""}>${Math.round(n * 100)} %</option>`).join("")}</select></label>
      <h3>Interview dates</h3>
      <div class="grid2"><label class="field">Recruiter<input type="date" data-k="date_recruiter" value="${esc(setting("date_recruiter", ""))}"></label><label class="field">Hiring manager<input type="date" data-k="date_hm" value="${esc(setting("date_hm", ""))}"></label></div>
      <label class="field" style="max-width:50%">Technical<input type="date" data-k="date_technical" value="${esc(setting("date_technical", ""))}"></label>
      <h3>Sync</h3>
      <div data-sync><p class="small muted">Loading…</p></div>
      <h3>Your data</h3>
      <p class="small muted">Progress is an append-only log in <code>${esc(info.dir)}</code>. Device ${esc(info.device)}.</p>
      <div class="row">${info.android ? `<button data-backup>Save backup to Downloads</button>` : `<a class="btn" href="/api/export?t=${esc(tokenValue())}" download>Download backup</a>`}${info.native ? `<button data-quit>Quit FortiTatake</button>` : ""}</div>
      <p class="tiny">FortiTatake ${esc(info.version)} · content ${esc(S.content.version)}</p>
    </div></div>`);
  main.replaceChildren(el);
  $$("input[name=skin]", el).forEach((r) => (r.onchange = () => { record("setting_set", { key: "skin", value: r.value }); document.documentElement.dataset.skin = r.value; }));
  $$("[data-k]", el).forEach((x) => (x.onchange = () => record("setting_set", { key: x.dataset.k, value: x.type === "date" ? x.value : (isNaN(+x.value) ? x.value : +x.value) })));
  const q = $("[data-quit]", el);
  if (q) q.onclick = () => api("quit", { method: "POST" });
  const bk = $("[data-backup]", el);
  if (bk) bk.onclick = async () => {
    const r = await fetch("/api/export?t=" + tokenValue());
    download(`fortitatake-backup-${new Date().toISOString().slice(0, 10)}.ftbackup.jsonl`, await r.text(), "application/x-ndjson");
  };
  syncPanel($("[data-sync]", el));
}
