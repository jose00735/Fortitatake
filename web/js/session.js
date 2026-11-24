// The 4-hour sortie: ten blocks run in order, resumable at block level.
import { h, $, $$, esc, inline, md, shuffle, fmtMin } from "./core.js";
import { S, record, dueItems } from "./state.js";
import { flashcard, quiz, lab, scenario, drill, anyItem, setKeys } from "./widgets.js";
import { labPart } from "./labs/view.js";

// emulated-CLI lab parts that teach this module, freshest first (not yet passed, then lower tier)
function labParts(m, test) {
  const out = [];
  for (const l of (S.labsByModule && S.labsByModule.get(m.id)) || []) {
    if (!test(l)) continue;
    l.parts.forEach((p, i) => out.push({ lab: l, part: p, i, done: S.p.labParts.has(l.id + ":" + p.id) }));
  }
  return out.sort((a, b) => (a.done - b.done) || (a.lab.tier - b.lab.tier) || (a.i - b.i) || a.lab.id.localeCompare(b.lab.id));
}
const isTicket = (l) => l.kind === "ticket" || l.kind === "investigation";

export const BLOCKS = [
  { id: "warmup", name: "Warm-up", min: 20, desc: "Due reviews, overdue first" },
  { id: "pretest", name: "Pretest", min: 10, desc: "Ungraded guesses to prime your attention" },
  { id: "learn", name: "A · Learn", min: 50, desc: "Reading chunks with recall and why prompts, then first-pass cards" },
  { id: "break1", name: "Break", min: 10, brk: true },
  { id: "apply", name: "B · Apply", min: 50, desc: "Quiz ladder, written labs, then a part of an emulated-CLI lab" },
  { id: "break2", name: "Break", min: 10, brk: true },
  { id: "arena", name: "C · PS Arena", min: 50, desc: "Consultant situations and raids, then a live ticket" },
  { id: "break3", name: "Break", min: 10, brk: true },
  { id: "boss", name: "D · Boss", min: 20, desc: "Timed, interleaved, no hints, with a ticket in exam mode as the final strike" },
  { id: "close", name: "Close", min: 10, desc: "Interview drills, reflection, your own cards" },
];

export function newSession(moduleId) {
  const sid = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
  record("session_start", { sid, module: moduleId });
  return sid;
}

export function runSession(main, sid) {
  const s = S.p.sessions.get(sid);
  if (!s) { location.hash = "#/home"; return; }
  const m = S.mods.get(s.module);
  const frame = h(`<div class="wrap">
    <div class="row spread"><div><div class="tiny">Sortie · ${esc(m.id)}</div><h1 style="margin:0">${esc(m.title)}</h1></div>
      <div class="row"><span class="num muted" data-el></span><a class="btn ghost" href="#/home">Pause</a></div></div>
    <div class="timeline"></div>
    <div class="row spread"><div><h2 style="margin:0" data-bname></h2><div class="small muted" data-bdesc></div></div><button class="ghost" data-skip>Skip block</button></div>
    <div data-stage style="margin-top:14px"></div></div>`);
  main.replaceChildren(frame);
  const tick = setInterval(() => {
    const e = $("[data-el]", frame);
    if (!e) return clearInterval(tick);
    const mins = Math.floor((Date.now() - s.start) / 60000);
    e.textContent = `Elapsed ${Math.floor(mins / 60)}h ${mins % 60}m`;
  }, 1000);

  const draw = () => {
    const s = S.p.sessions.get(sid); // projections are rebuilt on every event
    const cur = BLOCKS.find((b) => !s.blocks.has(b.id));
    $(".timeline", frame).innerHTML = BLOCKS.map((b) => `<div class="blk ${s.blocks.has(b.id) ? "done" : cur && b.id === cur.id ? "cur" : ""}" title="${esc(b.name)} · ${b.min} min"><i></i><span>${esc(b.name)}</span></div>`).join("");
    if (!cur) return finishSession();
    $("[data-bname]", frame).textContent = cur.name;
    $("[data-bdesc]", frame).textContent = cur.desc ? `${cur.desc} · about ${cur.min} min` : `${cur.min} minutes. Stand up, drink water, look away from the screen.`;
    const stage = $("[data-stage]", frame);
    const finish = () => { record("block_done", { sid, block: cur.id, module: m.id }); draw(); window.scrollTo(0, 0); };
    $("[data-skip]", frame).onclick = finish;
    RUN[cur.brk ? "break" : cur.id](stage, m, finish, s);
  };

  const finishSession = () => {
    const s = S.p.sessions.get(sid);
    clearInterval(tick);
    if (!s.end) record("session_end", { sid, module: m.id, minutes: Math.round((Date.now() - s.start) / 60000) });
    setKeys(null);
    $("[data-skip]", frame).hidden = true;
    $("[data-bname]", frame).textContent = "Sortie complete";
    $("[data-bdesc]", frame).textContent = "";
    const ms = S.p.mastery.get(m.id) || {};
    $("[data-stage]", frame).replaceChildren(h(`<div class="panel"><p>You finished all ten blocks of <b>${esc(m.title)}</b>. Mastery for this module is now <b>L${Math.floor(ms.level || 0)}</b>: ${esc(ms.note || "")}.</p>
      <p class="muted">Cards you rated Again come back in 10 minutes; the rest follow your FSRS schedule. Sleep is part of the method.</p>
      <div class="row"><a class="btn primary" href="#/home">Back to command</a><a class="btn" href="#/progress">See progress</a></div></div>`));
  };
  draw();
}

// ---------- Block runners ----------
function sequence(stage, items, render, done, empty) {
  let i = 0;
  if (!items.length) {
    stage.replaceChildren(h(`<div class="panel"><p>${empty}</p><button class="primary">Continue</button></div>`));
    $("button", stage).onclick = done;
    return;
  }
  const step = () => (i < items.length ? render(items[i], `${i + 1} of ${items.length}`, () => { i++; step(); }) : done());
  step();
}

const RUN = {
  warmup(stage, m, done) {
    const start = Date.now();
    const items = dueItems().slice(0, 30).map((x) => x.id);
    let i = 0;
    const step = () => {
      if (i >= items.length || Date.now() - start > 20 * 60000) return done();
      anyItem(stage, items[i], () => { i++; step(); }, { label: `Review ${i + 1} of ${items.length}` });
    };
    if (!items.length) {
      stage.replaceChildren(h(`<div class="panel"><p>Nothing is due. Your memory queue is clear, so the sortie starts with the pretest.</p><button class="primary">Continue</button></div>`));
      $("button", stage).onclick = done;
    } else step();
  },

  pretest(stage, m, done) {
    let pool = (m.quiz || []).filter((q) => q.pretest);
    if (!pool.length) pool = (m.quiz || []).filter((q) => (q.tier || 1) <= 2).slice(0, 6);
    let right = 0;
    sequence(stage, pool, (q, label, next) => quiz(stage, q, m.id, (ok) => { if (ok) right++; next(); }, { mode: "pretest", label: "Pretest " + label }), () => {
      stage.replaceChildren(h(`<div class="panel"><p>Pretest: <b class="num">${right} / ${pool.length}</b>. Wrong guesses here are useful: your brain now knows what to look for in the reading.</p><button class="primary">Start learning</button></div>`));
      $("button", stage).onclick = done;
    }, "This module has no pretest.");
  },

  learn(stage, m, done) {
    const units = m.units || [];
    let ui = 0;
    const showUnit = () => {
      if (ui >= units.length) return done();
      const u = units[ui];
      const read = S.p.unitsDone.has(u.id);
      const el = h(`<div class="panel md read">
        <div class="row spread"><span class="tag acc">Unit ${ui + 1} of ${units.length}</span><span class="tiny">D${u.tier || 1} · ~${u.est_min || 10} min${read ? " · read before" : ""}</span></div>
        <h2 style="margin-top:10px">${esc(u.title)}</h2>${md(u.body)}
        ${u.source ? `<div class="tiny">Source: ${esc(u.source)}</div>` : ""}
        <hr class="sep"><div class="row"><button class="primary" data-done>Done reading · first-pass cards</button>${read ? `<button data-skipu>Skip, already read</button>` : ""}</div></div>`);
      stage.replaceChildren(el);
      setKeys(null);
      $("[data-done]", el).onclick = () => {
        record("unit_done", { unit: u.id, module: m.id });
        const cards = (m.cards || []).filter((c) => c.unit === u.id && !S.p.items.has(c.id));
        let ci = 0;
        const nextCard = () => {
          if (ci >= cards.length) { ui++; window.scrollTo(0, 0); return showUnit(); }
          flashcard(stage, cards[ci].id, () => { ci++; nextCard(); }, { label: `New card ${ci + 1} of ${cards.length} · ${u.title}` });
        };
        window.scrollTo(0, 0);
        nextCard();
      };
      const sk = $("[data-skipu]", el);
      if (sk) sk.onclick = () => { ui++; window.scrollTo(0, 0); showUnit(); };
    };
    showUnit();
  },

  apply(stage, m, done, s) {
    const qs = (m.quiz || []).filter((q) => !q.pretest);
    const low = qs.filter((q) => (q.tier || 1) <= 2);
    const high = qs.filter((q) => (q.tier || 1) >= 3).sort((a, b) => a.tier - b.tier);
    const steps = [...low.map((q) => ({ q })), ...(m.labs || []).map((l) => ({ l })), ...high.map((q) => ({ q }))];
    // Leftover cards from units read earlier get their first pass here too.
    const fresh = (m.cards || []).filter((c) => !S.p.items.has(c.id)).map((c) => ({ c }));
    const lp = labParts(m, (l) => !isTicket(l))[0];
    sequence(stage, [...fresh, ...steps, ...(lp ? [{ lp }] : [])], (x, label, next) => {
      if (x.lp) return labPart(stage, x.lp.lab.id, x.lp.part.id, { label: `Apply ${label} · lab ${x.lp.lab.id}${x.lp.lab.parts.length > 1 ? " part " + (x.lp.i + 1) : ""}`, slot: s.sid }, next);
      if (x.c) return flashcard(stage, x.c.id, next, { label: "Card " + label });
      if (x.l) return lab(stage, x.l, m.id, next);
      return quiz(stage, x.q, m.id, next, { label: "Apply " + label });
    }, done, "No practice items in this module.");
  },

  arena(stage, m, done, s) {
    const scs = [...(m.scenarios || [])].sort((a, b) => (a.kind === "raid") - (b.kind === "raid")).map((sc) => ({ sc }));
    const t = labParts(m, isTicket)[0];
    sequence(stage, [...scs, ...(t ? [{ t }] : [])], (x, label, next) => {
      if (x.t) return labPart(stage, x.t.lab.id, x.t.part.id, { label: `Live ticket ${x.t.lab.id} · par ${x.t.lab.par || 20} min`, slot: s.sid }, next);
      return scenario(stage, x.sc, m.id, next);
    }, done, "No PS situations in this module.");
  },

  boss(stage, m, done, s) {
    const own = (m.quiz || []).filter((q) => !q.pretest || true);
    const missedFirst = (q) => (S.p.quizFirst.get(q.id) && !S.p.quizFirst.get(q.id).correct ? 0 : 1);
    const mine = shuffle(own).sort((a, b) => missedFirst(a) - missedFirst(b)).slice(0, 12);
    const others = shuffle(S.content.modules.filter((x) => x.id !== m.id && (x.quiz || []).some((q) => S.p.quizFirst.has(q.id))).flatMap((x) => x.quiz.filter((q) => S.p.quizFirst.has(q.id)).map((q) => ({ q, mod: x.id })))).slice(0, 6);
    const pool = shuffle([...mine.map((q) => ({ q, mod: m.id })), ...others]);
    let hits = 0, i = 0;
    const t0 = Date.now();
    const bossName = S.p.settings.skin === "hellforge" ? "The Gatekeeper of " + m.id : "Boss exam · " + m.id;
    const frame = h(`<div><div class="hp"><b>${esc(bossName)}</b><div class="meter"><i style="width:100%"></i></div><span class="num" data-hp>100</span></div><div data-q></div></div>`);
    stage.replaceChildren(frame);
    const step = () => {
      if (i >= pool.length) return finish();
      const { q, mod } = pool[i];
      quiz($("[data-q]", frame), q, mod, (ok) => { i++; step(); }, {
        mode: "boss", label: `Strike ${i + 1} of ${pool.length} · ${fmtMin(Date.now() - t0)} elapsed (target 20:00)`,
        onAnswer: (ok) => { if (ok) hits++; const hp = Math.max(0, Math.round(100 - (hits / pool.length) * 100)); $(".hp .meter i", frame).style.width = hp + "%"; $("[data-hp]", frame).textContent = hp; },
      });
    };
    // final strike: a ticket in exam mode (no hints, no solution), preferably one not used in the arena
    const tickets = labParts(m, isTicket);
    const strike = tickets[1] || tickets[0] || labParts(m, () => true)[0];
    const finish = () => {
      if (!strike) return verdict(null);
      labPart($("[data-q]", frame), strike.lab.id, strike.part.id, { label: `Final strike · ${strike.lab.id}`, exam: true, slot: s.sid + "-boss" }, (r) => verdict(r));
    };
    const verdict = (lr) => {
      const n = pool.length + (strike ? 1 : 0);
      const got = hits + (lr && lr.passed ? 1 : 0);
      const score = n ? got / n : 0;
      const passed = score >= 0.8;
      record("boss_result", { sid: s.sid, module: m.id, score, passed, n, lab: strike ? strike.lab.id + ":" + strike.part.id : undefined, labPassed: !!(lr && lr.passed) });
      stage.replaceChildren(h(`<div class="panel"><h2 style="margin-top:0">${passed ? "Boss down" : "The boss survives"}</h2>
        <p>You landed <b class="num">${got} / ${n}</b> (${Math.round(score * 100)} %)${strike ? `, and the final-strike ticket ${lr && lr.passed ? "fell" : "held"}` : ""}. ${passed ? "That counts toward L5 mastery when it is 85 % or higher." : "Missed items are already back in your review queue. Rematch in the next sortie."}</p>
        <button class="primary">Continue</button></div>`));
      $("button", stage).onclick = done;
    };
    step();
  },

  close(stage, m, done) {
    const iv = (m.interview || []);
    const n = m.kind === "interview" ? 6 : 2;
    const score = (q) => (S.p.drills.get(q.id) ? S.p.drills.get(q.id).score : 0);
    const picks = shuffle(iv).sort((a, b) => score(a) - score(b)).slice(0, n);
    sequence(stage, picks, (q, label, next) => drill(stage, q, m.id, next, { label: "Drill " + label }), () => {
      const el = h(`<div class="panel stack">
        <h3 style="margin-top:0">Reflection</h3>
        <label class="field">What did I learn today?<textarea data-r="learned"></textarea></label>
        <label class="field">What still confuses me?<textarea data-r="confused"></textarea></label>
        <label class="field">What do I do next session?<textarea data-r="next"></textarea></label>
        <h3>Write up to three cards of your own</h3>
        ${[0, 1, 2].map((k) => `<div class="grid2"><input type="text" data-f="${k}" placeholder="Front (question)"><input type="text" data-b="${k}" placeholder="Back (answer)"></div>`).join("")}
        <div class="row"><button class="primary" data-save>Finish the sortie</button></div></div>`);
      stage.replaceChildren(el);
      setKeys(null);
      $("[data-save]", el).onclick = () => {
        const r = {};
        $$("[data-r]", el).forEach((t) => (r[t.dataset.r] = t.value.slice(0, 3000)));
        if (r.learned || r.confused || r.next) record("reflection", { module: m.id, ...r });
        [0, 1, 2].forEach((k) => {
          const f = $(`[data-f="${k}"]`, el).value.trim(), b = $(`[data-b="${k}"]`, el).value.trim();
          if (f && b) record("card_create", { id: `U.${Date.now().toString(36)}${k}`, module: m.id, front: f, back: b });
        });
        done();
      };
    }, "No interview drills for this module.");
  },

  break(stage, m, done) {
    const fr = m.field_reports || [];
    const pick = fr.length ? fr[Math.floor(Math.random() * fr.length)] : null;
    const end = Date.now() + 10 * 60000;
    const el = h(`<div class="panel breakbox"><div class="clock num" data-c>10:00</div><p class="muted">Stand up. Water. Look at something far away. Your brain consolidates during the pause.</p>
      ${pick ? `<div class="call threat" style="text-align:left;max-width:640px;margin:18px auto"><b>Field report · ${esc(pick.title)}</b>${md(pick.body)}${pick.source ? `<div class="tiny">${esc(pick.source)}</div>` : ""}</div>` : ""}
      <button class="primary" data-go>I'm back, continue</button></div>`);
    stage.replaceChildren(el);
    setKeys(null);
    const t = setInterval(() => {
      const c = $("[data-c]", el);
      if (!c || !c.isConnected) return clearInterval(t);
      const left = Math.max(0, end - Date.now());
      c.textContent = fmtMin(left);
      if (!left) clearInterval(t);
    }, 500);
    $("[data-go]", el).onclick = () => { clearInterval(t); done(); };
  },
};
