// Widgets: one study task each. Every widget records its own events and calls done().
import { labPart } from "./labs/view.js";
import { h, $, $$, esc, inline, md, shuffle, norm, download } from "./core.js";
import { S, record } from "./state.js";

const TIER = (t) => `<span class="tag" title="Difficulty tier">D${t || 1}</span>`;
const src = (s) => (s ? `<div class="tiny">Source: ${esc(s)}</div>` : "");

// Keyboard: one active handler at a time.
let keyHandler = null;
document.addEventListener("keydown", (e) => {
  if (!keyHandler) return;
  const tag = (e.target.tagName || "").toLowerCase();
  if (tag === "textarea" || (tag === "input" && e.target.type === "text")) return;
  keyHandler(e);
});
export function setKeys(fn) { keyHandler = fn; }

// ---------- Flashcard ----------
export function flashcard(root, id, done, opts = {}) {
  const ref = S.itemIndex.get(id);
  const c = ref.item;
  const el = h(`<div class="panel task">
    ${opts.label ? `<div class="progress-line">${esc(opts.label)}</div>` : ""}
    <div class="flash">
      <div class="row spread"><span class="tag acc">Flashcard</span>${TIER(c.tier)}</div>
      <div class="front">${inline(c.front)}</div>
      <div class="back" hidden><div>${md(c.back)}</div>${c.extra ? `<div class="muted small">${inline(c.extra)}</div>` : ""}${src(c.source)}</div>
    </div>
    <div class="row" data-reveal><button class="primary">Show answer <span class="kbd">Space</span></button></div>
    <div class="rates" hidden>
      <button class="r1" data-r="1">Again<span class="tiny">forgot · 1</span></button>
      <button class="r2" data-r="2">Hard<span class="tiny">struggled · 2</span></button>
      <button class="r3" data-r="3">Good<span class="tiny">recalled · 3</span></button>
      <button class="r4" data-r="4">Easy<span class="tiny">instant · 4</span></button>
    </div></div>`);
  const t0 = Date.now();
  const reveal = () => { $(".back", el).hidden = false; $("[data-reveal]", el).hidden = true; $(".rates", el).hidden = false; };
  const rate = (r) => {
    record("review", { item: id, kind: "card", module: ref.module, rating: r, ms: Date.now() - t0 });
    setKeys(null);
    done(r);
  };
  $("[data-reveal] button", el).onclick = reveal;
  $$(".rates button", el).forEach((b) => (b.onclick = () => rate(+b.dataset.r)));
  setKeys((e) => {
    if (e.code === "Space") { e.preventDefault(); if ($(".rates", el).hidden) reveal(); }
    if (!$(".rates", el).hidden && /^[1-4]$/.test(e.key)) rate(+e.key);
  });
  root.replaceChildren(el);
}

// ---------- Quiz item ----------
// mode: pretest | graded | boss | review | practice
export function quiz(root, q, module, done, opts = {}) {
  const mode = opts.mode || "graded";
  const el = h(`<div class="panel task">
    ${opts.label ? `<div class="progress-line">${esc(opts.label)}</div>` : ""}
    <div class="row spread" style="margin-bottom:10px"><span class="tag acc">${mode === "pretest" ? "Pretest · ungraded" : "Question"}</span>${TIER(q.tier)}</div>
    ${q.output ? `<pre><code>${esc(q.output)}</code></pre>` : ""}
    <div class="q">${inline(q.stem)}</div>
    <div class="body"></div>
    <div class="fb"></div>
    <div class="row"><button class="primary" data-submit>Check <span class="kbd">Enter</span></button><button data-next hidden>Next <span class="kbd">Enter</span></button></div>
  </div>`);
  const body = $(".body", el);
  let getAnswer, grade, showResult;

  if (q.type === "single" || q.type === "multi" || q.type === "output") {
    const multi = q.type === "multi";
    const opts2 = q.shuffle === false ? q.options : shuffle(q.options);
    body.innerHTML = opts2.map((o) => `<label class="opt" data-id="${esc(o.id)}"><input type="${multi ? "checkbox" : "radio"}" name="o" value="${esc(o.id)}"><span>${inline(o.text)}<span class="why" hidden>${inline(o.why_wrong || "")}</span></span></label>`).join("") + (multi ? `<div class="tiny">Select all that apply.</div>` : "");
    getAnswer = () => $$("input:checked", body).map((i) => i.value);
    grade = (a) => {
      const right = q.options.filter((o) => o.correct).map((o) => o.id).sort();
      return a.length === right.length && [...a].sort().every((x, i) => x === right[i]);
    };
    showResult = () => {
      $$(".opt", body).forEach((l) => {
        const o = q.options.find((x) => x.id === l.dataset.id);
        const picked = $("input", l).checked;
        if (o.correct) l.classList.add("right");
        else if (picked) l.classList.add("wrong");
        if (!o.correct && o.why_wrong && (picked || mode !== "boss")) $(".why", l).hidden = false;
        $("input", l).disabled = true;
      });
    };
  } else if (q.type === "order") {
    let cur = shuffle(q.items.map((t, i) => ({ t, i })));
    const draw = () => {
      body.innerHTML = `<ol class="order-list">${cur.map((x, k) => `<li><b class="num">${k + 1}</b><span>${inline(x.t)}</span><button data-up="${k}" aria-label="Move up">↑</button><button data-dn="${k}" aria-label="Move down">↓</button></li>`).join("")}</ol>`;
      $$("[data-up]", body).forEach((b) => (b.onclick = () => { const k = +b.dataset.up; if (k > 0) { [cur[k - 1], cur[k]] = [cur[k], cur[k - 1]]; draw(); } }));
      $$("[data-dn]", body).forEach((b) => (b.onclick = () => { const k = +b.dataset.dn; if (k < cur.length - 1) { [cur[k + 1], cur[k]] = [cur[k], cur[k + 1]]; draw(); } }));
    };
    draw();
    getAnswer = () => cur.map((x) => x.i);
    grade = (a) => a.every((v, i) => v === i);
    showResult = () => {
      $$("button", body).forEach((b) => (b.disabled = true));
      body.insertAdjacentHTML("beforeend", `<div class="small muted"><b>Correct order:</b><ol>${q.items.map((t) => `<li>${inline(t)}</li>`).join("")}</ol></div>`);
    };
  } else {
    // numeric | text
    body.innerHTML = `<input type="text" class="code" placeholder="${q.type === "numeric" ? "Number" : "Your answer"}" autocomplete="off">`;
    const inp = $("input", body);
    setTimeout(() => inp.focus(), 30);
    getAnswer = () => inp.value;
    grade = (a) => {
      if (q.type === "numeric") return Math.abs(parseFloat(String(a).replace(/,/g, "")) - q.answer) <= (q.tolerance || 0);
      return (q.accept || []).some((x) => norm(x) === norm(a));
    };
    showResult = () => {
      inp.disabled = true;
      body.insertAdjacentHTML("beforeend", `<div class="small muted" style="margin-top:6px">Answer: <code>${esc(q.type === "numeric" ? q.answer : (q.accept || [])[0])}</code></div>`);
    };
  }

  let answered = false, correct = false;
  const submit = () => {
    if (answered) return next();
    const a = getAnswer();
    if ((Array.isArray(a) && !a.length && q.type !== "order") || a === "") return;
    answered = true;
    correct = grade(a);
    showResult();
    const fb = $(".fb", el);
    fb.innerHTML = `<div class="verdict ${correct ? "ok" : "no"}">${correct ? "Correct" : "Not quite"}</div>` +
      (q.explanation ? `<div class="md small">${md(q.explanation)}</div>` : "") + src(q.source);
    record("quiz_attempt", { item: q.id, module, correct, tier: q.tier || 1, pretest: mode === "pretest", boss: mode === "boss" });
    if (mode !== "pretest" && S.itemIndex.has(q.id)) record("review", { item: q.id, kind: "quiz", module, rating: correct ? 3 : 1 });
    $("[data-submit]", el).hidden = true;
    $("[data-next]", el).hidden = false;
    $("[data-next]", el).focus();
    if (opts.onAnswer) opts.onAnswer(correct);
  };
  const next = () => { setKeys(null); done(correct); };
  $("[data-submit]", el).onclick = submit;
  $("[data-next]", el).onclick = next;
  el.addEventListener("keydown", (e) => { if (e.key === "Enter" && e.target.tagName === "INPUT" && e.target.type === "text") { e.preventDefault(); submit(); } });
  setKeys((e) => { if (e.key === "Enter") { e.preventDefault(); submit(); } });
  root.replaceChildren(el);
}

// ---------- Lab: worked -> faded -> solo ----------
export function lab(root, L, module, done) {
  const stages = ["worked", "faded", "solo"].filter((s) => L[s]);
  let si = 0;
  const show = () => {
    const st = stages[si];
    const head = `<div class="row spread"><span class="tag acc">Lab · ${st === "worked" ? "Worked example" : st === "faded" ? "Fill the gaps" : "Solo"}</span><span class="tiny">${si + 1} / ${stages.length}</span></div>
      <h3 style="margin-top:8px">${inline(L.title)}</h3><p class="muted">${inline(L.goal)}</p>`;
    let el;
    if (st === "worked") {
      el = h(`<div class="panel task">${head}<pre><code>${esc(L.worked.config)}</code></pre>
        ${(L.worked.notes || []).length ? `<ul class="md small">${L.worked.notes.map((n) => `<li>${inline(n)}</li>`).join("")}</ul>` : ""}
        <div class="row"><button class="primary" data-go>I've studied it, next</button></div></div>`);
      $("[data-go]", el).onclick = () => { si++; si < stages.length ? show() : done(); };
    } else if (st === "faded") {
      let k = 0;
      const answers = [];
      const html = esc(L.faded.template).replace(/\{\{([^}]+)\}\}/g, (_, a) => { answers.push(a); return `<input type="text" class="blank" data-k="${k++}" autocomplete="off" aria-label="blank ${k}">`; });
      el = h(`<div class="panel task">${head}${L.faded.prompt ? `<p>${inline(L.faded.prompt)}</p>` : ""}<pre><code>${html}</code></pre><div class="fb"></div>
        <div class="row"><button class="primary" data-check>Check</button><button data-go hidden>Next</button></div></div>`);
      $("[data-check]", el).onclick = () => {
        let ok = true;
        $$(".blank", el).forEach((inp) => {
          const want = answers[+inp.dataset.k];
          const good = want.split("|").some((w) => norm(w) === norm(inp.value));
          inp.classList.toggle("ok", good);
          inp.classList.toggle("no", !good);
          if (!good) { ok = false; inp.title = "Expected: " + want.split("|")[0]; }
        });
        $(".fb", el).innerHTML = ok ? `<div class="verdict ok">All blanks right</div>` :
          `<div class="verdict no">Some blanks are off. Hover them to see the expected value, fix and check again, or move on.</div>`;
        record("lab_result", { lab: L.id, module, stage: "faded", correct: ok });
        $("[data-go]", el).hidden = false;
      };
      $("[data-go]", el).onclick = () => { si++; si < stages.length ? show() : done(); };
    } else {
      el = h(`<div class="panel task">${head}<p><b>Task:</b> ${inline(L.solo.prompt)}</p>
        <textarea class="code" spellcheck="false" placeholder="Type the CLI or your answer here"></textarea>
        <div class="fb"></div>
        <div class="row"><button class="primary" data-check>Check</button><button data-show>Show solution</button><button data-go hidden>Done</button></div></div>`);
      const check = () => {
        const text = norm($("textarea", el).value);
        const missing = (L.solo.required || []).filter((r) => !text.includes(norm(r)));
        const ok = missing.length === 0;
        $(".fb", el).innerHTML = ok ? `<div class="verdict ok">Every required line is there</div>` :
          `<div class="verdict no">Missing or different:</div><pre><code>${esc(missing.join("\n"))}</code></pre>`;
        record("lab_result", { lab: L.id, module, stage: "solo", correct: ok });
        $("[data-go]", el).hidden = false;
      };
      $("[data-check]", el).onclick = check;
      $("[data-show]", el).onclick = () => { $(".fb", el).insertAdjacentHTML("beforeend", `<h3>Solution</h3><pre><code>${esc(L.solo.solution)}</code></pre>${L.solo.notes ? `<div class="md small">${md(L.solo.notes)}</div>` : ""}`); $("[data-go]", el).hidden = false; $("[data-show]", el).disabled = true; };
      $("[data-go]", el).onclick = () => done();
    }
    root.replaceChildren(el);
  };
  setKeys(null);
  show();
}

// ---------- Self-score rubric helper ----------
function dots(name, n = 5) {
  return `<div class="dots" data-name="${esc(name)}">${Array.from({ length: n }, (_, i) => `<button type="button" data-v="${i + 1}">${i + 1}</button>`).join("")}</div>`;
}
function wireDots(el) {
  $$(".dots", el).forEach((d) => $$("button", d).forEach((b) => (b.onclick = () => { $$("button", d).forEach((x) => x.classList.toggle("on", x === b)); d.dataset.val = b.dataset.v; })));
}

// ---------- PS situation / raid ----------
export function scenario(root, sc, module, done) {
  const list = (a) => (a && a.length ? `<ul>${a.map((x) => `<li>${inline(x)}</li>`).join("")}</ul>` : "");
  const el = h(`<div class="panel task">
    <div class="row spread"><span class="tag acc">${sc.kind === "raid" ? "Raid" : "PS situation"}</span>${TIER(sc.tier)}</div>
    <h3 style="margin-top:8px">${inline(sc.title)}</h3>
    <div class="md">${md(sc.situation)}</div>
    ${sc.constraints ? `<div class="md small"><b>Constraints</b>${list(sc.constraints)}</div>` : ""}
    ${sc.stakeholders ? `<div class="md small"><b>Stakeholders</b>${list(sc.stakeholders)}</div>` : ""}
    <p class="q">${inline(sc.ask)}</p>
    <textarea placeholder="Your plan: what you ask, what you check, what you do, how you roll back, who you tell"></textarea>
    <div class="row" style="margin-top:10px"><button class="primary" data-reveal>Reveal the consultant's answer</button></div>
    <div class="reveal md" hidden>
      <hr class="sep">
      <h3>The right thinking</h3><ol>${(sc.right_thinking || []).map((x) => `<li>${inline(x)}</li>`).join("")}</ol>
      ${sc.what ? `<p><b>What:</b> ${inline(sc.what)}</p>` : ""}
      ${sc.why ? `<p><b>Why:</b> ${inline(sc.why)}</p>` : ""}
      ${sc.how ? `<div><b>How:</b>${list(sc.how)}</div>` : ""}
      ${sc.pitfalls ? `<div class="call pitfall"><b>Pitfalls</b>${list(sc.pitfalls)}</div>` : ""}
      ${sc.model_answer ? `<h3>Model answer</h3>${md(sc.model_answer)}` : ""}
      ${sc.could_have_added ? `<div class="call tip"><b>What a great answer adds</b>${list(sc.could_have_added)}</div>` : ""}
      ${sc.best_way ? `<div class="call why"><b>Best way to say it</b><p>${inline(sc.best_way)}</p></div>` : ""}
      ${src(sc.source)}
      <h3>Score yourself</h3>
      <div class="rubric">${(sc.rubric || ["clarify", "risk", "plan and rollback", "validation", "communication"]).map((r) => `<div class="r"><span>${esc(r)}</span>${dots(r)}</div>`).join("")}</div>
      <div class="row" style="margin-top:12px"><button class="primary" data-save>Save score and continue</button></div>
    </div></div>`);
  setKeys(null);
  wireDots(el);
  $("[data-reveal]", el).onclick = () => { $(".reveal", el).hidden = false; $("[data-reveal]", el).hidden = true; };
  $("[data-save]", el).onclick = () => {
    const vals = $$(".dots", el).map((d) => +d.dataset.val || 0);
    if (vals.some((v) => !v)) { alertInline(el, "Score every line first."); return; }
    const scores = {};
    $$(".dots", el).forEach((d) => (scores[d.dataset.name] = +d.dataset.val));
    const avg = vals.reduce((a, b) => a + b, 0) / vals.length;
    record("scenario_score", { item: sc.id, module, scores, avg, plan: $("textarea", el).value.slice(0, 4000) });
    done(avg);
  };
  root.replaceChildren(el);
}

function alertInline(el, msg) {
  let n = $(".inline-alert", el);
  if (!n) { n = h(`<div class="verdict no inline-alert"></div>`); const r = $(".rubric", el); if (r) r.after(n); else el.append(n); }
  n.textContent = msg;
}

// ---------- Interview drill ----------
export function telecyborg(items, title) {
  const body = items.map((q) => `# ${q.question.replace(/\n/g, " ")}\n${(q.best_way || q.model_answer || "").trim()}\n\n[pause 1]\n`).join("\n");
  const wpm = 150;
  const words = body.split(/\s+/).length;
  const secs = Math.round((words / wpm) * 60);
  return `---\ntitle: ${title}\nwpm: ${wpm}\ntarget: ${Math.floor(secs / 60)}:${String(secs % 60).padStart(2, "0")}\nlang: en\n---\n\n${body}`;
}

export function drill(root, q, module, done, opts = {}) {
  const list = (a) => (a && a.length ? `<ul>${a.map((x) => `<li>${inline(x)}</li>`).join("")}</ul>` : "");
  const el = h(`<div class="panel task">
    ${opts.label ? `<div class="progress-line">${esc(opts.label)}</div>` : ""}
    <div class="row spread"><span class="tag acc">Interview · ${esc({ recruiter: "Recruiter", hm: "Hiring manager", technical: "Technical" }[q.stage] || q.stage)}</span><span class="tiny num" data-clock>0:00</span></div>
    <p class="q" style="margin-top:10px">${inline(q.question)}</p>
    <p class="small muted">Answer out loud first (aim for ${esc(q.target || "1:30")}). Jot your key points below, then reveal.</p>
    <textarea placeholder="Key points of your answer"></textarea>
    <div class="row" style="margin-top:10px"><button class="primary" data-reveal>Reveal the model answer <span class="kbd">Space</span></button></div>
    <div class="reveal md" hidden>
      <hr class="sep">
      ${q.testing ? `<p><b>What they are really testing:</b> ${inline(q.testing)}</p>` : ""}
      ${q.framework ? `<p><b>Framework:</b> ${inline(q.framework)}</p>` : ""}
      <h3>Model answer</h3>${md(q.model_answer || "")}
      ${q.could_have_added ? `<div class="call tip"><b>What a great answer adds</b>${list(q.could_have_added)}</div>` : ""}
      ${q.best_way ? `<div class="call why"><b>Best way to say it</b><p>${inline(q.best_way)}</p></div>` : ""}
      ${q.follow_ups ? `<div class="small"><b>Likely follow-ups</b>${list(q.follow_ups)}</div>` : ""}
      <h3>How did your spoken answer compare?</h3>
      <div class="rubric"><div class="r"><span>1 lost · 3 decent · 5 as good as the model</span>${dots("score")}</div></div>
      <div class="row" style="margin-top:12px"><button class="primary" data-save>Save and continue</button><button data-tc>Export to TeleCyborg</button></div>
    </div></div>`);
  wireDots(el);
  const t0 = Date.now();
  const clock = setInterval(() => { const s = Math.floor((Date.now() - t0) / 1000); const c = $("[data-clock]", el); if (!c) return clearInterval(clock); c.textContent = `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`; }, 1000);
  const reveal = () => { $(".reveal", el).hidden = false; $("[data-reveal]", el).hidden = true; };
  $("[data-reveal]", el).onclick = reveal;
  setKeys((e) => { if (e.code === "Space") { e.preventDefault(); reveal(); } });
  $("[data-tc]", el).onclick = () => download(`${q.id}.md`, telecyborg([q], q.question.slice(0, 60)));
  $("[data-save]", el).onclick = () => {
    const v = +($(".dots", el).dataset.val || 0);
    if (!v) { alertInline(el, "Pick a score from 1 to 5."); return; }
    clearInterval(clock);
    record("drill", { item: q.id, module, stage: q.stage, score: v, ms: Date.now() - t0, notes: $("textarea", el).value.slice(0, 4000) });
    record("review", { item: q.id, kind: "interview", module, rating: v <= 2 ? 1 : v === 3 ? 2 : v === 4 ? 3 : 4 });
    setKeys(null);
    done(v);
  };
  root.replaceChildren(el);
}

// Render any due item by kind (used by Review and the warm-up block).
export function anyItem(root, id, done, opts = {}) {
  const ref = S.itemIndex.get(id);
  if (!ref) return done();
  if (ref.kind === "card") return flashcard(root, id, done, opts);
  if (ref.kind === "quiz") return quiz(root, ref.item, ref.module, done, { ...opts, mode: "review" });
  if (ref.kind === "labpart") return labPart(root, ref.item.lab, ref.item.part, { label: `${opts.label || "Review"} · lab ${ref.item.lab}`, slot: "review" }, () => done());
  return drill(root, ref.item, ref.module, done, opts);
}
