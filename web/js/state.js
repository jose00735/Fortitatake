// State: loads content, replays the event log into projections, and records new events.
import { api, schedule, retrievability } from "./core.js";

export const S = {
  content: null,       // bundle
  mods: new Map(),     // id -> module
  itemIndex: new Map(),// item id -> { item, kind, module }
  events: [],         // confirmed + pending, what projections replay
  confirmed: [],       // events as stored by the engine (in log order)
  pending: [],         // recorded here, not yet acknowledged by the engine
  serverCount: 0,      // how many log entries `confirmed` covers
  p: null,             // projections
  listeners: new Set(),
};

export async function loadAll() {
  const res = await fetch("content/bundle.json", { cache: "no-store" });
  S.content = await res.json();
  for (const m of S.content.modules) {
    S.mods.set(m.id, m);
    for (const c of m.cards || []) S.itemIndex.set(c.id, { item: c, kind: "card", module: m.id });
    for (const q of m.quiz || []) S.itemIndex.set(q.id, { item: q, kind: "quiz", module: m.id });
    for (const q of m.interview || []) S.itemIndex.set(q.id, { item: q, kind: "interview", module: m.id });
  }
  // lab parts are review items as well (LAB.<lab>.<part>), indexed under each module they teach
  S.labs = [];
  S.labsByModule = new Map();
  try {
    const cat = await (await fetch("content/labs.json", { cache: "no-store" })).json();
    S.labs = cat.labs.map((l) => ({ id: l.id, title: l.title, kind: l.kind, tier: l.tier, track: l.track, par: l.par, modules: l.modules || [], parts: l.parts.map((p) => ({ id: p.id, title: p.title })) }));
    for (const l of S.labs) {
      for (const m of l.modules) { if (!S.labsByModule.has(m)) S.labsByModule.set(m, []); S.labsByModule.get(m).push(l); }
      for (const p of l.parts) S.itemIndex.set(`LAB.${l.id}.${p.id}`, { item: { lab: l.id, part: p.id, title: p.title, labTitle: l.title }, kind: "labpart", module: l.modules[0] });
    }
  } catch (e) { /* labs are optional for sorties */ }
  const r = await api("events");
  S.confirmed = r.events || [];
  S.serverCount = S.confirmed.length;
  S.events = S.confirmed.slice();
  rebuild();
}

// pullLocal fetches events the engine stored since we last looked: our own flushed
// events and anything merged in by a sync. Returns how many arrived.
let pulling = null;
export function pullLocal() {
  if (!pulling) pulling = (async () => {
    try {
      const r = await api("events?since=" + S.serverCount);
      const got = r.events || [];
      if (!got.length) return 0;
      S.confirmed.push(...got);
      S.serverCount += got.length;
      S.events = S.confirmed.concat(S.pending);
      rebuild();
      return got.length;
    } finally { pulling = null; }
  })();
  return pulling;
}

export function onChange(fn) { S.listeners.add(fn); return () => S.listeners.delete(fn); }

let queue = [], flushing = null;
// record appends events locally at once (optimistic) and persists them in order.
export function record(type, body) {
  const ev = { type, v: 1, ts: Date.now(), body };
  const local = { ...ev, dev: "local", seq: 0, id: "pending" };
  S.pending.push(local);
  S.events.push(local);
  queue.push({ ev, local });
  const before = S.p ? { level: S.p.level, medals: new Set(S.p.medals.map((m) => m.id)) } : null;
  rebuild();
  if (before) announce(before);
  if (!flushing) flushing = flush();
  return ev;
}
async function flush() {
  while (queue.length) {
    const batch = queue.splice(0, queue.length);
    try {
      await api("events", { method: "POST", body: { events: batch.map((b) => b.ev) } });
      const done = new Set(batch.map((b) => b.local));
      S.pending = S.pending.filter((x) => !done.has(x));
      await pullLocal(); // swaps the placeholders for the stored events
    } catch (e) { queue.unshift(...batch); await new Promise((r) => setTimeout(r, 2000)); }
  }
  flushing = null;
}

let announcer = () => {};
export function setAnnouncer(fn) { announcer = fn; }
function announce(before) {
  if (S.p.level > before.level) announcer({ kind: "level", level: S.p.level, rank: S.p.rank });
  for (const m of S.p.medals) if (!before.medals.has(m.id)) announcer({ kind: "medal", medal: m });
}

export const setting = (k, d) => (S.p && S.p.settings[k] !== undefined ? S.p.settings[k] : d);

// ---------- Projections ----------
const RANKS = {
  fabric: ["Trainee", "Associate", "Professional", "Specialist", "Expert", "Architect"],
  hellforge: ["Kindling", "Ember", "Blaze", "Inferno", "Hellforged", "Unbroken"],
};
export const xpForNext = (lvl) => 150 + 50 * lvl;

export function rebuild() {
  const p = {
    settings: {}, items: new Map(), unitsDone: new Set(), labs: new Map(),
    quizFirst: new Map(), // item -> correct on first graded try
    scenarios: [], drills: new Map(), bosses: new Map(), sessions: new Map(),
    userCards: [], reflections: [], xp: 0, reviews: 0, days: new Set(), pretests: 0,
    xpByDay: new Map(), labParts: new Set(), labDone: new Map(),
  };
  const retention = () => Number(p.settings.retention || 0.9);
  const dayKey = (ts) => new Date(ts).toLocaleDateString("en-CA");
  const addXP = (n, ts) => { p.xp += n; const k = dayKey(ts); p.xpByDay.set(k, (p.xpByDay.get(k) || 0) + n); };

  const evs = [...S.events].sort((a, b) => (a.ts - b.ts) || String(a.dev).localeCompare(String(b.dev)) || (a.seq - b.seq));
  for (const e of evs) {
    const b = e.body || {};
    if (e.type !== "setting_set") p.days.add(dayKey(e.ts));
    switch (e.type) {
      case "setting_set": p.settings[b.key] = b.value; break;
      case "review": {
        const prev = p.items.get(b.item);
        const overdue = prev && e.ts - prev.due > 86400000;
        const st = schedule(prev, b.rating, e.ts, retention());
        st.kind = b.kind; st.module = b.module;
        p.items.set(b.item, st);
        p.reviews++;
        if (b.rating >= 3) addXP(overdue ? 2 : 1, e.ts);
        break;
      }
      case "quiz_attempt":
        if (b.pretest) { p.pretests++; break; }
        if (!p.quizFirst.has(b.item)) {
          p.quizFirst.set(b.item, { correct: !!b.correct, tier: b.tier, module: b.module });
          if (b.correct) addXP(2 * (b.tier || 1), e.ts);
        }
        break;
      case "unit_done":
        if (!p.unitsDone.has(b.unit)) { p.unitsDone.add(b.unit); addXP(10, e.ts); }
        break;
      case "lab_result": {
        const key = b.lab + ":" + b.stage;
        const was = p.labs.get(key);
        if (b.correct && !was) addXP(b.stage === "solo" ? 30 : 15, e.ts);
        p.labs.set(key, was || !!b.correct);
        break;
      }
      case "scenario_score":
        p.scenarios.push({ item: b.item, module: b.module, avg: b.avg, ts: e.ts });
        addXP(Math.round((b.avg || 0) * 10), e.ts);
        break;
      case "drill":
        p.drills.set(b.item, { score: b.score, module: b.module, stage: b.stage, ts: e.ts, count: ((p.drills.get(b.item) || {}).count || 0) + 1 });
        addXP((b.score || 0) * 8, e.ts);
        break;
      case "boss_result": {
        const prev = p.bosses.get(b.module);
        if (!prev || b.score > prev.score) p.bosses.set(b.module, { score: b.score, passed: b.passed, ts: e.ts });
        addXP(b.passed && !(prev && prev.passed) ? 300 : 50, e.ts);
        break;
      }
      case "session_start":
        p.sessions.set(b.sid, { sid: b.sid, module: b.module, start: e.ts, blocks: new Set(), end: null });
        break;
      case "block_done": {
        const s = p.sessions.get(b.sid);
        if (s) s.blocks.add(b.block);
        break;
      }
      case "session_end": {
        const s = p.sessions.get(b.sid);
        if (s && !s.end) { s.end = e.ts; addXP(100, e.ts); }
        break;
      }
      case "lab_part": {
        const k = b.lab + ":" + b.part;
        if (!p.labParts.has(k)) { p.labParts.add(k); addXP(b.revealed ? 10 : 40, e.ts); }
        break;
      }
      case "lab_done": {
        const prev = p.labDone.get(b.lab);
        if (!prev) addXP(Math.round(b.score || 0) + (b.exam ? 50 : 0), e.ts);
        if (!prev || (b.score || 0) > prev.score) p.labDone.set(b.lab, { score: b.score || 0, kind: b.kind, track: b.track, tier: b.tier, exam: !!b.exam, ts: e.ts });
        break;
      }
      case "reflection": p.reflections.push({ ...b, ts: e.ts }); break;
      case "card_create":
        p.userCards.push({ id: b.id, module: b.module, front: b.front, back: b.back, tier: 1, user: true });
        break;
    }
  }
  for (const c of p.userCards) if (!S.itemIndex.has(c.id)) S.itemIndex.set(c.id, { item: c, kind: "card", module: c.module });

  // level and rank
  let lvl = 1, left = p.xp;
  while (left >= xpForNext(lvl) && lvl < 30) { left -= xpForNext(lvl); lvl++; }
  p.level = lvl; p.levelXP = left; p.levelNeed = xpForNext(lvl);
  const skin = p.settings.skin || "fabric";
  p.rank = RANKS[skin][Math.min(5, Math.floor((lvl - 1) / 5))];

  // streak (study days ending today or yesterday)
  let streak = 0;
  const d = new Date();
  if (!p.days.has(d.toLocaleDateString("en-CA"))) d.setDate(d.getDate() - 1);
  while (p.days.has(d.toLocaleDateString("en-CA"))) { streak++; d.setDate(d.getDate() - 1); }
  p.streak = streak;

  p.mastery = new Map();
  if (S.content) for (const m of S.content.modules) p.mastery.set(m.id, masteryOf(m, p));
  p.medals = medalsOf(p);
  S.p = p;
  for (const fn of S.listeners) fn();
}

function masteryOf(m, p) {
  const now = Date.now();
  const units = m.units || [];
  if (!units.length || !units.every((u) => p.unitsDone.has(u.id))) {
    return { level: units.some((u) => p.unitsDone.has(u.id)) ? 0.5 : 0, note: "Read the units" };
  }
  const cards = m.cards || [];
  // "Strong" = currently recallable AND consolidated by at least one spaced review (stability >= 7 days).
  // Same-day re-ratings don't raise stability in FSRS, so L2 can't be reached by cramming.
  const strong = cards.filter((c) => { const st = p.items.get(c.id); return st && st.s >= 7 && retrievability(st, now) >= 0.8; }).length;
  if (cards.length && strong / cards.length < 0.7) return { level: 1, note: `Cards consolidated: ${strong}/${cards.length} (70% needed)` };
  const acc = (tier) => {
    const xs = [...p.quizFirst.entries()].filter(([, v]) => v.module === m.id && v.tier === tier).map(([, v]) => v.correct);
    return { n: xs.length, rate: xs.length ? xs.filter(Boolean).length / xs.length : 0 };
  };
  const d3 = acc(3);
  if (d3.n < 3 || d3.rate < 0.75) return { level: 2, note: "Apply: D3 items at 75%" };
  const d4 = acc(4);
  const sc = p.scenarios.filter((s) => s.module === m.id);
  const scAvg = sc.length ? sc.reduce((a, s) => a + s.avg, 0) / sc.length : 0;
  if ((d4.n >= 3 && d4.rate < 0.75) || (sc.length && scAvg < 3.5) || (!d4.n && !sc.length)) return { level: 3, note: "Analyze: D4 items and scenarios" };
  const boss = p.bosses.get(m.id);
  if (!boss || boss.score < 0.85) return { level: 4, note: "Beat the boss at 85%" };
  return { level: 5, note: "Mastered" };
}

export const MEDALS = [
  { id: "first-sortie", name: "First Sortie", desc: "Finish a full 4-hour session", test: (p) => [...p.sessions.values()].some((s) => s.end) },
  { id: "triple-sortie", name: "Triple Sortie", desc: "Three sessions finished in one day", test: (p) => { const c = {}; for (const s of p.sessions.values()) if (s.end) { const k = new Date(s.end).toDateString(); c[k] = (c[k] || 0) + 1; } return Object.values(c).some((n) => n >= 3); } },
  { id: "review-100", name: "Hundred Recalls", desc: "100 reviews", test: (p) => p.reviews >= 100 },
  { id: "review-500", name: "Iron Memory", desc: "500 reviews", test: (p) => p.reviews >= 500 },
  { id: "boss-1", name: "Gatekeeper Down", desc: "Beat your first boss", test: (p) => [...p.bosses.values()].some((b) => b.passed) },
  { id: "boss-perfect", name: "Flawless", desc: "Beat a boss without a miss", test: (p) => [...p.bosses.values()].some((b) => b.score >= 1) },
  { id: "arena-ace", name: "Arena Ace", desc: "Average 4+ across 5 PS situations", test: (p) => p.scenarios.length >= 5 && p.scenarios.reduce((a, s) => a + s.avg, 0) / p.scenarios.length >= 4 },
  { id: "pitch-ready", name: "Recruiter Ready", desc: "Score 4+ on 10 recruiter drills", test: (p) => [...p.drills.values()].filter((d) => d.stage === "recruiter" && d.score >= 4).length >= 10 },
  { id: "hm-ready", name: "HM Ready", desc: "Score 4+ on 10 hiring-manager drills", test: (p) => [...p.drills.values()].filter((d) => d.stage === "hm" && d.score >= 4).length >= 10 },
  { id: "panel-ready", name: "Panel Ready", desc: "Score 4+ on 15 technical drills", test: (p) => [...p.drills.values()].filter((d) => d.stage === "technical" && d.score >= 4).length >= 15 },
  { id: "debug-whisperer", name: "Debug Flow Whisperer", desc: "90% first-try on 10+ diagnostics items", test: (p) => { const xs = [...p.quizFirst.values()].filter((v) => v.module === "M4.12"); return xs.length >= 10 && xs.filter((v) => v.correct).length / xs.length >= 0.9; } },
  { id: "nat-ninja", name: "NAT Ninja", desc: "90% first-try on 15+ policy and NAT items", test: (p) => { const xs = [...p.quizFirst.values()].filter((v) => v.module === "M4.03"); return xs.length >= 15 && xs.filter((v) => v.correct).length / xs.length >= 0.9; } },
  { id: "lab-rat", name: "Lab Rat", desc: "Solve 5 labs solo", test: (p) => [...p.labs.entries()].filter(([k, v]) => k.endsWith(":solo") && v).length >= 5 },
  { id: "first-console", name: "Console Cowboy", desc: "Finish your first simulator lab", test: (p) => p.labDone.size >= 1 },
  { id: "sim-10", name: "Change Window Veteran", desc: "Finish 10 simulator labs", test: (p) => p.labDone.size >= 10 },
  { id: "breakfix-3", name: "Ticket Slayer", desc: "Close 3 break-fix tickets", test: (p) => [...p.labDone.values()].filter((d) => d.kind === "ticket").length >= 3 },
  { id: "exam-pass", name: "Under the Clock", desc: "Finish a lab in exam mode with 80+ points", test: (p) => [...p.labDone.values()].some((d) => d.exam && d.score >= 80) },
  { id: "streak-7", name: "Seven Fires", desc: "Study 7 days in a row", test: (p) => p.streak >= 7 },
  { id: "self-made", name: "Card Smith", desc: "Write 10 of your own cards", test: (p) => p.userCards.length >= 10 },
  { id: "level-10", name: "Double Digits", desc: "Reach level 10", test: (p) => p.level >= 10 },
];
function medalsOf(p) { return MEDALS.filter((m) => { try { return m.test(p); } catch (e) { return false; } }); }

// ---------- Queries ----------
export function dueItems(now = Date.now(), filter = () => true) {
  const out = [];
  for (const [id, st] of S.p.items) {
    if (st.due <= now && S.itemIndex.has(id) && filter(id, st)) out.push({ id, st });
  }
  return out.sort((a, b) => a.st.due - b.st.due);
}

export function moduleOrder() {
  return [...S.content.modules].sort((a, b) => a.order - b.order);
}
// Next module to study: first whose units are not all done.
export function nextModule() {
  const list = moduleOrder();
  return list.find((m) => (S.p.mastery.get(m.id) || {}).level < 1) || list[list.length - 1];
}
export function openSession() {
  const open = [...S.p.sessions.values()].filter((s) => !s.end).sort((a, b) => b.start - a.start);
  return open[0] || null;
}
