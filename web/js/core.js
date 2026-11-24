// Core: API client, FSRS scheduler, Markdown renderer and small DOM helpers.

// ---------- API ----------
let token = "";
export function initToken() {
  const m = location.hash.match(/t=([0-9a-f]+)/);
  if (m) {
    token = m[1];
    try { sessionStorage.setItem("ft-token", token); } catch (e) { /* ignore */ }
    history.replaceState(null, "", location.pathname + "#/home");
  } else {
    try { token = sessionStorage.getItem("ft-token") || ""; } catch (e) { token = ""; }
  }
  return token;
}
export function tokenValue() { return token; }

export async function api(path, opts = {}) {
  const res = await fetch("/api/" + path, {
    method: opts.method || "GET",
    headers: { "X-FT-Token": token, "Content-Type": "application/json" },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  if (!res.ok) {
    const t = await res.text();
    let msg = t || res.statusText;
    try { const j = JSON.parse(t); if (j && j.error) msg = typeof j.error === "string" ? j.error : j.error.message; } catch (e) { /* plain text */ }
    throw new Error(msg);
  }
  return res.json();
}

// ---------- FSRS (v4.5 default parameters) ----------
const W = [0.4872, 1.4003, 3.7145, 13.8206, 5.1618, 1.2298, 0.8975, 0.031, 1.6474, 0.1367, 1.0461, 2.1072, 0.0793, 0.3246, 1.587, 0.2272, 2.8755];
const DECAY = -0.5;
const FACTOR = 19 / 81;
const DAY = 86400000;
const clampD = (d) => Math.min(10, Math.max(1, d));
const initS = (g) => Math.max(0.1, W[g - 1]);
const initD = (g) => clampD(W[4] - (g - 3) * W[5]);

export function retrievability(st, now = Date.now()) {
  if (!st || !st.s) return 0;
  const t = Math.max(0, (now - st.last) / DAY);
  return Math.pow(1 + FACTOR * t / st.s, DECAY);
}

function intervalDays(s, retention) {
  return (s / FACTOR) * (Math.pow(retention, 1 / DECAY) - 1);
}

// Apply rating g (1 Again, 2 Hard, 3 Good, 4 Easy) at time now; returns new state.
export function schedule(prev, g, now, retention = 0.9) {
  let s, d, lapses = prev ? prev.lapses : 0, reps = prev ? prev.reps + 1 : 1;
  if (!prev || !prev.s) {
    s = initS(g);
    d = initD(g);
  } else {
    const r = retrievability(prev, now);
    d = clampD(W[7] * initD(4) + (1 - W[7]) * (prev.d - W[6] * (g - 3)));
    if (g === 1) {
      lapses += 1;
      s = W[11] * Math.pow(prev.d, -W[12]) * (Math.pow(prev.s + 1, W[13]) - 1) * Math.exp((1 - r) * W[14]);
      s = Math.min(s, prev.s);
    } else {
      const hard = g === 2 ? W[15] : 1;
      const easy = g === 4 ? W[16] : 1;
      s = prev.s * (1 + Math.exp(W[8]) * (11 - prev.d) * Math.pow(prev.s, -W[9]) * (Math.exp((1 - r) * W[10]) - 1) * hard * easy);
    }
  }
  s = Math.max(0.1, s);
  let due;
  if (g === 1) due = now + 10 * 60000; // relearn in the same session
  else due = now + Math.max(1, Math.round(intervalDays(s, retention))) * DAY;
  return { s, d, last: now, due, reps, lapses };
}

// ---------- Markdown (small, safe subset) ----------
const esc = (t) => String(t ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
export { esc };

function inline(t) {
  let s = esc(t);
  s = s.replace(/`([^`]+)`/g, "<code>$1</code>");
  s = s.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  s = s.replace(/(^|[^*])\*([^*\s][^*]*)\*/g, "$1<em>$2</em>");
  return s;
}
export { inline };

const CALLOUT = { recall: "Recall", why: "Why?", pitfall: "Pitfall", threat: "Threat landscape", delta: "Version note", tip: "Field tip", ps: "PS lens" };

export function md(src) {
  const lines = String(src || "").replace(/\r/g, "").split("\n");
  let out = "", i = 0;
  while (i < lines.length) {
    let line = lines[i];
    if (/^:::(\w+)/.test(line)) {
      const kind = line.match(/^:::(\w+)/)[1];
      const body = [];
      i++;
      while (i < lines.length && !/^:::\s*$/.test(lines[i])) body.push(lines[i++]);
      i++;
      if (kind === "cli") {
        out += `<pre><code>${esc(body.join("\n"))}</code></pre>`;
      } else if (kind === "recall" || kind === "why") {
        const text = body.join("\n");
        const [q, a] = text.split(/\n\s*A:\s*/);
        out += `<div class="call ${kind}"><b>${CALLOUT[kind]}</b><div>${inline(q.replace(/^Q:\s*/, ""))}</div>` +
          (a ? `<details class="ans"><summary>Check your answer</summary><div>${inline(a)}</div></details>` : "") + `</div>`;
      } else {
        out += `<div class="call ${kind}"><b>${CALLOUT[kind] || kind}</b>${md(body.join("\n"))}</div>`;
      }
      continue;
    }
    if (/^```/.test(line)) {
      const body = [];
      i++;
      while (i < lines.length && !/^```/.test(lines[i])) body.push(lines[i++]);
      i++;
      out += `<pre><code>${esc(body.join("\n"))}</code></pre>`;
      continue;
    }
    if (/^#{2,4}\s/.test(line)) {
      const n = line.match(/^(#+)/)[1].length;
      out += `<h${n}>${inline(line.replace(/^#+\s*/, ""))}</h${n}>`;
      i++;
      continue;
    }
    if (/^\|/.test(line)) {
      const rows = [];
      while (i < lines.length && /^\|/.test(lines[i])) rows.push(lines[i++]);
      const cells = (r) => r.replace(/^\||\|$/g, "").split("|").map((c) => c.trim());
      const head = cells(rows[0]);
      const body = rows.slice(2).map(cells);
      out += `<table><thead><tr>${head.map((h) => `<th>${inline(h)}</th>`).join("")}</tr></thead><tbody>` +
        body.map((r) => `<tr>${r.map((c) => `<td>${inline(c)}</td>`).join("")}</tr>`).join("") + `</tbody></table>`;
      continue;
    }
    if (/^\s*[-*]\s/.test(line) || /^\s*\d+\.\s/.test(line)) {
      const ordered = /^\s*\d+\./.test(line);
      const items = [];
      while (i < lines.length && (/^\s*[-*]\s/.test(lines[i]) || /^\s*\d+\.\s/.test(lines[i]))) {
        items.push(lines[i].replace(/^\s*([-*]|\d+\.)\s/, ""));
        i++;
        // an indented line that isn't a new item continues the item above (wrapped text)
        while (i < lines.length && /^\s{2,}\S/.test(lines[i]) && !/^\s*([-*]|\d+\.)\s/.test(lines[i])) items[items.length - 1] += " " + lines[i++].trim();
      }
      const tag = ordered ? "ol" : "ul";
      out += `<${tag}>${items.map((t) => `<li>${inline(t)}</li>`).join("")}</${tag}>`;
      continue;
    }
    if (!line.trim()) { i++; continue; }
    const para = [];
    while (i < lines.length && lines[i].trim() && !/^(:::|```|#{2,4}\s|\||\s*[-*]\s|\s*\d+\.\s)/.test(lines[i])) para.push(lines[i++]);
    out += `<p>${inline(para.join(" "))}</p>`;
  }
  return out;
}

// ---------- DOM helpers ----------
export function h(html) {
  const t = document.createElement("template");
  t.innerHTML = html.trim();
  return t.content.firstElementChild;
}
export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
export function shuffle(a) {
  const x = [...a];
  for (let i = x.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [x[i], x[j]] = [x[j], x[i]];
  }
  return x;
}
export function norm(t) {
  return String(t || "").toLowerCase().replace(/["'“”‘’]/g, "").replace(/\s+/g, " ").trim();
}
export function fmtMin(ms) {
  const m = Math.floor(ms / 60000), s = Math.floor((ms % 60000) / 1000);
  return `${m}:${String(s).padStart(2, "0")}`;
}
export function download(name, text, type = "text/markdown") {
  if (window.FTAndroid && window.FTAndroid.saveFile) { window.FTAndroid.saveFile(name, type, text); return; }
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type }));
  a.download = name;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
}

// Icons: one stroke family, 24px grid.
const P = {
  home: "M3 11 12 4l9 7v9a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1z",
  play: "M7 4.5v15l12-7.5z",
  cards: "M4 7h12v13H4zM8 4h12v13",
  book: "M4 5a2 2 0 0 1 2-2h13v16H6a2 2 0 0 0-2 2zM4 19V5M9 7h6",
  mic: "M12 3a3 3 0 0 1 3 3v6a3 3 0 0 1-6 0V6a3 3 0 0 1 3-3zM5 11a7 7 0 0 0 14 0M12 18v3",
  chart: "M4 20V10M10 20V4M16 20v-7M22 20H2",
  gear: "M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6zM19 12l2-1-1-3-2 .2-1.3-1.3.2-2-3-1-1 2h-1.8l-1-2-3 1 .2 2L7 7.2 5 7 4 10l2 1v1.8l-2 1 1 3 2-.2 1.3 1.3-.2 2 3 1 1-2h1.8l1 2 3-1-.2-2 1.3-1.3 2 .2 1-3-2-1z",
  term: "M3 5h18v14H3zM7 10l3 2-3 2M12 15h5",
  flame: "M12 3c1 4 6 6 6 11a6 6 0 0 1-12 0c0-3 2-4 2-7 2 1 3 2 3 4 1-2 1-5 1-8z",
};
export function icon(name) {
  return `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="${P[name]}"/></svg>`;
}
// Original FortiTatake mark: firewall-grid shield with a molten core.
export const MARK = `<svg viewBox="0 0 64 64" aria-hidden="true"><defs><linearGradient id="mk" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ff7a1a"/><stop offset="1" stop-color="#c8281c"/></linearGradient></defs><path d="M32 4 56 13v17c0 15-10 25-24 30C18 55 8 45 8 30V13z" fill="url(#mk)"/><path d="M16 22h32M16 31h32M16 40h32M24 22v9M40 22v9M32 31v9M24 40v8M40 40v6" stroke="#1a0d08" stroke-width="3" stroke-linecap="round" opacity=".85"/></svg>`;
