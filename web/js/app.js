// FortiTatake app shell and router.
import { initToken, api, h, $, $$, esc, icon, MARK } from "./core.js";
import { S, loadAll, setAnnouncer, setting, onChange, dueItems } from "./state.js";
import { runSession } from "./session.js";
import { home, review, library, moduleView, interview, progress, settings } from "./views.js";
import { startPolling } from "./sync.js";

const NAV = [["home", "Command", "home"], ["review", "Review", "cards"], ["library", "Library", "book"], ["interview", "Interview", "mic"], ["progress", "Progress", "chart"], ["settings", "Settings", "gear"]];
let info = {};

function shell() {
  const app = h(`<div class="app">
    <nav class="rail" aria-label="Main">
      <div class="brand">${MARK}<b>FortiTatake</b></div>
      <div class="nav">${NAV.map(([k, n, i]) => `<a href="#/${k}" data-nav="${k}">${icon(i)}<span>${n}</span></a>`).join("")}</div>
      <div class="foot lvl"><span data-rank></span><div class="meter"><i data-xp style="width:0"></i></div><span data-due class="tiny"></span></div>
    </nav>
    <main class="main" id="main"></main></div>`);
  document.body.replaceChildren(app);
}

function updateRail() {
  const p = S.p;
  if (!p) return;
  $("[data-rank]").textContent = `${p.rank} · L${p.level}`;
  $("[data-xp]").style.width = Math.round((p.levelXP / p.levelNeed) * 100) + "%";
  const due = dueItems().length;
  $("[data-due]").textContent = due ? `${due} reviews due` : "No reviews due";
  document.documentElement.dataset.skin = setting("skin", "fabric");
}

function route() {
  const main = $("#main");
  const parts = (location.hash.replace(/^#\/?/, "") || "home").split("/");
  const [view, a, b] = parts;
  $$("[data-nav]").forEach((x) => x.classList.toggle("on", x.dataset.nav === view || (view === "module" && x.dataset.nav === "library") || (view === "session" && x.dataset.nav === "home")));
  window.scrollTo(0, 0);
  switch (view) {
    case "session": return runSession(main, a);
    case "review": return review(main);
    case "library": return library(main);
    case "module": return moduleView(main, a, b);
    case "interview": return interview(main, a);
    case "progress": return progress(main);
    case "settings": return settings(main, info);
    default: return home(main);
  }
}

function toast(title, text) {
  const t = h(`<div class="toast" role="status"><b>${esc(title)}</b><span class="small muted">${esc(text)}</span></div>`);
  document.body.append(t);
  setTimeout(() => t.remove(), 4200);
}
function moment(title, text) {
  const m = h(`<div class="moment" role="dialog" aria-label="${esc(title)}"><div class="card"><h1>${esc(title)}</h1><p>${esc(text)}</p><button class="primary">Keep going</button></div></div>`);
  document.body.append(m);
  $("button", m).focus();
  $("button", m).onclick = () => m.remove();
}

async function start() {
  initToken();
  shell();
  try {
    info = await api("info");
    await loadAll();
  } catch (e) {
    $("#main").replaceChildren(h(`<div class="wrap"><h1>FortiTatake can't reach its engine</h1><p class="muted">Close this window and open FortiTatake again. Details: ${esc(e.message)}</p></div>`));
    return;
  }
  setAnnouncer((a) => {
    if (a.kind === "level") moment(`Level ${a.level}`, `Rank: ${a.rank}. Keep the pressure on.`);
    if (a.kind === "medal") toast("Medal earned: " + a.medal.name, a.medal.desc);
  });
  onChange(updateRail);
  updateRail();
  window.addEventListener("hashchange", route);
  route();
  startPolling(() => {
    if (document.querySelector(".update-bar")) return;
    const bar = h(`<div class="update-bar" role="status"><span class="small"><b>New study content arrived from your PC.</b> Reload to see it.</span><button class="primary">Reload</button></div>`);
    $("button", bar).onclick = () => location.reload();
    document.body.append(bar);
  });
}
start();
