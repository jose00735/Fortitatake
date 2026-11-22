// Sync: the Settings panel for LAN sync (PC = hub, phone = spoke) and the
// background poll that picks up events merged in by a sync.
import { api, h, $, $$, esc } from "./core.js";
import { S, pullLocal } from "./state.js";

const android = () => window.FTAndroid || null;

function ago(ms) {
  if (!ms) return "never";
  const s = Math.round((Date.now() - ms) / 1000);
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return new Date(ms).toLocaleDateString();
}

// ---------- background poll ----------
let contentSeen = null;
export function startPolling(onContent) {
  const tick = async () => {
    if (document.hidden) return;
    try {
      const info = await api("info");
      if (info.count !== S.serverCount) await pullLocal();
      if (contentSeen === null) contentSeen = info.content;
      if (info.content && info.content !== contentSeen && S.content && info.content !== S.content.version) {
        contentSeen = info.content;
        onContent(info.content);
      }
    } catch (e) { /* engine busy or restarting; try again next tick */ }
  };
  setInterval(tick, 5000);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) tick(); });
}

// ---------- Android bridge callbacks ----------
let scanCb = null, discCb = null;
window.FT_onScan = (text) => { const cb = scanCb; scanCb = null; if (cb) cb(text || ""); };
window.FT_onDiscover = (json) => { const cb = discCb; discCb = null; if (cb) { try { cb(JSON.parse(json || "[]")); } catch (e) { cb([]); } } };
function scanQr() { return new Promise((res) => { scanCb = res; android().scanQr(); }); }
function discover(ms = 4000) {
  return new Promise((res) => { discCb = res; android().discover(ms); setTimeout(() => window.FT_onDiscover("[]"), ms + 3000); });
}

// ---------- panel ----------
export async function syncPanel(box) {
  let st;
  try { st = await api("sync"); } catch (e) { box.replaceChildren(h(`<p class="small muted">Sync status unavailable: ${esc(e.message)}</p>`)); return; }
  if (st.role === "hub") return hubPanel(box, st);
  if (st.role === "spoke") return spokePanel(box, st);
  box.replaceChildren(h(`<p class="small muted">Sync is off in this build.</p>`));
}

function err(box, msg) {
  const e = $("[data-err]", box);
  if (e) { e.textContent = msg || ""; e.hidden = !msg; }
}

// ----- PC -----
let pairTimer = null;
function hubPanel(box, st) {
  clearInterval(pairTimer);
  if (!st.enabled) {
    box.replaceChildren(h(`<div class="stack">
      <p class="small">Keep your progress identical on this PC and the FortiTatake app on your phone. Sync runs over your own Wi-Fi: no cloud, no account.</p>
      <p class="tiny muted">The first time, Windows asks whether FortiTatake may use the network. Choose <b>Private networks</b> and Allow.</p>
      <div class="row"><button class="primary" data-on>Turn on sync</button></div>
      <p class="alert" data-err hidden></p></div>`));
    $("[data-on]", box).onclick = async () => {
      try { await api("sync/hub", { method: "POST", body: { enabled: true, port: st.port, name: st.name } }); syncPanel(box); }
      catch (e) { err(box, e.message); }
    };
    return;
  }
  const devs = st.devices || [];
  box.replaceChildren(h(`<div class="stack">
    <div class="row spread"><div><b>${st.running ? "Sync is on" : "Sync is on but not listening"}</b>
      <div class="tiny muted">${esc(st.name)} · port ${st.port}${(st.hosts || []).length ? " · " + st.hosts.map(esc).join(", ") : ""}</div>
      ${st.words ? `<div class="tiny muted">Identity: <span class="words">${esc(st.words)}</span></div>` : ""}</div>
      <div class="row"><button class="primary" data-pair ${st.running ? "" : "disabled"}>Pair a phone</button><button class="ghost" data-off>Turn off</button></div></div>
    ${st.error ? `<p class="alert">${esc(st.error)}</p>` : ""}
    ${st.mdns_error ? `<p class="tiny muted">${esc(st.mdns_error)}</p>` : ""}
    <div data-pairbox></div>
    <div><div class="tiny muted" style="margin-bottom:6px">Paired phones</div>
      ${devs.length ? `<ul class="devlist">${devs.map((d) => `<li><div><b>${esc(d.name)}</b><div class="tiny muted">last synced ${esc(ago(Date.parse(d.last_seen)))}${d.last_addr ? " · " + esc(d.last_addr) : ""}</div></div><button class="ghost" data-revoke="${esc(d.id)}">Remove</button></li>`).join("")}</ul>`
      : `<p class="small muted">No phone yet. Install the Android app, then press <b>Pair a phone</b>.</p>`}</div>
    <p class="alert" data-err hidden></p></div>`));
  $("[data-off]", box).onclick = async () => { await api("sync/hub", { method: "POST", body: { enabled: false, port: st.port, name: st.name } }); syncPanel(box); };
  $$("[data-revoke]", box).forEach((b) => (b.onclick = async () => { await api("sync/devices/revoke", { method: "POST", body: { id: b.dataset.revoke } }); syncPanel(box); }));
  $("[data-pair]", box).onclick = async () => {
    let p;
    try { p = await api("sync/pair/open", { method: "POST" }); } catch (e) { err(box, e.message); return; }
    const before = devs.length;
    const pb = $("[data-pairbox]", box);
    pb.replaceChildren(h(`<div class="pairbox">
      <div class="qr" aria-label="Pairing QR code">${p.qr_svg}</div>
      <div class="stack">
        <p class="small" style="margin:0">On the phone: <b>Settings → Sync → Scan the QR code</b>. No camera? Type the address and code instead.</p>
        <div><div class="tiny muted">Code</div><div class="code-big num">${esc(p.code)}</div></div>
        <div><div class="tiny muted">Address</div><div class="num">${(p.hosts || []).map(esc).join(" or ") || "no Wi-Fi address found"} : ${p.port}</div></div>
        <div><div class="tiny muted">The phone must show these words</div><div class="words">${esc(p.words)}</div></div>
        <div class="row"><span class="tiny muted" data-left></span><button class="ghost" data-close>Cancel</button></div>
      </div></div>`));
    const close = async () => { clearInterval(pairTimer); await api("sync/pair/close", { method: "POST" }).catch(() => {}); syncPanel(box); };
    $("[data-close]", pb).onclick = close;
    pairTimer = setInterval(async () => {
      const left = p.exp * 1000 - Date.now();
      const l = $("[data-left]", pb);
      if (l) l.textContent = left > 0 ? `Closes in ${Math.floor(left / 60000)}:${String(Math.floor(left / 1000) % 60).padStart(2, "0")}` : "Expired";
      if (left <= 0) return close();
      try {
        const s2 = await api("sync");
        if ((s2.devices || []).length > before || !s2.pairing) { clearInterval(pairTimer); syncPanel(box); }
      } catch (e) { /* keep waiting */ }
    }, 1500);
  };
}

// ----- phone -----
let autoFound = false;
function spokePanel(box, st) {
  const A = android();
  if (!st.paired) {
    box.replaceChildren(h(`<div class="stack">
      <p class="small">On your PC open <b>Settings → Sync</b>, turn sync on and press <b>Pair a phone</b>.</p>
      ${A ? `<div class="row"><button class="primary" data-scan>Scan the QR code</button></div>` : ""}
      <details ${A ? "" : "open"}><summary class="small">Type the address and code instead</summary>
        <div class="grid2" style="margin-top:8px"><label class="field">PC address<input data-host inputmode="decimal" placeholder="192.168.1.20" autocomplete="off"></label>
        <label class="field">Code<input data-code placeholder="ABCD-EFGH" autocapitalize="characters" autocomplete="off"></label></div>
        <label class="field" style="max-width:160px">Port<input data-port inputmode="numeric" value="47431"></label>
        <div class="row"><button data-check>Check the PC</button></div>
        <div data-confirm></div>
      </details>
      <p class="alert" data-err hidden></p></div>`));
    const pairWith = async (body) => {
      err(box, "");
      try { await api("sync/pair", { method: "POST", body }); await syncNow(box, true); }
      catch (e) { err(box, e.message); }
    };
    const sc = $("[data-scan]", box);
    if (sc) sc.onclick = async () => { const t = await scanQr(); if (t) pairWith({ qr: t }); };
    $("[data-check]", box).onclick = async () => {
      err(box, "");
      const host = $("[data-host]", box).value.trim(), port = +$("[data-port]", box).value || 47431, code = $("[data-code]", box).value.trim();
      if (!host || !code) return err(box, "Type the PC address and the code shown on the PC.");
      let pr;
      try { pr = await api("sync/probe", { method: "POST", body: { host, port } }); } catch (e) { return err(box, e.message); }
      const cf = $("[data-confirm]", box);
      cf.replaceChildren(h(`<div class="panel stack" style="margin-top:10px"><div class="tiny muted">Found <b>${esc(pr.name)}</b>. Do these words match the PC screen?</div>
        <div class="words">${esc(pr.words)}</div>
        <div class="row"><button class="primary" data-yes>They match, pair</button><button class="ghost" data-no>They don't match</button></div></div>`));
      $("[data-yes]", cf).onclick = () => pairWith({ host, port, code, fp: pr.fp });
      $("[data-no]", cf).onclick = () => { cf.replaceChildren(); err(box, "Don't pair: something else on this network answered. Check the address on the PC screen."); };
    };
    return;
  }
  box.replaceChildren(h(`<div class="stack">
    <div class="row spread"><div><b>Paired with ${esc(st.hub_name || "your PC")}</b>
      <div class="tiny muted">${st.busy ? "Syncing…" : "Last sync " + esc(ago(st.last_sync))}${st.last_sync ? ` · ${st.last_pulled} in, ${st.last_pushed} out` : ""}</div>
      ${st.words ? `<div class="tiny muted">Identity: <span class="words">${esc(st.words)}</span></div>` : ""}</div>
      <div class="row"><button class="primary" data-now>Sync now</button><button class="ghost" data-unpair>Unpair</button></div></div>
    ${st.last_error ? `<p class="alert">${esc(st.last_error)}</p>` : ""}
    <p class="tiny muted">Syncs when the app opens and every 5 minutes while the PC is reachable.</p>
    <p class="alert" data-err hidden></p></div>`));
  $("[data-now]", box).onclick = () => syncNow(box, true);
  $("[data-unpair]", box).onclick = async () => { await api("sync/unpair", { method: "POST" }); syncPanel(box); };
  // The PC's address may have changed (DHCP): look it up by its id and retry once.
  if (st.last_error && A && !autoFound) { autoFound = true; rediscover(st).then((ok) => ok && syncNow(box, false)); }
}

async function rediscover(st) {
  const found = (await discover()).filter((x) => x.id === st.hub_id);
  if (!found.length) return false;
  const r = await api("sync/hosts", { method: "POST", body: { hub: st.hub_id, hosts: found.map((x) => x.host), port: found[0].port } });
  return r.updated;
}

async function syncNow(box, showErr) {
  const b = $("[data-now]", box);
  if (b) { b.disabled = true; b.textContent = "Syncing…"; }
  let msg = "";
  try {
    const r = await api("sync/now", { method: "POST" });
    await pullLocal();
    if (r.content_updated) { location.reload(); return; }
  } catch (e) { msg = e.message; }
  await syncPanel(box);
  if (msg && showErr) err(box, msg);
}
