// FortiTatake OS: build screen, power gauge, stage 0 test.
import { api, h, $, esc } from "./core.js";

const PHASES = [
  ["sources", "Gathering sources"], ["toolchain", "Forging the toolchain"], ["kernel", "Shaping the kernel"],
  ["core", "Compiling the core"], ["protocols", "Mounting protocols"], ["seal", "Stripping and sealing"],
  ["pack", "Packing the image"], ["sign", "Signing"], ["ready", "Ready"],
];
const ORDER = PHASES.map((p) => p[0]);

let timer = null;

function fresh() {
  return {
    seq: 0, pct: 0, phase: {}, cur: "", dl: null, sources: null, kernel: null, protocols: [],
    cores: [], active: [], log: [], job: null, error: "", resume: null, build: null, test: null, vm: null, step: "",
  };
}

function bytes(n) {
  if (!n && n !== 0) return "";
  if (n > 1e9) return (n / 1e9).toFixed(2) + " GB";
  if (n > 1e6) return (n / 1e6).toFixed(1) + " MB";
  if (n > 1e3) return Math.round(n / 1e3) + " KB";
  return n + " B";
}

function setPhase(st, k, state) {
  if (!ORDER.includes(k)) return;
  st.phase[k] = state;
  if (state === "active") {
    st.cur = k;
    for (const p of ORDER.slice(0, ORDER.indexOf(k))) if (st.phase[p] !== "done" && ["seal", "pack", "sign", "ready"].includes(k)) st.phase[p] = "done";
  }
}

function apply(st, e) {
  const d = e.data || {};
  st.seq = Math.max(st.seq, e.seq);
  switch (e.ev) {
    case "log":
      st.log.push(e.line);
      if (st.log.length > 400) st.log.splice(0, st.log.length - 400);
      break;
    case "job":
      if (d.state === "start") {
        const keep = { log: st.log, sync: st.sync };
        Object.assign(st, fresh(), keep, { seq: st.seq });
        st.job = { kind: d.kind, running: true };
      } else st.job = { kind: d.kind, running: false, failed: d.state === "failed", seconds: d.seconds };
      if (d.error) st.error = d.error;
      break;
    case "resume": st.resume = d; st.pct = d.pct || 0; break;
    case "build": st.build = d; break;
    case "step": st.step = d.label; break;
    case "phase":
      if (d.phase === "sources") setPhase(st, "sources", d.state === "done" ? "done" : "active");
      else if (d.phase === "build" && d.state === "start") setPhase(st, "sources", "done");
      else if (["seal", "pack", "sign"].includes(d.phase)) {
        setPhase(st, d.phase, d.state === "done" ? "done" : "active");
        st.pct = Math.max(st.pct, { seal: 95, pack: 97, sign: 99 }[d.phase]);
      } else if (d.phase === "test" || d.phase === "setup") st.step = d.label;
      break;
    case "sources": st.sources = d; st.pct = Math.max(st.pct, 10 * (d.ready / Math.max(1, d.total))); break;
    case "dl": st.dl = d; break;
    case "pkg":
      if (d.phase) {
        if (st.phase[d.phase] !== "done") setPhase(st, d.phase, "active");
      }
      st.active = d.active || [];
      st.pct = Math.max(st.pct, 10 + 0.85 * (d.pct || 0));
      st.pkgs = { done: d.done, total: d.total, last: `${d.name} ${d.version}: ${d.step}` };
      if (d.protocol && !st.protocols.includes(d.protocol)) st.protocols.push(d.protocol);
      break;
    case "kernel": st.kernel = d; break;
    case "cpu": st.cores = d.cores || []; break;
    case "ready":
      for (const p of ORDER) st.phase[p] = "done";
      st.pct = 100; st.cur = "ready"; st.ready = d;
      break;
    case "error": st.error = d.msg + (d.tail ? "\n" + d.tail.slice(-12).join("\n") : ""); break;
    case "vm": st.vm = d; break;
    case "sync": st.sync = Object.assign(st.sync || {}, d, { at: Date.now() }); break;
    case "phone_report": st.phoneReport = d; break;
    case "test": st.test = d; break;
  }
}

function gauge(st) {
  const p = Math.round(st.pct * 10) / 10;
  return `<div class="pw">
    <div class="pw-head"><span class="pw-label">Power</span><b class="pw-num">${p.toFixed(p < 100 ? 1 : 0)}%</b></div>
    <div class="pw-bar" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${Math.round(p)}"><i style="width:${p}%"></i><span class="pw-glow" style="left:${p}%"></span></div>
    <div class="small muted">${esc(st.step || (st.pkgs ? st.pkgs.last : "") || "")}</div>
  </div>`;
}

function phases(st) {
  return `<ol class="ph">${PHASES.map(([k, n]) => {
    const s = st.phase[k] || "todo";
    return `<li class="ph-${s}${st.cur === k && s === "active" ? " ph-cur" : ""}"><span class="ph-dot"></span>${esc(n)}</li>`;
  }).join("")}</ol>`;
}

function details(st) {
  const parts = [];
  if (st.resume && st.job && st.job.running) parts.push(`<div class="note">Resuming: ${st.resume.done} packages already built, ${Math.round(st.resume.pct)}% power kept.</div>`);
  if (st.dl && st.phase.sources === "active") {
    const pc = st.dl.total ? Math.round((100 * st.dl.done) / st.dl.total) : 0;
    parts.push(`<div class="eg-box"><b>Gathering sources</b> <span class="muted small">${st.sources ? `${st.sources.ready} of ${st.sources.total} ready` : ""}</span>
      <div class="small">${esc(st.dl.file)} · ${bytes(st.dl.done)}${st.dl.total ? " of " + bytes(st.dl.total) : ""}</div><div class="meter"><i style="width:${pc}%"></i></div></div>`);
  }
  if (st.kernel) {
    parts.push(`<div class="eg-box"><b>Shaping the kernel</b> <span class="muted small">${st.kernel.retired} options retired · ${st.kernel.kept} kept</span>
      <div class="chips"><span class="small muted">Retiring:</span> ${st.kernel.retiring.map((x) => `<span class="chip off">${esc(x)}</span>`).join("")}</div>
      <div class="chips"><span class="small muted">Keeping:</span> ${st.kernel.keeping.map((x) => `<span class="chip on">${esc(x)}</span>`).join("")}</div></div>`);
  }
  const PROTOS = ["DHCP and DNS", "HTTPS (lighttpd)", "TLS", "SSH", "HTTP client", "Packet capture", "RSTP", "LLDP", "Connection tracking"];
  if (st.phase.protocols || st.protocols.length) {
    parts.push(`<div class="eg-box"><b>Mounting protocols</b><div class="chips">${PROTOS.map((p) => `<span class="chip ${st.protocols.includes(p) ? "lit" : "dim"}">${esc(p)}</span>`).join("")}</div></div>`);
  }
  if (st.cores.length && st.job && st.job.running) {
    parts.push(`<div class="eg-box"><b>CPU load</b> <span class="muted small">${st.active.length ? "compiling " + esc(st.active.slice(0, 6).join(", ")) + (st.active.length > 6 ? "…" : "") : ""}</span>
      <div class="cores">${st.cores.map((c) => `<i style="height:${Math.max(4, c)}%" title="${c}%"></i>`).join("")}</div></div>`);
  }
  return parts.join("");
}

// Power flowing from the PC to the phone while a build syncs.
function powerLink(st, android) {
  const s = st.sync;
  if (!s) return "";
  const live = Date.now() - s.at < 4000 && s.phase !== "charged" && s.phase !== "failed";
  const pct = s.total ? Math.min(100, Math.round((100 * s.done) / s.total)) : 0;
  const pcLevel = 100 - pct, phoneLevel = s.phase === "charged" ? 100 : pct;
  const title = s.phase === "failed" ? "Transfer stopped" : s.phase === "charged" ? "Charged" : s.phase === "verify" ? "Verifying the seal" : android ? "Receiving power from the PC" : "Sending power to the phone";
  const dev = (name, level, ic) => `<div class="pl-dev"><div class="pl-cell"><i style="height:${level}%"></i></div><span>${ic} ${name}</span></div>`;
  return `<div class="card pl ${live ? "pl-live" : ""} ${s.phase === "charged" ? "pl-done" : ""}">
    <div class="row"><h3 style="margin:0">${esc(title)}</h3><span class="muted small">${s.total ? bytes(s.done) + " of " + bytes(s.total) : ""}</span></div>
    <div class="pl-wire">${dev("PC", android ? 100 : pcLevel, "")}<div class="pl-line">${live ? "<b></b><b></b><b></b>" : ""}</div>${dev("Phone", phoneLevel, "")}</div>
    ${s.error ? `<p class="small" style="color:var(--bad)">${esc(s.error)}</p>` : ""}
    ${s.phase === "charged" ? `<p class="small muted">Signature and every file checked. The phone keeps its previous build if a check ever fails.</p>` : ""}
  </div>`;
}

function testCard(st, report) {
  const t = st.test || (report && (report["tests.windows"] || report["tests.android"] || report["tests.linux"]));
  if (!t) return "";
  const b = t.bench || {};
  const tcp = (b.tcp_ms || []).map((x) => x.toFixed(2)).join(", ");
  const avail = (k) => (b[k] && b[k].MemAvailable_kb ? Math.round(b[k].MemAvailable_kb / 1024) + " MB" : "?");
  return `<div class="card eg-test"><h3>Stage 0 result</h3>
    <table class="kv"><tr><th>Accelerator</th><td>${esc(t.accel || "")}</td></tr>
    <tr><th>Boot to agent ready</th><td>${t.boot_ms} ms</td></tr>
    <tr><th>10-device topology</th><td>${b.topo ? b.topo.ms + " ms" : "?"}</td></tr>
    <tr><th>TCP across 9 hops</th><td>${tcp} ms</td></tr>
    <tr><th>QEMU memory</th><td>${bytes(t.qemu_rss_bytes)}</td></tr>
    <tr><th>Free inside the VM</th><td>${avail("mem_before")} before, ${avail("mem_during")} during the lab</td></tr></table>
    <p class="small muted">Saved in the report file in your FortiTatake folder (ftkos\\report.json). Share it to tune FortiTatake OS on real numbers.</p></div>`;
}

export async function engineView(main) {
  if (timer) clearInterval(timer);
  const st = fresh();
  let status = {}, report = null;
  main.replaceChildren(h(`<div class="wrap eg">
    <h1>FortiTatake OS</h1>
    <p class="muted">Your own lab Linux, compiled from source on this PC and sent to your phone. Every lab device runs on a real network stack inside it.</p>
    <div data-status></div><div data-controls class="row"></div>
    <div class="card eg-main"><div data-gauge></div><div class="eg-cols"><div data-phases></div><div data-details></div></div>
      <div data-error></div>
      <details class="eg-log"><summary>Raw build log</summary><pre data-log></pre></details></div>
    <div data-link></div><div data-test></div><div data-builds></div>
  </div>`));

  async function refreshStatus() {
    try { status = await api("engine/status"); } catch { return; }
    try { report = await api("engine/report"); } catch { report = null; }
    renderStatic();
  }

  // "AMD Ryzen 9 7950X 16-Core Processor" -> "AMD Ryzen 9 7950X"
  const cpuName = (n) => String(n || "").replace(/\(R\)|\(TM\)|CPU|@.*$|\d+-Core Processor|Processor/gi, "").replace(/\s+/g, " ").trim();
  function renderStatic() {
    const b = status.builder;
    const chips = [];
    if (status.can_build) {
      if (!b || !b.wsl) chips.push(`<span class="chip off">WSL not found</span>`);
      else chips.push(`<span class="chip ${b.ready ? "on" : "off"}">Builder: ${esc(b.distro)} ${b.ready ? "ready" : "not set up"}</span><span class="chip on">${esc(cpuName(b.cpu) || "CPU")}${b.ram_bytes ? ` · ${Math.round(b.ram_bytes / 2 ** 30)} GB RAM` : ""}</span>`);
    } else chips.push(`<span class="chip">Builds arrive from your PC by sync</span>`);
    chips.push(`<span class="chip ${status.runner && status.runner.qemu ? "on" : "off"}">Runner ${status.runner && status.runner.qemu ? "installed" : "missing"}</span>`);
    $("[data-status]", main).innerHTML = `<div class="chips">${chips.join("")}</div>`;
    const running = status.job && !status.job.done;
    const ctl = [];
    if (status.can_build) {
      if (!b || !b.ready) ctl.push(`<button class="primary" data-act="setup">Set up the builder</button>`);
      else {
        ctl.push(`<button class="primary" data-act="build" data-arch="x86_64" data-variant="generic">Build for this PC</button>`);
        ctl.push(`<button data-act="build" data-arch="aarch64" data-variant="generic">Build for the phone</button>`);
      }
    }
    if (status.runner && status.runner.build) ctl.push(`<button data-act="test">Run the stage 0 test</button>`);
    if (running) ctl.push(`<button class="danger" data-act="stop">Stop</button>`);
    const c = $("[data-controls]", main);
    c.innerHTML = ctl.join("");
    c.querySelectorAll("button").forEach((x) => { x.disabled = running && x.dataset.act !== "stop"; });
    const builds = status.builds || [];
    $("[data-builds]", main).innerHTML = builds.length ? `<div class="card"><h3>Builds on this device</h3><table class="kv">${builds.map((x) =>
      `<tr><th>${esc(x.arch)} ${esc(x.variant)}</th><td>${bytes(x.bytes)} · kernel ${esc(x.kernel || "")} · ${x.seconds ? Math.round(x.seconds / 60) + " min to build" : ""} · ${esc((x.created || "").slice(0, 16).replace("T", " "))}</td></tr>`).join("")}</table></div>` : "";
    $("[data-test]", main).innerHTML = testCard(st, report);
  }

  function renderLive() {
    $("[data-gauge]", main).innerHTML = gauge(st);
    $("[data-phases]", main).innerHTML = phases(st);
    $("[data-details]", main).innerHTML = details(st);
    $("[data-error]", main).innerHTML = st.error ? `<pre class="eg-err">${esc(st.error)}</pre>` : "";
    $("[data-link]", main).innerHTML = powerLink(st, status.platform === "android");
    const pre = $("[data-log]", main);
    const atEnd = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 20;
    pre.textContent = st.log.slice(-250).join("\n");
    if (atEnd) pre.scrollTop = pre.scrollHeight;
  }

  main.addEventListener("click", async (ev) => {
    const btn = ev.target.closest("button[data-act]");
    if (!btn) return;
    const act = btn.dataset.act;
    const body = act === "build" ? { arch: btn.dataset.arch, variant: btn.dataset.variant } : {};
    try { await api("engine/" + act, { method: "POST", body }); } catch (e) { st.error = e.message; renderLive(); }
    setTimeout(refreshStatus, 300);
  });

  let polling = false, lastStatus = 0;
  async function poll() {
    if (polling || !document.body.contains(main.firstChild)) return;
    polling = true;
    try {
      const r = await api(`engine/events?since=${st.seq}`);
      let jobEnded = false;
      for (const e of r.events || []) { apply(st, e); if (e.ev === "job" && e.data && e.data.state !== "start") jobEnded = true; }
      if ((r.events || []).length) renderLive();
      if (jobEnded || Date.now() - lastStatus > 5000) { lastStatus = Date.now(); await refreshStatus(); }
    } catch { /* engine busy */ }
    polling = false;
  }
  await refreshStatus();
  renderLive();
  await poll();
  timer = setInterval(() => { if (!document.body.contains(main.firstChild)) { clearInterval(timer); timer = null; return; } poll(); }, 700);
}
