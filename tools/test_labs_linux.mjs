// Run labs on the real Linux network stack: the agent runs on this machine (as root, in network
// namespaces), each part's solution is applied, and every probe check goes through the kernel.
// Reports checks that fail for real and every place the simulator and the kernel disagree.
// Usage: sudo node tools/test_labs_linux.mjs [--tier 1] [labId...]   (needs ip, nft, ping)
import fs from "fs";
import path from "path";
import { spawn, execFileSync } from "child_process";
import { fileURLToPath } from "url";
import { LabRun } from "../web/js/labs/runtime.js";
import { RealNet, runChecksReal, unsupported } from "../web/js/labs/real.js";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const schemas = Object.fromEntries(["fortios", "fortianalyzer", "fortimanager"].map((p) => [p, JSON.parse(fs.readFileSync(path.join(root, `web/schema/${p}-8.0.2.json`)))]));
const { labs } = JSON.parse(fs.readFileSync(path.join(root, "web/content/labs.json")));
const args = process.argv.slice(2);
const tierAt = args.indexOf("--tier");
const maxTier = tierAt >= 0 ? Number(args.splice(tierAt, 2)[1]) : 1;
const only = args;

// --vm <kernel> <rootfs.erofs>: boot FortiTatake OS in QEMU (the real thing); otherwise run the agent here.
const vmAt = args.indexOf("--vm");
const vm = vmAt >= 0 ? args.splice(vmAt, 3).slice(1) : null;
let agent, io;
if (vm) {
  const port = 20000 + Math.floor(Math.random() * 20000);
  const kvm = fs.existsSync("/dev/kvm");
  agent = spawn("qemu-system-x86_64", ["-machine", "q35", "-nodefaults", "-nographic", "-no-reboot", "-m", "256", "-smp", "2",
    "-kernel", vm[0], "-append", "console=ttyS0 root=/dev/vda ro rootfstype=erofs panic=-1 quiet",
    "-drive", `if=none,id=root,format=raw,readonly=on,file=${vm[1]}`, "-device", "virtio-blk-pci,drive=root",
    "-device", "virtio-serial-pci", "-chardev", `socket,id=agent,host=127.0.0.1,port=${port},server=on,wait=off`,
    "-device", "virtconsole,chardev=agent", "-device", "virtio-rng-pci", "-serial", "file:/tmp/ftk-vm-console.log",
    "-accel", kvm ? "kvm" : "tcg"], { stdio: "ignore" });
  const net = await import("net");
  for (let i = 0; i < 100 && !io; i++) {
    await new Promise((r) => setTimeout(r, 200));
    io = await new Promise((res) => { const s = net.connect(port, "127.0.0.1", () => res(s)); s.on("error", () => res(null)); });
  }
  if (!io) { console.log("could not reach the VM's agent"); process.exit(2); }
  io = { stdin: io, stdout: io };
} else {
  const bin = path.join((await import("os")).tmpdir(), "ftk-agent-host");
  execFileSync("go", ["build", "-o", bin, "."], { cwd: path.join(root, "ftkos/agent"), stdio: "inherit" });
  agent = spawn(bin, ["--stdio"], { stdio: ["pipe", "pipe", "inherit"], env: { ...process.env, FTK_NO_DUMMY: fs.existsSync("/sys/module/dummy") ? "" : "1" } });
  io = agent;
}
const wait = new Map();
let buf = "", seq = 0;
io.stdout.on("data", (d) => {
  buf += d;
  let i;
  while ((i = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, i); buf = buf.slice(i + 1);
    let m; try { m = JSON.parse(line); } catch { continue; }
    const w = wait.get(m.id);
    if (w) { wait.delete(m.id); m.ok ? w.res(m) : w.rej(new Error(m.err)); }
  }
});
const call = (req, ms = 10000) => new Promise((res, rej) => {
  const id = ++seq;
  wait.set(id, { res, rej });
  io.stdin.write(JSON.stringify({ ...req, id }) + "\n");
  setTimeout(() => { if (wait.has(id)) { wait.delete(id); rej(new Error(`agent timeout on ${req.op}`)); } }, ms);
});

let bad = 0, disagreements = 0, checked = 0;
if (vm) for (let i = 0; i < 60; i++) { if (await call({ op: "hello" }, 2000).then(() => true, () => false)) break; }
const console_warn = console.warn;
for (const def of labs) {
  if (only.length ? !only.includes(def.id) : (def.tier ?? 9) > maxTier) continue;
  console.warn = () => {};
  const run = new LabRun(def, schemas);
  console.warn = console_warn;
  const why = unsupported(run.lab);
  if (why.length) { console.log(`- ${def.id}: stays on the simulator (${why.join(", ")})`); continue; }
  const real = new RealNet(call);
  let ok = true;
  for (let i = 0; i < def.parts.length; i++) {
    const p = def.parts[i];
    run.goto(i);
    for (const c of p.checks) if (c.answer) run.answers[c.id] = c.answer.sample || String([].concat(c.answer.accept)[0]).replace(/^~/, "").split("|")[0].replace(/\.\?|\.\*|\.\+/g, "").replace(/[\\^$()]/g, "");
    const before = await runChecksReal(run.lab, p.checks, run.answers, real);
    for (const r of before) if (r.disagree) { disagreements++; console.log(`  ≠ ${def.id}/${p.id} before: ${r.text}\n      kernel: ${r.detail}\n      sim:    ${r.simDetail}`); }
    run.applySolution(p);
    let after;
    try { after = await runChecksReal(run.lab, p.checks, run.answers, real); }
    catch (e) { ok = false; console.log(`✗ ${def.id}/${p.id}: engine error ${e.message}`); break; }
    for (const r of after) {
      if (r.engine === "linux") checked++;
      if (r.disagree) { disagreements++; console.log(`  ≠ ${def.id}/${p.id} after: ${r.text}\n      kernel: ${r.detail}\n      sim:    ${r.simDetail}`); }
      if (r.engineError) console.log(`  ! ${def.id}/${p.id}: ${r.text}: ${r.engineError}`);
    }
    const failed = after.filter((r) => !r.pass);
    if (failed.length) { ok = false; console.log(`✗ ${def.id}/${p.id}: ${failed.length} failing on the real network\n  ${failed.map((f) => `${f.text} -> ${f.detail}`).join("\n  ")}`); }
  }
  if (process.env.FTK_DUMP) fs.writeFileSync(`/tmp/ftk-${def.id}.json`, JSON.stringify(real.c, null, 1));
  console.log(`${ok ? "✓" : "✗"} ${def.id} (apply ${real.applyMs} ms)`);
  if (!ok) bad++;
}
await call({ op: "topo.clear" }).catch(() => {});
agent.kill();
console.log(`\n${checked} probe checks on the kernel, ${disagreements} simulator disagreement(s), ${bad} lab(s) failing`);
process.exit(bad ? 1 : 0);
