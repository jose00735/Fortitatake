// Verify every lab: the start state must fail at least one check of each part,
// and the reference solution must pass every check. Usage: node tools/test_labs.mjs [labId...]
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { LabRun } from "../web/js/labs/runtime.js";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const schemas = Object.fromEntries(["fortios", "fortianalyzer", "fortimanager"].map((p) => [p, JSON.parse(fs.readFileSync(path.join(root, `web/schema/${p}-8.0.2.json`)))]));
const { labs } = JSON.parse(fs.readFileSync(path.join(root, "web/content/labs.json")));
const only = process.argv.slice(2);
let bad = 0;
const origWarn = console.warn;
for (const def of labs) {
  if (only.length && !only.includes(def.id)) continue;
  const warnings = [];
  console.warn = (...a) => warnings.push(a.join(" "));
  const run = new LabRun(def, schemas);
  console.warn = origWarn;
  if (warnings.length) { bad++; console.log(`✗ ${def.id}: start config errors\n  ${warnings.join("\n  ")}`); continue; }
  let ok = true;
  def.parts.forEach((p, i) => {
    run.goto(i);
    // answers: fill with the first accepted value for the solution run
    const before = run.check();
    if (!p.allow_pre_pass && before.every((r) => r.pass)) { ok = false; console.log(`✗ ${def.id}/${p.id}: passes before any work`); }
    for (const c of p.checks) if (c.answer) run.answers[c.id] = c.answer.sample || String([].concat(c.answer.accept)[0]).replace(/^~/, "").split("|")[0].replace(/\.\?|\.\*|\.\+/g, "").replace(/[\\^$()]/g, "");
    const logLen = run.log.length;
    run.applySolution(p);
    const errs = [];
    for (const d of run.lab.devices.values()) if (d.history) for (const h of d.history.slice(-200)) if (h.out && /Command fail|parse error/.test(h.out) && !(p.expect_fail || []).includes(h.line) && run.log.slice(logLen).some((x) => x.line === h.line)) errs.push(`${d.id}: ${h.line} -> ${h.out.split("\n").pop()}`);
    const after = run.check();
    const failed = after.filter((r) => !r.pass);
    if (failed.length || errs.length) {
      ok = false;
      console.log(`✗ ${def.id}/${p.id}: solution leaves ${failed.length} failing\n  ${failed.map((f) => `${f.id}: ${f.text} -> ${f.detail}`).join("\n  ")}${errs.length ? "\n  CLI errors:\n  " + [...new Set(errs)].join("\n  ") : ""}`);
    }
  });
  if (ok) console.log(`✓ ${def.id} (${def.parts.length} part${def.parts.length > 1 ? "s" : ""}, ${def.parts.reduce((a, p) => a + p.checks.length, 0)} checks)`);
  else bad++;
}
console.log(bad ? `\n${bad} lab(s) failed` : "\nall labs pass");
process.exit(bad ? 1 : 0);
