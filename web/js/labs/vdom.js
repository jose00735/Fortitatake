// VDOMs for the lab simulator: inter-VDOM links and VDOMs declared in a lab spec.
// The CLI side (config vdom / config global, per-VDOM instances sharing the global tables) lives in fgt.js.
import { Lab } from "./sim.js";
import { Entry } from "./fgt.js";

const baseCommit = Lab.prototype.onCommit;
Lab.prototype.onCommit = function (fg, path, key) {
  baseCommit.call(this, fg, path, key);
  if (path === "system vdom-link" && key) {
    const t = fg.inst("system interface");
    for (const i of [0, 1]) {
      if (t.entries.has(key + i)) continue;
      const e = new Entry(key + i);
      e.attrs.set("vdom", ["root"]);
      e.attrs.set("type", ["vdom-link"]);
      t.entries.set(key + i, e);
    }
  }
};
const baseDelete = Lab.prototype.onDelete;
Lab.prototype.onDelete = function (fg, path, key) {
  baseDelete.call(this, fg, path, key);
  if (path === "system vdom-link" && key) { const t = fg.inst("system interface"); t.entries.delete(key + "0"); t.entries.delete(key + "1"); }
};

// spec: vdoms: { CUST-A: "config firewall policy ..." } → create the VDOMs and load their configuration
Lab.prototype.loadVdoms = function () {
  for (const d of [...this.devices.values()]) {
    const v = d.spec && d.spec.vdoms;
    if (!v || !d.makeVdom || d.parent) continue;
    for (const [name, cli] of Object.entries(v)) {
      const inst = name === "root" ? d : d.vdomInst(name) || d.makeVdom(name);
      if (cli) inst.load(cli);
      inst.history = [];
    }
  }
};
