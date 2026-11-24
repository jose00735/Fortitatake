// FortiSwitch over FortiLink for the lab simulator. Physical cables to a switch are drawn but not used for
// forwarding: the switch turns them into one L2 domain per FortiLink VLAN (from the FortiGate's managed-switch
// port settings), once the switch is authorized. Unauthorized switches pass nothing.
import { Lab } from "./sim.js";
import { FortiGate, Entry, Table } from "./fgt.js";

const MS = "switch-controller managed-switch";

// which FortiGate instance and FortiLink interface a switch's uplink lands on
Lab.prototype.fslUplink = function (sw) {
  const cable = (this.baseSegments || this.segments).find((s) => s.members.some((m) => m.dev === sw.id && m.port === sw.uplink));
  if (!cable) return null;
  const peer = cable.members.find((m) => m.dev !== sw.id && this.dev(m.dev) instanceof FortiGate);
  if (!peer) return null;
  const fgPhys = this.dev(peer.dev);
  for (const inst of fgPhys.allVdoms()) {
    for (const e of inst.entries("system interface")) {
      if ((e.attrs.get("vdom") || ["root"])[0] !== inst.vdomName) continue;
      if (inst.one("system interface", e, "fortilink") !== "enable") continue;
      const members = inst.val("system interface", e, "member");
      if (e.key === peer.port || members.includes(peer.port)) return { fg: inst, fl: e.key, fgPort: peer.port, cable };
    }
  }
  return { fg: null, fl: null, fgPort: peer.port, cable };
};

// make sure the FortiGate lists a switch it can see on FortiLink (as FortiOS does on discovery)
Lab.prototype.fslDiscover = function (sw, up) {
  if (!up || !up.fg) return null;
  const t = up.fg.inst(MS);
  let e = t.entries.get(sw.serial);
  if (!e) {
    e = new Entry(sw.serial);
    e.attrs.set("fsw-wan1-peer", [up.fl]);
    e.attrs.set("fsw-wan1-admin", ["discovered"]);
    t.entries.set(sw.serial, e);
  }
  if (!e.children.get("ports")) {
    const pt = new Table();
    for (const p of sw.ports) pt.entries.set(p, new Entry(p));
    e.children.set("ports", pt);
  }
  return e;
};

Lab.prototype.fslState = function (sw) {
  const up = this.fslUplink(sw);
  if (!up || !up.fg) return { state: "no FortiLink", up };
  const e = this.fslDiscover(sw, up);
  const admin = up.fg.one(MS, e, "fsw-wan1-admin") || "discovered";
  return { state: admin === "enable" ? "Authorized/Up" : admin === "disable" ? "Disabled" : "Discovered", up, e, authorized: admin === "enable" };
};

Lab.prototype.switchSegments = function () {
  const out = [];
  for (const sw of this.devices.values()) {
    if (sw.kind !== "fortiswitch") continue;
    const st = this.fslState(sw);
    if (!st.authorized) continue;
    const { fg, fl } = st.up;
    // FortiLink VLAN interfaces → vlan id
    const vlans = new Map([[fl, 0]]);
    for (const e of fg.entries("system interface")) if (fg.one("system interface", e, "type") === "vlan" && fg.one("system interface", e, "interface") === fl) vlans.set(e.key, Number(fg.one("system interface", e, "vlanid") || 0));
    const dom = new Map();
    for (const [name, vid] of vlans) dom.set(name, { id: `fsw:${sw.id}:${name}`, l2: true, label: "", members: [{ dev: fg.physId, port: fl, vlan: vid }] });
    const ports = st.e.children.get("ports");
    for (const p of sw.ports) {
      const pe = ports && ports.entries.get(p);
      const v = (a) => pe ? fg.val(MS, pe, a, ["ports"]) : [];
      if ((v("status")[0] || "up") === "down") continue;
      const native = v("vlan")[0] || fl;
      const cable = (this.baseSegments || this.segments).find((s) => s.members.some((m) => m.dev === sw.id && m.port === p));
      if (!cable) continue;
      for (const m of cable.members) {
        if (m.dev === sw.id) continue;
        const d = dom.get(native);
        if (d) d.members.push({ dev: m.dev, port: m.port, vlan: 0 });
      }
    }
    out.push(...dom.values());
  }
  return out;
};

Lab.prototype.switchConsole = function (sw, line) {
  const t = line.trim().toLowerCase();
  if (!t) return "";
  const st = this.fslState(sw);
  if (t === "get system status") return `Version: ${sw.model} ${sw.version},build0915,260212 (GA)\nSerial-Number: ${sw.serial}\nHostname: ${sw.id}\nSystem time: Tue Nov 24 10:41:07 2026\nFortiLink: ${st.state}${st.up && st.up.fg ? ` (managed by ${st.up.fg.hostname()} on ${st.up.fl})` : ""}`;
  if (t.startsWith("diagnose switch mac-address list") || t.startsWith("show switch interface") || t.startsWith("get switch interface")) {
    const seg = this.segments.filter((s) => s.l2 && s.id.startsWith(`fsw:${sw.id}:`));
    const rows = sw.ports.map((p) => {
      const pe = st.e && st.e.children.get("ports") && st.e.children.get("ports").entries.get(p);
      const vlan = pe && st.up.fg ? st.up.fg.val(MS, pe, "vlan", ["ports"])[0] || st.up.fl : "-";
      const status = pe && st.up.fg ? st.up.fg.val(MS, pe, "status", ["ports"])[0] || "up" : "up";
      const cable = (this.baseSegments || this.segments).find((s) => s.members.some((m) => m.dev === sw.id && m.port === p));
      const peer = cable ? cable.members.filter((m) => m.dev !== sw.id).map((m) => m.dev).join(",") : "";
      return `${p.padEnd(10)}${status.padEnd(8)}${String(vlan).padEnd(18)}${peer}`;
    });
    return [`Port      Status  Native VLAN       Connected to`, ...rows, ``, `FortiLink: ${st.state}`].join("\n");
  }
  if (t === "help" || t === "?") return "This switch is managed over FortiLink: configure it from the FortiGate (config switch-controller managed-switch).\nRead-only commands here: get system status, show switch interface";
  return `This switch is managed by the FortiGate over FortiLink: configure it there. Try: get system status, show switch interface`;
};

// FortiGate side: execute switch-controller get-conn-status
Lab.prototype.switchDiag = function (fg, words, head) {
  const w = words.join(" ");
  if (head === "execute" && /^switch-controller get-conn-status/.test(w)) {
    const rows = [];
    for (const sw of this.devices.values()) {
      if (sw.kind !== "fortiswitch") continue;
      const st = this.fslState(sw);
      if (!st.up || st.up.fg !== fg) continue;
      rows.push(`${sw.serial.padEnd(20)}${(sw.version + " (" + sw.model.replace("FortiSwitch-", "") + ")").padEnd(26)}${st.state.padEnd(16)}-     ${("169.254.1." + (2 + rows.length)).padEnd(16)}Tue Nov 24 09:58:12 2026  ${(st.e && fg.one(MS, st.e, "description")) || sw.id}`);
    }
    return [`Managed-devices in current vdom ${fg.vdomName}:`, ``, `STACK-NAME: FortiSwitch-Stack-${[...fg.allVdoms ? [fg] : []].length ? "fortilink" : ""}`, `SWITCH-ID           VERSION                   STATUS          FLAG  ADDRESS         JOIN-TIME                 NAME`, ...rows, ``, `Flags: C=config sync, U=upgrading, S=staged, D=delayed reboot pending, E=config sync error`].join("\n");
  }
  return null;
};
