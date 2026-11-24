// Authentication for the lab simulator: LDAP and RADIUS servers on lab hosts, local users, user groups,
// firewall (captive portal) authentication, FSSO through a collector agent, and the diagnose commands.
//
// A directory server is a lab host with a `directory:` spec:
//   directory:
//     domain: andes.local
//     base: DC=andes,DC=local
//     ldap: { ports: [389, 636], bind: { dn: "CN=svc-fortigate,OU=Service,DC=andes,DC=local", pass: "..." }, require_tls: false, anonymous: false }
//     radius: { secret: "...", clients: [10.20.10.1], groups: true, allow: [VPN-Users] }
//     fsso: { port: 8000, password: "...", groups: [Finance, Staff], logons: [{ user: jperez, ip: 10.20.10.50 }] }
//     users: [{ sam: jperez, cn: Juan Perez, ou: "OU=Staff,DC=andes,DC=local", pass: "...", groups: [Finance], disabled: false }]
import { Lab } from "./sim.js";
import { FortiGate } from "./fgt.js";
import { ipToInt, intToIp } from "./net.js";

const lc = (x) => String(x || "").toLowerCase();

Lab.prototype.directoryAt = function (ip) {
  for (const d of this.devices.values()) if (d.spec && d.spec.directory && d.ip && d.ip() === ip) return d;
  return null;
};
function dirOf(h) {
  const d = h.spec.directory;
  if (!d._norm) {
    const base = d.base || d.domain.split(".").map((x) => "DC=" + x).join(",");
    d._norm = {
      base, domain: d.domain,
      groupDn: (g) => `CN=${g},${d.groups_ou || "OU=Groups," + base}`,
      users: (d.users || []).map((u) => ({ ...u, dn: `CN=${u.cn || u.sam},${u.ou || "CN=Users," + base}`, upn: `${u.sam}@${d.domain}`, groups: u.groups || [] })),
    };
  }
  return d._norm;
}
function attrOf(u, cnid) {
  const a = lc(cnid);
  if (a === "samaccountname" || a === "uid") return u.sam;
  if (a === "userprincipalname") return u.upn;
  if (a === "cn") return u.cn || u.sam;
  return null;
}

// Can the FortiGate open proto/port to this server? Uses the simulator (routes, tunnels, source-ip).
Lab.prototype.reachServer = function (fg, server, proto, port, sourceIp) {
  let dst = ipToInt(server || "");
  if (dst === null && server) dst = this.names.get(lc(server)) ?? null;
  if (dst === null) return { ok: false, why: server ? `can't resolve ${server}` : "no server address" };
  const src = sourceIp && sourceIp !== "0.0.0.0" ? ipToInt(sourceIp) : undefined;
  this.quiet = (this.quiet || 0) + 1;
  let p;
  try { p = this.probe(fg.id, { dst, proto, dport: port, src }); } finally { this.quiet--; }
  const h = this.directoryAt(dst);
  return { ok: !!p.ok, why: p.ok ? "" : (p.drop ? p.drop.reason : "no answer"), host: h, src: p.seenSrc !== undefined ? p.seenSrc : p.req && p.req.src };
};

// ---------- LDAP ----------
Lab.prototype.ldapAuth = function (fg, name, user, pass, trace) {
  const e = fg.entry("user ldap", name);
  if (!e) return { ok: false, err: `no LDAP server named ${name}` };
  const one = (a) => fg.one("user ldap", e, a);
  const server = one("server"), secure = one("secure") || "disable";
  const port = e.attrs.has("port") ? Number(one("port")) : secure === "ldaps" ? 636 : 389;
  const t = (x) => trace && trace.push(x);
  t(`[1909] fnbamd_ldap_init-search filter is: ${one("cnid") || "cn"}=${user}`);
  const r = this.reachServer(fg, server, 6, port, one("source-ip"));
  if (!r.ok || !r.host || !r.host.spec.directory.ldap) {
    t(`[1103] fnbamd_ldap_result-Result for ldap svr ${server} is ERROR: can't contact LDAP server`);
    return { ok: false, err: `can't contact LDAP server ${server}:${port}${r.why ? ` (${r.why})` : ""}`, code: "unreach" };
  }
  const L = r.host.spec.directory.ldap, D = dirOf(r.host);
  if (!(L.ports || [389, 636]).includes(port)) return { ok: false, err: `${server} refused port ${port}`, code: "unreach" };
  if (port === 636 && secure !== "ldaps") return { ok: false, err: `port 636 speaks LDAPS, but secure is ${secure}: the TLS handshake never starts`, code: "tls" };
  if (L.require_tls && secure === "disable") { t(`[1103] fnbamd_ldap_result-Result for ldap svr ${server} is ERROR: Strong(er) authentication required`); return { ok: false, err: "the domain controller requires a signed or encrypted LDAP session (Strong(er) authentication required); set secure starttls or ldaps", code: "tls" }; }
  if (secure !== "disable" && one("server-identity-check") !== "disable" && L.cert_name && lc(L.cert_name) !== lc(server)) return { ok: false, err: `the server certificate is issued to ${L.cert_name}, not ${server} (server-identity-check)`, code: "tls" };
  const type = one("type") || "simple";
  if (type === "regular") {
    const b = L.bind || {};
    if (lc(one("username")) !== lc(b.dn) || (e.attrs.get("password") || [""])[0] !== b.pass) { t(`[1103] fnbamd_ldap_result-Result for ldap svr ${server} is ERROR: Invalid credentials (49)`); return { ok: false, err: "the service account bind failed: invalid credentials (49)", code: "bind" }; }
  } else if (type === "anonymous" && !L.anonymous) return { ok: false, err: "the directory doesn't allow anonymous searches (operations error)", code: "bind" };
  const cnid = one("cnid") || "cn", dn = lc(one("dn"));
  if (!dn) return { ok: false, err: "no distinguished name (dn) to search under", code: "nouser" };
  const found = D.users.filter((u) => lc(attrOf(u, cnid)) === lc(user) && lc(u.dn).endsWith(dn) && (type !== "simple" || lc(u.dn) === lc(`${cnid}=${user},${one("dn")}`)));
  if (!found.length) { t(`[1103] fnbamd_ldap_result-Result for ldap svr ${server} is ERROR: user not found`); return { ok: false, err: `no entry with ${cnid}=${user} under ${one("dn")}${type === "simple" ? " (simple bind needs the exact user DN: cnid=user,dn)" : ""}`, code: "nouser" }; }
  const u = found[0];
  if (u.disabled) return { ok: false, err: "the account is disabled in the directory", code: "disabled" };
  if (u.pass !== pass) { t(`[1103] fnbamd_ldap_result-Result for ldap svr ${server} is DENY`); return { ok: false, err: "wrong password for the user", code: "badpass" }; }
  t(`[1103] fnbamd_ldap_result-Result for ldap svr ${server} is SUCCESS`);
  const groups = u.groups.map(D.groupDn);
  t(`[1225] fnbamd_ldap_get_result-Going to SEARCH state`, ...groups.map((g) => `[1230] __get_member_of_groups-Get the memberOf groups: ${g}`));
  return { ok: true, user: u, groups, server: name };
};

// ---------- RADIUS ----------
Lab.prototype.radiusAuth = function (fg, name, user, pass, trace) {
  const e = fg.entry("user radius", name);
  if (!e) return { ok: false, err: `no RADIUS server named ${name}` };
  const one = (a) => fg.one("user radius", e, a);
  const server = one("server"), port = Number(one("radius-port")) || 1812;
  const t = (x) => trace && trace.push(x);
  const r = this.reachServer(fg, server, 17, port, one("source-ip"));
  if (!r.ok || !r.host || !r.host.spec.directory.radius) { t(`[491] fnbamd_rad_dns_cb-${server}->${server}`, `[300] fnbamd_rad_send-Sent radius req to server '${name}': fd=0, IP=${server}(${server}:${port})`, `[1103] fnbamd_rad_result-Timeout`); return { ok: false, err: `no answer from ${server}:${port}${r.why ? ` (${r.why})` : ""}`, code: "timeout" }; }
  const R = r.host.spec.directory.radius, D = dirOf(r.host);
  const nas = one("nas-ip") && one("nas-ip") !== "0.0.0.0" ? ipToInt(one("nas-ip")) : r.src;
  t(`[300] fnbamd_rad_send-Sent radius req to server '${name}': fd=0, IP=${server}(${server}:${port}) code=1 id=7 len=${80 + user.length}`);
  if (!(R.clients || []).map(ipToInt).includes(r.src)) { t(`[1103] fnbamd_rad_result-Timeout`); return { ok: false, err: `the RADIUS server has no client entry for ${intToIp(r.src)}, so it silently drops the request (timeout)`, code: "client" }; }
  const secret = (e.attrs.get("secret") || [""])[0];
  if (secret !== R.secret) { t(`[1103] fnbamd_rad_result-Result for radius svr '${name}' ${server}(1) is 3`); return { ok: false, err: "Access-Reject: the shared secret is wrong, so the server decrypts a garbage password", code: "secret" }; }
  const u = D.users.find((x) => lc(x.sam) === lc(user) || lc(x.upn) === lc(user));
  if (!u || u.pass !== pass || u.disabled) { t(`[1103] fnbamd_rad_result-Result for radius svr '${name}' ${server}(1) is 3`); return { ok: false, err: u ? "Access-Reject: wrong password" : "Access-Reject: unknown user", code: "badpass" }; }
  if (R.allow && R.allow.length && !u.groups.some((g) => R.allow.includes(g))) { t(`[1103] fnbamd_rad_result-Result for radius svr '${name}' ${server}(1) is 3`); return { ok: false, err: `Access-Reject: the network policy only allows ${R.allow.join(", ")}`, code: "policy" }; }
  t(`[1103] fnbamd_rad_result-Result for radius svr '${name}' ${server}(1) is 0`);
  return { ok: true, user: u, groups: R.groups ? u.groups : [], server: name };
};

// ---------- FSSO (collector agent) ----------
Lab.prototype.fssoAgents = function (fg) {
  if (!this._fsso || this._fssoVer !== this.ver) { this._fsso = new Map(); this._fssoVer = this.ver; }
  if (this._fsso.has(fg.id)) return this._fsso.get(fg.id);
  const out = [];
  for (const e of fg.entries("user fsso")) {
    const one = (a) => fg.one("user fsso", e, a);
    if ((one("type") || "default") !== "default") continue;
    const server = one("server"), port = Number(one("port") || 8000);
    const r = this.reachServer(fg, server, 6, port, one("source-ip"));
    const F = r.host && r.host.spec.directory.fsso;
    let status = "connected", why = "";
    if (!r.ok || !F) { status = "disconnected"; why = r.why || "no collector agent listening"; }
    else if ((F.port || 8000) !== port) { status = "disconnected"; why = `the collector agent listens on ${F.port || 8000}`; }
    else if ((e.attrs.get("password") || [""])[0] !== F.password) { status = "disconnected"; why = "wrong collector agent password (authentication failed)"; }
    const D = r.host ? dirOf(r.host) : null;
    const groups = status === "connected" ? (F.groups || []).map((g) => D.groupDn(g).toUpperCase()) : [];
    const logons = status === "connected" ? (F.logons || []).map((l) => { const u = D.users.find((x) => lc(x.sam) === lc(l.user)); return { ip: ipToInt(l.ip), user: String(l.user).toUpperCase(), groups: (u ? u.groups : []).map((g) => D.groupDn(g).toUpperCase()).filter((g) => groups.includes(g)), ws: l.ws || "" }; }) : [];
    out.push({ name: e.key, server, port, status, why, groups, logons, domain: D ? D.domain.toUpperCase() : "" });
  }
  this._fsso.set(fg.id, out);
  return out;
};
// adgrp names the collector agent pushes are valid user group members
Lab.prototype.extraRefs = function (fg, kind) {
  if (kind !== "adgrp" || !(fg instanceof FortiGate) || fg.product !== "fortios" || !this.ready) return [];
  return this.fssoAgents(fg).flatMap((a) => a.groups);
};

// ---------- who is behind an IP, and does the policy accept them ----------
Lab.prototype.authUser = function (fg, ip) {
  const a = (fg.authList || []).find((x) => x.ip === ip);
  if (a) return a;
  for (const ag of this.fssoAgents(fg)) {
    const l = ag.logons.find((x) => x.ip === ip);
    if (l) return { ip, user: l.user, method: "fsso", server: ag.name, adgroups: l.groups, fgGroups: this.fssoGroupsFor(fg, l.groups) };
  }
  return null;
};
Lab.prototype.fssoGroupsFor = function (fg, adgroups) {
  return fg.entries("user group").filter((g) => fg.one("user group", g, "group-type") === "fsso-service" && fg.val("user group", g, "member").some((m) => adgroups.includes(String(m).toUpperCase()))).map((g) => g.key);
};
Lab.prototype.identityOk = function (fg, who, groups, users) {
  if (users.length && who.method !== "fsso" && users.includes(who.localUser || who.user)) return true;
  return groups.some((g) => (who.fgGroups || []).includes(g));
};

// Check one user against every firewall user group; returns the groups they qualify for.
Lab.prototype.groupsForLogin = function (fg, user, pass, trace) {
  const okGroups = [];
  let first = null, lastErr = null;
  for (const g of fg.entries("user group")) {
    if ((fg.one("user group", g, "group-type") || "firewall") !== "firewall") continue;
    const match = g.children.get("match");
    const rules = match ? match.list().map((m) => ({ server: (m.attrs.get("server-name") || [""])[0], group: (m.attrs.get("group-name") || [""])[0] })) : [];
    for (const m of fg.val("user group", g, "member")) {
      let r = null;
      const lu = fg.entry("user local", m);
      if (lu) {
        if (lc(m) !== lc(user) || fg.one("user local", lu, "status") === "disable") continue;
        const type = fg.one("user local", lu, "type") || "password";
        if (type === "password") r = (lu.attrs.get("passwd") || [""])[0] === pass ? { ok: true, server: "local" } : { ok: false, err: "wrong password for the local user" };
        else if (type === "ldap") r = this.ldapAuth(fg, fg.one("user local", lu, "ldap-server"), user, pass, trace);
        else if (type === "radius") r = this.radiusAuth(fg, fg.one("user local", lu, "radius-server"), user, pass, trace);
        if (r && r.ok) r.localUser = m;
      } else if (fg.entry("user ldap", m)) r = this.ldapAuth(fg, m, user, pass, trace);
      else if (fg.entry("user radius", m)) r = this.radiusAuth(fg, m, user, pass, trace);
      if (!r) continue;
      if (!r.ok) { lastErr = r; continue; }
      const mine = rules.filter((x) => x.server === m);
      // LDAP groups match on the full DN; RADIUS returns plain group names (Fortinet-Group-Name)
      if (mine.length && !mine.some((x) => (r.groups || []).some((ug) => lc(ug) === lc(x.group)))) { trace && trace.push(`[1213] fnbamd_ldap_result-Failed group matching for ${g.key}`); lastErr = { ok: false, err: `${user} authenticated, but isn't in the group ${g.key} matches on ${m} (${mine.map((x) => x.group).join(", ")})`, code: "group" }; continue; }
      trace && trace.push(`[1210] fnbamd_ldap_result-Passed group matching for ${g.key}`);
      okGroups.push(g.key);
      if (!first) first = r;
      break;
    }
  }
  return okGroups.length ? { ok: true, groups: okGroups, method: first.server === "local" ? "local" : "remote", server: first.server, localUser: first.localUser } : { ok: false, err: lastErr ? lastErr.err : `${user} is not a member of any firewall user group`, code: lastErr && lastErr.code };
};

// Captive-portal login from a host (what typing the credentials into the FortiGate's auth page does).
Lab.prototype.portalLogin = function (h, user, pass) {
  const ip = h.ip && h.ip();
  if (!ip) return { ok: false, err: "this PC has no IP address" };
  let target = h.authPending ? this.dev(h.authPending.fg) : null;
  if (!target) {
    this.quiet = (this.quiet || 0) + 1;
    let p;
    try { p = this.probe(h.id, { dst: ipToInt("142.250.78.4"), proto: 6, dport: 80 }); } finally { this.quiet--; }
    target = p.drop && p.drop.auth ? this.dev(p.drop.auth.fg) : null;
    if (!target) { const ev = (p.fwd && p.fwd.fgt || []).find((e) => !e.reply); target = ev ? this.dev(ev.dev) : null; }
  }
  if (!target) return { ok: false, err: "no FortiGate asked this PC to authenticate" };
  const trace = [];
  const r = this.groupsForLogin(target, user, pass, trace);
  if (target.dbg && target.dbg.fnbamd) for (const l of trace) target.async.push(l);
  if (!r.ok) return { ok: false, err: r.err, fg: target };
  target.authList = (target.authList || []).filter((x) => x.ip !== ip);
  target.authList.push({ ip, user, method: r.method, server: r.server, fgGroups: r.groups, localUser: r.localUser, since: this.clock });
  this.ver++;
  h.authPending = null;
  return { ok: true, fg: target, groups: r.groups };
};

// ---------- consoles ----------
Lab.prototype.authDiag = function (fg, words, raw, head) {
  const w = words.join(" ");
  if (head === "diagnose" && /^test authserver ldap /.test(w)) {
    const [, , , server, user, pass] = raw;
    if (!user || pass === undefined) return "Usage: diagnose test authserver ldap <server> <user> <password>";
    const tr = [];
    const r = this.ldapAuth(fg, server, user, pass, tr);
    if (fg.dbg.fnbamd) fg.async.push(...tr);
    if (!r.ok && /no LDAP server named/.test(r.err)) return `Can't find the LDAP server '${server}'.`;
    return r.ok ? `authenticate '${user}' against '${server}' succeeded!\nGroup membership(s) - ${r.groups.join("\n                     ")}` : r.code === "unreach" || r.code === "tls" ? `Can't contact LDAP server!` : `authenticate '${user}' against '${server}' failed!`;
  }
  if (head === "diagnose" && /^test authserver radius /.test(w)) {
    const [server, method, user, pass] = raw.slice(3);
    if (!pass) return "Usage: diagnose test authserver radius <server> <chap | pap | mschap | mschap2> <user> <password>";
    const tr = [];
    const r = this.radiusAuth(fg, server, user, pass, tr);
    if (fg.dbg.fnbamd) fg.async.push(...tr);
    if (!r.ok && /no RADIUS server named/.test(r.err)) return `Can't find the RADIUS server '${server}'.`;
    if (r.ok) return `authenticate '${user}' against '${method}' succeeded, server=primary assigned_rad_session_id=${(this.rand() * 1e9) | 0} session_timeout=0 secs idle_timeout=0 secs!${r.groups.length ? `\nGroup membership(s) - ${r.groups.join("\n                     ")}` : ""}`;
    return r.code === "timeout" || r.code === "client" ? `authenticate '${user}' against '${method}' failed(no response), assigned_rad_session_id=${(this.rand() * 1e9) | 0} session_timeout=0 secs idle_timeout=0 secs!` : `authenticate '${user}' against '${method}' failed, assigned_rad_session_id=${(this.rand() * 1e9) | 0} session_timeout=0 secs idle_timeout=0 secs!`;
  }
  if (head === "diagnose" && /^debug application fnbamd/.test(w)) { fg.dbg.fnbamd = !/ 0$/.test(w); return ""; }
  if (head === "diagnose" && /^firewall auth (list|l)/.test(w)) {
    const list = fg.authList || [];
    if (!list.length) return "----- 0 listed, 0 filtered ------";
    return list.map((a) => `${intToIp(a.ip)}, ${a.user}\n\tsrc_mac: ${"00:0c:29:" + ((a.ip >>> 0) & 255).toString(16).padStart(2, "0") + ":4e:1a"}\n\ttype: fw, id: 0, duration: ${Math.round((this.clock - a.since) / 1000)}, idled: 0\n\texpire: ${Number(fg.one("user setting", fg.obj("user setting"), "auth-timeout") || 5) * 60}, allow-idle: ${Number(fg.one("user setting", fg.obj("user setting"), "auth-timeout") || 5) * 60}\n\tserver: ${a.server}\n\tpackets: in 0 out 0, bytes: in 0 out 0\n\tgroup_id: ${fg.entries("user group").findIndex((g) => g.key === a.fgGroups[0]) + 2}\n\tgroup_name: ${a.fgGroups.join(" ")}`).join("\n\n") + `\n\n----- ${list.length} listed, 0 filtered ------`;
  }
  if (head === "diagnose" && /^firewall auth clear/.test(w)) { fg.authList = []; this.ver++; return ""; }
  if (head === "diagnose" && /^debug authd fsso server-status/.test(w)) {
    const ag = this.fssoAgents(fg);
    if (!ag.length) return "No FSSO collector agent configured.";
    return ["Server Name                Connection Status      Version                     Address", "-----------                -----------------      -------                     -------",
      ...ag.map((a) => `${a.name.padEnd(27)}${a.status.padEnd(23)}${(a.status === "connected" ? "FSSO 5.0.0327" : "").padEnd(28)}${a.server}`)].join("\n");
  }
  if (head === "diagnose" && /^debug authd fsso list/.test(w)) {
    const ls = this.fssoAgents(fg).flatMap((a) => a.logons.map((l) => ({ ...l, domain: a.domain })));
    return ["----FSSO logons----", ...ls.map((l) => `IP: ${intToIp(l.ip)}  User: ${l.user}  Groups: ${l.groups.join("+") || "(none monitored)"}  Workstation: ${l.ws || "PC-" + (l.ip & 255)}.${l.domain}`), `Total number of logons listed: ${ls.length}, filtered: 0`, "----end of FSSO logons----"].join("\n");
  }
  return null;
};

// host console: `login <user> <password>` stands for the FortiGate's authentication page
Lab.prototype.hostLogin = function (h, args) {
  const [user, pass] = args;
  if (!user || pass === undefined) return "Usage: login <user> <password>   (submits the FortiGate authentication page; open a website with curl first to get it)";
  const r = this.portalLogin(h, user, pass);
  if (!r.ok) return `The FortiGate page says: "Authentication failed. Please try again."\n(The reason is on the FortiGate: diagnose debug application fnbamd -1, then log in again.)`;
  return `Authentication successful as ${user} (${r.groups.join(", ")}). You can now open the page you requested.`;
};
