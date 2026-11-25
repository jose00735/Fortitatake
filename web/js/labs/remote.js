// SSH and Telnet between lab devices. On the real network the agent carries the bytes (a real TCP
// session with an SSH handshake that advertises modern algorithms but protects the payload with a
// weak lab cipher); FortiTatake answers as the device's CLI. Without the real network the same
// sessions run inside the simulator, after a TCP probe decides whether the port can be reached.

const WIN_MOTD = "Microsoft Windows [Version 10.0.19045.6466]\n(c) Microsoft Corporation. All rights reserved.\n\n";
const UBU_MOTD = (from) => `Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-48-generic x86_64)\n\n * Documentation:  https://help.ubuntu.com\n\nLast login: ${new Date().toUTCString().replace(/ GMT$/, "")} from ${from}\n`;

// what a client console typed: {proto, user, host, port, verbose} or {error} or null (not a remote command)
export function parseRemoteCmd(d, line, localUser) {
  const t = line.trim();
  const fgt = d.kind === "fortigate" || d.kind === "fortianalyzer" || d.kind === "fortimanager";
  let w = t.split(/\s+/);
  if (fgt) {
    if (!/^exec/i.test(w[0] || "") || !/^(ssh|telnet)$/i.test(w[1] || "")) return null;
    w = w.slice(1);
  }
  const cmd = (w[0] || "").toLowerCase();
  if (cmd !== "ssh" && cmd !== "telnet") return null;
  const usage = cmd === "ssh"
    ? (d.kind === "router" ? "% Incomplete command.\n  ssh -l <user> [-p <port>] <ip>" : fgt ? "Command fail. Usage: execute ssh <user@host> [port]" : "usage: ssh [-v] [-p port] [-l login_name] [user@]hostname")
    : (d.kind === "router" ? "% Incomplete command." : fgt ? "Command fail. Usage: execute telnet <host> [port]" : "usage: telnet host [port]");
  let user = null, host = null, port = cmd === "ssh" ? 22 : 23, verbose = false;
  for (let i = 1; i < w.length; i++) {
    const a = w[i];
    if (a === "-v" || a === "-vv") verbose = true;
    else if (a === "-l" && w[i + 1]) user = w[++i];
    else if (a === "-p" && w[i + 1]) port = Number(w[++i]);
    else if (a.startsWith("-")) continue;
    else if (!host) { const m = a.split("@"); if (m.length === 2) { user = m[0]; host = m[1]; } else host = a; }
    else if (/^\d+$/.test(a)) port = Number(a);
  }
  if (!host || !(port > 0 && port < 65536)) return { error: usage };
  if (cmd === "ssh" && d.kind === "router" && !user) return { error: usage };
  return { proto: cmd, user: user || localUser || "admin", host, port, verbose };
}

// error lines when the connection can't be made, in the client's own words
export function connectError(d, r, err) {
  const why = /refused/i.test(err) ? "refused" : /no route|unreachable/i.test(err) ? "unreachable" : "timeout";
  const fgt = /^forti/.test(d.kind);
  if (d.kind === "router") return r.proto === "telnet" ? `Trying ${r.host} ...\n% ${why === "refused" ? "Connection refused by remote host" : why === "unreachable" ? "Destination unreachable; gateway or host down" : "Connection timed out; remote host not responding"}` : `% ${why === "refused" ? "Connection refused by remote host" : "Connection timed out; remote host not responding"}`;
  if (r.proto === "ssh") return `ssh: connect to host ${r.host} port ${r.port}: ${why === "refused" ? "Connection refused" : why === "unreachable" ? "No route to host" : "Connection timed out"}`;
  if (d.os === "windows" && !fgt) return `Connecting To ${r.host}...Could not open connection to the host, on port ${r.port}: Connect failed`;
  return `Trying ${r.host}...\ntelnet: Unable to connect to remote host: ${why === "refused" ? "Connection refused" : why === "unreachable" ? "No route to host" : "Connection timed out"}`;
}

// the client's lines once connected, before the server's first bytes
export function connectedLines(d, r, info, known) {
  const L = [];
  if (r.proto === "ssh") {
    if (r.verbose && d.kind !== "router") {
      const local = d.os === "windows" ? "OpenSSH_for_Windows_9.5" : "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5";
      L.push(d.os === "windows" ? "OpenSSH_for_Windows_9.5p1, LibreSSL 3.8.2" : "OpenSSH_9.6p1 Ubuntu-3ubuntu13.5, OpenSSL 3.0.13 30 Jan 2024",
        `debug1: Connecting to ${r.host} [${r.host}] port ${r.port}.`, "debug1: Connection established.",
        `debug1: Local version string SSH-2.0-${local}`,
        `debug1: Remote protocol version 2.0, remote software version ${String(info.server || "").replace(/^SSH-2\.0-/, "")}`,
        "debug1: SSH2_MSG_KEXINIT sent", "debug1: SSH2_MSG_KEXINIT received",
        `debug1: kex: algorithm: ${info.kex}`, `debug1: kex: host key algorithm: ${info.hostkey}`,
        `debug1: kex: server->client cipher: ${info.cipher} MAC: <implicit> compression: none`,
        `debug1: kex: client->server cipher: ${info.cipher} MAC: <implicit> compression: none`,
        "debug1: expecting SSH2_MSG_KEX_ECDH_REPLY", "debug1: SSH2_MSG_KEX_ECDH_REPLY received",
        `debug1: Server host key: ${info.hostkey} ${info.fingerprint}`,
        "debug1: rekey out after 134217728 blocks", "debug1: SSH2_MSG_NEWKEYS sent", "debug1: SSH2_MSG_NEWKEYS received",
        "debug1: Next authentication method: password");
    }
    if (!known && d.kind !== "router") L.push(`Warning: Permanently added '${r.host}' (ED25519) to the list of known hosts.`);
  } else if (d.kind === "router") L.push(`Trying ${r.host} ... Open`);
  else if (d.os !== "windows" || /^forti/.test(d.kind)) L.push(`Trying ${r.host}...`, `Connected to ${r.host}.`, "Escape character is '^]'.");
  return L;
}

// the password prompt for an SSH client (the server asks for nothing else in the lab)
export function passPrompt(d, r) { return d.kind === "router" ? "Password: " : `${r.user}@${r.host}'s password: `; }

export function closedLine(d, r) {
  if (d.kind === "router") return `\n[Connection to ${r.host} closed by foreign host]`;
  if (r.proto === "ssh") return `Connection to ${r.host} closed.`;
  if (d.os === "windows" && !/^forti/.test(d.kind)) return "\nConnection to host lost.";
  return "Connection closed by foreign host.";
}

// One session arriving at a lab device. write(text) sends to the client, close() ends it,
// answer(line) resolves with the device's output for a command.
export class ServerSession {
  constructor({ dev, proto, user, from, prompt, answer, write, close }) {
    Object.assign(this, { dev, proto, user, from, promptFor: prompt, answer, write, close });
    this.stage = proto === "telnet" ? "login" : "shell";
    this.q = Promise.resolve();
  }
  get win() { return this.dev.os === "windows" && !/^forti/.test(this.dev.kind) && this.dev.kind !== "router"; }
  get kind() { const d = this.dev; return d.kind === "router" ? "ios" : /^forti/.test(d.kind) || d.kind === "fortiswitch" ? "fortios" : d.os === "windows" ? "windows" : "linux"; }
  start() {
    const k = this.kind;
    if (this.proto === "telnet") {
      this.write(k === "ios" ? "\nUser Access Verification\n\nUsername: " : k === "windows" ? "Welcome to Microsoft Telnet Service \n\nlogin: " : k === "linux" ? `Ubuntu 24.04.1 LTS\n${this.dev.hostname.toLowerCase()} login: ` : `${this.dev.hostname || this.dev.id} login: `);
      return;
    }
    this.write(this.motd() + this.prompt());
  }
  motd() {
    const k = this.kind;
    return k === "windows" ? WIN_MOTD : k === "linux" ? UBU_MOTD(this.from) : k === "ios" && this.proto === "ssh" ? "\n" : "";
  }
  prompt() { return this.promptFor(this.user); }
  line(l) { this.q = this.q.then(() => this.handle(l)).catch(() => {}); return this.q; }
  async handle(l) {
    const t = l.trim();
    if (this.stage === "login") {
      if (!t) { this.write(this.kind === "ios" ? "Username: " : this.kind === "windows" ? "login: " : `${this.dev.hostname || this.dev.id} login: `); return; }
      this.user = t; this.stage = "pass";
      this.write(this.kind === "windows" ? "password: " : "Password: ");
      return;
    }
    if (this.stage === "pass") {
      if (!t) {
        this.stage = "login";
        this.write(this.kind === "ios" ? "% Login invalid\n\nUsername: " : this.kind === "windows" ? "\nThe handle is invalid.\n\nLogin Failed\n\nlogin: " : `\nLogin incorrect\n${this.dev.hostname || this.dev.id} login: `);
        return;
      }
      this.stage = "shell";
      const tel = this.kind === "windows" ? "\n*===============================================================\nMicrosoft Telnet Server.\n*===============================================================\n" : "\n";
      this.write(tel + this.motd() + this.prompt());
      return;
    }
    if (/^(exit|logout|quit)$/i.test(t)) { this.write(this.kind === "linux" ? "logout\n" : ""); this.close(); return; }
    if (!t) { this.write(this.prompt()); return; }
    if (/^(cls|clear)$/i.test(t)) { this.write(this.prompt()); return; }
    if (/^(ssh|telnet|exec\S*\s+(ssh|telnet))\b/i.test(t)) { this.write("Nested sessions aren't available in the lab: type exit, then connect from your own console.\n" + this.prompt()); return; }
    let out = "";
    try { out = await this.answer(l); } catch (e) { out = String(e.message || e); }
    this.write((out ? String(out).replace(/\n?$/, "\n") : "") + this.prompt());
  }
}
