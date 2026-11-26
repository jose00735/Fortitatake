# Attack sequences

One file per sequence. A sequence is a timed chain of steps against the Range environment
(`andes-range`); each step is something an attacker does, and each can be stopped by a control
you configure (FortiGate policy, IPS, threat feed, FortiEDR prevention, isolation). A run ends at
the first stopped step and says which control stopped it. The same file drives the real network
(real connections, real IPS verdicts, real collector telemetry, emulated Windows process events)
and the simulator (the same decisions on the lab model, nominal telemetry).

Step kinds (`do:`):
- `connect: {from, to, port, times, every, process}`: TCP connections; `to` is a lab name, an IP,
  or a feed pick: `c2:N`, `url:N`, `phish:N` (the lab's threat-feed snapshot, sinkholed).
- `attack: {pack, from, to, port}`: a threat pack's requests (`from: "@attacker"` = the lab Internet).
- `proc: {host, name, cmd, parent, path, user}`: a process start (emulated on Windows hosts).
- `cpu: {host}`: real CPU load on the host (a miner) for about 95 seconds.
- `files: {host, count, ext, process}`: a burst of renamed files (an encryptor).
- `logins: {from, to, port, attempts, user}`: failed logins against a service, then one success.

Commands in `cmd` are what the attacker would type, shown in the console and telemetry; nothing
here is executed on Windows hosts, and Linux steps only run harmless stand-ins (wget to a sinkhole,
an awk loop).
