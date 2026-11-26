# FortiTatake — Status

> Updated by every build or content session. Read this first.

## Build

| Phase | State |
|---|---|
| P0 Blueprint | Done, v0.1 (21 Nov 2026) |
| P1 Engine MVP (Windows) | **Done, v0.1.0 (21 Nov 2026).** Go core + WebView2 window, event store, all ten session blocks, review, library, interview studio, progress, medals, both skins |
| P2 Android + LAN sync (FTSP/1) | **Built, v0.2.0 (21 Nov 2026).** Protocol tested on Linux (unit, security and property tests; two-instance UI test). Not yet run on a real phone or across real Wi-Fi |
| P3 Advanced items (topology, packet diagrams, voice capture) | Not started |
| L1 Labs engine + tiers 0, 1, 4 | **Built, v0.4.0 (23 Nov 2026).** Emulated FortiOS 8.0.2 CLI, network simulator, grader, 24 labs |
| L2 Core PS labs: IPsec, SD-WAN, HA | **Built, v0.5.0 (24 Nov 2026).** 14 more labs (38 total, 50 parts) |
| L3 Profiles, FortiAnalyzer, FortiManager, integration | **Built, v0.6.0 (24 Nov 2026).** 8 more labs (46 total, 64 parts, 229 checks) |

### What v0.1.0 does

- `fortitatake.exe` serves the embedded web UI on 127.0.0.1 (random port, per-launch token) inside a WebView2 window; falls back to the browser.
- Append-only `events.jsonl` (device id, seq, HLC) in `%APPDATA%\FortiTatake`, so sync can be added without migrating data.
- Sortie runner: warm-up → pretest → learn → break → apply → break → PS arena → break → boss → close. Resumable, skippable blocks.
- FSRS-4.5 scheduling for cards and graded questions; Again = due in 10 minutes.
- Quiz types: single, multi, order, numeric, text, output. Labs: worked → faded → solo. Situations scored on a rubric. Spoken drills with timer, self-score and TeleCyborg export.
- XP, 30 levels, two rank ladders (Fabric / Hellforge), 16 medals, five mastery levels.

### Tested

- Headless Chromium bot played one full sortie for each of the six modules, plus every view in both skins and at phone width: no console errors.
- Windows exe cross-compiled (PE32+ GUI). Not yet launched on a real Windows machine: first run on Jose's PC is the real test.

### Known gaps

- Session timing is a guide: blocks end when the work is done, not when the clock says.
- Self-scored drills and situations depend on honest scoring.

### What v0.2.0 adds

- **Hub (PC):** Settings → Sync → Turn on sync, then Pair a phone. TLS on port 47431 with a self-signed ECDSA P-256 certificate, a 5-minute single-use pairing window (QR + 8-character code), four-word fingerprint, device list with Remove, LAN-only sources, 20 req/s per device, hashed device tokens, a small built-in mDNS responder (`_fortitatake._tcp`).
- **Spoke (phone):** scan the QR (ZXing) or type address + code and confirm the four words; pinned TLS; pull → push → content pack; syncs on open, every 5 minutes and on Sync now; follows the PC's address with Android NSD if it changes.
- **Content packs:** the hub serves its content bundle; a phone with older content downloads it, verifies the SHA-256 and reloads. A newer `bundle.json` in the data folder's `content/` overrides the embedded one, so new modules can reach the PC without rebuilding the exe.
- **Android app:** Kotlin WebView shell that runs the same Go engine (`lib/<abi>/libfortitatake.so`: android/arm64, static linux armv7 and x86_64). Backups and TeleCyborg exports save to Downloads.
- Build: `tools/build_android.sh` (needs ANDROID_HOME). APK signed with the committed sideload key so every build updates the installed app.

### v0.2.1

- Three modules: M4.09 IPsec VPN, M4.10 HA, M8.03 SD-WAN (FortiOS 8.0.2 guide, printed pages; in these chapters PDF page = printed page).
- Windows exe and window now carry the shield icon (`assets/fortitatake.ico`, `rsrc_windows_amd64.syso`, IconId 1).

### v0.2.2

- Two modules: M4.07 Certificates and SSL inspection (pp. 3048–3060, 4411–4436), M4.08 Security profiles (pp. 2480–2850, 3034, 3125).
- Labs that need FortiGuard category IDs say so: confirm IDs on the unit.

### v0.3.0

- Four stages: interview track (I2 hiring manager, I3 technical panel), S11 (M11.02 implementation and migrations, M11.04 design and customer handling), S5 FortiManager (M5.01, M5.03, M5.04), S6 FortiAnalyzer (M6.01, M6.03, M6.04).
- Merges: M11.2+M11.3 → M11.02; M11.4+M11.5 → M11.04; FMG M5.1+M5.2 → M5.01, M5.3 → M5.03, M5.4+M5.5 → M5.04; FAZ M6.1+M6.2 → M6.01, M6.3 → M6.03, M6.4+M6.5 → M6.04.
- Sources: FortiManager 7.6.8 and FortiAnalyzer 8.0.2 Admin Guides (printed page = PDF page in the chapters used); super-cv evidence for interview stories.
- Interview modules I2/I3 sort right after I1 (order 12, 14).

### P2 gaps

- First real-device run pending; if the engine fails to start, the app shows its output on screen.
- mDNS was only verified at packet level (no multicast in the build container). QR and typed address don't depend on it.
- The device token lives in the app's private storage, not Android Keystore.
- Backup restore (import) and `/v1/blobs` are not built yet.

### Release convention (standing)

- **Windows is always delivered as a zip containing an installer:** `fortitatake-vX.Y.Z-windows-setup.zip` with `FortiTatake-Setup-vX.Y.Z.exe` (NSIS, per-user, no admin) and `INSTALL.txt`. Build with `tools/build_windows.sh`; the script is `installer/fortitatake.nsi`.
- Android is delivered as `fortitatake-vX.Y.Z.apk` from `tools/build_android.sh`.

### What v0.4.0 adds (Labs)

- **Labs** section: PS projects and tickets on an emulated FortiOS 8.0.2 CLI. Blueprint: Claude Doc "FortiTatake Labs — CLI Simulator Blueprint".
- `tools/extract_cli.py` turns the FortiOS 8.0.2 CLI Reference PDF into `web/schema/fortios-8.0.2.json`: 644 config paths with attribute types, options, ranges and defaults, plus 5,751 diagnose/execute command names. **No Fortinet descriptions are copied** (the repo is public).
- Engine (`web/js/labs/`, no DOM, tested in Node): `fgt.js` CLI and config tree (config/edit/set/unset/append/next/end/abort, delete/rename/clone/move/purge, show, show full-configuration, get, `?`, Tab, abbreviations, reference checks, FortiOS-style errors); `sim.js` packet path (VIP DNAT, local-in and allowaccess, trusted hosts, routing with distance/priority, loose/strict RPF, policies in order with zones, addresses, groups, FQDN, services, schedules, SNAT and IP pools, proxy ARP, sessions, MTU, TTL); `diag.js` (debug flow, sniffer, session list, iprope lookup, routing table, ARP, ping/traceroute, backup, DHCP leases; Windows/Linux host consoles; read-only ISP routers); `grader.js` (probe, config, DHCP, route, ran, backup, answer checks with plain-language explanations).
- Lab packs in `content/labs/*.yaml` with reusable topologies (`_templates.yaml`: clinic, clinic-live, retail, retail-live, andes). `tools/build_labs.py` builds `web/content/labs.json`; `tools/test_labs.mjs` proves each lab fails at start and passes with its reference solution. Release scripts run both.
- Labs can have parts (sub-labs unlocked in order), hints in three steps, a reveal (score capped), Exam mode (no hints, timed), and score → XP and four new medals. Progress resumes from localStorage by replaying the command log.

| Tier | Labs |
|---|---|
| 0 Console | C0.01–C0.04 |
| 1 Fundamentals | F1.01 (5-part clinic deployment), F1.02–F1.12 (F1.07 has 2 parts) |
| 4 Break-fix | B4.01–B4.08 |

### What v0.5.0 adds (Labs)

- `vpn.js`: route-based IPsec between FortiGates (phase1/phase2 negotiation: version, proposals, DH, PSK, mode, peer ID, mirrored selectors, PFS), tunnel interfaces created with each phase1, routes removed when a tunnel is down, encryption path with selector checks and tunnel MTU, IKE debug (`diagnose debug application ike -1` + `diagnose vpn ike gateway clear`), `get vpn ipsec tunnel summary`, `diagnose vpn ike gateway list`, `diagnose vpn tunnel list`. Dial-up: FortiClient on lab laptops (`forticlient connect`), mode-cfg pools, EAP/XAuth user groups, split tunnel, add-route.
- `sdwan.js`: members, zones (policies and `sdwan-zone` static routes), health checks fed by ISP link quality (latency, jitter, loss), dead members removed from routing, service rules (manual, best quality, SLA), `diagnose sys sdwan health-check|member|service`, and the FortiOS rule that a member can't be referenced elsewhere.
- `ha.js`: FGCP formation over the heartbeat (mode, group name/ID, password, model), election (monitored ports, override, priority, uptime, serial), config sync (priority/override per unit), only the primary answers ARP, failover on monitored link loss, `get system ha status`, `diagnose sys ha checksum cluster`, `execute ha failover set`.
- Part events: a part can fail a link or port, degrade an ISP, or change DNS when it starts (used for failover and SLA tests).
- New topologies: andes-vpn(-live), sdwan-branch / sdwan-live, pharma-ha(-live).

| Track | Labs |
|---|---|
| VPN | V2.01 (3-part site-to-site), V2.02 (2-part dial-up replacing SSL VPN), V4.01–V4.05 tickets |
| SD-WAN | S2.01 (3-part branch), S2.02 voice, S4.01–S4.02 tickets |
| HA | H2.01 (3-part cluster + failover test), H4.01–H4.02 tickets |

### What v0.12.0 adds (threat packs and a real inline IPS)

- **Threat packs** (`content/threats/`, format in its README): one YAML file per CVE with our own dotted attack name, severity, targets, the IPS signatures and the generator requests. `python3 tools/build_threats.py` checks every pack: each attack variant trips its own signatures, ten ordinary office and admin requests trip none, and requests may only aim at `{{target_host}}`. A newer CVE is one new file. The packs are the only signatures the lab IPS knows.
- **Three packs:** TP-2021-44228 (Log4Shell: JNDI lookups in headers, URI and nested-lookup obfuscation), TP-2022-40684 (FortiOS admin API with `User-Agent: Report Runner` and a loopback `Forwarded` header, as in Horizon3.ai's write-up), TP-2023-46805 (Ivanti Connect Secure `/api/v1/totp/user-backup-code/../../` traversal and the keys-status command separator, per Rapid7's analysis). Requests carry only the shape the signatures key on and go to lab stand-ins.
- **Real inline IPS (agent 0.12, needs the v0.11 kernel).** Each accept policy with `utm-status enable` and an `ips-sensor` gets an NFQUEUE rule in the FortiGate's namespace for the first 12 packets of its sessions on the signatures' ports; the agent (a small netlink client, no libraries) matches the request and gives the verdict inline: accept, drop (block, and the rest of the session with it) or a TCP reset. `config ips global` `fail-open enable` adds the queue bypass. Matching is a literal/regex scan over the HTTP buffers (method, URI, headers, body, raw), the same in the agent, the simulator and the build check.
- **Sensors as on FortiOS:** entries pick signatures by rule id, severity, location, OS, application, protocol or CVE, first matching entry wins, actions pass, block, reset or default (critical and high block). Built-in names (`default`, `high_security`, `protect_http_server`, ...) work without a config entry.
- **HTTPS needs deep inspection.** FortiTatake doesn't re-sign certificates: the lab's attack runner hands the FortiGate engine the plaintext of each TLS request, and the IPS reads it only when the policy's SSL profile is deep-inspection. With certificate inspection the sensor sees ciphertext and the attack gets through, as on a real FortiGate.
- **IPS logs:** every hit becomes a FortiOS-style `utm/ips` log (attack, attackid, severity, CVE, action dropped/reset/detected, policy, interfaces, URL) that flows to FortiAnalyzer and FortiSIEM like the others. `execute log filter category <0-4>` and `execute log display` on the FortiGate now show its memory log (traffic, event, virus, webfilter, IPS).
- **Attacks panel** (next to the device tabs): pick a pack, a source (the lab Internet's attacker at 198.51.100.66 or a lab device), a target and a port; each request shows whether it was answered, dropped or reset and which policy and signature acted. In the simulator the same packs and sensors give the same verdicts.
- **New lab P2.02, "IPS for the published portal"** (clinic, 2 parts): a sensor with deep inspection on the VIP policy, then closing the HTTPS admin a contractor left on the WAN (the CVE-2022-40684 lesson: exposure, not signatures). New `attack:` check type (`expect: blocked | reset | allowed | stopped`).
- Tested in QEMU and in the app with the real network: no sensor → the server answers; sensor with certificate inspection → still answered; with deep inspection → every request dropped and logged; action reset → connection reset; ordinary HTTPS through the same policy unaffected.
- Not yet: the 12-packet window means requests split across many segments aren't reassembled; client-side packs and non-HTTP protocols come with later packs.

### What v0.11.0 adds (OS stage 4 kernel, office traffic generators, per-device cgroups)

- **FortiTatake OS kernel:** cgroup v2 with the cpu, memory and pids controllers, and NFQUEUE (`CONFIG_NETFILTER_NETLINK_QUEUE`, `CONFIG_NFT_QUEUE`) for the inline IPS that comes next. Tested in QEMU: a busy loop in a lab shell is throttled to half a core (`nr_throttled` climbs, `cpu.max` 50000/100000), and an nft `queue flags bypass` rule loads in a FortiGate namespace. **Rebuild FortiTatake OS** to get it; the app keeps working on an older image, without caps and without office traffic.
- **Per-device cgroups.** Lab shells and services start inside `/sys/fs/cgroup/ftk/<device>` (clone3 into the cgroup, so children can't escape): half a core, 96 MB, 256 processes per device, and 60 % of the VM's memory for the whole lab. `cg.stat` returns CPU time, throttling, memory, peak and OOM kills per device, which the EDR collectors read in v0.13.
- **Office traffic** (button next to "Linux shell" when the real network is live). Five generators run inside the PCs' namespaces and talk to stand-in servers, all real connections through your FortiGate:
  - **web:** a DNS lookup through the PC's own resolver, then HTTP/HTTPS pages of 1-6 objects with browser headers over keep-alive, to real site names (answered by the Internet stand-in) and the lab's published servers.
  - **dns:** A and AAAA lookups, about 3 % for names that don't exist, NTP to a lab time server.
  - **smb:** SMB2 negotiate, session setup, tree connect, create, then reads or writes of 4 KB-2 MB to the NAS (its stand-in logs each command and file).
  - **mail:** SMTP submission on 587 with STARTTLS, IMAPS polls on 993, HTTPS API calls to a SaaS name; the mail and SaaS stand-ins live in the lab Internet on 198.51.100.0/24 (documentation space, never routed out).
  - **voice:** SIP REGISTER, INVITE and BYE on UDP 5060 and an RTP stream at 50 packets/s (172-byte G.711 frames) to a PBX.
  - Speeds 1×, 10× and 60×; seeded from the lab, so a run repeats. A PC behind an ISP router (a teleworker) browses and reads mail but doesn't use the office file share or PBX. Labs can set their own profile with `topology.traffic: {rate, hosts: {DEVICE: [web, dns, mail, smb, voice]}}`; otherwise PCs get web, dns and mail, plus smb when a NAS exists and voice when a PBX exists (no current lab has a PBX or phones, so voice only runs where a lab profile asks for it).
  - The panel lists each generator's flows, failures and bytes and a live log of every flow; failures are named (timeout, refused, NXDOMAIN), so a missing policy or DNS setting shows up at once.
- **Baseline recorder.** "Record a workday" runs a 9-hour office day at 120× (about 4.5 minutes) and keeps its flows, with virtual 08:00-17:00 timestamps, as the lab's baseline (in the browser, and as a JSON download). The SIEM `test_rule` replay still uses the scripted normal week; switching it to recorded traffic comes with the EDR and SIEM work in v0.13.
- Tested in QEMU on the clinic lab: 16 generators, 285 FortiGate sessions in 25 s at 60×, SMB commands and SMTP/IMAPS sessions logged by the stand-ins, SIP and RTP to a PBX stand-in, and the live wire sniffer showing the generated packets.

### What v0.10.2 adds (wire sniffer, man pages, sessions that stay visible)

- **Click a link on the lab map to sniff it.** Each wire opens a small square window, like `diagnose sniffer packet <port> 'none' 4 0 l`: local timestamps, the port, in/out and the packet. It captures at the better-placed end (FortiGate, then router, then server, then PC); on a LAN switch it sees what crosses that device's port. Pause, Clear and close; drag it by the title bar and resize it from the corner; up to a few at once. On the real network it runs tcpdump in that device's namespace; in the simulator it taps the packet walk, including unanswered ARP requests.
- **`man <command>` on every CLI.** Windows, Linux, IOS-style routers, FortiOS, FortiSIEM, FortiEDR, FortiAnalyzer, FortiManager and FortiSwitch each have pages with a synopsis, what the command does and worked examples. `man` alone lists the pages; `help` and `?` now list only command names (FortiGate keeps its own `?` behaviour).
- **Fixed: a curl or wget from a lab PC left nothing in `diagnose sys session list`.** The command was answered by the simulator only. It now also runs on the real network, and the agent holds the TCP connection open (idle keep-alive, up to 60 s) so the session stays in the table the way a browser's would; the FortiOS-like conntrack timers close a finished connection within a second. **Needs FortiTatake OS rebuilt** (agent 0.10.2): with an older image the request still happens but closes at once.
- **`diagnose debug flow trace start` without a count** traces one packet, as on FortiOS. The CLI now says so, because a PC that gets no answer from its first DNS server retries the second one and only the first try was being traced. In the reported case the first DNS server was the FortiGate itself, which had no `system dns-server` entry for that interface, so local-in dropped the query correctly and the retry to 8.8.8.8 was routed.

### What v0.10.1 adds (addressing on lab devices, a nano-style editor)

- **Windows PCs:** `netsh interface ip set address name="Ethernet0" static <ip> <mask> [<gw>]` or `dhcp`, `netsh interface ip set|add|delete dns`, `netsh interface ip show config`, `netsh interface set interface ... admin=disable|enable`, `route add|delete 0.0.0.0 mask 0.0.0.0 <gw>`, `ipconfig /flushdns`, and the PowerShell cmdlets `Get-NetIPConfiguration`, `New-NetIPAddress`, `Remove-NetIPAddress`, `Set-DnsClientServerAddress`, `Set-NetIPInterface -Dhcp`, `New-/Remove-NetRoute` (default route), `Disable-/Enable-NetAdapter`.
- **Linux servers (sudo needed, as on Ubuntu):** `ip addr add|del|flush`, `ip route add|replace|del default via`, `ip link set eth0 up|down`, `netplan get|apply|try` from `/etc/netplan/50-cloud-init.yaml`, `dhclient [-r]`, `resolvectl status`, `hostnamectl`; `cat`/`ls` on the config files. `/etc/resolv.conf` takes effect at once; netplan applies on `netplan apply`.
- **ISP routers, IOS style:** `enable`, `configure terminal`, `interface <name>`, `ip address`, `[no] shutdown`, `description`, `ip route <net> <mask> <next-hop|Null0>`, `no ip route`, `hostname`, `ip name-server`, `do <command>`, `exit`/`end`, `write memory`. Prompts follow the mode (`>`, `#`, `(config)#`, `(config-if)#`); the running config shows the changes.
- **Editor:** `nano` (also `vi`, `vim`, `pico` on Linux) and `notepad` on Windows open a small in-console editor: ^O write out, ^X exit with the Y/N prompt, ^W search, ^K/^U cut and paste, with buttons for phones. Editing `/etc/*` without sudo shows nano's permission error on save. Hosts files (`/etc/hosts`, `C:\Windows\System32\drivers\etc\hosts`) answer before DNS for ping, curl and friends; nslookup and dig skip them, as on the real systems.
- **Real network:** every change rebuilds the device's namespace from the simulator (tested in the VM: new addresses, default routes and Null0 blackhole routes appear in the kernel). No OS rebuild needed. Changes and editor saves replay from the lab log, so they survive a reload.
- Lab hosts still model one adapter with one IPv4 address and a default route; extra static routes on PCs and servers are refused with a message.

### What v0.10.0 adds (question quality overhaul, confidence rating)

- **Every module is now `quality: 2`** (71 modules, 548 items: 364 single, 62 multi, 42 order, 27 output, 25 numeric, 28 text) and `python3 tools/quiz_lint.py --strict` passes: balanced option lengths, no hedge, parenthesis or absolute-word cues on one side only, labelled traps (misconception / irrelevant / near-miss) with specific why_wrong, two near-misses at tier 3+, text answers of 3+ characters, and an output, first-step, answer-reason or not-work item in every module with tier 3+ questions. Two short text items became numeric or single-choice items.
- **Cue bot, before → after (share of items it gets right from test-taking cues alone):** S1 57.9 → 7.9 %, S2 23.1 → 6.7 %, S4 66.3 → 3.1 %, S5 56.7 → 6.5 %, S6 68.0 → 8.0 %, S7 50.0 → 0 %, S8 65.5 → 6.5 %, S9 72.7 → 0 %, S10 54.5 → 0 %, S11 62.2 → 0 %, interview track 79.3 → 3.4 %; all stages 48.8 → 4.4 % (chance about 22 %).
- **Residual cue, recorded honestly.** Because distractors were lengthened to stop "pick the longest", a guesser who always picks the shortest option now scores 31.7 % and "second longest" 36.1 % against 25 % chance (the lint prints these lines). The next content pass makes the right answer the longest in about a quarter of each module's items.
- **Confidence rating** on Boss strikes and review items: pick Sure or Not sure before checking. A confident miss costs XP (tier points on a first attempt, 3 on a review) and is scheduled as Again; a right-but-unsure answer is rated Hard so it returns sooner.
- Text answers can use `~text` (contains), as labs already do.
- `tools/quiz_patch.py`: `--dump <module>` for a compact view and patch files that rewrite items in place without reformatting the module.
- Not built yet: the two-step answer-plus-reason screen (items are tagged `format: answer-reason` and read as one choice for now) and the "too easy" usage flag.

### What v0.9.0 adds (SOC/SecOps and FortiSASE depth, capstones, real Internet DNS and ping)

- **Real Internet for ICMP and DNS.** The lab ISP's Internet side now forwards ping and DNS for real public addresses through the app (OS agent 0.9.0 + engine relay): `ping 8.8.8.8`, `nslookup fortinet.com` and `dig @1.1.1.1 …` from a lab PC give real answers, TTLs and round-trip times. Lab-defined names still win; public resolvers (8.8.8.8, 1.1.1.1, 9.9.9.9 …) are relayed even if a lab defines them. TCP 80/443 to real addresses is answered by stand-in web listeners that log the original destination. Nothing else leaves the lab. The simulator answers the same way for real addresses.
- **DNS from the PCs is visible.** `nslookup`/`dig` run a real lookup from the device's namespace (`dns.query`), with Windows, Ubuntu and dig output formats; curl, wget, Test-NetConnection and nc resolve names the same way first, so DNS packets show up in captures and FortiGate DNS logs.
- **Phone OS transfer spinner fixed.** The sync link stops animating once the transfer finishes ("sent") or pauses, and the panel refreshes even when no new events arrive.
- **S13 · SOC & SecOps (consultant level):** M13.01–M13.06 (SOC operations and metrics, detection engineering with AD attack telemetry, incident response, threat hunting, SOAR automation, SOC stack delivery and EPS sizing).
- **S14 · FortiSASE (consultant level):** M14.01–M14.03 (architecture and the SSL→IPsec agent transition, security policies, SPA and ZTNA, operations, log forwarding and migrations including from Netskope).
- **Remaining modules:** M0.01 diagnostic, M1.01–M1.02 network foundations, M3.01–M3.03 and M3.05 (crypto/PKI, TLS inspection theory, VPN theory, defense and threat landscape), M11.03 vendor migrations, M11.05 executive storytelling, M12.01 design case, M12.02 exam simulations, M12.03 mock interview gauntlet.
- **Capstones (tier 6):** K6.01 "Andes long night" (triage, two custom SIEM rules, a CISO requirement change, a syslog fault injected mid-lab, the customer update) and K6.02 "Detection sprint" (Kerberos spray, AS-REP roast, remote service install, LSASS access, each rule replayed against an attack and a normal week).
- **SOC engine:** FortiSIEM custom rules (`rule new "<name>" where … group … count|distinct … window …`, globs, `a|b`, `~contains`, `!not`), Windows/Sysmon field mapping, story `repeat`, graded by replaying attack and baseline streams; `receiving` check for log flow; FortiEDR isolation compiled to an nft drop-all table on the real engine.
- **Question lint (`tools/quiz_lint.py`).** Every new module is `quality: 2` and passes it: length balance, no cue words only in one side, near-miss counts by tier, labelled traps, specific why_wrong, an output or first-step item per module. A cue-only bot measures how guessable each stage is (new stages: S3 12.5 %, S12 15.4 %, S13 4.3 %, S14 5.0 %; the older stages are the v0.10.0 work).
- **The OS must be rebuilt** for the relay and `dns.query` (agent 0.9.0). An older build keeps working; DNS then falls back to the simulator and real-Internet pings get no reply.

### What v0.8.12 adds (SSH and Telnet between lab devices, troubleshooting commands)

- **Consoles that look like the real thing.** Windows PCs open like CMD (`Microsoft Windows [Version 10.0.19045.6466]`, prompt `C:\Users\<user>>`), Linux servers like Ubuntu 24.04, ISP routers like a Cisco IOS XE vty.
- **Windows troubleshooting commands:** `arp -a`, `route print`, `netstat -ano`, `pathping`, `ver`, `systeminfo`; `uname` answers the way CMD does. **Linux:** `uname [-a|-r]`, `ip neigh`, `ip route`, `ss`, `cat /etc/resolv.conf`. On the real network ping, tracert/traceroute, arp, route, netstat/ss and uname come from the device's namespace.
- **ISP routers (IOS style, abbreviations work):** `show ip interface brief`, `show ip route`, `show interfaces`, `show arp`, `show running-config`, `show version`, `show access-lists`, `show logging`, `show clock`, `ping`, `traceroute`.
- **SSH and Telnet.** PCs, servers and ISP routers listen on TCP 22 and 23 (a lab can turn this off with `remote: false`); FortiGates on their admin SSH port and Telnet when allowaccess permits. Clients: `ssh [-v] [-p port] [user@]host`, `telnet host [port]` on PCs and servers, `ssh -l user ip` / `telnet ip` on routers, `execute ssh user@host` / `execute telnet host` on FortiGates. `~.` or Ctrl+C before login ends a session.
- **The SSH is deliberately weak.** On the wire it is real: TCP between the namespaces, a version exchange (`SSH-2.0-OpenSSH_9.6p1 Ubuntu…`, `SSH-2.0-Cisco-1.25`, …), binary-packet KEXINIT offering curve25519-sha256, ssh-ed25519, chacha20-poly1305 and AES-GCM, an ECDH exchange and NEWKEYS; `ssh -v` shows the negotiation. After that the payload is XORed with a SHA-256 counter stream keyed only by the two public values sent in the clear, so anyone with the pcap can decrypt it, and it costs nothing on a phone. Telnet is plain text. Tested in the VM: commands never appear in an SSH pcap and do appear in a Telnet one.
- **Agent ops** `remote.open/send/read/close` (client side) and `console.poll/reply` (server side); listener binds take `mode: ssh|telnet` and `banner`. FortiTatake answers each session with the device's CLI. **The OS must be rebuilt**; an older build falls back to simulated sessions.

### What v0.8.11 adds (SecOps on real protocols, IPsec on the real network)

Needs an OS rebuild on the PC (and a new phone build): the agent gained log collectors and a sender.

- **Traffic logs from the kernel.** For accept policies with `logtraffic all`, each session that ends in the FortiGate's namespace (conntrack DESTROY events, `-o id`) becomes a FortiOS traffic log: srcip/dstip/ports, srcintf/dstintf, policyid (conntrack mark), sentbyte/rcvdbyte/packets (conntrack accounting), service, `trandisp` snat/dnat with transip/tranip, action `close` for TCP and `accept` for the rest. Closed sessions are reaped within ~2 s (FortiGate-like TCP close timers plus a periodic table walk; Linux otherwise reaps lazily, up to a minute later). Deny policies (unless `logtraffic disable`) and the implicit deny (`fwpolicy-implicit-log enable`) carry an nftables `log prefix "FTKD <fgt> <policy>"`; the kernel log lines (`/dev/kmsg`, `nf_log_all_netns=1`) become deny logs. The simulator's own traffic logs are off while live; scripted story logs (IPS, Windows, EDR) keep their content.
- **Logs travel for real.** `config log fortianalyzer setting` → a TCP connection from the FortiGate's namespace to the FortiAnalyzer on 514 (from `source-ip` if set), one key=value line per log (an OFTP stand-in: same port and direction, no OFTP TLS framing). `config log syslogd setting` → UDP syslog datagrams (`<189>` + the log) to the server and port, plus a periodic system event log. If routing, a policy, NAT or the tunnel is wrong, nothing arrives, and the FortiGate keeps retrying (FortiAnalyzer lines stay queued until they arrive).
- **Collectors.** FortiAnalyzer (TCP 514), FortiSIEM (UDP/TCP 514, TCP 443) are compiled as devices on the lab network; the agent keeps each received line. FortiAnalyzer's Device Manager lists a FortiGate when its connection arrives; only authorized devices' logs are stored (Log View, FortiView, handlers). FortiSIEM's analytics, CMDB, rules and incidents run on the syslog that actually arrived.
- **Connections the consoles report** (FortiAnalyzer/FortiManager registration, Windows agents to FortiSIEM on 443, FortiEDR collectors on 8081) come from real TCP connections from the right namespace, refreshed every few seconds.
- **IPsec on the real network** (site-to-site, route-based). Each phase1-interface is a Linux xfrm interface; when FortiTatake's IKE check says phase 1 and phase 2 come up (vpn.js: version, proposals, DH groups, PSK, IDs, selectors, reachability), both ends get ESP SAs (AES-GCM, keys derived from the PSK and the tunnel names) and the tunnel routes; otherwise the interface stays down and routes over it don't install. The traffic between the FortiGates is real ESP (the sniffer shows it as ESP); IKE packets themselves aren't exchanged. Dial-up (FortiClient) stays simulated.
- **Checks that read FortiAnalyzer/FortiSIEM/FortiEDR** wait up to 12 s for real delivery; `action=accept` in a log check also matches `close`/`timeout` (an allowed session's end on a real FortiGate).

### What v0.8.10 adds (FortiTatake OS on the phone)

- **QEMU for Android** in the APK (`jniLibs/arm64-v8a/libqemu.so`): qemu-system-aarch64 11.1.3 as a fully static aarch64 Linux binary (musl, built with zig cc; glib 2.84, pcre2, libffi, zlib, libfdt static; only the `virt` machine, TCG, no graphics; 28 MB). Android runs it from the app's native library folder like the Go engine. `tools/build_qemu_android.sh` builds it from sources on the Ubuntu archive and download.qemu.org.
- The phone tries KVM when the phone lets apps open `/dev/kvm`, else TCG (multi-threaded, 64 MB translation cache instead of QEMU's default, which can reach 1 GB).
- Tested here: the Android binary boots the ARM64 FortiTatake OS kernel and the agent answers (under qemu-user on x86, i.e. double emulation, 38 s; native ARM64 TCG is far faster). Not yet tested on Jose's Xiaomi 17T.
- On the phone the OS tab's "Test the build" is enabled once a phone build has synced, and labs go live exactly as on the PC.

### What v0.8.9 adds (FortiGate diagnostics from the real network)

With the lab live, these FortiGate commands read the kernel in the FortiGate's namespace and print in FortiOS format (the simulator still answers when the OS isn't running). No OS rebuild needed: the agent is unchanged.

- **`diagnose debug flow`** in real time: the flow filter (`addr`, `saddr`, `daddr`, `proto`, `port`) becomes nftables rules that set `nftrace` in a separate `ftktrace` table; `trace start <n>` + `debug enable` run `nft monitor trace`, and each traced packet is translated (`realdiag.js` FlowTrace) into FortiOS lines: received a packet, allocate a new session / Find an existing session (original/reply), `iprope_dnat_check` matched or no-match with find DNAT, find a route (gateway from the compiled routes, egress from the trace), `__iprope_fwd_check`, Allowed by Policy-N (from the rule's conntrack mark) or Denied by forward policy check (policy N / 0), SNAT/DNAT, `iprope_in_check() check failed on policy 0, drop` for local-in. Stops after n packets or on `debug disable`; survives policy edits (the trace table is reinstalled after each nftables reload). Function names and line numbers are FortiOS-shaped; the decisions are the kernel's.
- **`diagnose sys session list`** from `conntrack -L` with accounting on (bytes/packets per direction), FortiOS-like timeouts (TCP established 3600 s, UDP stream 180 s), `policy_id` from the conntrack mark, `orgin->sink` interfaces and gateway from the compiled routes, SNAT/DNAT hooks from the reply tuple, honours `diagnose sys session filter`. `diagnose sys session clear` flushes conntrack.
- **`get router info routing-table all`** from `ip -j route`: what the kernel actually installed, with FortiOS codes; distance and priority come from the FortiGate's config (Linux has no such fields). `details` and `database` stay simulated (inactive routes never reach the kernel).
- **pcap**: `diagnose sniffer packet` also writes a pcap (`tcpdump -w … --print`); afterwards "Download .pcap" appears next to Linux shell on that FortiGate's tab (Linux cooked v2, opens in Wireshark). On Android it saves to Downloads.

### v0.8.8 changes

- **Always the real network.** The "Real network" switch is gone (Jose: always as real as possible). When this device has a build and QEMU, every lab runs live on FortiTatake OS; the simulator answers only where the OS can't (no build, the phone until it runs the OS, features not compiled yet). The status next to "Real network" says which.
- **Phone OS tab** shows only what the phone does: "Sync builds from the PC" and "Test the build" (disabled until the phone can run the OS), plus the builds it holds; no build phases.

- "Build tuned for this CPU" is gone (Jose: useless). The VM sees QEMU's CPU model, not the host's, so a PC build tuned for the Ryzen gains nothing and `-march=native` broke it. PC builds are generic only; an older `x86_64-tuned` folder is ignored. Tuning stays possible for the phone build only (its CPU report is kept), not exposed in the UI.
- **Delete a build.** Each row under "Builds on this device" has Delete (asks first). The lab VM is stopped so Windows lets go of the files, the build folder and its entry in `report.json` are removed; refused while a build or test runs. Rows are tagged "labs use this", "not used" or "won't boot here" (with the reason on hover). Works the same on the phone for builds it received.

### What v0.8.7 fixes

- On Jose's PC the lab VM kept "starting…": the tuned build was compiled with `-march=native` (Zen 3 instructions), but under WHPX the VM sees QEMU's generic CPU model, so init died with an illegal instruction, QEMU exited, and the lab retried every 0.7 s. Now: the tuned x86_64 build uses `-mtune=native` (same instruction set, scheduling tuned for the CPU); a build that can't boot on any accelerator is marked `boot-failed` and the runner falls back to the next build (tuned → generic) until it's rebuilt; the lab waits 30 s before retrying a VM that wouldn't start and shows the reason on hover.
- Stage 0 on Jose's Ryzen 9 5950X (generic build): WHPX, boot 1.2 s, 10-device lab built in 1.1 s, TCP across it in 0.2–1.4 ms, QEMU resident memory 95 MB.

### What v0.8.6 adds

- With the real network live, the FortiGate console's `diagnose sniffer packet <intf> '<filter>' <verbose> <count> [a]` captures real packets in the FortiGate's namespace (tcpdump underneath) and prints them in FortiOS format (verbose 1 and 4 layouts, relative or absolute time, count, Ctrl+C, the "packets received by filter" footer). Forwarded traffic shows on both interfaces, after NAT on the way out, as on a FortiGate.
- `execute ping <ip|name>` sends real pings from the FortiGate (honouring `execute ping-options source`).
- The commands still go into the lab history, so "ran a sniffer/ping" checks see them.

### What v0.8.5 adds (live real network)

- **Live mode.** With Real network on, FortiTatake OS boots when a lab opens (status next to the switch: starting…, applying…, live) and follows the lab as you work: every config change is applied within about a second. Only what changed is redone: a policy edit reloads that FortiGate's nftables; address, route or cabling changes rebuild the lab network.
- **Linux shell** on every device tab (button at the right of the device tabs): a real shell inside that device's namespace, on the real lab network: `ip`, `ping`, `traceroute`, `nslookup`, `curl`, `nft`, `tcpdump`. Output streams line by line (the shell writes to a pseudo-terminal); Ctrl+C interrupts the running command; `exit` or the button goes back to the device console. A network rebuild ends open shells; the next command starts a new one.

### What v0.8.4 fixes

- "Build for this PC" (tuned) failed at once: `--opt -march=native` looked like a flag to the build driver's argument parser. It's passed as `--opt=-march=native` now.
- The "Gathering sources" counter stayed at 0 until every download finished; it now counts each source as it arrives.
- wsl.exe dropped the backslashes from the path given to `wslpath` (so it always fell back); the path goes with forward slashes.

### What v0.8.3 fixes

- After the builder was created, setup stopped at `wslpath: exit status 1` on Jose's PC. The app now falls back to working out the `/mnt/<drive>/…` path itself and checking it inside Linux; if Linux still can't see the folder, the raw log shows what WSL said, how drives are mounted and the distro's `wsl.conf`.

### What v0.8.2 fixes

- When `wsl --import` fails because WSL 2's Windows features (Virtual Machine Platform) are off, the app now asks Windows for administrator permission itself (one UAC prompt) and turns on Virtual Machine Platform and WSL (`wsl --install --no-distribution`) plus Windows Hypervisor Platform (so the lab VM uses WHPX instead of TCG), then asks for a restart. Seen on Jose's PC as `HCS_E_SERVICE_NOT_AVAILABLE`. Other import errors show WSL's own message instead of a generic one, and a half-registered distro is removed. The Ubuntu download is kept between attempts.

### What v0.8.1 fixes

- "Set up the builder" failed on Jose's PC: that WSL has no `--install --name`, and `wsl --install -d Ubuntu-24.04` answered "Invalid distribution name" (WSL_E_DISTRO_NOT_FOUND). The app now downloads Canonical's Ubuntu 24.04 WSL image itself (cloud-images.ubuntu.com, resumable, checked against SHA256SUMS) and creates `FortiTatake-Builder` with `wsl --import … --version 2`: no Microsoft Store, no `--name`, no administrator.
- The OS tab shows the PC's CPU model and RAM instead of a thread count.

### What v0.8.0 adds (FortiTatake OS, stages 0–3)

- **OS tab.** Sets up the builder (a dedicated WSL2 distro, `FortiTatake-Builder`), builds FortiTatake OS from source with Buildroot 2026.02.3 (Linux 6.12 from allnoconfig plus fragments, musl, BusyBox, iproute2, nftables, conntrack-tools, tcpdump, dnsmasq, lighttpd, Dropbear, curl, mstpd, lldpd; EROFS LZ4HC root, no initramfs), shows the build as phases, a power gauge and a per-thread strip, and resumes interrupted downloads from `.part` files and the build journal. "Build for the phone" makes the ARM64 build; generic or tuned to the CPU (x86_64 `-march=native`; ARM64 from the phone's reported CPU parts).
- **Signed builds.** Each build is sealed with the PC's Ed25519 key (`manifest.json` + `manifest.sig`); the runner refuses a build whose seal fails.
- **Runner.** A stripped QEMU 11.1.3 cross-built for Windows (x86_64 machine only, WHPX + TCG, no graphics; 26 MB with its DLLs and firmware) installed in `<install>\qemu`. WHPX is tried first (`kernel-irqchip=off`), TCG if Windows Hypervisor Platform is off. Stage 0 test: boot, a 10-device lab, traffic across it, memory; results in `%APPDATA%\FortiTatake\ftkos\report.json`.
- **Sync to the phone.** The PC offers ARM64 builds over the existing LAN sync (`/v1/os`), the phone downloads them with HTTP ranges (resumable), pins the PC's key on first use, checks the signature and every hash, and posts its CPU and test results back (`/v1/os/report`). The OS tab animates the transfer as power flowing from the PC to the phone.
- **Lab agent** (`ftkos/agent`, static Go): JSON lines on virtio-console. Namespaces, veth, VLAN-filtering bridges, 802.1Q sub-interfaces, dummies, routes (incl. blackhole), netem, nftables per device, probes (tcp/http/https/dns/udp/icmp), AF_PACKET capture to pcap, and in-namespace servers that log who connected (web, TLS, SSH banner, DNS answering from the lab's names, plain TCP/UDP).
- **FortiOS compiler** (`web/js/labs/compile.js`): a running lab becomes one namespace per device plus a switching fabric; FortiGate interfaces (physical, VLAN, loopback), static and dynamic routes, policies in order (zones, address objects and groups, FQDN, services and groups, schedules evaluated on the lab clock, deny), VIPs (static and port-forward; DNAT only when a policy uses the VIP), NAT (interface IP or IP pool), allowaccess with admin ports and trusted hosts; hosts with their DHCP leases and services; ISP routers (drop private addresses toward the Internet) and the Internet cloud with every lab name. SD-WAN, VDOMs, IPsec, HA, identity policies and FortiAnalyzer/FortiManager labs stay on the simulator.
- **Real-network checks.** With a build installed, a lab shows **Real network** (on by default). Probe checks then run on FortiTatake OS: the kernel decides pass or fail, the simulator still explains which policy and NAT. If they disagree the check says so ("worth reporting"). The lab VM boots on the first check and powers off after 10 idle minutes.
- **Tests.** `tools/test_labs_linux.mjs` runs every lab's start state and solution through the kernel (`--vm <kernel> <rootfs>` boots the OS in QEMU). All 71 labs: the ones the compiler covers pass on the kernel (79 probe checks in the final full run, plus every start state), 0 disagreements left after fixing the compiler; SD-WAN, IPsec, VDOM-from-start, HA and FAZ/FMG labs stay on the simulator.

Still to do after v0.8.12: the DNS/ICMP relay to the real Internet; SSH hops (a session from inside a session); dial-up IPsec, SD-WAN, VDOMs and HA on the real network; testing the phone runtime on the Xiaomi 17T.

### What v0.7.3 fixes

- The FortiOS schema had 9 attributes that were really wrapped "Type" cells from the reference tables (`address` under `system interface`, `system mobile-tunnel`, `user domain-controller`, `system central-management server-list`; `netmask` under `system ha`, `system dedicated-mgmt`, `system cellular-modem` modems). The CLI accepted `set address 10.10.10.1/24` on an interface and silently did nothing. Now it answers `command parse error before 'address'`, as FortiOS does; the extractor drops these artifacts.

### What v0.7.2 fixes

- `get router info routing-table database` lists static routes whose gateway is off the interface's subnet as `inactive` (they were hidden).
- B4.08: hint, root-cause explanation and lab notes now match what the simulator (and FortiOS) does: the old-gateway default route stays inactive, so there is no default route and debug flow shows "no route to destination".

### What v0.7.1 fixes

- A misspelling of a lab's own domain (edit distance 2 or less) no longer resolves to a generic public web host; it returns NXDOMAIN, so a typo can't look like a working site (found in B4.02).
- Drops by a deny policy now say so: "denied by policy 1 (name), action deny".

### What v0.7.0 adds (SecOps)

- `soc.js`: lab stories (`story:` on templates and parts) play timed events: FortiGate logs go through the normal log path (FortiAnalyzer, and FortiSIEM over syslog), Windows events land on hosts, EDR events get sequential ids from 1001 and record the policy mode at event time.
- FortiSIEM console: `cmdb`, `analytics … group-by=`, `rules`, `rule "<name>" enable|disable|threshold|exception`, `incidents`, `incident <id> [assign|clear]`. Events need a path: syslog from devices, Windows Agent over TCP 443. Default rules with thresholds and exceptions; incidents have deterministic ids.
- FortiEDR console: `inventory`, `policies`/`policy`, `events`, `event`, `forensics`, `classify`, `exception`, `remediate`, `isolate`/`unisolate`. Collectors need TCP 8081 to the manager; isolation is enforced on the host; simulation mode shows "Simulated Block".
- FortiAnalyzer SOC: `handlers`, `handler create|enable|disable`, `alerts`, `incident create <alert> assign=`, `incidents`.
- Grader: `siem`, `edr`, `fazinc` checks. Topology `andes-secops` (FSIEM-01, FEDR-01, CONTRACTOR-LT, collectors on DC-01/FIN-PC/HQ-PC) with a baseline story.
- Labs (track SecOps): S5.01 FortiSIEM go-live, S5.02 FortiEDR ransomware (4 parts), S5.03 EDR false positive, S5.04 FortiAnalyzer SOC. 71 labs, 107 parts.
- Modules: M9.01–M9.04 (S9 FortiSIEM), M10.01–M10.04 (S10 FortiEDR), M5.02 FMG Device Manager, M5.05 FMG operations, M6.02 FAZ devices and forwarding, M6.05 FAZ reports, M8.01 Security Fabric and automation, M8.04 Threat prevention at scale, M8.06 Central management at scale, M8.07 Troubleshooting master. Bundle: 967 cards and questions.
- Next (v0.8.0): capstone labs with sub-labs, modules S12, S0, S1, S3 and the rest of S11.

### What v0.6.4 adds (VDOMs, FortiSwitch, overlay)

- VDOMs (`fgt.js` + `vdom.js`): `set vdom-mode multi-vdom`, `config vdom` / `edit <name>` (creates VDOMs), `config global`; each VDOM is its own FortiGate instance (id `FGT[VDOM]`) sharing the global tables (interfaces, admins, HA, DNS…); per-VDOM / global command checks; inter-VDOM links (`config system vdom-link` creates `<name>0/1`, point-to-point segments); specs can declare `vdoms: {NAME: cli}`. Interfaces, routing, DHCP, ARP and debug output follow the VDOM that owns the port.
- FortiSwitch (`switch.js`): `kind: fortiswitch` devices cabled to a FortiLink interface; discovery creates the managed-switch entry by serial; authorization (`fsw-wan1-admin enable`); one L2 domain per FortiLink VLAN from port `vlan` settings; `status down` ports; `execute switch-controller get-conn-status`; switch console (`get system status`, `show switch interface`). Cables to switches are drawn but not used for forwarding.
- SD-WAN: members can be IPsec tunnels; member `source` for health-check probes (tunnels without an IP fail with a clear reason); reentrancy guard for probes through members.
- IPsec: phase2 without selectors means 0.0.0.0/0. Static routes whose gateway isn't on the interface subnet aren't installed (as in FortiOS).
- Grader: `fsw` check; `sdwan` checks take `hc` and `sla`; `dhcp` takes `expect: fail`.
- Topology: viewBox fits every device; switch access ports labelled at the device end; FortiSwitch glyph.
- Labs: D2.01 (3 parts), D4.01, W2.01 (3 parts), W4.01, W4.02, X3.02 (3 parts). Modules: M7.01, M7.02, M7.03, M8.05, M4.01, M4.02, M2.03.
- Not built: ADVPN emulation (dial-up FortiGate spokes and shortcuts); covered in M2.03 and M8.03 content instead.

### What v0.6.3 adds (dynamic routing)

- `routing.js`: a control plane computed per config version. OSPF: network statements, areas (regular/stub), passive interfaces, ospf-interface (cost, network type, hello/dead, text/MD5 auth, MTU, mtu-ignore, priority), adjacency rules (mask, area, timers, stub flag, auth, router ID, network type, MTU → ExStart), DR/BDR display, SPF with O / O IA / O E1 / O E2, redistribution, default-information-originate. BGP: eBGP/iBGP sessions (update-source, multihop, MD5, remote-as checks with FSM states and reasons), network statements with network-import-check, redistribution, prefix lists (ge/le), route maps (local preference, weight, MED, AS-path prepend), iBGP split horizon, route reflectors, next-hop-self, recursive next hops, best-path selection, distances 20/200.
- Lab routers can speak OSPF/BGP (`ospf:` / `bgp:` specs) and forward on learned routes; `show ip ospf neighbor`, `show ip bgp summary`, `show ip bgp`.
- FortiGate: `get router info ospf neighbor|interface|database`, `get router info bgp summary|network|neighbors [ip advertised-routes|received-routes]`, routing table with O/B codes and recursive next hops, `diagnose ip router ospf|bgp all enable`, `execute router clear bgp`.
- Grader: `ospf` and `bgp` checks; `route` checks take `type` and work on routers. Part events can patch a router's OSPF/BGP spec.
- Topologies `andes-ospf` (CORE-SW campus) and `andes-bgp` (carrier PE in AS 64600). Track "Routing".
- Labs: O2.01 (3 parts), O4.01–O4.03, G2.01 (3 parts), G4.01–G4.02. Modules: M2.01 OSPF, M2.02 BGP, M4.05 Routing on FortiGate, M8.02 Advanced routing.

### What v0.6.2 adds (identity)

- `auth.js`: directory servers are lab hosts with a `directory:` spec (users, groups, LDAP bind account and TLS requirements, NPS RADIUS clients and secret, FSSO collector agent with monitored groups and logons). LDAP (simple/anonymous/regular binds, cnid, DN, LDAPS/STARTTLS, server-identity-check against the certificate name, FQDN servers), RADIUS (client IP, shared secret, Fortinet-Group-Name groups, NPS policy), local users, `user group` with `match` entries, FSSO agents and `fsso-service` groups.
- Identity-based policies (`groups`, `users`): unauthenticated traffic falls through (auth-on-demand implicitly); if nothing else matches, HTTP/HTTPS gets the captive portal and hosts log in with `login <user> <password>`.
- Diagnostics: `diagnose test authserver ldap|radius`, `diagnose debug application fnbamd -1`, `diagnose firewall auth list|clear`, `diagnose debug authd fsso server-status|list`.
- Grader: `login`, `authserver`, `fsso` checks; probes take `as: [user, password]` or `fresh: true`. Part events can change the directory (`directory:`).
- Topology `andes-id` (DC-01 with AD/NPS/FSSO, servers segment on port4, FIN-PC).
- Labs: U1.01, U2.01 (3 parts), U2.02, U2.03, U4.01–U4.04. Modules: M4.06 Authentication, M3.04 Identity and access.

### What v0.6.1 adds (labs in sorties)

- Every lab carries `modules:` (curriculum ids it teaches; required by `build_labs.py`).
- Sorties: **Apply** ends with one emulated-CLI lab part for the module (projects and drills, unpassed and lower tier first), **PS Arena** ends with a live ticket, **Boss** ends with a ticket in exam mode as the final strike (it counts toward the 80 % pass).
- Lab parts are review items (`LAB.<lab>.<part>`): passing a part records a review (revealed = Again, hints = Hard, clean = Good), so struggled parts come back in Warm-up and Review.
- Sortie and review runs use their own save slot and start mid-lab with the earlier parts' reference solutions applied (`LabRun.jumpTo`), so they never disturb the catalogue run.

### What v0.6.0 adds (Labs)

- `utm.js`: security profiles on policies. SSL inspection (certificate / deep, wildcard-FQDN, address and regex exemptions; pinned sites and clients that don't trust the FortiGate CA give certificate errors under deep inspection), URL filter tables (simple, wildcard, regex; block, monitor, allow, exempt), antivirus on HTTP (EICAR test file). `curl` on lab hosts shows the block page, the AV alert or the certificate error. Traffic and UTM logs in FortiOS format.
- `mgmt.js`: FortiAnalyzer and FortiManager appliances with their own 8.0.2 CLI schemas. GUI actions are typed in the console: FAZ `devices`, `authorize`, `logview`, `fortiview`; FMG `devices`, `authorize`, `dbconsole` (edit the device database), `install preview`, `install`, `retrieve`, `revisions`. Logging and FGFM need a path to the appliance (log `source-ip` and `fmg-source-ip` over tunnels). FMG status: synchronized, modified, out of sync, unauthorized; install is blocked after a local change.
- DNS realism: any public-looking name now resolves (to a generic web host) unless the lab defines it; `.local`, `.lan`, `.internal`, `.corp`, `.home`, `.test` and similar stay NXDOMAIN. Fixes B4.01, where `google.com` failed after the fix.
- Lists in lab briefs keep wrapped lines in the same item. Appliance icons on the topology; console banner names the product.
- Schema fix: FAZ/FMG `allowaccess` is a multi-value option and `system route device` takes an interface name (corrected in `extract_cli.py`).

| Track | Labs |
|---|---|
| Profiles | P2.01 (2-part web filter + AV), P4.01 guest certificate errors |
| FortiAnalyzer | A2.01 (2-part logging + authorize), A2.02 RDP investigation, A4.01 no traffic logs ticket |
| FortiManager | M2.01 (3-part add, change, install), M4.01 branch missing ticket |
| Multi-product | X3.01 (3-part Security Fabric change window: FMG install, web filter, FAZ evidence) |

## Amendments to the blueprint

1. **All learning logic lives in the shared web JS** (FSRS, projections, planner, XP, medals, mastery). The Go core only stores events, serves content, opens the window and, later, syncs. Android will reuse the same `web/` folder unchanged.
2. **Mastery L2** counts a card as strong only when it has been *consolidated*: stability ≥ 7 days and retrievability ≥ 0.8. Same-day re-ratings can't reach L2.
3. **Module ids** use two digits inside a stage (CURRICULUM M4.3 → M4.03). The planned M4.3 (policies) and M4.4 (NAT) were merged into **M4.03**; M1.04 also covers the FortiGate route lookup from M4.5.
4. **Page citations** use the printed footer page of each guide. For the FortiOS 8.0.2 guide, PDF page ≈ printed page + 1.
5. **Kickoff I1** combines the recruiter screen, the WhyMe positioning and the diagnostic pretest.
6. **Sync is off on the PC until turned on** in Settings (avoids a firewall prompt at first launch). The hub listens on all interfaces and refuses non-LAN sources.
7. **One content pack** (`bundle`) instead of per-module packs for now. Bundle versions are `YYYY-MM-DD.HHMM`.

## Content

Sprint order follows the `order` field: interview track first (I1–I3), then foundations, FortiGate core, SD-WAN, PS mastery, FortiManager, FortiAnalyzer.

| # | Module | Cards | Quiz | Labs | Situations | Interview items |
|---|---|---|---|---|---|---|
| 1 | I1 Kickoff: recruiter screen and why you're a strong PS asset | 15 | 12 | 0 | 3 | 18 |
| 2 | I2 Hiring manager: prove you can deliver, own customers and ramp fast | 14 | 10 | 0 | 3 | 15 |
| 3 | I3 Technical panel: whiteboard designs and live troubleshooting | 12 | 10 | 0 | 3 | 12 |
| 4 | M1.03 Transport, state and NAT theory | 20 | 20 | 2 | 3 | 5 |
| 5 | M1.04 Routing fundamentals and the FortiGate route lookup | 20 | 19 | 2 | 3 | 5 |
| 6 | M4.03 FortiGate firewall policies, objects and NAT | 22 | 21 | 3 | 3 | 6 |
| 7 | M4.12 FortiGate diagnostics: debug flow, sniffer and sessions | 20 | 19 | 3 | 3 | 5 |
| 8 | M11.01 PS delivery: from kickoff to handover, plus your STAR bank | 18 | 14 | 2 | 3 | 12 |
| 9 | M11.02 Implementation craft and migrations: MOPs, cutovers and vendor conversions | 13 | 10 | 2 | 2 | 4 |
| 10 | M11.04 Design documents and customer handling: HLD, LLD, status, scope and escalations | 12 | 8 | 0 | 2 | 5 |
| 11 | M4.09 IPsec VPN on FortiGate: build, verify and troubleshoot | 19 | 14 | 2 | 3 | 5 |
| 12 | M4.10 High availability: FGCP clusters, failover and upgrades | 20 | 15 | 2 | 3 | 5 |
| 13 | M8.03 SD-WAN: members, health checks, rules and troubleshooting | 20 | 14 | 2 | 3 | 5 |
| 14 | M4.07 Certificates and SSL inspection: see inside encrypted traffic, safely | 19 | 13 | 2 | 3 | 5 |
| 15 | M4.08 Security profiles: AV, web and DNS filter, application control, IPS | 19 | 13 | 2 | 3 | 5 |
| 16 | M5.01 FortiManager foundations: architecture, ADOMs, devices and provisioning | 15 | 9 | 2 | 2 | 4 |
| 17 | M5.03 FortiManager Policy & Objects and the install process | 14 | 9 | 1 | 2 | 3 |
| 18 | M5.04 FortiManager SD-WAN and VPN Manager, FortiGuard, firmware and HA | 11 | 8 | 1 | 1 | 3 |
| 19 | M6.01 FortiAnalyzer foundations: modes, logs, storage, forwarding and HA | 14 | 9 | 2 | 1 | 3 |
| 20 | M6.03 FortiAnalyzer FortiView, Log View and Fabric View: investigating with logs | 11 | 7 | 1 | 1 | 2 |
| 21 | M6.04 FortiAnalyzer incidents, alerts, automation and reports | 11 | 7 | 2 | 1 | 2 |
| | **Total (21 modules)** | **339** | **261** | **33** | **51** | **129** |

Interview pool by stage: recruiter 17, hiring manager 40, technical 72.

## Roadmap

### v0.8.0: FortiTatake OS

A purpose-built Linux compiled from source on Jose's workstation by the FortiTatake PC app: minimal kernel (netns, veth, bridges, nftables, conntrack and helpers, XFRM, netem) plus musl, BusyBox and open-source protocol daemons (iproute2, nftables, tcpdump, dnsmasq, lighttpd, Dropbear, FRR, strongSwan, conntrackd), booting straight into the lab agent. Two signed builds from one source: x86_64 for Windows (QEMU with Windows Hypervisor Platform) and ARM64 for Android (QEMU shipped in the APK, emulated CPU), the Android build synced over Wi-Fi. Every lab device is a namespace; the agent compiles FortiOS config into Linux state and adds FortiOS behaviours (SD-WAN, FGCP, auth). Encryption keeps real algorithm names and negotiation with near-free maths underneath. Switches (VLAN-filtering bridges, RSTP, LLDP) and routers (FRR, vtysh console) are Linux namespaces too; no traffic inspection; the real Internet is reachable only for DNS and ICMP, through a relay in the app (not a VM network card); any link can be captured to pcap for Wireshark; On Android, stage 0 tries hardware virtualization (KVM/AVF if the phone allows it), then Linux as a native library (LKL), then the emulated CPU; each architecture gets a generic and a CPU-tuned build. FortiAnalyzer and FortiSIEM become lab devices with tiny web servers serving a product-like UI over real logs (no Fortinet artwork). Optimizations adopted: the FortiOS compiler, output formatting, grading and the FAZ/FSIEM consoles run natively in the app; a thin agent talks netlink and spawns no tools; read-only EROFS image; services start on first use; one FRR across routers as VRFs if stage 5 confirms it; memory balloon; one warm snapshot. Estimated lab engine RAM at most ~305 MB on Windows, ~370 MB on Android (VM paths) and ~135 MB on the LKL path. Stages 0–3 are v0.8.0 (stage 0 is a go/no-go spike). Decided: capstones and remaining modules follow as v0.9.0, the question overhaul as v0.10.0, then OS stages 4–7 as v0.11.0–v0.14.0, and FortiSASE on the real engine as v0.15.0 (OS stages come first). Blueprint: the "FortiTatake OS — Blueprint" doc (supersedes the Alpine-based one).

### v0.9.0: capstones and the last stages (done, see "What v0.9.0 adds")

- Labs: tier 6 capstones with sub-labs (timed, faults injected mid-lab, a customer who changes a requirement), including a cross-tool investigation (FortiSIEM + FortiEDR + FortiGate). MOP and acceptance-test deliverables.
- Modules: S12 (M12.01 design case, M12.02 exam simulations, M12.03 mock interview gauntlet), S0 (M0.01), S1 (M1.01, M1.02), S3 (M3.01, M3.02, M3.03, M3.05), S11 (M11.03, M11.05).
- New questions in these modules are written to the v0.10.0 rules below from the start.
- Small fixes reported from use (output that looks wrong to a FortiOS eye).

### v0.10.0: question quality overhaul (done, see "What v0.10.0 adds")

**Problem.** In many questions the right option can be picked without knowing the subject: it is the longest and most specific, it is the only one that hedges, and the wrong options are things no practitioner would choose. Questions must make you think, above all in SecOps and non-fundamental topics.

**Scope.** Every multiple-choice item in the app: all module quizzes (pretests included), so also every Warm-up, Apply and Boss strike drawn from them. Today that is 385 questions in 50 modules (265 single, 48 multi, 28 order, 23 text, 15 numeric, 6 output), plus anything v0.8.0 adds. Text and numeric items are checked for accepted answers that are too loose.

**Rules for every wrong option.** Each one must be one of:

1. A real misconception a mid-level engineer holds (e.g. "a firewall policy to the broadband interface makes guest traffic use broadband": routing picks the egress before policy match).
2. A true statement that doesn't solve this problem (valid technique, wrong scope or side effect).
3. A near-miss: the right idea with one wrong detail (wrong strategy, wrong order, wrong default, wrong port).

Its `why_wrong` names the misconception it targets. No option that a practitioner would dismiss on sight.

**Rules for the set of options.**

- Same length and grammatical shape (correct option within about ±20 % of the average length).
- Hedges, parentheses, examples and qualifiers appear in wrong options as often as in the right one.
- No absolute words ("always", "never", "only") used only in wrong options.
- The right option doesn't repeat the stem's wording more than the others do.
- At least one distractor is "almost right" for tier 2+ questions; at least two for tier 3+.
- Correct position is random after shuffling (already done at display time).

**New formats** (mix them in, mainly tier 3+ and every Boss):

- Output-based: a debug flow, routing table, IKE debug, FortiSIEM incident or FortiEDR event; pick the cause. Distractors are causes that produce similar output.
- Best first step: all options are valid actions; only one comes first.
- Answer plus reason: pick the answer, then pick why; both must be right.
- Select all that apply without telling how many.
- "Which would NOT work".
- Confidence rating on Boss and review items: a confident wrong answer costs more XP and returns sooner in review.

**Tooling.**

- `build_content.py` lint (fails the build): length outlier, hedge or parenthesis only in the right option, absolute words only in wrong options, stem overlap only in the right option, missing or generic `why_wrong` ("No.", "Unrelated."), tier 3+ without enough near-misses.
- Blind-guess test: a separate agent with no access to the material answers every question from test-taking cues alone. Any item it gets right is rewritten. Target: blind accuracy no better than chance (about 25 % on 4 options).
- Usage signal: an item answered right in under 5 seconds on 3 reviews in a row is flagged "too easy" and listed for the next content pass.

**Order of work.** S9 FortiSIEM and S10 FortiEDR → S8 Enterprise Firewall → S5 FortiManager and S6 FortiAnalyzer → S11 Professional Services → S2, S4, S7 → S1, S3, S0 fundamentals (recall may stay simpler there, but no throwaway options).

**Done when.**

- Every question passes the lint.
- The blind-guess test scores at or below chance on every stage.
- Each module has at least one output-based or best-first-step question at tier 3+.
- STATUS records the before/after counts and blind-guess scores per stage.

### v0.11.0–v0.14.0: FortiTatake OS stages 4–7 (v0.11.0 done: kernel, cgroups, office traffic; v0.12.0 done: threat packs and the inline IPS)

Before any FortiSASE engine work. Stage 4: FRR routers and BGP/OSPF on the real engine for every routing lab. Stage 6: strongSwan-backed IPsec interop with third-party peers and ADVPN shortcuts. Decided by Jose (2026-11-25): the Range screen is its own app section; the EDR console follows FortiEDR's screens and workflow, adapted for phones, in FortiTatake's own style (no Fortinet logos, artwork or copied screens). Dropped by Jose (2026-11-25): stage 5 (one FRR across routers as VRFs, memory balloon, warm snapshot) and stage 7 (Android KVM/AVF and LKL paths, CPU-tuned builds). Each stage ships with the tier-run probe check (simulator vs kernel, 0 disagreements).

### v0.15.0: FortiSASE on the real engine

PoP namespaces, the FortiClient agent tunnel (IPsec), SPA hubs with BGP per overlay, ZTNA with posture tags, log forwarding to the lab FortiAnalyzer/FortiSIEM. Blueprint: "Labs on the real engine — SOC, SecOps and SASE" doc.

## Open decisions

1. Interview dates (recruiter, hiring manager, technical) for sprint mode.
2. Repo visibility: it is public now. The interview modules contain personal positioning, so **private is recommended**.
3. Name spelling: FortiTatake (current) vs FortiTatakae.
4. Default sessions per day and usual start times.
5. Job description for req. 24928, if available.

## Inputs a session may need to ask for

- Guides:
  - FortiOS-8_0_2-Administration_Guide.pdf
  - FortiAnalyzer-8_0_2-Administration_Guide.pdf
  - FortiManager-7_6_8-Administration_Guide.pdf
  - FortiSwitchOS-8.0.2-Administration_Guide_Standalone_Mode.pdf
  - FortiSIEM-7.6.1-User_Guide.pdf
  - FortiEDR-7.2.5-Administration_Guide.pdf
- Threat landscape: 2026 DBIR (md), Cost of a Data Breach Report 2026 (md).
- Personal evidence: the latest super-cv zip; cato_interview_cheatsheet.pdf.
