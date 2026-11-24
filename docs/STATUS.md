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

### Proposed v0.8.0: FortiTatake OS (order pending Jose's decision)

A purpose-built Linux compiled from source on Jose's workstation by the FortiTatake PC app: minimal kernel (netns, veth, bridges, nftables, conntrack and helpers, XFRM, netem) plus musl, BusyBox and open-source protocol daemons (iproute2, nftables, tcpdump, dnsmasq, lighttpd, Dropbear, FRR, strongSwan, conntrackd), booting straight into the lab agent. Two signed builds from one source: x86_64 for Windows (QEMU with Windows Hypervisor Platform) and ARM64 for Android (QEMU shipped in the APK, emulated CPU), the Android build synced over Wi-Fi. Every lab device is a namespace; the agent compiles FortiOS config into Linux state and adds FortiOS behaviours (SD-WAN, FGCP, auth). Encryption keeps real algorithm names and negotiation with near-free maths underneath. Stages 0–3 are v0.8.0 (stage 0 is a go/no-go spike); one minor version per later stage. Blueprint: the "FortiTatake OS — Blueprint" doc (supersedes the Alpine-based one).

### v0.8.0: capstones and the last stages

- Labs: tier 6 capstones with sub-labs (timed, faults injected mid-lab, a customer who changes a requirement), including a cross-tool investigation (FortiSIEM + FortiEDR + FortiGate). MOP and acceptance-test deliverables.
- Modules: S12 (M12.01 design case, M12.02 exam simulations, M12.03 mock interview gauntlet), S0 (M0.01), S1 (M1.01, M1.02), S3 (M3.01, M3.02, M3.03, M3.05), S11 (M11.03, M11.05).
- New questions in these modules are written to the v0.9.0 rules below from the start.
- Small fixes reported from use (output that looks wrong to a FortiOS eye).

### v0.9.0: question quality overhaul (all existing content)

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
