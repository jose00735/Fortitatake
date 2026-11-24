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

### Next in the queue (labs)

1. v0.6.x users (LDAP/FSSO), more integration labs (VPN over SD-WAN, HA + VPN), FortiSwitch, BGP/OSPF/ADVPN, VDOMs, more break-fix per technology.
2. v0.7.0 SecOps consoles: FortiAnalyzer SOC, FortiSIEM, FortiEDR, log generator.
3. v0.8.0 Capstones and multi-product integration labs.

### Next in the queue (study content)

Ids follow CURRICULUM.md, written with two digits (M4.9 → M4.09).

1. S12 Capstone: M12.3 mock interview gauntlet, M12.1 full design case, M12.2 exam simulations.
2. S8 Enterprise Firewall: Security Fabric, OSPF/BGP on FortiGate, threat prevention at scale, VDOMs and advanced HA, FMG+FAZ together, troubleshooting master.
3. S4 remaining: M4.01 administration, M4.02 interfaces, M4.05 routing (partly in M1.04), M4.06 authentication, M4.11 logging.
4. S2 routing (OSPF, BGP, WAN concepts) and S3 security theory.
5. S7 FortiSwitch, S9 FortiSIEM, S10 FortiEDR.
6. S0 full diagnostic and S1 M1.01–M1.02.

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
