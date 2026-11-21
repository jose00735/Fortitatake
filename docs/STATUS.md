# FortiTatake — Status

> Updated by every build or content session. Read this first.

## Build

| Phase | State |
|---|---|
| P0 Blueprint | Done, v0.1 (21 Nov 2026) |
| P1 Engine MVP (Windows) | **Done, v0.1.0 (21 Nov 2026).** Go core + WebView2 window, event store, all ten session blocks, review, library, interview studio, progress, medals, both skins |
| P2 Android + LAN sync (FTSP/1) | Not started. Next build session |
| P3 Advanced items (topology, packet diagrams, voice capture) | Not started |

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

- No embedded .ico in the exe yet (Explorer shows the default icon; the window and pages use the shield).
- Session timing is a guide: blocks end when the work is done, not when the clock says.
- Self-scored drills and situations depend on honest scoring.

## Amendments to the blueprint

1. **All learning logic lives in the shared web JS** (FSRS, projections, planner, XP, medals, mastery). The Go core only stores events, serves content, opens the window and, later, syncs. Android will reuse the same `web/` folder unchanged.
2. **Mastery L2** counts a card as strong only when it has been *consolidated*: stability ≥ 7 days and retrievability ≥ 0.8. Same-day re-ratings can't reach L2.
3. **Module ids** use two digits inside a stage (CURRICULUM M4.3 → M4.03). The planned M4.3 (policies) and M4.4 (NAT) were merged into **M4.03**; M1.04 also covers the FortiGate route lookup from M4.5.
4. **Page citations** use the printed footer page of each guide. For the FortiOS 8.0.2 guide, PDF page ≈ printed page + 1.
5. **Kickoff I1** combines the recruiter screen, the WhyMe positioning and the diagnostic pretest.

## Content

Sprint order for the first 24 hours (six sorties of about 4 hours):

| # | Module | Cards | Quiz | Labs | Situations | Interview items | Version |
|---|---|---|---|---|---|---|---|
| 1 | I1 Kickoff: recruiter screen and why you're a strong PS asset | 15 | 12 | 0 | 3 | 18 | 2026-11-21 |
| 2 | M1.03 Transport, state and NAT theory | 20 | 20 | 2 | 3 | 5 | 2026-11-21 |
| 3 | M1.04 Routing fundamentals and the FortiGate route lookup | 20 | 19 | 2 | 3 | 5 | 2026-11-21 |
| 4 | M4.03 FortiGate firewall policies, objects and NAT | 22 | 21 | 3 | 3 | 6 | 2026-11-21 |
| 5 | M4.12 FortiGate diagnostics: debug flow, sniffer and sessions | 20 | 19 | 3 | 3 | 5 | 2026-11-21 |
| 6 | M11.01 PS delivery: kickoff to handover, plus the STAR bank | 18 | 14 | 2 | 3 | 12 | 2026-11-21 |
| | **Total** | **115** | **105** | **12** | **18** | **51** | |

Interview pool by stage: recruiter 17, hiring manager 13, technical 21.

### Next in the queue

Ids follow CURRICULUM.md, written with two digits (M4.9 → M4.09).

1. M8.03 SD-WAN deep dive (members, zones, SLA, rules, ADVPN), with M2.3 concepts folded in.
2. M4.09 VPN on FortiGate (site-to-site, dial-up, troubleshooting).
3. M4.10 High availability (FGCP, failover, upgrades).
4. M4.07 Certificates and SSL inspection, then M4.08 Security profiles.
5. I2 hiring-manager and I3 technical-panel kickoff modules (the STAR bank already lives in M11.01).
6. S5 FortiManager and S6 FortiAnalyzer.
7. Fundamentals gaps (M0/M1 remaining modules) if pretest scores show weakness.

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
