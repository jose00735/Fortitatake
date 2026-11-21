# FortiTatake — Blueprint

> Status: **v0.1 draft for approval** · 21 Nov 2026
> Owner: José Acosta Hernández · Built with Claude
> Companion specs: [CURRICULUM.md](CURRICULUM.md) · [CONTENT-SPEC.md](CONTENT-SPEC.md) · [SYNC-PROTOCOL.md](SYNC-PROTOCOL.md)

FortiTatake is an intensive study engine for one mission: **win the three Fortinet interviews for Professional Services Consultant** (recruiter, hiring manager, technical) and, on the way, **rebuild certification-level mastery** of FortiGate/FortiOS, FortiManager, FortiAnalyzer, FortiSwitch, FortiSIEM and FortiEDR. It runs on Windows (Go + web UI) and Android, and keeps progress in sync over the local network.

The engine is built once. Content arrives as **modules**, generated one per request over the coming days, in the order set in CURRICULUM.md.

---

## 1. Goals and success criteria

| Goal | Measured by | Target |
|---|---|---|
| Pass the recruiter screen | I1 drill pool complete, 30 s / 90 s / 3 min pitch rehearsed | All I1 questions self-scored ≥ 4/5 |
| Pass the hiring-manager interview | I2 STAR bank complete, PS scenarios answered | 12 stories ready; scenario rubric ≥ 4/5 |
| Pass the technical interview | Stage mastery on S1–S4, S8, S11; design whiteboard drills | Mastery ≥ L4 on those stages |
| Exam-level knowledge (expired certs) | Timed exam simulations per track | ≥ 80 % on each simulation, twice in a row |
| Long-term retention | FSRS retrievability across all cards | ≥ 0.90 at 30 days |
| Keep showing up | Sessions completed vs planned | ≥ 85 % of planned sessions |

Non-goals: being a general LMS, multi-user accounts, cloud sync, or AI grading inside the app (all of it works offline).

---

## 2. Who uses it and how (design brief, impeccable "shape")

- **Job and audience.** One learner: a former Fortinet TAC P3 engineer with expired certs, preparing for PS interviews under time pressure. He studies in **4-hour sessions** at his Windows desk and reviews on his **Android phone** between sessions.
- **Mode.** Operate (sessions, quizzes, reviews) with Read surfaces (reading chunks). The tool must disappear into the task: one click to resume, always obvious what comes next.
- **Outcome and proof.** Success is "I know what to do next and I can see I am getting better": mastery bars per topic, medals, retention curve, interview readiness meter.
- **Product-specific truth.** Every fact cites its official guide and page. Every "why" ties to the real 2026 threat landscape (Verizon DBIR 2026, IBM Cost of a Data Breach 2026). Every interview answer is built only from his real, evidenced experience (super-cv).
- **Two pinned visual worlds** (see §8): a Fortinet-like enterprise skin and a Doom Eternal-inspired skin, switchable at any time.
- **Anti-goals.** No streak guilt, no decorative motion during study, no walls of text (readings are chunked to ≤ 12 minutes), no invented metrics in interview answers.

---

## 3. Learning method: what the research says and how the app applies it

Each feature exists because it maps to a well-supported learning method.

| Method | Why it works | How FortiTatake applies it |
|---|---|---|
| **Retrieval practice** (testing effect) | Pulling information out of memory strengthens it more than re-reading | Every reading chunk ends with recall prompts; quizzes before explanations |
| **Spaced repetition** (FSRS scheduler) | Reviews timed just before forgetting give the most retention per minute | All flashcards and missed quiz items enter an FSRS queue, target retention 0.90 |
| **Pretesting** | Guessing before learning primes attention, even when the guesses are wrong | Each module opens with 5–8 ungraded questions |
| **Interleaving** | Mixing topics trains choosing the right tool, not just using it | Once a topic reaches L2, its items join mixed review blocks and boss quizzes |
| **Elaborative interrogation** | Asking "why is this true?" links new facts to what you know | `:::why` prompts inside readings; every answer explains the why |
| **Self-explanation / Feynman** | Explaining in plain words exposes gaps | "Explain it to the customer" boxes, compared with a model answer |
| **Worked → faded examples** | Novices learn from full examples; experts from solving | CLI labs go worked example → partly blank → blank |
| **Dual coding** | Words plus diagrams beat words alone | Figures from the official guides, packet-flow walk-throughs |
| **Concrete, case-based learning** | Real situations make knowledge usable | PS scenarios and incident "raids" with what / why / how |
| **Deliberate practice + feedback** | Targeted practice at the edge of ability | The planner pulls the weakest topics; rubrics show exactly what was missing |
| **Metacognitive calibration** | Knowing what you don't know steers study time | Confidence rating before each reveal; calibration chart |
| **Desirable difficulty ladder** | Difficulty rising just ahead of skill keeps learning efficient | Items tagged D1–D5; each module climbs the ladder |
| **Chunking and cognitive load** | Working memory is small | Units ≤ 12 min reading; one idea per card |
| **Distributed practice and rest** | Breaks and sleep consolidate memory | Enforced breaks; the 3rd session of a day is review-only by default |
| **Rehearsal out loud** | Interviews are spoken | Spoken drills with recording, rubric self-scoring, export to TeleCyborg |
| **Motivation (competence, autonomy)** | Visible progress keeps effort going | XP, levels, medals, boss fights, choice of skin and session count |

---

## 4. The learning loop

### 4.1 The 4-hour session ("Sortie")

Sessions are fixed at 4 hours. Jose chooses 1, 2 or 3 sessions per day. The planner fills each session from the template below, using the curriculum queue and his weakest topics.

| Time | Block | Contents |
|---|---|---|
| 0:00–0:20 | **Warm-up** | Due FSRS reviews (capped at 20 min, overdue first) |
| 0:20–0:30 | **Pretest** | 5–8 ungraded questions on today's module |
| 0:30–1:20 | **A · Learn** | 3–4 reading chunks (≤ 12 min each). Each ends with 2–3 recall prompts and one `why` prompt. Figures from the official guides. |
| 1:20–1:30 | Break | Stand-up screen; a 2-minute *Field Report* (a threat-landscape fact) is optional |
| 1:30–2:20 | **B · Apply** | Worked → faded → solo CLI and configuration labs; output-reading drills ("what's wrong in this debug?") |
| 2:20–2:30 | Break | |
| 2:30–3:20 | **C · PS Arena** | Two PS situations and one incident raid: your plan → the right thinking → what / why / how → what a great answer adds → the best way to say it |
| 3:20–3:30 | Break | |
| 3:30–4:00 | **D · Boss & Close** | Interleaved timed quiz (mixed topics), two spoken interview drills, reflection (learned / confused / next), write 3 of your own flashcards |

Rules:
- **Session 2** of the day continues the module or starts the next one.
- **Session 3** is *Consolidation* by default: no new material; interleaved review, exam simulations, mock interviews. It can be switched to learning mode if he insists.
- After 8 hours of study in a day the app shows a rest reminder. It never blocks.
- A session can be paused and resumed on the other device (state is synced).
- **Sprint mode** (when an interview date is set): the planner raises the weight of the matching interview track and the modules it depends on.

### 4.2 Difficulty ladder

Every item has a difficulty tier tied to a Bloom level:

| Tier | Bloom | Example |
|---|---|---|
| D1 Recall | Remember | "Which protocol does FortiManager use to manage FortiGates?" |
| D2 Understand | Understand | "Why does central NAT change how policies match?" |
| D3 Apply | Apply | "Write the CLI for a VIP with port forwarding" |
| D4 Analyze | Analyze / troubleshoot | "Read this `diagnose debug flow` output: why is the traffic dropped?" |
| D5 Design | Evaluate / create | "Design SD-WAN for 40 branches with two ISPs and a DC pair" |

Within a module, units climb D1 → D5. Across the curriculum, vendor-neutral fundamentals come first, then the FortiGate core, then management and analytics, then the advanced and specialist products, then PS mastery and capstone.

### 4.3 Mastery levels (per topic)

| Level | Name | Rule |
|---|---|---|
| L0 | Unseen | No exposure |
| L1 | Exposed | Read the units |
| L2 | Recall | ≥ 70 % of cards at retrievability ≥ 0.80 |
| L3 | Apply | ≥ 75 % on D3 items (first try) |
| L4 | Analyze | ≥ 75 % on D4 items and scenarios (rubric ≥ 3.5/5) |
| L5 | Master | Stage boss beaten and exam simulation ≥ 85 % |

Mastery can decay: if retrievability drops, the level drops one step until the reviews are done.

### 4.4 Answer frameworks taught by the app

These come from Jose's own Cato interview cheatsheet. They are used in every model answer so they become habits.

- **Technical answer:** anchor definition (plain words) → contrast with the older way → rule of three (pillars) → one protocol-level mechanism → troubleshooting flow (L1 → L7: verify, logs, policy, escalate with a timeline) → business impact.
- **Behavioral answer:** context → specific actions → measurable result (STAR), then the **concrete audit** (swap vague nouns for real products and names), **quantify** the "so what", and the **strategic link** (why this path, what he owned).
- **PS situation ("right thinking"):** clarify the ask → assess risk and blast radius → plan with a rollback → validate → communicate → document.
- **Every model answer ends with** *what a great answer adds* and *the best way to say it* (a polished phrasing he can memorize).

---

## 5. Content types

Detailed schemas live in CONTENT-SPEC.md. Summary:

| Type | Purpose | Notes |
|---|---|---|
| Reading unit | Learn a concept | Markdown chunk ≤ 900 words with `recall`, `why`, `diagram`, `cli`, `pitfall`, `threat`, `delta` (version-difference) callouts |
| Flashcard | Memorize | Basic, reverse, cloze, image occlusion on guide figures |
| Quiz item | Check and train | Single or multiple choice (exam style, with an explanation for every wrong option), ordering, matching, numeric (subnetting), CLI fill-in, output reading, diagram hotspot |
| Lab | Apply | Worked → faded → solo configuration sequences, checked by a tolerant CLI matcher |
| PS situation | Think like a consultant | Situation, constraints, stakeholders, ask → right thinking, what / why / how, pitfalls, threat link, rubric, model answer, could-have-added, best way to say it |
| Raid | Hypothetical incident | Branching, multi-step ("40 branches dropped after an FMG install — go"), timed |
| Interview question | Rehearse | Stage (recruiter, HM, technical), what they are really testing, framework, model answer, follow-ups, could-have-added, best way to say it |
| Field Report | Motivation and "why" | 2-minute reading tying a threat-landscape fact to the module |
| Boss | Stage exam | Timed mixed quiz plus one raid; HP bar |
| Exam simulation | Certification readiness | Timed, exam-format, per track |

**Question pool targets.** Each module ships with 30–50 flashcards, 40–80 quiz items, 3–6 labs, 3–5 PS situations and 10–20 interview questions. Across 65 modules that is roughly **2,500 flashcards, 3,500 quiz items, 250 scenarios and 900 interview questions**. The interview track adds its own pools (recruiter about 40, hiring manager about 120, technical about 200 open questions).

---

## 6. Curriculum overview

The full map, with sources and page ranges, is in CURRICULUM.md. Two tracks run in parallel.

**Mastery track** (ordered by rising difficulty, fundamentals first):

| Stage | Name | Modules |
|---|---|---|
| S0 | Orientation and diagnostic | 1 |
| S1 | Network foundations | 4 |
| S2 | Routing and WAN protocols | 3 |
| S3 | Security, crypto and identity foundations, and the 2026 threat landscape | 5 |
| S4 | FortiGate core (FortiGate Administrator / NSE 4 level, FortiOS 8.0) | 12 |
| S5 | FortiManager (FortiManager 7.6 Administrator) | 5 |
| S6 | FortiAnalyzer (FortiAnalyzer Analyst) | 5 |
| S7 | FortiSwitch (FortiSwitch Administrator) | 3 |
| S8 | Enterprise Firewall (NSE 7 level) | 7 |
| S9 | FortiSIEM (FortiSIEM Analyst) | 4 |
| S10 | FortiEDR (FortiEDR Administrator) | 4 |
| S11 | Professional Services mastery | 5 |
| S12 | Capstone: design case, exam simulations, mock interviews | 3 |

**Interview track** (available from day one):

| Track | Contents |
|---|---|
| I1 Recruiter | Pitch (30 s / 90 s / 3 min), why Fortinet again, why PS, availability, travel, salary range, the Netskope exit (neutral, private), English check, questions to ask |
| I2 Hiring manager | STAR bank from real evidence, PS delivery situations, gap handling ("have you led full implementations?"), questions to ask |
| I3 Technical | Whiteboard designs, live troubleshooting, configuration questions, FMG/FAZ operations, "explain it to the customer" |
| WhyMe | "Why I'm a strong PS asset": ex-Fortinet P3, knows FortiOS and TAC from inside, partner PS QA at Netskope, customer-facing, trilingual, travel-ready. Built only from super-cv evidence |

**Certification naming.** Fortinet renamed its exams in 2025 and moved to NSE levels by track on 15 July 2026 (FortiGate Administrator → NSE 4; FortiManager Administrator → NSE 6 Secure Networking; FortiAnalyzer Analyst → NSE 5 Security Operations; FortiSwitch Administrator → NSE 5 Secure Networking; Enterprise Firewall Administrator → NSE 7 Secure Networking). The app tags items by **exam track** ("FortiGate Administrator", "Enterprise Firewall", …), not by level numbers. Each exam simulation module re-checks the current official exam description before it is generated.

**Versions.** The source guides are FortiOS 8.0.2, FortiAnalyzer 8.0.2, FortiManager 7.6.8, FortiSwitchOS 8.0.2, FortiSIEM 7.6.1 and FortiEDR 7.2.5. Exams currently target 7.4/7.6, so readings carry `delta` callouts where 8.0 differs. For example, the FortiOS 8.0 guide calls the browser-based (web-mode) SSL VPN **Agentless VPN** and covers remote access under IPsec VPN.

---

## 7. Gamification

**XP.** Correct on first try only (no farming):
- review: 1 XP (2 if overdue and recalled)
- quiz item: 2 × difficulty
- lab: 15–40
- PS situation: up to 50 (by rubric)
- raid: up to 120
- boss: 300
- exam simulation: 400
- mock interview: 200

**Levels.** 30 levels; XP for the next level = 150 + 50 × current level. Every 5 levels is a **rank**, named by the active skin:

| Levels | Fabric skin | Hellforge skin |
|---|---|---|
| 1–5 | Trainee | Kindling |
| 6–10 | Associate | Ember |
| 11–15 | Professional | Blaze |
| 16–20 | Specialist | Inferno |
| 21–25 | Expert | Hellforged |
| 26–30 | Architect | Unbroken |

**Medals** (examples; the full list grows with modules):

| Medal | Earned by |
|---|---|
| First Sortie | Completing the first full session |
| Subnet Sniper | 50 subnetting items correct in a row |
| Debug Flow Whisperer | 20 D4 debug-output items at ≥ 90 % |
| Best-Path Oracle | Perfect BGP best-path ordering, 3 times |
| Zero Bypass | Perfect score on a security-profiles boss |
| Split-Brain Slayer | Beating the HA boss |
| Change Window Hero | Perfect score on a cutover raid |
| Iron Retention | 30 days at ≥ 0.90 retrievability |
| Calibrated | Confidence accuracy ≥ 85 % over 200 items |
| Triple Sortie | Three sessions in one day (at most once a week, so it never rewards burnout) |
| Recruiter Ready / HM Ready / Panel Ready | Interview track thresholds met |
| Stage medals | One per stage at L5 (bronze, silver, gold by score) |

**Streaks without guilt.** A streak counts study days. Two "shield" days a week are allowed; missing a day never resets visible progress.

**Bosses and raids.** Each stage ends with a boss: a timed mixed quiz plus a raid. The boss has an HP bar; correct answers deal damage and wrong ones cost you HP. Boss and raid failures feed the weakest-topic planner.

---

## 8. Experience design and skins

Built with the **impeccable** design workflow:
- `init` writes PRODUCT.md from this brief.
- The two worlds are pinned by this brief (the brief wins).
- `new-work` concept rounds decide the composition of the main surfaces: Home, Session runner, Review, Library, Interview Studio, Progress.
- The study surfaces are **Operate mode**: system-familiar controls, 150–250 ms state motion only, every component with all states. Heavy expression is saved for **moments**: level up, medals, boss intros, skin switch.

**Main surfaces**
1. **Home ("Command")**: next session card (one button: *Start sortie*), today's due reviews, interview countdowns, mastery map.
2. **Session runner**: block timeline at the top, one task at a time, keyboard first (Space reveals; 1–4 rate; Enter submits).
3. **Review**: FSRS queue, quick-fire.
4. **Library**: stages → modules → units; search across everything; citations open the source page reference.
5. **Interview Studio**: recruiter / HM / technical pools, record a spoken answer, self-score with the rubric, compare with the model answer, export to TeleCyborg.
6. **Progress**: mastery heat map, retention curve, calibration chart, XP and medals, weak-topic list.
7. **Settings and Sync**: skin, sessions per day, interview dates, paired devices.

**Skin 1, "Fabric" (Fortinet-like enterprise).**
- Restrained palette: cool neutral grays, white or graphite surfaces, one Fortinet-style red accent reserved for primary actions and state.
- System UI font.
- Dense, calm and professional, with a dark variant.

**Skin 2, "Hellforge" (Doom Eternal-inspired).**
- Dark charcoal and gunmetal surfaces, molten orange-red accents, industrial heavy display type for headings only.
- HUD-style counters, metallic textures and ember particles on *moments* (level up, boss intro).
- Louder boss fights; skin-specific microcopy, ranks and medal flavor text.
- All art is original: no Doom logos, characters, symbols, music or screenshots.

Skins are implemented as design-token sets (`[data-skin="fabric"|"hellforge"]`) plus a small microcopy dictionary, so every component works in both. Reduced-motion settings disable particles and screen effects.

**Icon.**
- The default is an original mark: a firewall-grid shield in Fortinet-style red on a molten, hellforge-style background.
- The app can't reproduce Fortinet's real logo. If Jose wants it for his own copy, he can swap in his own icon file locally.

---

## 9. Architecture

```
fortitatake/
  core/                Go: content loader, planner, FSRS scheduler, quiz/lab checkers,
                       scoring, gamification, event store, projections, sync (FTSP/1)
  cmd/fortitatake/     Windows app: WebView2 window (pure Go, CGO off), local server
  cmd/ftcore/          Same core as a headless server, cross-compiled for android/arm64
  web/                 Shared UI: vanilla HTML/CSS/JS, two skins, no build step
  android/             Kotlin shell: WebView, starts ftcore, NSD discovery, QR pairing
  content/             Module sources (Markdown + YAML), original text with page citations
  tools/ftpack         Builds content packs (.ftpack) and validates them (ft lint)
  tools/assetx         Extracts and crops figures from the official PDFs (local only)
  assets-local/        Extracted guide figures — gitignored, never committed
  docs/                This blueprint and the specs
```

**One engine, two platforms.** The Go core contains all logic. The UI is the same web front end on both platforms. This is the pattern already proven in TeleCyborg:
- **Windows:** `fortitatake.exe` runs the core on `127.0.0.1:<random port>` with a per-launch token header and opens a WebView2 window (browser fallback). Data lives in `%APPDATA%\FortiTatake\`.
- **Android:**
  - The Kotlin shell starts the same core, cross-compiled to `android/arm64` (pure Go), shipped as `libftcore.so` in the APK's native-library folder and run from there. It is bound to `127.0.0.1` with a token, and the WebView loads it.
  - No NDK is needed. Plan B, if Android blocks that approach, is `gomobile bind`.
  - Minimum Android 8 (API 26).
- **Storage:**
  - An append-only **event log**: JSON Lines segments with an fsync per batch, plus periodic snapshots of the projections.
  - No SQLite, which keeps the build free of CGO and portable to Android.
  - Expected size is tens of thousands of events.
- **Event sourcing:**
  - Every action is an immutable event: review, quiz attempt, lab result, scenario score, drill, session block, settings change, user-made card, pack install.
  - All state (FSRS card states, XP, mastery, medals, streaks) is a **projection** rebuilt by replaying events in a deterministic order.
  - This is what makes LAN sync conflict-free.
- **Sync:** FTSP/1 over the LAN, Windows as hub and Android as spoke. mDNS discovery, QR pairing with certificate pinning, and version-vector exchange of events. Content packs travel from hub to phone. Full spec in SYNC-PROTOCOL.md.
- **Scheduler:** FSRS, with default parameters at first and re-fitted to his own review history after about 1,000 reviews. Target retention is 0.90 (adjustable).
- **Planner:** builds each session from:
  - the curriculum queue (next module)
  - the due reviews
  - weakness scores (low mastery × high interview or exam weight)
  - sprint-mode weights
  - the session template
- **Checkers:**
  - Exact and multiple choice.
  - Ordered lists.
  - Numeric checks with tolerance.
  - A tolerant CLI matcher: normalizes whitespace and quotes, accepts abbreviations FortiOS accepts, compares `config/edit/set/next/end` trees instead of raw text.
  - Rubric self-scoring for open answers.
- **Audio drills:** the WebView's MediaRecorder; files stay on the device (opt-in sync as blobs).
- **Export:**
  - Interview answers to **TeleCyborg** script format (front matter with `title`, `wpm`, `target`, `lang`).
  - Full backup to `.ftbackup` (events, settings, packs list).
- **Accessibility:** keyboard first on desktop, large touch targets on Android, high-contrast and reduced-motion options, every state visible without color alone.

---

## 10. Content pipeline and sources

1. **Sources.** The official guides Jose provided:
   - FortiOS 8.0.2 Administration Guide (5,619 pp.)
   - FortiAnalyzer 8.0.2 Administration Guide (697 pp.)
   - FortiManager 7.6.8 Administration Guide (1,247 pp.)
   - FortiSwitchOS 8.0.2 Administration Guide, Standalone Mode (580 pp.)
   - FortiSIEM 7.6.1 User Guide (1,860 pp.)
   - FortiEDR 7.2.5 Administration Guide (467 pp.)

   Threat landscape: Verizon 2026 DBIR, IBM Cost of a Data Breach Report 2026. Personal evidence: super-cv, the Cato cheatsheet frameworks, his CVs.
2. **Generation.** Each module is generated in its own session (see the generation contract in CONTENT-SPEC.md). The module's page ranges are read straight from the guides. Text is written fresh and paraphrased, never copied. CLI syntax is reproduced as needed. Every item carries a citation (guide, version, page).
3. **Figures.** `tools/assetx` renders the cited pages and crops figures into `assets-local/<module>/` with a `figures.yaml` (guide, page, crop box, caption). They ship to devices inside the module's asset pack, **not** in the git repo.
4. **Validation.** `ft lint` checks schemas, unique stable IDs, citations on every item, the difficulty mix, word limits and orphaned assets.
5. **Packaging.** `ftpack` bundles module content and assets into `<module>@<version>.ftpack` (zip plus manifest and sha256). The Windows app imports packs, and sync pushes them to the phone.

**Copyright and repo visibility.**
- The GitHub repo `jose00735/fortitatake` is currently **public**.
- Fortinet's guides and figures are copyrighted, so the repo holds only original text and citations, and guide figures stay in `assets-local/` (gitignored).
- **Recommendation: make the repo private** if you ever want packs with figures in releases.

---

## 11. Threat landscape: the "why" behind the features

Readings, Field Reports and model answers tie features to these 2026 facts:

| Fact (source) | Used to explain |
|---|---|
| Exploiting vulnerabilities is now the **#1 initial access vector at 31 %**; credential abuse fell to 13 % (DBIR 2026) | IPS, virtual patching, FortiGuard, patch-cadence advice in PS work |
| Only **26 % of CISA KEV vulnerabilities** were fully remediated in 2025; median fix time **43 days** (DBIR 2026) | Why virtual patching and segmentation buy time |
| **Ransomware in 48 % of breaches**; 69 % of victims didn't pay (DBIR 2026) | FortiEDR ransomware prevention, segmentation, backups, FortiAnalyzer playbooks |
| **Third-party involvement in 48 % of breaches**, up 60 % (DBIR 2026) | ZTNA for vendors, least privilege, MFA, Security Fabric visibility |
| **Human element in 62 %**; pretexting 6 %, phishing 16 % (DBIR 2026) | MFA and FortiToken, email filtering, user training |
| **45 % of employees are regular AI users**; Shadow AI is the 3rd most common non-malicious insider DLP action (DBIR 2026) | FortiOS AI protection, DLP, inline CASB, FortiAnalyzer Shadow AI dashboard; his Globe Life shadow-AI story |
| Global average breach cost **USD 4.99M** (+12 %), US **USD 11.5M** (IBM 2026) | Business value in recruiter, HM and executive answers |
| AI-driven attacks **+56 %**, adding **USD 1M** per breach (IBM 2026) | Why speed of detection and response matters |
| Extensive security AI and automation **saved USD 1.93M and 65 days** (IBM 2026) | FortiAnalyzer automation, FortiSIEM, automation stitches |
| **92 %** of organizations with an AI-related breach lacked AI access controls (IBM 2026) | Identity-based policy, ZTNA, AI governance in PS designs |

---

## 12. "Why I'm a strong PS asset"

Positioning lines, from evidenced facts only:
- **Ex-Fortinet TAC P3 (2022–2024).** One of the main escalation points for North American and Brazilian enterprise customers; 2,000+ cases with a CSAT above 4.7. Knows FortiOS behavior, debug flow, NPU offload, HA recovery, and how TAC and development work from inside.
- **Delivery mindset from Netskope.** Completed partner PS projects in stages (acting as PS QA), ran health checks and POCs, a rollout that took an account from below 50 % to 70 % use, QBRs with C-level, and kept more than USD 900k of contract value.
- **Design from requirements.** SD-WAN steering and failover designs, SSL inspection rollout through GPO, HA in AWS and Azure, Terraform labs to test before changing production.
- **Certifications.** NSE 7, NSE 5 FortiManager and FortiAnalyzer, NSE 4, SD-WAN Architect and others (expired; this app rebuilds them).
- **Field-ready.** English, Spanish and Portuguese; travel anywhere; US visa.

**Honest gaps the app rehearses answers for:** leading full end-to-end implementations as the owner, writing SOWs from scratch, and recent hands-on time with FortiOS 7.6/8.0.

**Note on the Cato cheatsheet.** It contains figures that super-cv does not evidence (for example "four years", "$50M", "153 %", "85 %"). They stay out of model answers until Jose confirms them.

---

## 13. Build plan

| Phase | Deliverable | Contents |
|---|---|---|
| P0 | **This blueprint** | Approved scope, curriculum, specs |
| P1 | **Engine MVP (Windows)** | Event store, content loader, FSRS reviews, quiz engine (choice, ordering, cloze, numeric, CLI fill-in), reading runner with callouts, session planner and 4-hour template, XP/levels/medals, both skins, import of `.ftpack`. Ships with S0, I1 and M1.1 so studying starts right away. |
| P2 | **Android + sync** | Kotlin shell, ftcore for android/arm64, mDNS and QR pairing, FTSP/1 sync, pack transfer, backup and restore |
| P3 | **Advanced items** | Diagram hotspots and image occlusion, debug-output drills, scenario and raid engine with branching, Interview Studio (recording, rubric, TeleCyborg export), exam simulator, bosses |
| P4+ | **Content modules** | One module per request, in queue order; each module = content files committed + asset pack delivered |

**Time budget.**
- 65 modules: about **75 learning sessions**, plus consolidation sessions, for roughly **90–100 sessions** in total.
- At 2 sessions a day that is about 7 weeks; at 3 a day, about 5 weeks (with session 3 used for consolidation).
- If an interview is closer than that, **Sprint mode** reorders the queue (see CURRICULUM.md §4).

---

## 14. Open decisions for Jose

1. **Interview dates** (recruiter, HM, technical), so Sprint mode can order the queue.
2. **Repo visibility:** keep public (no guide figures in the repo or releases) or make it private.
3. **App name spelling:** "FortiTatake", as the repo is named (your job-search app is "Tatakae").
4. **Default sessions per day** (1, 2 or 3) and the hour each usually starts, for reminders.
5. **The job description** for req. 24928, if you still have it; the I2 and I3 pools get sharper with it.
