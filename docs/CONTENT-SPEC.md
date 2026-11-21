# FortiTatake — Content specification and module generation contract

> v0.1 · 21 Nov 2026 · see [BLUEPRINT.md](BLUEPRINT.md)

This file defines:
- how a module is laid out on disk
- the schema of every item type
- the rules every item must pass
- the **contract** each future module-generation session follows

---

## 1. Layout

```
content/
  S04-fortigate-core/
    stage.yaml
    M4.04-nat/
      module.yaml          # metadata, objectives, sources, tags
      units/
        01-why-nat.md      # reading chunks, ≤ 900 words each
        02-policy-vs-central-nat.md
      cards.yaml           # flashcards
      quiz.yaml            # quiz items
      labs.yaml            # worked → faded → solo
      scenarios.yaml       # PS situations and raids
      interview.yaml       # interview questions tied to this module
      field-reports.yaml   # 2-minute threat-landscape readings
      boss.yaml            # only in the last module of a stage
interview/
  I1-recruiter/ I2-hiring-manager/ I3-technical/ WhyMe/   # same files as a module
assets-local/              # gitignored: figures cropped from the official guides
  M4.04-nat/fig-01.png
  M4.04-nat/figures.yaml
```

**IDs.**
- Format: `<module>.<type>.<nn>`, for example `M4.04.q.017` or `M4.04.card.032`.
- IDs never change after release, so FSRS history survives edits.
- Deleted items are marked `retired: true`; they are never removed.

**Versions.**
- `module.yaml` carries `version: MAJOR.MINOR.PATCH`.
- Typo fixes are patch releases; new items are minor; restructures are major.
- Packs are named `<module>@<version>.ftpack`.

---

## 2. module.yaml

```yaml
id: M4.04
title: NAT on FortiGate
stage: S04
order: 4
version: 1.0.0
est_sessions: 1
difficulty_band: [D1, D5]
prerequisites: [M1.03, M4.03]
exam_tags: [fgt-admin]
interview_weight: { recruiter: 0, hm: 1, technical: 3 }
objectives:
  - Explain the difference between policy NAT and central NAT and when to use each
  - Configure a VIP with port forwarding and an IP pool for source NAT
  - Read debug flow output to tell whether NAT happened and which rule matched
sources:
  - { guide: FOS, version: 8.0.2, pages: "2094-2297", topic: "Policies (NAT sections)" }
threat_links: [dbir-2026-vuln-exploitation-31pct]
deltas:
  - "8.0 vs 7.4/7.6: describe any GUI or CLI difference found in the pages read"
```

---

## 3. Reading units (`units/*.md`)

Front matter, then Markdown with fenced directives:

```markdown
---
id: M4.04.u.02
title: Policy NAT vs central NAT
est_min: 10
tier: D2
figures: [M4.04/fig-02]
source: { guide: FOS, version: 8.0.2, pages: "2120-2124" }
---

Paragraphs in plain, original words...

:::recall
Where is source NAT configured when central NAT is enabled?
:::

:::why
Why would a 300-policy firewall migrated from another vendor benefit from central NAT?
:::

:::diagram asset=M4.04/fig-02
Caption written in our own words. (FortiOS 8.0.2 Admin Guide, p. 2121)
:::

:::cli
config system settings
    set central-nat enable
end
:::

:::pitfall
Turning central NAT on or off changes how every policy matches; plan it as a change window.
:::

:::threat ref=dbir-2026-vuln-exploitation-31pct
Exposing a VIP publishes a service to the internet. With exploitation now the top
initial access vector (31 %, DBIR 2026), every VIP needs IPS and a patch owner.
:::

:::delta
FortiOS 8.0 vs 7.6: <difference found in the guide, or omit the block>.
:::
```

Rules for units:
- At most 900 words.
- Exactly one main idea per unit.
- Every unit has at least one `recall` and one `why`.
- Units climb the difficulty ladder (D1 → D5) within the module.

---

## 4. Item schemas

Common fields on every item: `id`, `tier` (D1–D5), `bloom`, `tags`, `source { guide, version, pages }`, `exam_tags`, and optionally `retired`.

### 4.1 Flashcards (`cards.yaml`)

```yaml
- id: M5.01.card.003
  type: basic            # basic | reverse | cloze | occlusion
  front: Which protocol does FortiManager use to communicate with the FortiGates it manages?
  back: FGFM, the FortiGate-FortiManager protocol.
  extra: Device Manager uses FGFM to manage devices, including config installs and status.
  tier: D1
  source: { guide: FMG, version: 7.6.8, pages: "49-51" }
```

- **Cloze** uses `text: "Central NAT moves SNAT into the {{c1::central SNAT}} table."`
- **Occlusion** uses `asset` plus `masks: [{x,y,w,h,label}]` on a guide figure.

### 4.2 Quiz items (`quiz.yaml`)

```yaml
- id: M4.04.q.011
  type: single           # single | multi | order | match | numeric | cli | output | hotspot
  tier: D2
  stem: With central NAT enabled, where do you configure source NAT for outbound traffic?
  options:
    - { id: a, text: "In each firewall policy, with an IP pool", why_wrong: "That is policy NAT mode; with central NAT the policy has no NAT settings." }
    - { id: b, text: "In the central SNAT table", correct: true }
    - { id: c, text: "In the VIP object", why_wrong: "VIPs translate destination addresses, not sources." }
    - { id: d, text: "In the interface settings", why_wrong: "Interfaces don't hold NAT rules on FortiGate." }
  explanation: Central NAT separates translation from access control; SNAT rules live in their own ordered table.
  exam_tags: [fgt-admin]
  source: { guide: FOS, version: 8.0.2, pages: "2177" }
```

Type-specific fields:
- **order:** `items: [...]`, `answer: [ids in order]`. Used for packet flow, IKE steps, best-path selection.
- **match:** `left: [...]`, `right: [...]`, `pairs: [[l, r], ...]`.
- **numeric:** `answer`, `tolerance`, `unit`. Used for subnetting and timers.
- **cli:** `prompt`, `answer_tree` (normalized `config/edit/set` tree), `accept_abbrev: true`, `required_keys`, `forbidden_keys`.
- **output:** `output` (pasted CLI or debug text written by us), plus a `single`/`multi` question about it.
- **hotspot:** `asset`, `regions: [{id, polygon}]`, `answer: region id`.

### 4.3 Labs (`labs.yaml`)

```yaml
- id: M4.04.lab.002
  title: Publish an HTTPS server with a VIP
  goal: Make 203.0.113.10:443 reach 10.0.10.20:443 and allow it with a policy.
  stages:
    - mode: worked       # shown fully with commentary
      config: |
        config firewall vip
            edit "WEB-VIP"
                set extip 203.0.113.10
                set mappedip "10.0.10.20"
                set extintf "port1"
                set portforward enable
                set extport 443
                set mappedport 443
            next
        end
      commentary: [ "extintf is where the traffic arrives", "portforward limits the VIP to one port" ]
    - mode: faded        # same task, some lines blank
      blanks: [extip, mappedport]
    - mode: solo         # new variation, nothing shown
      variation: "Publish SSH on external port 2222 to 10.0.10.30:22"
  check: { type: cli, answer_tree: "..." }
  source: { guide: FOS, version: 8.0.2, pages: "<page>" }
```

### 4.4 PS situations and raids (`scenarios.yaml`)

```yaml
- id: M4.07.sc.002
  kind: situation        # situation | raid
  tier: D4
  title: Deep inspection breaks the finance apps
  situation: >
    A retail customer wants SSL deep inspection on all 3,000 endpoints next week.
    The pilot broke two finance applications and the CFO is upset.
  constraints: [ "Change freeze starts in 10 days", "No PKI team; AD and GPO available" ]
  stakeholders: [ CISO (sponsor), CFO (angry), IT ops lead (implements) ]
  ask: What do you do in the next 48 hours, and how do you roll it out?
  right_thinking:
    - Clarify: which apps, what error, pinned certificates or mutual TLS?
    - Assess risk: blast radius of a full rollout vs the value of inspection
    - Plan: exemptions by app category and FQDN, CA via GPO, phased waves with rollback
    - Validate: test list per wave, success criteria agreed with the CFO's team
    - Communicate: CFO update today, wave calendar, owner per issue
    - Document: exemptions register with review dates
  what: Phased deep-inspection rollout with exemptions for pinned and finance apps
  why: >
    Most threats now hide in TLS; inspection lets IPS, AV and DLP see them. The DBIR 2026
    puts vulnerability exploitation as the top initial access vector at 31 %.
  how: [ "SSL/SSH inspection profile with exemptions", "CA certificate pushed via GPO", "Waves by OU", "Monitor with FortiView and logs" ]
  pitfalls: [ "Exempting by IP instead of FQDN or category", "No rollback plan", "Forgetting non-domain devices" ]
  rubric:
    - { dim: clarify, weight: 1 }
    - { dim: risk, weight: 1 }
    - { dim: plan_and_rollback, weight: 2 }
    - { dim: validation, weight: 1 }
    - { dim: communication, weight: 1 }
  model_answer: >
    Written in Jose's voice and grounded in his real SSL-inspection rollout
    (CA distributed through GPO) from super-cv.
  could_have_added: [ "An exemptions register with an owner and review date", "A metric: blocked threats in the first 30 days" ]
  best_way_to_say_it: >
    "Before we push this to 3,000 machines, let's make the CFO's apps safe in 48 hours:
    exempt them by category, prove the fix in a pilot group, then roll out in waves
    we can roll back in five minutes."
```

**Raids** add:
- `steps: [{ prompt, options | free_text, next_on: {...} }]` for branching
- `timer_s`
- `hp_damage` per wrong step

### 4.5 Interview questions (`interview.yaml`)

```yaml
- id: I2.q.014
  stage: hm              # recruiter | hm | technical
  question: Tell me about a project someone else started that you had to finish.
  testing: Ownership, quality judgment, handling partners without blame
  framework: behavioral  # technical | behavioral | ps
  evidence: [ach-ps-qa, ach-partner-codelivery]   # super-cv IDs; nothing without evidence
  model_answer: >
    STAR answer from the evidenced story, with real names of products and partners
    where allowed, and the measurable result.
  follow_ups: [ "What would you do differently?", "How did you handle the partner relationship?" ]
  could_have_added: [ "How you made sure it would not happen again (checklist / QA gate)" ]
  best_way_to_say_it: "<one tight version to memorize>"
  telecyborg: { wpm: 150, target: "1:30" }
```

### 4.6 Field reports (`field-reports.yaml`)

```yaml
- id: fr.dbir-2026-vuln-exploitation-31pct
  title: The front door is now the vulnerability
  body: >
    90-second original summary of the finding and what it means for a FortiGate design.
  stat: "Exploitation of vulnerabilities: 31 % of breaches' initial access (DBIR 2026)"
  source: { doc: DBIR, year: 2026, section: "Key topics and findings" }
```

### 4.7 Boss (`boss.yaml`)

```yaml
id: S4.boss
title: The Gatekeeper
time_limit_min: 35
hp: 100
draw: { from_stage: S04, tiers: {D2: 8, D3: 10, D4: 10, D5: 2}, interleave_previous: 6 }
raid: M4.12.raid.001
pass: 0.80
```

---

## 5. Quality rules (`ft lint` enforces them)

1. Every item has a `source`. Threat statements cite DBIR or IBM. Interview answers cite super-cv evidence IDs.
2. **No invented facts.** Every technical claim must be checked against the cited pages during generation. Every personal claim must come from super-cv (no new metrics).
3. **Original wording.** Text is paraphrased, with no copied paragraphs from the guides. CLI syntax and command names are reproduced exactly. Guide figures live only in `assets-local/`.
4. **Difficulty mix per module** (quiz + labs + scenarios): D1 15 %, D2 25 %, D3 30 %, D4 20 %, D5 10 % (±5 %).
5. **Distractors are plausible** and each has a `why_wrong`.
6. **One idea per card**; card backs at most 40 words.
7. **Minimum counts** per module: cards 30, quiz 40, labs 3, scenarios 3, interview 10, field reports 2. Interview modules: questions as in CURRICULUM.md §2.
8. **Version deltas:** when the guide version (8.0) differs from the exam version (7.4/7.6), add a `delta` callout instead of mixing the two silently.
9. **Unique IDs**, no orphan assets, figures referenced by at least one unit or item.

---

## 6. Module generation contract

This is what Claude does each time Jose says "generate the next module" (or names one).

**0. Locate state.** Read `docs/STATUS.md` for the queue, the last module finished and open issues. Pull the repo.

**1. Check inputs.** Inputs needed:
- the module row in CURRICULUM.md
- the cited guide PDFs and pages
- super-cv (for interview items)
- DBIR / IBM (for threat links)

If a needed PDF is not available in the session, **stop and ask Jose to attach it, naming the exact file**, for example "please attach FortiOS-8_0_2-Administration_Guide.pdf". If the context is getting full, finish the current file, update STATUS.md, and ask for a fresh session.

**2. Read the source.** Extract the cited pages (`pdftotext -layout -f A -l B`). Render the pages that hold figures (`pdftoppm -r 150`) and crop the useful figures into `assets-local/<module>/` with `figures.yaml`.

**3. Plan.** Write 3–6 objectives and the unit list (D1 → D5). Pick threat links and interview angles.

**4. Write.** Write the units, then cards, quiz, labs, scenarios (at least one raid in the last module of a stage), interview items and field reports, using the schemas above and the answer frameworks from BLUEPRINT.md §4.4.

**5. Verify.**
- Run `ft lint`.
- Do a fact-check pass: re-open each cited page and confirm the claim. Fix or drop anything unconfirmed.
- Check every personal claim against super-cv.

**6. Package and deliver.**
- Commit `content/` (text only) to the repo, with a CHANGELOG line.
- Build `<module>@<version>.ftpack` with the figures and send it to Jose.
- Update `docs/STATUS.md`: done, next, open issues, and counts per item type.

**7. Report.** Give Jose a short summary: objectives, counts, anything left out and why, and the next module in the queue.

One module per session keeps the focus on that module's pages and avoids mixing versions or products.
