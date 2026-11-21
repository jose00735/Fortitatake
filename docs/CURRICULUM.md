# FortiTatake — Curriculum map

> v0.1 · 21 Nov 2026 · see [BLUEPRINT.md](BLUEPRINT.md)

How to read this map:
- **Order** rises in difficulty: vendor-neutral fundamentals → FortiGate core → management and analytics → advanced and specialist → PS mastery → capstone.
- **Sources** are the official guides Jose provided; page numbers are PDF pages.
  - **FOS** = FortiOS 8.0.2 Admin Guide
  - **FAZ** = FortiAnalyzer 8.0.2 Admin Guide
  - **FMG** = FortiManager 7.6.8 Admin Guide
  - **FSW** = FortiSwitchOS 8.0.2 Admin Guide (Standalone)
  - **FSM** = FortiSIEM 7.6.1 User Guide
  - **FED** = FortiEDR 7.2.5 Admin Guide
  - **DBIR** = Verizon 2026 Data Breach Investigations Report
  - **IBM** = IBM Cost of a Data Breach Report 2026
- **Sess.** = estimated 4-hour sessions.
- **Exam** = exam track tag.
- **Interview weight**: R recruiter · HM hiring manager · T technical, each ●●● high / ●● medium / ● low.
- Vendor-neutral modules (S1–S3) cite the Fortinet guide sections where the concept is implemented, plus RFC-level knowledge.

---

## 1. Mastery track

### S0 · Orientation and diagnostic

| ID | Module | Scope | Sources | Sess. | Exam | R/HM/T |
|---|---|---|---|---|---|---|
| M0.1 | Diagnostic and baseline | 60-item placement test across S1–S11; record a 90 s baseline pitch; set interview dates and sessions/day; tour of both skins | All (sampled) | 0.5 | — | ●●/●●/●● |

### S1 · Network foundations (vendor-neutral)

| ID | Module | Scope | Sources | Sess. | Exam | R/HM/T |
|---|---|---|---|---|---|---|
| M1.1 | Layers, Ethernet and switching | OSI vs TCP/IP; Ethernet frames, MAC learning, ARP; VLANs and 802.1Q; STP/RSTP basics; MTU, MSS, fragmentation | FOS Interfaces p236+, FSW VLAN p370, STP p273 | 1 | FGT Admin | –/●/●● |
| M1.2 | Addressing and core services | IPv4/IPv6 addressing and subnetting drills; ICMP; DHCP (DORA, relay); DNS (records, resolution, split DNS); NTP | FOS DNS p405, DHCP p607, IPv6 p987 | 1 | FGT Admin | –/–/●● |
| M1.3 | Transport, state and NAT theory | TCP handshake, states, windowing, RST/FIN, timeouts; UDP; stateful inspection; SNAT/DNAT/PAT, hairpin NAT, session helpers and ALGs | FOS Policies p2094, Protocol options p2368 | 1 | FGT Admin | –/●/●●● |
| M1.4 | Routing fundamentals | RIB vs FIB; longest prefix match; distance, metric, priority; ECMP; PBR; RPF / anti-spoofing; asymmetric routing | FOS Static routing p644 | 1 | FGT Admin | –/●/●●● |

### S2 · Routing and WAN protocols

| ID | Module | Scope | Sources | Sess. | Exam | R/HM/T |
|---|---|---|---|---|---|---|
| M2.1 | OSPF | LSAs, areas, neighbor states, DR/BDR, stub/NSSA, summarization, debugging adjacency | FOS Dynamic routing p675 | 1 | EFW | –/●/●●● |
| M2.2 | BGP | Attributes and best-path selection, iBGP vs eBGP, route maps, communities, route reflectors, BFD, graceful restart | FOS Dynamic routing p675–830 | 1.5 | EFW | –/●/●●● |
| M2.3 | WAN, overlays and SD-WAN concepts | MPLS vs Internet, GRE, IPsec overlays, VXLAN, SLA probes, steering, multicast basics | FOS SD-WAN overview p1155, Multicast p831 | 1 | EFW | –/●●/●●● |

### S3 · Security, crypto, identity and the threat landscape

| ID | Module | Scope | Sources | Sess. | Exam | R/HM/T |
|---|---|---|---|---|---|---|
| M3.1 | Cryptography and PKI | Symmetric/asymmetric, hashing, DH and PFS, certificate chains, CRL/OCSP, post-quantum basics | FOS Certificates p4411, Cipher suites p4504, PQC p3898 | 1 | FGT Admin | –/–/●● |
| M3.2 | TLS and inspection theory | TLS 1.2 vs 1.3, SNI, ECH, certificate vs deep inspection, QUIC/HTTP3 implications | FOS SSL & SSH Inspection p3048 | 1 | FGT Admin | –/●/●●● |
| M3.3 | VPN theory | IKEv1/IKEv2 exchanges, ESP vs AH, NAT-T, DPD, dial-up vs site-to-site, VPN vs ZTNA | FOS IPsec p3128, ZTNA intro p1834 | 1 | FGT Admin | –/●/●●● |
| M3.4 | Identity and access | RADIUS, TACACS+, LDAP, SAML and OIDC, MFA, 802.1X/EAP, SCIM | FOS User & Authentication p3905 | 1 | FGT Admin | –/●/●● |
| M3.5 | Defense concepts and the 2026 threat landscape | NGFW engines (IPS, AV, sandbox, web/DNS filter, app control), DLP, CASB, WAF, EDR/XDR, SIEM/SOAR, MITRE ATT&CK, Zero Trust; DBIR and IBM 2026 findings | DBIR, IBM, FOS Security Profiles p2480 | 1 | — | ●●/●●●/●● |

### S4 · FortiGate core (FortiGate Administrator / NSE 4 level, FortiOS 8.0)

| ID | Module | Scope | Sources | Sess. | Exam | R/HM/T |
|---|---|---|---|---|---|---|
| M4.1 | FortiOS administration | GUI/CLI and config tree, admins and profiles, firmware, backup/restore, FortiGuard, VDOM intro, APIs | FOS Getting started p32–146, System p4139–4330, p4519 | 1 | FGT Admin | –/–/●● |
| M4.2 | Interfaces and network services | Physical/VLAN/aggregate/zone/loopback, DHCP, DNS, IPAM | FOS Network p236–643 | 1 | FGT Admin | –/–/●● |
| M4.3 | Firewall policies and objects | Policy match order, implicit deny, objects, ISDB, schedules, policy lookup, traffic shaping | FOS Policy and Objects p2094–2479 | 1.5 | FGT Admin | –/●/●●● |
| M4.4 | NAT on FortiGate | Policy NAT vs central NAT, VIPs, IP pools, port forwarding, hairpin; troubleshooting NAT | FOS Policies p2094+ (NAT sections) | 1 | FGT Admin | –/●/●●● |
| M4.5 | Routing on FortiGate | Static, PBR, route lookup, VRF, route monitor; routing table vs session | FOS Static routing p644–674, VRF p882–931 | 1 | FGT Admin | –/–/●●● |
| M4.6 | Authentication | Local users, LDAP, RADIUS, SAML, FSSO, FortiToken, PKI users | FOS User & Authentication p3905–4118 | 1 | FGT Admin | –/●/●● |
| M4.7 | Certificates and SSL/SSH inspection | CA distribution, certificate vs deep inspection, exemptions, HSTS / pinning pitfalls | FOS SSL & SSH Inspection p3048–3091, Certificates p4411–4462 | 1 | FGT Admin | –/●●/●●● |
| M4.8 | Security profiles | Inspection modes; AV, web filter, DNS filter, app control, IPS, file filter, DLP, virtual patching, AI protection, inline CASB | FOS Security Profiles p2480–3127 | 2 | FGT Admin | –/●●/●●● |
| M4.9 | VPN on FortiGate | Site-to-site, dial-up/remote access, aggregate and redundant VPN, Agentless VPN (8.0), troubleshooting | FOS IPsec p3128–3768, Agentless VPN p3769–3904 | 2 | FGT Admin | –/●●/●●● |
| M4.10 | High availability | FGCP (A-P/A-A, heartbeat, session sync, override), FGSP, VRRP, standalone config sync | FOS HA p4556–4813 | 1.5 | FGT Admin | –/●●/●●● |
| M4.11 | Logging, monitoring and FortiView | Log types, targets, FortiView, dashboards, sample logs | FOS Dashboard p147–235, Log and Report p5340–5474 | 1 | FGT Admin | –/●/●● |
| M4.12 | Diagnostics | Troubleshooting method, `diagnose debug flow`, sniffer, session table, CLI cheat sheet; **S4 boss** | FOS Network diagnostics p1143, Troubleshooting p5544–5616 | 1 | FGT Admin | –/●●/●●● |

### S5 · FortiManager (FortiManager 7.6 Administrator)

| ID | Module | Scope | Sources | Sess. | Exam | R/HM/T |
|---|---|---|---|---|---|---|
| M5.1 | Key concepts and ADOMs | FGFM communication, ADOMs, modes, revisions | FMG Key concepts p48–65, ADOMs p94 | 1 | FMG Admin | –/●/●● |
| M5.2 | Device Manager | Adding devices, model devices and ZTP, scripts, provisioning templates, firmware templates | FMG Device Manager p93–378 | 1.5 | FMG Admin | –/●●/●●● |
| M5.3 | Policy & Objects | Policy packages, install wizard and preview, policy blocks, dynamic objects, ADOM revisions, workspace/workflow | FMG Policy & Objects p379–571 | 1.5 | FMG Admin | –/●●/●●● |
| M5.4 | SD-WAN and VPN Manager | SD-WAN templates and overlay orchestration, central VPN | FMG SD-WAN Manager p572–635, VPN Manager p708–755 | 1 | FMG Admin | –/●●/●●● |
| M5.5 | FortiGuard, FortiSwitch Manager, operations | Local FDS, firmware management, FortiSwitch central management, HA and troubleshooting; **S5 boss** | FMG FortiGuard p912–969, FortiSwitch Manager p970–1024, System Settings p1037+ | 1 | FMG Admin | –/●/●● |

### S6 · FortiAnalyzer (FortiAnalyzer Analyst)

| ID | Module | Scope | Sources | Sess. | Exam | R/HM/T |
|---|---|---|---|---|---|---|
| M6.1 | Concepts and log storage | Analyzer vs collector mode, ADOMs, log storage and quotas | FAZ Key concepts p45–52, Log View and quota p158–190 | 1 | FAZ Analyst | –/●/●● |
| M6.2 | Devices, forwarding and HA | Adding devices, log forwarding and fetching, SIEM Collector, HA | FAZ Device Manager p95–111, Log Forwarding p573, Fetching p585, SIEM Collector p534 | 1 | FAZ Analyst | –/●/●● |
| M6.3 | FortiView, Log View and Fabric View | Monitors, filters, Asset Identity Center, Security Fabric correlation | FAZ FortiView p112–157, Fabric View p191–221 | 1 | FAZ Analyst | –/●/●● |
| M6.4 | Incidents, alerts and automation | Alert and event handlers, indicators, playbooks, SIEM log parsers, FortiAI | FAZ Incidents & Alerts p222–441, FortiAI p442–463 | 1.5 | FAZ Analyst | –/●●/●●● |
| M6.5 | Reports and datasets | Datasets (SQL), charts, macros, templates, schedules; **S6 boss** | FAZ Reports p465–515 | 1 | FAZ Analyst | –/●/●● |

### S7 · FortiSwitch (FortiSwitch Administrator)

| ID | Module | Scope | Sources | Sess. | Exam | R/HM/T |
|---|---|---|---|---|---|---|
| M7.1 | Switching on FortiSwitch | Ports, interfaces, VLANs, LAG, STP, flap guard | FSW Switch p146–387 | 1 | FSW Admin | –/–/●● |
| M7.2 | Access security | DHCP snooping, IP source guard, ACLs, 802.1X/MAB, storm control, LLDP-MED | FSW p288–340, p388–394, Deployment scenario p555 | 1 | FSW Admin | –/●/●● |
| M7.3 | FortiLink and managed switches | FortiLink from FortiGate, MCLAG, QoS, PoE, central management in FMG; **S7 boss** | FOS Switch Controller p4120, FMG FortiSwitch Manager p970, FSW QoS p394, PoE p355 | 1 | FSW Admin | –/●/●● |

### S8 · Enterprise Firewall (NSE 7 level)

| ID | Module | Scope | Sources | Sess. | Exam | R/HM/T |
|---|---|---|---|---|---|---|
| M8.1 | Security Fabric and automation | Fabric components, connectors, automation stitches, SDN connectors, security rating | FOS Security Fabric p4814–5339 | 1 | EFW | –/●●/●●● |
| M8.2 | Advanced routing on FortiGate | OSPF and BGP configuration and debugging, BFD, redistribution | FOS Dynamic routing p675–830 | 1.5 | EFW | –/●/●●● |
| M8.3 | SD-WAN deep dive | Members and zones, performance SLA, rules, overlays, ADVPN, Fabric Overlay Orchestrator, troubleshooting | FOS SD-WAN p1155–1833, ADVPN p3626, Overlay Orchestrator p3669 | 2 | EFW | –/●●●/●●● |
| M8.4 | Threat prevention at scale | IPS tuning, custom signatures, app control and web filtering at scale, overrides; NP/CP offload | FOS IPS p2812, Custom signatures p3092, Overrides p3104 | 1 | EFW | –/●/●● |
| M8.5 | VDOMs and advanced HA | VDOM design, inter-VDOM links, management VDOM, HA in VDOM environments, cloud HA | FOS VDOMs p4284–4325, HA p4556–4813, VM p5512 | 1 | EFW | –/●●/●●● |
| M8.6 | Central management at scale | FMG + FAZ operations together: install flows, revision control, log-driven troubleshooting | FMG p379–635, FAZ p222–515 | 1 | EFW | –/●●/●● |
| M8.7 | Troubleshooting master | Packet flow end to end, conserve mode, CPU/memory, session analysis, offload issues; **S8 boss** | FOS Conserve mode p4516, Troubleshooting p5544–5616 | 1 | EFW | –/●●/●●● |

### S9 · FortiSIEM (FortiSIEM Analyst)

| ID | Module | Scope | Sources | Sess. | Exam | R/HM/T |
|---|---|---|---|---|---|---|
| M9.1 | Architecture and setup | Supervisor, workers, collectors; CMDB; credentials and discovery | FSM Key concepts p365–384, Setup p409–487, CMDB p857–898 | 1 | FSM Analyst | –/●/●● |
| M9.2 | Ingestion and parsing | Event pulling, event types and attributes, parsers, JSON over HTTPS | FSM Device Support p489–583 | 1 | FSM Analyst | –/●/●● |
| M9.3 | Rules, incidents and cases | Rule logic, testing, Sigma import, incident views (risk, MITRE, UEBA), cases | FSM Rules p925–942, Cases p1229–1255, Incidents p1256–1311 | 1.5 | FSM Analyst | –/●●/●● |
| M9.4 | Analytics, ML, dashboards and automation | Analytics and advanced search, machine learning, dashboards, reports, FortiSOAR playbooks, threat feeds; **S9 boss** | FSM Analytics p1312–1367, ML p1368, Dashboards p1413+, Reports p900–924, Playbooks p1005–1052 | 1 | FSM Analyst | –/●/●● |

### S10 · FortiEDR (FortiEDR Administrator)

| ID | Module | Scope | Sources | Sess. | Exam | R/HM/T |
|---|---|---|---|---|---|---|
| M10.1 | Architecture and deployment | Collectors, aggregator, core, central manager, cloud; deployment and upgrades | FED Introducing p10–21, Deploying p22–76 | 1 | FED Admin | –/●/●● |
| M10.2 | Security policies and profiles | Execution prevention, exfiltration, ransomware, device control, application control, exceptions, exclusions | FED Profiles p203–263 | 1 | FED Admin | –/●/●● |
| M10.3 | Incidents and forensics | Incident pane, investigation view, flow analyzer, threat hunting | FED Incidents p87–127, Forensics p128–173 | 1 | FED Admin | –/●●/●● |
| M10.4 | Communication control, playbooks and integrations | App communication control, host firewall, playbooks, Fabric integrations, multi-tenancy; **S10 boss** | FED p174–202, Integrations p264–313, Playbooks p314–321, Multi-tenancy p422–451 | 1 | FED Admin | –/●/●● |

### S11 · Professional Services mastery

| ID | Module | Scope | Sources | Sess. | Exam | R/HM/T |
|---|---|---|---|---|---|---|
| M11.1 | The PS delivery lifecycle | Pre-sales handoff, kickoff, discovery workshop, requirements, HLD/LLD, SOW scope, change control | PS practice; Jose's super-cv evidence | 1 | — | ●/●●●/●● |
| M11.2 | Implementation craft | MOP, pre-checks, maintenance windows, cutover, rollback, acceptance test plan, as-built docs, knowledge transfer | PS practice; FOS Config backup p4530, FMG revisions p568 | 1 | — | –/●●●/●●● |
| M11.3 | Migrations | ASA / Palo Alto / Check Point → FortiGate, policy clean-up, NAT translation pitfalls, phased cutover | FOS Policies, NAT; FMG Policy packages | 1 | — | –/●●●/●●● |
| M11.4 | Design patterns | Branch SD-WAN with hub/ADVPN, DC HA pair, AWS/Azure HA, ZTNA rollout, SOC stack (FAZ/FSIEM/FEDR) | FOS SD-WAN, HA, VM, ZTNA; FAZ; FSM; FED | 1.5 | EFW | –/●●●/●●● |
| M11.5 | Customer handling and storytelling | Difficult stakeholders, scope creep, escalations, status reports, risk registers, executive readouts with threat data | DBIR, IBM, super-cv | 1 | — | ●●/●●●/● |

### S12 · Capstone

| ID | Module | Scope | Sources | Sess. | Exam | R/HM/T |
|---|---|---|---|---|---|---|
| M12.1 | Full design case | Multi-site enterprise (40 branches, 2 DCs, cloud): HLD, LLD, MOP, ATP, executive summary | All | 1.5 | EFW | –/●●●/●●● |
| M12.2 | Exam simulations | Timed simulations per track: FGT Admin, FMG Admin, FAZ Analyst, FSW Admin, EFW, FSM Analyst, FED Admin | All | 2 | All | –/–/●● |
| M12.3 | Mock interview gauntlet | Three full mock interviews (recruiter, HM, technical panel), self-scored with rubrics | Interview track | 1 | — | ●●●/●●●/●●● |

---

## 2. Interview track (parallel, available from day one)

| ID | Module | Scope | Pool target | Depends on |
|---|---|---|---|---|
| I1 | Recruiter screen | Pitch at 30 s / 90 s / 3 min; why Fortinet again and why PS; availability; travel; salary range (COP package); the Netskope exit (neutral, private); English; logistics; questions to ask | ~40 Q | — |
| I2 | Hiring manager | 12-story STAR bank from super-cv evidence; PS delivery situations; "have you led an implementation end to end?"; prioritization; customer conflict; questions to ask | ~120 Q, 12 stories | M11.1–M11.2 (partial) |
| I3 | Technical panel | Whiteboard designs (SD-WAN, HA, VPN, SOC stack); live troubleshooting walk-throughs; config questions; FMG/FAZ operations; "explain it to the customer" | ~200 Q | S1–S4, S8, S11 |
| WhyMe | Why I'm a strong PS asset | Positioning lines, proof points, honest-gap answers; uses the Cato cheatsheet frameworks with super-cv facts only | ~20 Q | — |

Every interview item has:
- what they are really testing
- the framework to use
- a model answer
- likely follow-ups
- what a great answer adds
- the best way to say it

Each item can be exported to TeleCyborg for rehearsal.

---

## 3. Default generation queue

Modules are generated one per request, in this order (the interview items are front-loaded because the recruiter call comes first):

1. **Engine MVP** content bundle: M0.1 + I1 + WhyMe
2. M1.1 → M1.2 → M1.3 → M1.4
3. I2 (STAR bank first pass)
4. M2.1 → M2.2 → M2.3
5. M3.1 → M3.2 → M3.3 → M3.4 → M3.5
6. M4.1 → M4.12 (S4 boss)
7. M11.1 → M11.2 (so I2 can be completed)
8. I3 (first pass)
9. M5.1 → M5.5, M6.1 → M6.5
10. M8.1 → M8.7
11. M11.3 → M11.5
12. M7.1 → M7.3, M9.1 → M9.4, M10.1 → M10.4
13. M12.1 → M12.3

Totals: **65 modules** (61 mastery + 4 interview), about **75 learning sessions**, plus consolidation sessions (reviews, exam simulations, mock interviews) for roughly **90–100 sessions** in all.

---

## 4. Sprint mode (when interview dates are set)

If the technical interview is less than about 3 weeks away, the queue reorders to:

1. M0.1 + I1 + WhyMe
2. **Essentials path:** M1.3, M1.4, M3.2, M3.3, M4.3, M4.4, M4.7, M4.9, M4.10, M4.12, M8.3, M11.1, M11.2, M11.4
3. I2 complete, then I3 complete
4. The remaining modules in the default order

In sprint mode the planner also:
- gives interview drills 40 % of each session (instead of 10 %)
- caps new flashcards at 60 per session
- adds a daily 15-minute "pitch rehearsal" block
