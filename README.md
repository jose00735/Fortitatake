# FortiTatake

An intensive, offline study engine for Fortinet Professional Services interviews and certification-level mastery (FortiGate/FortiOS, FortiManager, FortiAnalyzer, FortiSwitch, FortiSIEM, FortiEDR).

- **Windows** app in Go with a web UI (WebView2), and an **Android** app sharing the same Go core.
- Progress syncs over the local network with its own protocol (FTSP/1). No cloud, no accounts.
- 4-hour study sessions built on retrieval practice, spaced repetition (FSRS), interleaving, worked examples, PS scenarios and spoken interview drills.
- Two skins: **Fabric** (enterprise) and **Hellforge** (molten, game-style).

## Status

Blueprint stage. Start here:

| Doc | What it covers |
|---|---|
| [docs/BLUEPRINT.md](docs/BLUEPRINT.md) | Vision, learning design, session template, gamification, skins, architecture, build plan |
| [docs/CURRICULUM.md](docs/CURRICULUM.md) | Stages, modules, sources and page ranges, generation queue, sprint mode |
| [docs/CONTENT-SPEC.md](docs/CONTENT-SPEC.md) | File layout, item schemas, quality rules, module generation contract |
| [docs/SYNC-PROTOCOL.md](docs/SYNC-PROTOCOL.md) | LAN sync: discovery, pairing, events, endpoints, algorithm |
| [docs/STATUS.md](docs/STATUS.md) | Where the build and the content queue stand |

## Content and copyright

Study content in this repo is original text with page citations to Fortinet's official documentation. Figures taken from the official guides are extracted locally into `assets-local/` and are never committed. Fortinet and its product names are trademarks of Fortinet, Inc.; this is a personal, unofficial study project.

## How this is made

The idea, goals and study plan are José Acosta Hernández's. The design, code and content are written mostly by Claude (Anthropic), directed and reviewed by José.
