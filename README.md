# FortiTatake

An intensive, offline study engine for Fortinet Professional Services interviews and certification-level mastery (FortiGate/FortiOS, FortiManager, FortiAnalyzer, FortiSwitch, FortiSIEM, FortiEDR).

- **Windows** app in Go with a web UI (WebView2), and an **Android** app sharing the same Go core.
- Progress syncs over the local network with its own protocol (FTSP/1). No cloud, no accounts.
- 4-hour study sessions built on retrieval practice, spaced repetition (FSRS), interleaving, worked examples, PS scenarios and spoken interview drills.
- Two skins: **Fabric** (enterprise) and **Hellforge** (molten, game-style).

## Run it

**Windows:** unzip the release and double-click `fortitatake.exe`. It opens its own window (WebView2, built into Windows 10/11); if WebView2 is missing it opens your default browser instead. Progress is saved in `%APPDATA%\FortiTatake\events.jsonl`. Back it up from Settings.

**Android:** install `fortitatake-v0.2.0.apk` (allow installs from your browser or file manager). Then on the PC: Settings → Sync → Turn on sync → Pair a phone, and on the phone: Settings → Sync → Scan the QR code.

Flags: `-browser` (use the browser instead of the window), `-data <dir>`, `-port <n>`, `-no-open`, `-version`.

**Build from source** (Go 1.24+, Python 3 with PyYAML):

```
python3 tools/build_content.py          # lint content/*.yaml and write web/content/bundle.json
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-H windowsgui -s -w" -o dist/fortitatake.exe .
go run . -browser                       # any OS, opens in your browser
go test ./internal/...                  # sync protocol tests
ANDROID_HOME=~/Android/Sdk tools/build_android.sh   # APK into dist/
```

## Status

v0.2.0: Windows app, Android app and LAN sync (FTSP/1), plus six modules (about 24 hours of sorties). Docs:

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
