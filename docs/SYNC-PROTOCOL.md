# FortiTatake Sync Protocol — FTSP/1

> v0.1 · 21 Nov 2026 · see [BLUEPRINT.md](BLUEPRINT.md)

FTSP/1 keeps study progress, settings and content packs identical between the Windows app (the **hub**) and one or more Android phones (**spokes**) over the local network. There is no cloud and no account.

---

## 1. Design goals

1. **Offline first.** Both apps work fully without the other. Sync is a catch-up, not a requirement.
2. **No conflicts by design.** Progress is an append-only log of immutable events. Merging means taking the union of events. State is rebuilt by replaying events in a fixed order.
3. **Safe on a shared Wi-Fi.** TLS with certificate pinning set up through a QR code, a per-device bearer token, and a pairing window only while the user has it open.
4. **Simple.** HTTP/1.1 + JSON over TLS. A few endpoints. Debuggable with curl.
5. **Forward compatible.** Unknown event types are stored and forwarded untouched.

---

## 2. Roles and discovery

- **Hub (Windows).** Runs the FTSP server on a TCP port (default `47431`, configurable) bound to private LAN interfaces only. Advertises with mDNS / DNS-SD:
  - service: `_fortitatake._tcp.local`
  - TXT: `v=1`, `id=<hub_device_id>`, `name=<hub name>`, `fp=<first 16 hex of cert SHA-256>`
- **Spoke (Android).** Finds hubs with `NsdManager`. Fallbacks: the host and port inside the pairing QR code, or manual entry.
- Spokes only talk to the hub. Two phones stay in sync through the hub.
- The hub's port needs a Windows Firewall rule. The installer asks once, limited to private networks.

---

## 3. Identity and pairing

**Device identity.**
- Each install creates a random `device_id` (ULID) and a name ("José-PC", "Pixel").
- The hub creates a self-signed **ECDSA P-256** TLS certificate on first run, valid 10 years.

**Pairing flow**
1. On the hub, Jose opens *Settings → Sync → Pair a device*. The hub opens a **pairing window for 5 minutes** and shows a QR code:
   ```json
   {"ftsp":1,"host":"192.168.1.20","port":47431,"hub":"01J...","cert":"sha256:9F2C...","pt":"<128-bit pairing token, base32>","exp":1763760000}
   ```
2. The phone scans it (camera via the Kotlin shell). If scanning isn't possible, Jose types the 8-character code shown under the QR. The phone then connects with trust-on-first-use and **both screens show the same four-word fingerprint** to compare.
3. The phone connects over TLS and **pins** `cert`. Any other certificate is rejected.
4. `POST /v1/pair` with `{pt, device_id, name, platform}`.
5. The hub checks the token (single use, unexpired), stores the device, and returns `{device_token}`: 256 random bits, shown once and stored in Android Keystore-backed encrypted storage.
6. Every later request carries `Authorization: Bearer <device_token>` and `X-FT-Device: <device_id>`.

**Security rules**
- Pairing tokens are single-use, expire after 5 minutes, and only exist while the pairing window is open.
- Five failed pairing attempts close the window.
- Device tokens can be revoked from the hub's device list; a revoked device must pair again.
- The hub keeps hashes of the tokens, not the tokens themselves.
- Requests from public (non-RFC 1918 / non-link-local) source addresses are refused.
- Hub rate limit: 20 requests/second per device.

---

## 4. Data model

### 4.1 Event

```json
{
  "id": "01JD3X0Q8W9W3C1A9V6K0Y4ZQH",
  "dev": "01JD2...",
  "seq": 18234,
  "hlc": "2026-11-21T22:41:07.123Z/0004",
  "type": "review",
  "v": 1,
  "body": { "card": "M4.04.card.012", "rating": 3, "ms": 5400, "conf": 2 }
}
```

- `dev` + `seq`: a per-device counter that only goes up. Together they identify the event; re-sending it is harmless.
- `hlc`: hybrid logical clock (wall time + counter), so events from devices with slightly wrong clocks still order sensibly.
- `type` / `v`: the event type and its schema version.

**Event types (v1)**
- `review`, `quiz_attempt`, `lab_result`, `scenario_score`, `raid_result`, `drill`
- `session_start`, `block_done`, `session_end`
- `card_create` (his own cards), `item_flag` (report a bad item)
- `setting_set`, `pack_installed`
- `medal_claim_ack` (UI only; medals themselves are derived)

### 4.2 Replay order and projections

- Events are ordered by `(hlc, dev, seq)`. Because events never change and the order is fixed, every device that holds the same set of events computes **the same state**: FSRS card states, XP, levels, mastery, medals and streaks.
- `setting_set` is **last writer wins** per key by `hlc`.
- Projections are cached in snapshots (every 2,000 events) so start-up stays fast.
- An event that arrives out of order (an older `hlc`) triggers a replay from the snapshot before it.

### 4.3 Version vector

Each side summarizes what it holds as `{ device_id: highest contiguous seq }`, for example `{"01JD2…": 18234, "01JD9…": 5120}`.

### 4.4 Content packs

- A pack is `<module>@<version>.ftpack`: a zip with `manifest.json` (id, version, sha256 per file, schema version), content YAML/Markdown and figures.
- The hub is the source of truth for packs.
- The pack catalog is `[{id, version, sha256, size}]`.

---

## 5. Endpoints

All requests are over TLS and return JSON, except pack and blob downloads.

| Method | Path | Purpose |
|---|---|---|
| GET | `/v1/hello` | `{ftsp:1, hub, name, time, catalog_hash, min_client:1}`. No auth; used to check reachability and the pinned certificate. |
| POST | `/v1/pair` | Pairing (§3). |
| POST | `/v1/sync/pull` | Body `{vector, limit}` → `{events:[…], vector, more}`. Up to `limit` (default 2,000) events the caller lacks. |
| POST | `/v1/sync/push` | Body `{events:[…]}` → `{accepted, duplicates, vector}`. |
| GET | `/v1/packs` | Pack catalog. |
| GET | `/v1/packs/{id}/{version}` | Pack zip. Supports `Range` to resume; verified with sha256. |
| PUT/GET | `/v1/blobs/{sha256}` | Optional audio recordings (off by default). |
| DELETE | `/v1/devices/self` | Unpair from the phone side. |

Errors:
- Body: `{error:{code, message}}`.
- Codes: `unauthorized`, `pairing_closed`, `token_expired`, `version_unsupported`, `bad_event`, `rate_limited`.

---

## 6. Sync algorithm (spoke side)

```
on app open, on "Sync now", and every 5 minutes while the hub is reachable:
  hello = GET /v1/hello                      # check pinned cert and protocol
  loop:
     r = POST /v1/sync/pull {vector: my_vector}
     append r.events to my log (skip duplicates by dev+seq)
     until r.more == false
  missing = my events not covered by r.vector
  POST /v1/sync/push {events: missing} in batches of 2,000
  catalog = GET /v1/packs
  download packs whose (id, version) is missing or whose sha256 differs; verify; install
  rebuild projections from the earliest new hlc
```

The hub does the same merge on push. Both sides append, never overwrite.

Guarantees:
- **Idempotent.** Re-sending any batch is safe.
- **Resumable.** A dropped connection just means the next pull starts from the vector already saved.
- **Convergent.** After one pull plus push with no new activity, both sides hold the same event set, so the same state.

---

## 7. Sessions across devices

- A paused session is a sequence of `session_start` / `block_done` events.
- If Jose pauses on the PC and opens the phone, the phone shows **Resume sortie** with the next block. Only one device can drive a session at a time. If both made progress offline, both sets of block events are kept, the session counts as done when every block is done, and the block results are merged.

---

## 8. Backup and restore

- `Export → .ftbackup`: a zip with the full event log, settings, the paired-device list (no tokens) and the pack catalog.
- Restore on a new PC:
  1. Import the backup.
  2. Re-pair the phones.
  3. The phones push any events the backup lacks.
- Because state is derived from events, a backup is always complete.

---

## 9. Versioning

- The protocol version is in `/v1/hello` (`ftsp`, `min_client`). Breaking changes get `/v2`.
- Event schema versions are `v` per event. Unknown types or versions are stored and forwarded; projections ignore them until the app updates.
- Pack schema versions are in the manifest. A pack newer than the app shows "update the app to open this module" and is still kept.

---

## 10. Test plan

- **Unit tests:** HLC ordering, replay determinism (the same events in any arrival order give the same state), duplicate handling, vector math.
- **Property test:** two simulated devices doing random offline activity, then syncing in random partial batches, must end with identical projections.
- **Security tests:**
  - wrong cert is rejected
  - expired or reused pairing token is rejected
  - revoked token is rejected
  - public-IP source is rejected
- **Interop test:** the Windows build and the Android build syncing over a real Wi-Fi network, including a dropped connection in the middle of a pack transfer.
