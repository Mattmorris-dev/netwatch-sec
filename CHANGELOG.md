# Changelog

All notable changes to NetWatch are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 1.5.0 — 2026-07-15

### Added
- **Feed the hive (Free).** `netwatch join --community` opts a free node into a
  shared community hub — attack-vector fields only, never request payloads, over
  CA-pinned HTTPS. An opt-in nudge appears in the TUI header, startup banner, and
  web fleet tab until you join or silence it (`join nudge off` / `NETWATCH_NO_NUDGE`).
  The hub side adds a fail-closed open-enrollment mode (off by default; requires an
  enroll token, per-IP + global rate limits, and a community cap) that never lets a
  community node consume a paid seat and re-strips their events server-side.
- **Node seat enforcement (Business value).** The Apiary hub now enforces the
  license's `max_nodes` at mint time; defaults when unset are Pro 1 / Business 25 /
  Enterprise unlimited. Seats-used/total show in the TUI + web fleet tabs and
  `netwatch license`; revoking a node frees a seat.
- **Team accounts + RBAC (Business).** The web dashboard gains named users with
  `admin` / `operator` / `viewer` roles (scrypt-hashed store), managed via
  `netwatch users …` (CLI + TUI). Role checks gate mutating web commands and the
  new `/api/users` admin endpoint. The fixed web token remains an admin break-glass
  login, so single-token setups are unchanged.
- **Scheduled signed reports (Business).** `netwatch report schedule daily|weekly`
  auto-generates a signed PDF digest of the window's events, delivered via the
  existing email/webhook sinks and dropped to `~/netwatch-reports`. `report run-now`
  triggers one on demand.
- **Tamper-evident audit trail (Enterprise).** A hash-chained, append-only audit
  log records block/unblock, logins, token rotation, joins, user changes, node
  mint/revoke, license activation, and report generation. `netwatch audit verify`
  detects any mutation, reorder, or truncation; a new web audit tab and
  `/api/audit` surface it.
- **Compliance pack expansion (Enterprise).** The compliance report grows from 5 to
  28 controls across SOC 2, PCI-DSS, NIST 800-53, and CIS, each checked against live
  NetWatch state, with a `--framework` filter and a signed PDF evidence bundle
  (`netwatch compliance report --framework soc2 --pdf out.pdf`).
- **Automatic local Cortex feed (Free).** When a Cortex install is present, every
  honeypot event is mirrored (attack-vector fields only — no payloads/credentials)
  into the local Apiary store Cortex already reads, so the local threat brain learns
  from your honeypot automatically with zero network egress. Opt out with
  `NETWATCH_CORTEX_FEED=0`.
- **Buy additional Pro hub seats.** Pro stays 1 node; add nodes at +$25/yr each (an
  explicit node count on the license overrides the tier default). The seat-full
  message points to the purchase/upgrade path.

### Fixed
- **Packaging:** the wheel now ships `replay`, `netwatch_shipper`, and
  `netwatch_crowdsec` alongside `netwatch` — previously a clean PyPI install was
  missing modules that `netwatch` imports.

### Changed
- `NETWATCH_TIER=<tier>` dev override to exercise free-side tier gating without a
  license (paid modules still verify the real license and fail closed).
- Business/Enterprise gate decorators are centralized in `netwatch_license` and use
  the cached license load.

## 1.4.0 — 2026-07-12

### Added
- **NetWatch Pro — paid plans.** The free AGPL core (honeypots, capture, replay,
  dashboards) stays free forever; an optional paid add-on layers fleet
  aggregation, threat-intel enrichment, `ask`, signed reports/alerts, SIEM
  forwarding, and compliance reporting on top. Free/Pro/Business/Enterprise
  tiers — see the README and `netwatch activate <key>`. The free package detects
  a valid license and unlocks Pro features; without one it runs unchanged as Free.
- **`netwatch ask "<question>"`** — natural-language queries over this node's
  harvested intel (Pro add-on required). The default provider is fully local:
  answers are composed from retrieved, novelty-scored, cited evidence with
  zero network egress; cloud/ollama providers are explicit opt-in only.
- **Apiary shipper: edge-model fetch** — nodes can pull the distilled threat
  scoring model from the fleet hub over the existing TLS channel
  (`model_fetch`, default **off**; hub enroll token opts in), replacing
  hand-deployed model files. The fetch pins the hub CA, refuses redirects,
  validates the model before an atomic 0600 write, and falls back to the
  current model on any failure.
- **Fleet tab: Cortex card** — when the hub publishes a Cortex brain snapshot,
  the fleet view (TUI + web) shows fleet-wide novelty/threat stats. Credentials
  harvested by the honeypot are never included in the snapshot.

## 1.3.2 — 2026-07-02

### Fixed
- **TUI dashboard layout broke** on terminals narrower than ~106 cols: the tab
  bar (12 tabs since the `fleet` tab was added) overflowed and wrapped, shoving
  the whole dashboard down a row. `_tab_bar` is now width-aware — it degrades
  (full → single-space → drop the number prefix → clip) so it always fits.
- **Typing a tab name did nothing** if you were in console/CLI mode: it set the
  tab but didn't return to the dashboard, so nothing appeared to happen. Typing
  a tab name now switches to the dashboard too (matching number-hotkey behavior).
- Tab hotkey labels: the 11th/12th tabs no longer mislabel as `0:` (only the
  10th is `0`; 11+ have no numeric hotkey).

### Added
- `[` / `]` / Tab keys cycle through **all** tabs — the only way to reach the
  11th/12th (mesh, fleet), which have no number hotkey.
- Stability test nets: `tests/test_tui_stability.py` (render never crashes / tab
  bar never overflows) and `tests/test_input_dispatch.py` (tab-switch logic).

### Internal
- `_TAB_NAMES` is now derived from `TABS` so the two can't drift (the root cause
  of typed tab names silently failing for some tabs).

## 1.3.1 — 2026-07-02

### Added
- **Live `fleet` tab in the web dashboard** (`/api/fleet`) — auto-refreshing
  remote-node view alongside the TUI fleet tab. All remote data HTML-escaped.
- **Pro add-on wire-in** — with a valid license the app now detects and loads
  the `netwatch_pro` submodules: startup banner shows `✦ PRO <tier> active`,
  and `attacks` renders live MITRE ATT&CK technique tags. Free tier unchanged.
- `attacks` / `expose` are now runnable from the web command bar.

### Fixed
- `publish.yml` uses `skip-existing` so a moved-tag re-run no longer hard-fails
  on an already-published version.

## 1.3.0 — 2026-07-02

### Added
- **`expose`** — external exposure self-check. Free: public IP + geolocation +
  quick reachability probe of common ports. Pro runs an external `nmap -sV`
  service fingerprint with hardening advice.
- **`alert`** — send honeypot hits to a Discord/Slack/generic webhook
  (`alert set <url>` / `alert test` / `alert off`). Egress is fail-closed:
  https-only and routed through the SSRF guard. Throttled per source IP. Pro
  unlocks multi-channel (Slack/Teams/PagerDuty), email, and SIEM routing.
- **`netwatch activate <key>` / `netwatch license`** — license activation and
  tier status. The Free package ships no Pro code; paid tiers unlock only when
  the signed `netwatch-pro` add-on is installed and a valid license is present.
- **One-line installer** (`install.sh`) for a low-friction first run.

### Changed
- Tier gate is now license-based (Free / Pro / Business / Enterprise) with a
  graceful fall-back to Free when the add-on isn't installed. `NETWATCH_PRO=1`
  remains a dev/CI override.

### Fixed
- `pytest` no longer aborts collection on the runtime `logs/` directory
  (`testpaths`/`norecursedirs` scoped to `tests/`).
- Packaging excludes `netwatch_pro*` so Pro code can never leak into the Free
  wheel.

## 1.2.2 — 2026-06-10

### Security
- Hardened SSRF guards against DNS rebinding. The OSINT validators
  (`_validate_target_url`, `_validate_target_host`, `_is_internal_target`) now
  share one resolver that checks **every** A/AAAA record (not just the first),
  so a rebinding answer pairing a public and a private address is refused as a
  whole. Coverage extended to IPv4-mapped IPv6 (`::ffff:169.254.169.254`),
  RFC 6598 carrier-grade NAT (`100.64.0.0/10`), multicast, and unspecified.
- `_proxied_get` now re-resolves and pins the connection immediately before the
  fetch on the direct (non-proxy) path, closing the validate→fetch TOCTOU
  window. Plain-HTTP requests are pinned to the validated IP with the original
  `Host` header (cloud-metadata SSRF is always HTTP); HTTPS keeps its hostname
  so TLS SNI/cert validation is preserved.
- `osint_headers` no longer fails **open** on DNS error and now blocks
  loopback/link-local/metadata targets (previously only `is_private`).

## 1.2.1 — 2026-06-09

### Fixed
- `VERSION` constant bumped 1.1.0 → 1.2.1 (dashboard banner was reporting wrong version).
- Hardcoded developer-machine paths replaced — caused install crash for fresh users:
  - proxychains config now resolved via `BASE_DIR`, falls back to system default if missing
  - `PROXYCHAIN_SCRIPT` now reads `NETWATCH_PROXYCHAIN_SCRIPT` env or `~/scripts/proxychain.sh`
  - extra log-dir fallback now `~/agents/honeypot-captures` (expanded per user)
  - cloudflared binary lookup: `shutil.which` → `NETWATCH_CLOUDFLARED_BIN` → `~/agents/agent-office/cloudflared`

## 1.2.0 — 2026-06-05

### Added
- Session replay viewer (web + TUI) — scrubbable playback of captured attacker sessions.
- Same-IP telnet sessions roll up into one aggregated entry (`all_<ip>`) with visible `── ATTEMPT N ──` separator events; per-attempt drill-down still works via the original session_id.
- Honeypot tarpit — RTSP credential-capture handshake now streams a looped MP4 (`cat_loop.mp4` by default) at a rate-limited speed after auth; HTTP fake-cam endpoints (`/cam01.mp4`, `/video.mp4`, `/stream.mp4`, `/Streaming/Channels/<N>`, `/cgi-bin/snapshot.cgi`) trickle the same video. Configurable via `NETWATCH_TARPIT`, `NETWATCH_TARPIT_VIDEO`, `NETWATCH_TARPIT_RATE`, `NETWATCH_TARPIT_MAX_SEC`. Whitelisted IPs bypass.
- CrowdSec auto-ban integration — local `cscli` bridge, ipset-backed enforcement, 60s same-IP dedupe.
- Scan tab — HTTP probe events split off the honeypot tab so signal density stays high.
- Port configuration via env vars: `NETWATCH_HTTP_PORT`, `NETWATCH_TELNET_PORT`, `NETWATCH_FTP_PORT`, `NETWATCH_RTSP_PORT`.

### Security
- ANSI/control-char stripper applied to all attacker-influenced text in the replay UI (intel sidebar, event stream, session list) — defense vs `\x1b]52` clipboard hijack, screen wipe, fake-prompt class attacks.
- `_validate_session_id` now requires structural IP validation (`ipaddress.ip_address`) in addition to the regex shape check.
- `_group_telnet_by_ip` cached so unauthenticated `/api/replay/all_<random>` requests can't force repeated full log re-parses (DoS).
- `_index_cache` key now includes `NETWATCH_TELNET_GAP_SEC` so runtime env changes invalidate immediately.
- `NETWATCH_TELNET_GAP_SEC` clamped to 30-day max so absurd values can't OOM the renderer.

### Fixed
- Termux launcher — skip sudo re-exec on Android and fall through to passive mode.

## 1.1.0

Prior release. See git history for details.
