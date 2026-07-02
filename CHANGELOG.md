# Changelog

All notable changes to NetWatch are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
