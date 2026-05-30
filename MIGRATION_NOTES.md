# NetWatch Refactor — Migration Notes

Date: 2026-05-30
Scope: In-place edit of `netwatch.py` (single file preserved per user direction
— launcher scripts and entry path untouched).

## What changed

| # | Item | Status | Notes |
|---|------|--------|-------|
| 1 | Screen state via AppState dataclass | ✅ | 3 screens mounted once, F1/F2/F3 toggle, state preserved on return |
| 2 | CLI / Console buffers as `deque(maxlen=5000)` | ✅ | Up from `list` capped at 200 |
| 3 | Web UI Fernet key persisted at `~/.config/netwatch/web.key` | ✅ | `load_or_create_key`, `rotate_key`, `get_cipher` |
| 4 | Compression via dispatch + helper dedup | ⚠️ partial | See "half-cut tradeoff" below |

## Before / after line counts

| Slice | Lines |
|-------|-------|
| `netwatch.py` BEFORE | 6,431 |
| `netwatch.py` AFTER  | 6,613 |
| Delta | **+182** (net) |
| Compression savings  | −50 (OSINT helper dedup, iptables helper) |
| New code added       | +232 (AppState + 2 paint fns + screen wiring + helpers) |

Tests:

| Slice | Tests |
|-------|-------|
| Existing test files | 14 |
| New test files added | 2 (`test_app_state.py`, `test_deque_and_key.py`) |
| Pre-refactor passing | 1,842 |
| Post-refactor passing | **1,887** |
| Pre-refactor failing | 0 |
| Post-refactor failing | 0 |

## Half-cut tradeoff

Original spec called for cutting ~6,431 LOC down to ~3,200 (~half) via
module split into `app.py`, `state.py`, `screens/`, `tools/`, `security.py`,
`web/`, `utils.py`. **User overrode this mid-build** with explicit "EDIT
CURRENT CODEBASE" — meaning no module split.

Without splits, the only path to half-cut is aggressive in-place compression
of working code (templates, OSINT routines, web routes). That carries
high regression risk in a 1,887-test codebase. We declined that risk
and kept the change set surgical:

- Helpers (`_osint_err`, `_osint_record`, `_iptables_rule`,
  `_validate_ip_or_error`) collapse the most repetitive patterns
- Dispatch tables (`_SIMPLE_THREAD_CMDS`, `_DIRECT_CMDS`) were already in
  place and were preserved

If a future round wants the half-cut, the next move is a real module split.
Plan: keep `netwatch.py` as a 50-line facade re-exporting from a new
`netwatch_core/` package. Launcher script and all tests stay green.

## New public API

```python
# Screen state
from netwatch import AppState, SCREENS, SCREEN_DASHBOARD, SCREEN_CLI, SCREEN_CONSOLE, app_state

app_state.switch(SCREEN_CLI)            # toggle screen
app_state.scroll_for(SCREEN_CONSOLE)    # per-screen scrollback
app_state.set_scroll(SCREEN_CLI, 42)

# Persistent crypto
from netwatch import load_or_create_key, rotate_key, get_cipher, _KEY_PATH

key = load_or_create_key()              # idempotent; persists to ~/.config/netwatch/web.key
key = rotate_key()                       # generate new material, atomic replace
cipher = get_cipher(key)                 # Fernet instance

# Render helpers
from netwatch import _paint_dashboard, _paint_cli, _paint_console, _render_frame
# _render_frame() dispatches based on app_state.current_screen.
```

## New TUI behavior

| Action | Result |
|--------|--------|
| `F1` | Switch to Dashboard (restores tab + scroll) |
| `F2` | Switch to Command Line (full-screen prompt) |
| `F3` | Switch to Console (full-screen tool output log) |
| `1`–`9`, `0` | Jump to tab N (also returns to Dashboard) |
| `PgUp` / `PgDn` | Scroll the active screen's buffer (per-screen offset) |
| `Home` / `End` | Jump to top / bottom of active buffer |
| `clear` | Empty `console_output` AND reset all three scroll positions |
| `dashboard` / `dash` / `d` | Switch to Dashboard, set `console_mode = False` (legacy) |
| `cli` / `commandline` / `command-line` | Switch to Command Line |
| `console` | Switch to Console |

## State preservation guarantee

`AppState` keeps:

- `current_tab` (dashboard active subview)
- `dash_scroll`, `cli_scroll`, `console_scroll` (per-screen scrollback offset)
- `dash_focus` (cursor row hint, reserved for future use)
- `show_help_overlay` (help overlay flag)
- `last_screen` (toggle-back target)

Round-trip test verifies: set `current_tab = "nmap"`, `dash_scroll = 33`,
`switch(SCREEN_CLI)`, `switch(SCREEN_CONSOLE)`, `switch(SCREEN_DASHBOARD)` —
both fields are intact at end.

## Security upgrades

In addition to item 3 (key persistence):

- Key directory `~/.config/netwatch` chmod **0700**
- Key file `~/.config/netwatch/web.key` chmod **0600**
- Atomic rotation via `tmp` + `os.replace`
- Corrupt/invalid keys auto-regenerate (won't deadlock startup)
- Key bytes never logged or echoed
- Backwards-compat: existing per-startup random key flow still works if file
  cannot be written (permission, read-only FS) — `load_or_create_key`
  silently falls through to fresh material in memory

## Backward compatibility

- `netwatch.py` filename and launcher scripts (`netwatch`, `netwatch-start.sh`)
  unchanged
- 188 internal symbols still importable from `netwatch` top-level
- Legacy `console_mode` flag preserved (acts as render suppression for
  callers that own the terminal during a command)
- `MAX_CONSOLE` constant kept (now `5000` instead of `200`)
- `_cmd_history` still iterable, indexable, and `.append`-able — just
  bounded by deque rather than `pop(0)` cleanup

## Files touched

- `netwatch.py` — in-place edits
- `tests/test_refactor_v2.py` — updated assertions for new contract
- `tests/test_user_interactions.py` — updated `console_output` type check
- `tests/test_app_state.py` — **new**, 28 tests
- `tests/test_deque_and_key.py` — **new**, 17 tests
- `README.md` — banner + new screen/key documentation
- `docs/banner.png` — new (user-supplied)

## Files NOT touched

- All honeypot handlers (HTTP, Telnet, FTP, RTSP)
- All OSINT external-API functions (`osint_*`)
- Web dashboard HTML/CSS/JS
- GraphQL schema
- Mesh radio integration
- Launcher scripts (`netwatch`, `netwatch-start.sh`)
- Systemd unit file
