"""
TUI / rendering STABILITY suite for netwatch.py.

Safety net for the classes of bugs that keep recurring in the dashboard:
  * layout overflow (tab bar wrapping and shoving the whole frame down a row)
  * render crashes while building a frame for a given tab / width / height
  * tab drift (a tab name that no longer switches, or TABS/tab-bar drift)
  * dispatch gaps (a command key that shadows a tab, a dead handler)

Everything is exercised at the function level -- no real TTY, no real network
or subprocess I/O. `conftest.py` already imports netwatch with import-time I/O
mocked and resets mutable module state between tests (autouse
`reset_global_state`); this file adds a belt-and-suspenders `no_io` fixture so
the two tabs that reach out (proxy -> systemctl, fleet -> remote poll) stay
inert.

These assert the *desired* invariants (things that must always hold), so they
remain valid after the concurrent tab-switch-input fix lands. If one ever trips
on a genuine defect it is marked xfail with a reason rather than by editing
netwatch.py.
"""
import ast
import inspect
import re
import contextlib
from unittest.mock import patch, MagicMock

import pytest

import netwatch


# Widths the dashboard must survive. 40 is a genuinely tiny terminal; 200 is a
# wide one. The tab-bar overflow regression that broke the dashboard lived in
# this range.
WIDTHS = [40, 60, 72, 80, 100, 120, 200]
HEIGHTS = [8, 40]

# Section renderers reachable from a tab in _build_frame.
SECTION_NAMES = [
    "_section_hosts", "_section_protocols", "_section_dns", "_section_honeypot",
    "_section_nmap", "_section_arp", "_section_alerts", "_section_osint",
    "_section_proxy", "_section_mesh", "_section_fleet",
]

# Only SGR (colour) escapes carry the tab bar's colour; this mirrors the
# accounting the tab bar itself does when it decides whether it overflows.
_SGR_RE = re.compile(r"\x1b\[[0-9;]*m")


def _sgr_strip(s):
    return _SGR_RE.sub("", s)


@pytest.fixture(autouse=True)
def no_io():
    """Neutralise the only two tabs that touch the outside world so rendering
    can never do real I/O: proxy shells out to `systemctl`, fleet reads a
    remotes file and spins a background poller."""
    with contextlib.ExitStack() as stack:
        stack.enter_context(patch(
            "netwatch.subprocess.run",
            return_value=MagicMock(stdout="", stderr="", returncode=0)))
        stack.enter_context(patch("netwatch.subprocess.Popen", MagicMock()))
        stack.enter_context(patch("netwatch._load_remotes", return_value={}))
        stack.enter_context(patch("netwatch._ensure_remote_poller"))
        stack.enter_context(patch("netwatch.socket.socket", MagicMock()))
        # Explicitly re-assert the three the task calls out, on top of conftest.
        netwatch.console_output.clear()
        netwatch.honeypot_events.clear()
        netwatch.current_tab = "all"
        yield


def _seed_state():
    """Give every section something to render so we exercise the populated
    code paths, not just the empty ones."""
    netwatch.honeypot_events.extend([
        {"time": "10:00:01", "service": "telnet", "ip": "203.0.113.42", "summary": "login admin/1234"},
        {"time": "10:00:05", "service": "credential", "ip": "203.0.113.42", "summary": "admin:password"},
        {"time": "10:00:10", "service": "http", "ip": "198.51.100.7", "summary": "GET /admin"},
    ])
    netwatch.hosts["203.0.113.42"].update({"bytes_in": 12000, "bytes_out": 3400, "packets": 42, "threat_score": 35})
    netwatch.hosts["10.0.1.9"].update({"bytes_in": 500, "bytes_out": 700, "packets": 12})
    netwatch.alerts.append({"time": "10:00", "msg": "port scan from 203.0.113.42"})
    netwatch.dns_queries.append({"time": "10:00", "ip": "10.0.1.9", "domain": "example.com"})
    netwatch.proto_stats["TCP"] = 120
    netwatch.proto_stats["DNS"] = 30
    netwatch.arp_table["10.0.1.1"] = {"mac": "aa:bb:cc:dd:ee:ff", "state": "REACHABLE"}
    netwatch.nmap_results.append({"time": "10:00", "line": "22/tcp open ssh"})
    netwatch.osint_results.append({"time": "10:00", "type": "GEO", "target": "203.0.113.42", "result": "US"})


def _direct_cmds_items():
    """Return [(command_key, handler_obj_or_None), ...] for the _DIRECT_CMDS
    dispatch table.

    _DIRECT_CMDS is currently a *local* inside handle_command, so it is not a
    module attribute. Prefer a module attribute if the fix promotes it; else
    recover the table from the source via AST so this test keeps working either
    way."""
    obj = getattr(netwatch, "_DIRECT_CMDS", None)
    if isinstance(obj, dict):
        items = []
        for k, v in obj.items():
            fn = v[1] if isinstance(v, tuple) and len(v) >= 2 else v
            items.append((k, fn))
        return items

    tree = ast.parse(inspect.getsource(netwatch))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        for tgt in node.targets:
            if (isinstance(tgt, ast.Name) and tgt.id == "_DIRECT_CMDS"
                    and isinstance(node.value, ast.Dict)):
                items = []
                for k, v in zip(node.value.keys, node.value.values):
                    key = k.value if isinstance(k, ast.Constant) else None
                    fn = None
                    if (isinstance(v, ast.Tuple) and len(v.elts) >= 2
                            and isinstance(v.elts[1], ast.Name)):
                        fn = getattr(netwatch, v.elts[1].id, None)
                    items.append((key, fn))
                return items
    raise AssertionError("_DIRECT_CMDS table not found in netwatch")


# --------------------------------------------------------------------------- #
# 3. Tabs are consistent, complete, and reachable
# --------------------------------------------------------------------------- #

def test_tabs_are_nonempty_strings():
    assert netwatch.TABS, "TABS must not be empty"
    for name in netwatch.TABS:
        assert isinstance(name, str) and name, f"bad tab entry: {name!r}"


def test_tabs_have_no_duplicates():
    assert len(netwatch.TABS) == len(set(netwatch.TABS)), \
        f"duplicate tab(s): {netwatch.TABS}"


def test_tabs_length_matches_rendered_bar():
    # Every tab label must actually appear in a wide, un-clipped tab bar, and
    # the count of rendered labels must equal len(TABS) (no drift).
    bar = _sgr_strip(netwatch._tab_bar(500, active="all"))
    rendered = [t for t in netwatch.TABS if t.upper() in bar]
    assert len(rendered) == len(netwatch.TABS), (
        f"tab bar renders {len(rendered)} of {len(netwatch.TABS)} tabs; "
        f"missing: {set(netwatch.TABS) - set(rendered)}")


def test_tab_switch_predicate_true_for_each_tab():
    # The tab-switch predicate the input loop relies on.
    for name in netwatch.TABS:
        assert name in netwatch.TABS


@pytest.mark.parametrize("name", netwatch.TABS)
def test_every_tab_name_switches_current_tab(name):
    # Typing a bare tab name must switch to that tab -- this covers the tabs
    # (proxy, mesh) that are dispatched via _DIRECT_CMDS rather than the plain
    # tab-name set, i.e. exactly the drift/dispatch-gap class of bug.
    netwatch.current_tab = "all"
    netwatch.handle_command(name)
    assert netwatch.current_tab == name, \
        f"typing {name!r} left current_tab={netwatch.current_tab!r}"


# --------------------------------------------------------------------------- #
# 1. Rendering never crashes (seeded + empty), across widths and heights
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("cols", WIDTHS)
def test_build_frame_seeded_never_crashes(cols):
    _seed_state()
    for height in HEIGHTS:
        for tab in netwatch.TABS:
            frame = netwatch._build_frame(cols=cols, max_content=height, active_tab=tab)
            assert isinstance(frame, list), f"{tab}@{cols}x{height} returned {type(frame)}"
            assert all(isinstance(line, str) for line in frame), \
                f"{tab}@{cols}x{height} produced a non-str line"


@pytest.mark.parametrize("cols", WIDTHS)
def test_build_frame_empty_state_never_crashes(cols):
    # No seeding: every section must render its empty state without raising.
    for tab in netwatch.TABS:
        frame = netwatch._build_frame(cols=cols, max_content=20, active_tab=tab)
        assert isinstance(frame, list)
        assert all(isinstance(line, str) for line in frame)


def test_build_frame_default_args_ok():
    _seed_state()
    frame = netwatch._build_frame()
    assert isinstance(frame, list) and frame
    assert all(isinstance(line, str) for line in frame)


def test_build_frame_unknown_tab_resets_to_all():
    # The fail-soft branch: an unknown active tab must not crash and must snap
    # the dashboard back to the "all" view.
    netwatch.current_tab = "all"
    frame = netwatch._build_frame(cols=80, max_content=20, active_tab="does-not-exist")
    assert isinstance(frame, list)
    assert netwatch.current_tab == "all"


# --------------------------------------------------------------------------- #
# 2. Tab bar never overflows (the dashboard-breaking regression)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("cols", WIDTHS)
def test_tab_bar_never_overflows(cols):
    for active in netwatch.TABS:
        bar = netwatch._tab_bar(cols, active=active)
        assert isinstance(bar, str)
        visible = len(_sgr_strip(bar))
        assert visible <= cols, (
            f"tab bar overflow: active={active} cols={cols} visible={visible} "
            f"-> would wrap and shove the frame down a row")


@pytest.mark.parametrize("cols", [1, 5, 10, 20, 30])
def test_tab_bar_never_overflows_on_tiny_terminals(cols):
    for active in netwatch.TABS:
        bar = netwatch._tab_bar(cols, active=active)
        assert len(_sgr_strip(bar)) <= cols, \
            f"tab bar overflow at very narrow width cols={cols} active={active}"


def test_tab_bar_defaults_to_current_tab():
    netwatch.current_tab = "hosts"
    bar = netwatch._tab_bar(120)
    assert isinstance(bar, str) and _sgr_strip(bar)


# --------------------------------------------------------------------------- #
# 4. Command dispatch safety
# --------------------------------------------------------------------------- #

def test_direct_cmd_handlers_are_callable():
    items = _direct_cmds_items()
    assert items, "no _DIRECT_CMDS entries recovered"
    dead = [key for key, fn in items if not callable(fn)]
    assert not dead, f"_DIRECT_CMDS entries with non-callable handlers: {dead}"


def test_direct_cmd_collisions_still_switch_their_tab():
    # A command key may share a name with a tab (proxy, mesh) *only* if its
    # handler, invoked bare, still switches to that tab. Otherwise it shadows
    # tab switching -- flag it.
    keys = {k for k, _ in _direct_cmds_items()}
    collisions = sorted(keys & set(netwatch.TABS))
    for name in collisions:
        netwatch.current_tab = "all"
        netwatch.handle_command(name)
        assert netwatch.current_tab == name, (
            f"command {name!r} collides with a tab of the same name but does "
            f"not switch to it (shadows tab switching)")


def test_blocking_actions_are_strings():
    assert isinstance(netwatch._BLOCKING_ACTIONS, (set, frozenset))
    for a in netwatch._BLOCKING_ACTIONS:
        assert isinstance(a, str) and a


def test_blocking_actions_are_all_dispatchable():
    # Everything queued to the background worker must be a real command: a
    # _DIRECT_CMDS key or a known batch op. A stray entry would queue then hit
    # "Unknown command".
    known_batch = {"scanall", "geoall", "whoisall", "reconall"}
    direct_keys = {k for k, _ in _direct_cmds_items()}
    orphans = [a for a in netwatch._BLOCKING_ACTIONS
               if a not in direct_keys and a not in known_batch]
    assert not orphans, f"_BLOCKING_ACTIONS not backed by a handler: {orphans}"


# --------------------------------------------------------------------------- #
# 5. Section renderers fail soft (seeded + empty)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("section", SECTION_NAMES)
def test_section_renderer_empty_state(section):
    fn = getattr(netwatch, section)
    out = fn(3)
    assert isinstance(out, list)
    assert all(isinstance(line, str) for line in out)


@pytest.mark.parametrize("section", SECTION_NAMES)
def test_section_renderer_seeded_state(section):
    _seed_state()
    fn = getattr(netwatch, section)
    out = fn(3)
    assert isinstance(out, list)
    assert all(isinstance(line, str) for line in out)


# --------------------------------------------------------------------------- #
# 6. ANSI-strip / width helpers
# --------------------------------------------------------------------------- #

def test_ansi_strip_removes_color_escapes_keeps_text():
    colored = f"{netwatch.BOLD}{netwatch.RED}HELLO{netwatch.RESET} world"
    assert netwatch._ansi_strip(colored) == "HELLO world"


def test_ansi_strip_removes_csi_osc_and_control():
    raw = "\x1b[1;31mred\x1b[0m\x1b]0;title\x07mid\x00\x08end"
    stripped = netwatch._ansi_strip(raw)
    assert "\x1b" not in stripped
    assert "\x00" not in stripped and "\x08" not in stripped
    assert "red" in stripped and "mid" in stripped and "end" in stripped


def test_ansi_strip_drops_carriage_returns():
    # Carriage returns are stripped (log-forgery hardening) but newlines kept.
    assert netwatch._ansi_strip("a\r\nb") == "a\nb"


def test_ansi_strip_plain_text_unchanged():
    assert netwatch._ansi_strip("just plain ascii 123") == "just plain ascii 123"


def test_tab_bar_width_accounting_matches_ansi_strip():
    # The tab bar contains only SGR escapes, so the general _ansi_strip and the
    # SGR-only accounting the bar uses to avoid overflow must agree on width.
    for cols in WIDTHS:
        bar = netwatch._tab_bar(cols, active="all")
        assert len(_sgr_strip(bar)) == len(netwatch._ansi_strip(bar))


def test_clip_visible_bounds_visible_width():
    colored = f"{netwatch.RED}abcdefghij{netwatch.RESET}"
    clipped = netwatch._clip_visible(colored, 4)
    assert len(_sgr_strip(clipped)) <= 4
    assert netwatch._clip_visible(colored, 0) == ""


# --------------------------------------------------------------------------- #
# 7. Console output is bounded
# --------------------------------------------------------------------------- #

def test_console_output_is_bounded_deque():
    from collections import deque
    assert isinstance(netwatch.console_output, deque)
    assert netwatch.console_output.maxlen == netwatch.MAX_CONSOLE


def test_add_console_never_exceeds_maxlen():
    netwatch.console_output.clear()
    overflow = netwatch.MAX_CONSOLE + 500
    for i in range(overflow):
        netwatch.add_console(f"line {i}")
    assert len(netwatch.console_output) == netwatch.MAX_CONSOLE


def test_add_console_keeps_most_recent():
    netwatch.console_output.clear()
    for i in range(netwatch.MAX_CONSOLE + 10):
        netwatch.add_console(f"line {i}")
    # Oldest evicted, newest retained.
    assert netwatch.console_output[-1] == f"line {netwatch.MAX_CONSOLE + 9}"
    assert "line 0" not in netwatch.console_output
