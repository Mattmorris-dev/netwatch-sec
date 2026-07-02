"""Regression tests for TUI tab-switching input (the bug where typing a tab
name did nothing because it set current_tab without showing the dashboard).

These exercise the pure helpers the raw input loop delegates to, so they run
without a real TTY.
"""
import netwatch


def test_tab_names_stay_in_sync_with_tabs():
    # Derived from TABS so the two can never drift (the old hardcoded subset
    # was missing tabs, which is how typed names silently failed).
    assert netwatch._TAB_NAMES == frozenset(netwatch.TABS)


def test_every_tab_name_resolves():
    for t in netwatch.TABS:
        assert netwatch._tab_for_command(t) == t
        assert netwatch._tab_for_command(f"  {t.upper()}  ") == t  # case/space tolerant


def test_non_tab_command_is_not_a_tab():
    for cmd in ("scan 1.2.3.4", "help", "", "   ", "whois example.com", "notatab"):
        assert netwatch._tab_for_command(cmd) is None


def test_cycle_tab_forward_and_back_wraps():
    first, last = netwatch.TABS[0], netwatch.TABS[-1]
    assert netwatch._cycle_tab(first, -1) == last          # wrap backwards
    assert netwatch._cycle_tab(last, 1) == first           # wrap forwards
    assert netwatch._cycle_tab(netwatch.TABS[0], 1) == netwatch.TABS[1]


def test_cycle_reaches_every_tab_including_11th_12th():
    # The whole point: mesh/fleet (no number hotkey) must be reachable by cycling.
    seen, cur = set(), netwatch.TABS[0]
    for _ in range(len(netwatch.TABS)):
        seen.add(cur)
        cur = netwatch._cycle_tab(cur, 1)
    assert seen == set(netwatch.TABS)
    assert "fleet" in seen and "mesh" in seen


def test_cycle_tab_handles_unknown_current():
    # A stale/unknown current tab must not crash — falls back to a valid tab.
    assert netwatch._cycle_tab("bogus-not-a-tab", 1) in netwatch.TABS
