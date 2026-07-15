"""Tier resolution: NETWATCH_TIER / NETWATCH_PRO dev overrides and ordering.

The free app never contains paid logic — these overrides only flip the
free-side gates (hints, tabs, delegation seams). Pro modules still verify the
real license and fail closed regardless of these env vars.
"""
import netwatch


def test_default_is_community(monkeypatch):
    monkeypatch.delenv("NETWATCH_TIER", raising=False)
    monkeypatch.delenv("NETWATCH_PRO", raising=False)
    monkeypatch.setattr(netwatch, "_license_tier", lambda: None)
    assert netwatch.current_tier() == "community"


def test_netwatch_tier_forces_each_tier(monkeypatch):
    monkeypatch.delenv("NETWATCH_PRO", raising=False)
    monkeypatch.setattr(netwatch, "_license_tier", lambda: None)
    for tier in ("community", "pro", "team", "enterprise"):
        monkeypatch.setenv("NETWATCH_TIER", tier)
        assert netwatch.current_tier() == tier


def test_netwatch_tier_accepts_marketing_aliases(monkeypatch):
    monkeypatch.setattr(netwatch, "_license_tier", lambda: None)
    monkeypatch.setenv("NETWATCH_TIER", "business")
    assert netwatch.current_tier() == "team"
    monkeypatch.setenv("NETWATCH_TIER", "free")
    assert netwatch.current_tier() == "community"


def test_netwatch_tier_garbage_ignored(monkeypatch):
    monkeypatch.delenv("NETWATCH_PRO", raising=False)
    monkeypatch.setattr(netwatch, "_license_tier", lambda: None)
    monkeypatch.setenv("NETWATCH_TIER", "gold-plated")
    assert netwatch.current_tier() == "community"


def test_netwatch_tier_beats_netwatch_pro(monkeypatch):
    monkeypatch.setattr(netwatch, "_license_tier", lambda: None)
    monkeypatch.setenv("NETWATCH_PRO", "1")
    monkeypatch.setenv("NETWATCH_TIER", "enterprise")
    assert netwatch.current_tier() == "enterprise"


def test_netwatch_pro_still_works(monkeypatch):
    monkeypatch.delenv("NETWATCH_TIER", raising=False)
    monkeypatch.setattr(netwatch, "_license_tier", lambda: None)
    monkeypatch.setenv("NETWATCH_PRO", "1")
    assert netwatch.current_tier() == "pro"


def test_tier_at_least_ordering(monkeypatch):
    monkeypatch.setenv("NETWATCH_TIER", "team")
    assert netwatch.tier_at_least("pro")
    assert netwatch.tier_at_least("team")
    assert netwatch.tier_at_least("business")  # alias
    assert not netwatch.tier_at_least("enterprise")
