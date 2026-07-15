"""The Apiary hub rollup is wired into the `fleet` TUI tab."""
import netwatch


_ROLL = {
    "total_events": 202, "nodes_active": 2,
    "nodes": [
        {"node_id": "droplet", "name": "droplet", "events": 2,
         "last_seen": "2026-07-08T23:00:00", "revoked": False},
        {"node_id": "pi", "name": "pi", "events": 200,
         "last_seen": "2026-07-08T05:00:00", "revoked": False},
    ],
    "top_services": [("ssh", 77), ("telnet", 70)],
    "top_sources": [("45.9.1.1", 30)],
}


_CORTEX = {
    "generated": "2026-07-10T12:00:00Z", "trained_on": 57000, "events": 57000,
    "attackers": 42, "peak_score": 97,
    "top_attackers": [
        {"ip": "185.223.235.44", "score": 97, "hits": 12, "services": ["rtsp", "telnet"]},
        {"ip": "45.9.148.1", "score": 88, "hits": 5, "services": ["mongo"]},
    ],
}
_ROLL_CX = dict(_ROLL, cortex=_CORTEX)


class _FakeAnalytics:
    @staticmethod
    def fleet_rollup(days=7):
        return _ROLL


class _FakeAnalyticsCX:
    @staticmethod
    def fleet_rollup(days=7):
        return _ROLL_CX


def test_apiary_fleet_lines_render(monkeypatch):
    monkeypatch.setattr(netwatch, "_pro_sub",
                        lambda name: _FakeAnalytics if name == "analytics" else None)
    netwatch._apiary_roll_cache["data"] = None          # bypass any cached value
    text = "\n".join(netwatch._apiary_fleet_lines())
    assert "APIARY HUB" in text
    assert "202 events" in text and "2 active node(s)" in text
    assert "events:200" in text                         # per-node counts
    assert "ssh:77" in text                             # top services
    assert "45.9.1.1(30)" in text                       # top sources
    netwatch._apiary_roll_cache["data"] = None          # don't leak the fake


def test_fleet_tab_shows_apiary_without_remotes(monkeypatch):
    # An Apiary hub operator may have no `remote add` nodes at all — the rollup
    # must still appear (the old code returned early on no remotes).
    monkeypatch.setattr(netwatch, "tier_at_least", lambda t: True)
    monkeypatch.setattr(netwatch, "_load_remotes", lambda: {})
    monkeypatch.setattr(netwatch, "_apiary_fleet_lines",
                        lambda *a, **k: ["  APIARY HUB — fleet rollup", "  ◦ droplet events:2"])
    text = "\n".join(netwatch._section_fleet(50))
    assert "APIARY HUB" in text


def test_fleet_tab_free_tier_skips_apiary(monkeypatch):
    monkeypatch.setattr(netwatch, "tier_at_least", lambda t: False)
    monkeypatch.setattr(netwatch, "_load_remotes", lambda: {})
    called = []
    monkeypatch.setattr(netwatch, "_apiary_fleet_lines", lambda *a, **k: called.append(1) or [])
    netwatch._section_fleet(50)
    assert not called                                   # Free never computes the rollup


def test_api_fleet_includes_apiary(monkeypatch):
    monkeypatch.setattr(netwatch, "tier_at_least", lambda t: True)
    monkeypatch.setattr(netwatch, "_load_remotes", lambda: {})
    monkeypatch.setattr(netwatch, "_pro_sub",
                        lambda name: _FakeAnalytics if name == "analytics" else None)
    netwatch._apiary_roll_cache["data"] = None
    netwatch.web_app.config["TESTING"] = True
    with netwatch.web_app.test_client() as c:
        c.post("/auth", json={"token": netwatch.WEB_TOKEN},
               headers={"Origin": f"http://127.0.0.1:{netwatch.WEB_PORT}"})
        r = c.get("/api/fleet")
        assert r.status_code == 200
        data = r.get_json()
    netwatch._apiary_roll_cache["data"] = None
    assert "apiary" in data
    assert data["apiary"]["total_events"] == 202
    assert data["apiary"]["nodes_active"] == 2
    assert any(n["node_id"] == "pi" for n in data["apiary"]["nodes"])
    assert data["apiary"]["top_services"][0][0] == "ssh"
    assert "recent" not in data["apiary"]               # raw events not shipped to browser


def test_api_fleet_free_tier_no_apiary(monkeypatch):
    monkeypatch.setattr(netwatch, "tier_at_least", lambda t: False)
    monkeypatch.setattr(netwatch, "_load_remotes", lambda: {})
    netwatch.web_app.config["TESTING"] = True
    with netwatch.web_app.test_client() as c:
        c.post("/auth", json={"token": netwatch.WEB_TOKEN},
               headers={"Origin": f"http://127.0.0.1:{netwatch.WEB_PORT}"})
        data = c.get("/api/fleet").get_json()
    assert "apiary" not in data                          # Pro-gated


def test_apiary_fleet_lines_render_cortex(monkeypatch):
    monkeypatch.setattr(netwatch, "_pro_sub",
                        lambda name: _FakeAnalyticsCX if name == "analytics" else None)
    netwatch._apiary_roll_cache["data"] = None
    text = "\n".join(netwatch._apiary_fleet_lines())
    assert "CORTEX brain" in text
    assert "42 attackers" in text and "peak novelty 97" in text
    assert "185.223.235.44" in text and "novelty:97" in text
    netwatch._apiary_roll_cache["data"] = None


def test_api_fleet_includes_cortex(monkeypatch):
    monkeypatch.setattr(netwatch, "tier_at_least", lambda t: True)
    monkeypatch.setattr(netwatch, "_load_remotes", lambda: {})
    monkeypatch.setattr(netwatch, "_pro_sub",
                        lambda name: _FakeAnalyticsCX if name == "analytics" else None)
    netwatch._apiary_roll_cache["data"] = None
    netwatch.web_app.config["TESTING"] = True
    with netwatch.web_app.test_client() as c:
        c.post("/auth", json={"token": netwatch.WEB_TOKEN},
               headers={"Origin": f"http://127.0.0.1:{netwatch.WEB_PORT}"})
        data = c.get("/api/fleet").get_json()
    netwatch._apiary_roll_cache["data"] = None
    assert data["apiary"]["cortex"]["peak_score"] == 97
    assert data["apiary"]["cortex"]["top_attackers"][0]["ip"] == "185.223.235.44"


def test_api_fleet_includes_seats(monkeypatch):
    monkeypatch.setattr(netwatch, "tier_at_least", lambda t: True)
    monkeypatch.setattr(netwatch, "_load_remotes", lambda: {})
    monkeypatch.setattr(netwatch, "_pro_sub", lambda name: None)
    monkeypatch.setattr(netwatch, "_hub_seats", lambda: {"used": 3, "limit": 25})
    netwatch.web_app.config["TESTING"] = True
    with netwatch.web_app.test_client() as c:
        c.post("/auth", json={"token": netwatch.WEB_TOKEN},
               headers={"Origin": f"http://127.0.0.1:{netwatch.WEB_PORT}"})
        data = c.get("/api/fleet").get_json()
    assert data["seats"] == {"used": 3, "limit": 25}


def test_api_fleet_seats_omitted_when_unavailable(monkeypatch):
    monkeypatch.setattr(netwatch, "tier_at_least", lambda t: True)
    monkeypatch.setattr(netwatch, "_load_remotes", lambda: {})
    monkeypatch.setattr(netwatch, "_pro_sub", lambda name: None)
    monkeypatch.setattr(netwatch, "_hub_seats", lambda: None)
    netwatch.web_app.config["TESTING"] = True
    with netwatch.web_app.test_client() as c:
        c.post("/auth", json={"token": netwatch.WEB_TOKEN},
               headers={"Origin": f"http://127.0.0.1:{netwatch.WEB_PORT}"})
        data = c.get("/api/fleet").get_json()
    assert "seats" not in data


def test_hub_seats_never_raises(monkeypatch):
    class _Boom:
        class NodeRegistry:
            def __init__(self):
                raise RuntimeError("no registry")
    monkeypatch.setattr(netwatch, "_pro_sub",
                        lambda name: _Boom if name == "collector" else None)
    assert netwatch._hub_seats() is None
    monkeypatch.setattr(netwatch, "_pro_sub", lambda name: None)
    assert netwatch._hub_seats() is None


def test_fmt_seats():
    assert netwatch._fmt_seats({"used": 3, "limit": 25}) == "3/25 nodes"
    assert netwatch._fmt_seats({"used": 7, "limit": None}) == "7/unlimited nodes"
