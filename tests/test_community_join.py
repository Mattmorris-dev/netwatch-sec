"""Community hive: shipper enroll_community(), join surfaces, nudges."""
import io
import json
import os
from unittest.mock import MagicMock, patch

import pytest

import netwatch
import netwatch_shipper as ship


def _resp(payload: dict):
    """Minimal context-manager response like _https_get returns."""
    m = MagicMock()
    m.read.return_value = json.dumps(payload).encode()
    m.__enter__ = lambda s: s
    m.__exit__ = MagicMock(return_value=False)
    return m


@pytest.fixture
def cfg_path(tmp_path):
    return tmp_path / "apiary_node.json"


# ─── enroll_community ────────────────────────────────────────────────────


def test_enroll_happy_path(cfg_path, monkeypatch):
    monkeypatch.setenv("NETWATCH_COMMUNITY_TOKEN", "hive-tok")
    with patch.object(ship, "_https_get",
                      return_value=_resp({"node_id": "cm-pi", "key": "k" * 40})) as g:
        cfg = ship.enroll_community("https://hive.example:8443",
                                    config_path=cfg_path)
    assert cfg["node_id"] == "cm-pi" and cfg["community"] is True
    assert cfg["hub_url"] == "https://hive.example:8443"
    req = g.call_args[0][1]
    assert req.full_url == "https://hive.example:8443/enroll"
    sent = json.loads(req.data)
    assert sent["token"] == "hive-tok"
    assert oct(os.stat(cfg_path).st_mode & 0o777) == "0o600"
    saved = json.loads(cfg_path.read_text())
    assert saved["node_key"] == "k" * 40
    assert "payload_optin" not in saved            # community never ships payloads


def test_enroll_refuses_http(cfg_path):
    with pytest.raises(ValueError, match="https"):
        ship.enroll_community("http://hive.example:8443", token="t",
                              config_path=cfg_path)


def test_enroll_requires_token(cfg_path, monkeypatch):
    monkeypatch.delenv("NETWATCH_COMMUNITY_TOKEN", raising=False)
    with pytest.raises(ValueError, match="token"):
        ship.enroll_community("https://hive.example:8443", config_path=cfg_path)


def test_enroll_no_default_hub(cfg_path, monkeypatch):
    monkeypatch.delenv("NETWATCH_COMMUNITY_HUB", raising=False)
    monkeypatch.setattr(ship, "DEFAULT_COMMUNITY_HUB", "")
    with pytest.raises(ValueError, match="community hub"):
        ship.enroll_community(token="t", config_path=cfg_path)


def test_enroll_rejects_garbage_response(cfg_path):
    for payload in ({"node_id": "../evil", "key": "k"},
                    {"node_id": "cm-ok", "key": ""},
                    {"node_id": "cm-ok", "key": "k" * 600},
                    {"nope": 1}):
        with patch.object(ship, "_https_get", return_value=_resp(payload)):
            with pytest.raises(ValueError, match="invalid credentials"):
                ship.enroll_community("https://h.example", token="t",
                                      config_path=cfg_path)
    assert not cfg_path.exists()                   # nothing persisted on failure


def test_enroll_hub_refusal_message(cfg_path):
    import urllib.error
    err = urllib.error.HTTPError("https://h.example/enroll", 503, "busy", {},
                                 io.BytesIO(b'{"error": "hive full"}'))
    with patch.object(ship, "_https_get", side_effect=err):
        with pytest.raises(ValueError, match="hive full"):
            ship.enroll_community("https://h.example", token="t",
                                  config_path=cfg_path)


def test_community_shipper_never_ships_payloads(cfg_path):
    cfg = {"hub_url": "https://h.example", "node_id": "cm-x", "node_key": "k",
           "community": True, "payload_optin": True}      # hand-edited config
    s = ship.Shipper(config=cfg, state_path=cfg_path.parent / "st.json",
                     spool_dir=cfg_path.parent / "spool")
    assert s.payload_optin is False


# ─── netwatch surfaces ───────────────────────────────────────────────────


def test_tui_join_community_dispatch(monkeypatch):
    calls = {}

    class _FakeShipper:
        def __init__(self, cfg):
            calls["cfg"] = cfg

        def start_background(self):
            calls["started"] = True

        def stop(self):
            pass

    fake = MagicMock()
    fake.enroll_community.return_value = {"node_id": "cm-pi", "hub_url": "https://h"}
    fake.Shipper = _FakeShipper
    monkeypatch.setitem(__import__("sys").modules, "netwatch_shipper", fake)
    out = []
    monkeypatch.setattr(netwatch, "add_console", lambda s: out.append(str(s)))
    netwatch._disp_join(["join", "community"])
    fake.enroll_community.assert_called_once_with(None)
    assert calls.get("started") is True
    assert any("hive" in l.lower() for l in out)


def test_tui_join_community_error_surfaces(monkeypatch):
    fake = MagicMock()
    fake.enroll_community.side_effect = ValueError("no community hub configured")
    monkeypatch.setitem(__import__("sys").modules, "netwatch_shipper", fake)
    out = []
    monkeypatch.setattr(netwatch, "add_console", lambda s: out.append(str(s)))
    netwatch._disp_join(["join", "community"])
    assert any("no community hub" in l for l in out)


def test_hive_nudge_line_when_not_joined(monkeypatch):
    monkeypatch.setattr(netwatch, "_hive_status",
                        lambda ttl=60.0: {"joined": False, "nudge_off": False})
    line = netwatch._hive_nudge_line()
    assert line and "join community" in line


def test_hive_nudge_suppressed(monkeypatch):
    for st in ({"joined": True, "nudge_off": False},
               {"joined": False, "nudge_off": True}):
        monkeypatch.setattr(netwatch, "_hive_status", lambda ttl=60.0, s=st: s)
        assert netwatch._hive_nudge_line() is None


def test_hive_status_cached_and_never_raises(monkeypatch, tmp_path):
    netwatch._hive_status_cache["ts"] = 0.0
    fake = MagicMock()
    fake.load_config.side_effect = RuntimeError("disk on fire")
    monkeypatch.setitem(__import__("sys").modules, "netwatch_shipper", fake)
    st = netwatch._hive_status()
    assert st["joined"] is False
    netwatch._hive_status_cache["ts"] = 0.0


def test_api_state_carries_hive_joined(monkeypatch):
    monkeypatch.setattr(netwatch, "_hive_status",
                        lambda ttl=60.0: {"joined": True, "nudge_off": False})
    snap = netwatch._state_snapshot()
    assert snap["hive_joined"] is True


# ─── CLI ─────────────────────────────────────────────────────────────────


def test_cli_join_community(monkeypatch, capsys):
    fake = MagicMock()
    fake.enroll_community.return_value = {"node_id": "cm-pi"}
    monkeypatch.setitem(__import__("sys").modules, "netwatch_shipper", fake)
    rc = netwatch._cli_subcommand(["join", "--community"])
    assert rc == 0
    assert "cm-pi" in capsys.readouterr().out


def test_cli_join_community_error(monkeypatch, capsys):
    fake = MagicMock()
    fake.enroll_community.side_effect = ValueError("boom")
    monkeypatch.setitem(__import__("sys").modules, "netwatch_shipper", fake)
    rc = netwatch._cli_subcommand(["join", "--community"])
    assert rc == 1
    assert "boom" in capsys.readouterr().out


def test_cli_join_usage(monkeypatch, capsys):
    monkeypatch.setitem(__import__("sys").modules, "netwatch_shipper", MagicMock())
    rc = netwatch._cli_subcommand(["join"])
    assert rc == 1
    assert "usage" in capsys.readouterr().out


def test_cli_join_in_subcommand_list():
    assert "join" in netwatch._CLI_SUBCOMMANDS
