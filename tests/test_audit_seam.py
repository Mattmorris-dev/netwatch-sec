"""Free-side audit seam: audit_emit no-ops below Enterprise, delegates above,
and /api/audit gates correctly. LOG-path suite runs at community tier."""
from unittest.mock import MagicMock

import netwatch


def test_audit_emit_noop_at_community(monkeypatch):
    monkeypatch.setattr(netwatch, "tier_at_least", lambda t: False)
    called = []
    monkeypatch.setattr(netwatch, "_pro_sub", lambda n: called.append(n) or None)
    netwatch.audit_emit("net.block", {"ip": "1.2.3.4"})
    assert called == []                                # never even reaches _pro_sub


def test_audit_emit_delegates_at_enterprise(monkeypatch):
    monkeypatch.setattr(netwatch, "tier_at_least", lambda t: t in ("enterprise",))
    mod = MagicMock()
    monkeypatch.setattr(netwatch, "_pro_sub",
                        lambda n: mod if n == "audit" else None)
    netwatch.audit_emit("net.block", {"ip": "9.9.9.9"}, actor="local")
    mod.append.assert_called_once_with("net.block", {"ip": "9.9.9.9"}, "local")


def test_audit_emit_never_raises(monkeypatch):
    monkeypatch.setattr(netwatch, "tier_at_least", lambda t: True)
    mod = MagicMock()
    mod.append.side_effect = RuntimeError("disk full")
    monkeypatch.setattr(netwatch, "_pro_sub",
                        lambda n: mod if n == "audit" else None)
    netwatch.audit_emit("x")                            # must not raise


def _origin():
    return {"Origin": f"http://127.0.0.1:{netwatch.WEB_PORT}"}


def _admin_client():
    netwatch.web_app.config["TESTING"] = True
    c = netwatch.web_app.test_client()
    c.post("/auth", json={"token": netwatch.WEB_TOKEN}, headers=_origin())
    return c


def test_api_audit_disabled_below_enterprise(monkeypatch):
    monkeypatch.setattr(netwatch, "tier_at_least", lambda t: False)
    c = _admin_client()
    data = c.get("/api/audit").get_json()
    assert data["enabled"] is False and "hint" in data


def test_api_audit_enabled_at_enterprise(monkeypatch):
    monkeypatch.setattr(netwatch, "tier_at_least", lambda t: True)
    mod = MagicMock()
    mod.list_records.return_value = [{"ts": "t", "actor": "local",
                                      "action": "net.block", "detail": {}}]
    mod.verify.return_value = {"ok": True, "records": 1}
    monkeypatch.setattr(netwatch, "_pro_sub",
                        lambda n: mod if n == "audit" else None)
    c = _admin_client()
    data = c.get("/api/audit").get_json()
    assert data["enabled"] is True
    assert data["records"][0]["action"] == "net.block"
    assert data["verify"]["ok"] is True


def test_audit_in_cli_subcommands():
    assert "audit" in netwatch._CLI_SUBCOMMANDS
