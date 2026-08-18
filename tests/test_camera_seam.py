"""Camera Sentry free-side seam: /cam routes, tier gating, TUI verb.
All Pro substance is mocked — these tests prove the free app's wiring."""
import pytest
from unittest.mock import MagicMock

import netwatch


@pytest.fixture(autouse=True)
def _fresh_auth_limiter():
    """Every test authenticates once; clear the /auth rate limiter so the
    10-per-minute cap can't trip across the file."""
    netwatch._auth_attempts.clear()
    yield


def _origin():
    return {"Origin": f"http://127.0.0.1:{netwatch.WEB_PORT}"}


def _admin_client():
    netwatch.web_app.config["TESTING"] = True
    c = netwatch.web_app.test_client()
    c.post("/auth", json={"token": netwatch.WEB_TOKEN}, headers=_origin())
    return c


def _cam_mod(**kw):
    mod = MagicMock()
    mod.status.return_value = {
        "running": True, "viewers": 0, "person_detect": True,
        "cameras": [{"id": 0, "source": "0", "online": True,
                     "frames": 42, "alerts": 1, "last_alert": None}],
        "events": ["[t] cam0: ALERT camera_person"],
    }
    mod.mjpeg_stream.return_value = iter([b"--frame\r\nchunk\r\n"])
    for k, v in kw.items():
        setattr(mod, k, v)
    return mod


# ── seam function ────────────────────────────────────────────────────────────

def test_seam_noop_below_pro(monkeypatch):
    monkeypatch.setattr(netwatch, "tier_at_least", lambda t: False)
    called = []
    monkeypatch.setattr(netwatch, "_pro_sub",
                        lambda n: called.append(n) or None)
    netwatch._maybe_start_camera_sentry()
    assert not called


def test_seam_never_raises(monkeypatch):
    monkeypatch.setattr(netwatch, "tier_at_least", lambda t: True)
    mod = MagicMock()
    mod.ensure_background.side_effect = RuntimeError("no cv2")
    monkeypatch.setattr(netwatch, "_pro_sub",
                        lambda n: mod if n == "camera" else None)
    netwatch._maybe_start_camera_sentry()            # must not raise


def test_seam_starts_when_configured(monkeypatch):
    monkeypatch.setattr(netwatch, "tier_at_least", lambda t: True)
    mod = MagicMock()
    mod.ensure_background.return_value = True
    monkeypatch.setattr(netwatch, "_pro_sub",
                        lambda n: mod if n == "camera" else None)
    netwatch._maybe_start_camera_sentry()
    mod.ensure_background.assert_called_once()


# ── web routes ───────────────────────────────────────────────────────────────

def test_cam_page_requires_auth():
    netwatch.web_app.config["TESTING"] = True
    c = netwatch.web_app.test_client()          # no /auth
    r = c.get("/cam")
    assert r.status_code == 401


def test_cam_page_upsell_below_pro(monkeypatch):
    monkeypatch.setattr(netwatch, "tier_at_least", lambda t: False)
    monkeypatch.setattr(netwatch, "_pro_sub", lambda n: None)
    r = _admin_client().get("/cam")
    assert r.status_code == 200
    assert b"Pro" in r.data and b"/api/cam/stream" not in r.data


def test_cam_page_renders_with_pro(monkeypatch):
    monkeypatch.setattr(netwatch, "tier_at_least", lambda t: True)
    monkeypatch.setattr(netwatch, "_pro_sub",
                        lambda n: _cam_mod() if n == "camera" else None)
    r = _admin_client().get("/cam")
    assert r.status_code == 200
    assert b"CAMERA SENTRY" in r.data and b"/api/cam/status" in r.data


def test_cam_status_404_without_module(monkeypatch):
    monkeypatch.setattr(netwatch, "_pro_sub", lambda n: None)
    r = _admin_client().get("/api/cam/status")
    assert r.status_code == 404


def test_cam_status_returns_module_payload(monkeypatch):
    monkeypatch.setattr(netwatch, "_pro_sub",
                        lambda n: _cam_mod() if n == "camera" else None)
    r = _admin_client().get("/api/cam/status")
    assert r.status_code == 200
    data = r.get_json()
    assert data["running"] is True and data["cameras"][0]["frames"] == 42


def test_cam_status_gated_module_error_is_404(monkeypatch):
    mod = _cam_mod()
    mod.status.side_effect = RuntimeError("license expired")
    monkeypatch.setattr(netwatch, "_pro_sub",
                        lambda n: mod if n == "camera" else None)
    r = _admin_client().get("/api/cam/status")
    assert r.status_code == 404


def test_cam_stream_streams_chunks(monkeypatch):
    monkeypatch.setattr(netwatch, "_pro_sub",
                        lambda n: _cam_mod() if n == "camera" else None)
    r = _admin_client().get("/api/cam/stream/0")
    assert r.status_code == 200
    assert r.mimetype == "multipart/x-mixed-replace"
    assert b"chunk" in r.data


def test_cam_stream_viewer_cap_is_429(monkeypatch):
    mod = _cam_mod()
    mod.mjpeg_stream.side_effect = RuntimeError(
        "too many concurrent stream viewers")
    monkeypatch.setattr(netwatch, "_pro_sub",
                        lambda n: mod if n == "camera" else None)
    r = _admin_client().get("/api/cam/stream/0")
    assert r.status_code == 429


def test_cam_stream_not_running_is_503(monkeypatch):
    mod = _cam_mod()
    mod.mjpeg_stream.side_effect = RuntimeError("camera sentry not running")
    monkeypatch.setattr(netwatch, "_pro_sub",
                        lambda n: mod if n == "camera" else None)
    r = _admin_client().get("/api/cam/stream/0")
    assert r.status_code == 503


def test_cam_stream_unknown_id_is_404(monkeypatch):
    mod = _cam_mod()
    mod.mjpeg_stream.side_effect = ValueError("unknown camera id: 999")
    monkeypatch.setattr(netwatch, "_pro_sub",
                        lambda n: mod if n == "camera" else None)
    r = _admin_client().get("/api/cam/stream/999")
    assert r.status_code == 404


def test_cam_stream_head_does_not_error(monkeypatch):
    mod = _cam_mod()
    monkeypatch.setattr(netwatch, "_pro_sub",
                        lambda n: mod if n == "camera" else None)
    r = _admin_client().head("/api/cam/stream/0")
    assert r.status_code == 200          # body discarded, no 5xx, no leak


def test_cam_stream_404_without_module(monkeypatch):
    monkeypatch.setattr(netwatch, "_pro_sub", lambda n: None)
    r = _admin_client().get("/api/cam/stream/0")
    assert r.status_code == 404


def test_dashboard_cam_link_tier_gated(monkeypatch):
    monkeypatch.setattr(netwatch, "tier_at_least", lambda t: False)
    monkeypatch.setattr(netwatch, "_pro_sub", lambda n: None)
    assert b'href="/cam"' not in _admin_client().get("/").data
    monkeypatch.setattr(netwatch, "tier_at_least", lambda t: True)
    monkeypatch.setattr(netwatch, "_pro_sub",
                        lambda n: _cam_mod() if n == "camera" else None)
    assert b'href="/cam"' in _admin_client().get("/").data


# ── TUI verb ─────────────────────────────────────────────────────────────────

def _console_text():
    return "\n".join(str(line) for line in netwatch.console_output)


def test_cam_cmd_upsell_below_pro(monkeypatch):
    monkeypatch.setattr(netwatch, "tier_at_least", lambda t: False)
    netwatch._disp_cam(["cam"])
    assert "Pro feature" in _console_text()


def test_cam_cmd_prints_status(monkeypatch):
    monkeypatch.setattr(netwatch, "tier_at_least", lambda t: True)
    monkeypatch.setattr(netwatch, "_pro_sub",
                        lambda n: _cam_mod() if n == "camera" else None)
    netwatch._disp_cam(["cam"])
    out = _console_text()
    assert "CAMERA SENTRY" in out and "cam0" in out and "alerts: 1" in out


def test_cam_cmd_never_raises_on_module_error(monkeypatch):
    monkeypatch.setattr(netwatch, "tier_at_least", lambda t: True)
    mod = _cam_mod()
    mod.status.side_effect = RuntimeError("boom")
    monkeypatch.setattr(netwatch, "_pro_sub",
                        lambda n: mod if n == "camera" else None)
    netwatch._disp_cam(["cam"])
    assert "boom" in _console_text()


def test_cam_registered_as_cli_subcommand():
    # Every Pro verb must be reachable from the shell, not only the TUI/web.
    assert "cam" in netwatch._CLI_SUBCOMMANDS


def test_camera_in_pro_active_modules(monkeypatch):
    monkeypatch.setattr(netwatch, "tier_at_least", lambda t: True)
    monkeypatch.setattr(netwatch, "_pro_sub",
                        lambda n: object() if n == "camera" else None)
    assert "camera" in netwatch.pro_active_modules()


def test_cam_cli_subcommand_prints_status(monkeypatch):
    monkeypatch.setattr(netwatch, "tier_at_least", lambda t: True)
    monkeypatch.setattr(netwatch, "_pro_sub",
                        lambda n: _cam_mod() if n == "camera" else None)
    rc = netwatch._cli_subcommand(["cam"])
    assert rc == 0


def test_cam_cli_subcommand_upsell_below_pro(monkeypatch):
    monkeypatch.setattr(netwatch, "tier_at_least", lambda t: False)
    rc = netwatch._cli_subcommand(["cam"])
    assert rc == 1
