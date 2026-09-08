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


def test_cam_status_explains_a_missing_module(monkeypatch):
    """A bare 404 made the panel say "no cameras configured" for what was
    really a missing add-on — the payload now names the real reason."""
    monkeypatch.setattr(netwatch, "_pro_sub", lambda n: None)
    r = _admin_client().get("/api/cam/status")
    assert r.status_code == 200
    data = r.get_json()
    assert data["running"] is False and data["cameras"] == []
    assert "netwatch-pro[camera]" in data["reason"]


def test_cam_status_returns_module_payload(monkeypatch):
    monkeypatch.setattr(netwatch, "_pro_sub",
                        lambda n: _cam_mod() if n == "camera" else None)
    r = _admin_client().get("/api/cam/status")
    assert r.status_code == 200
    data = r.get_json()
    assert data["running"] is True and data["cameras"][0]["frames"] == 42


def test_cam_status_module_error_is_typed_not_leaked(monkeypatch):
    mod = _cam_mod()
    mod.status.side_effect = RuntimeError("license expired: /home/u/secret.dat")
    monkeypatch.setattr(netwatch, "_pro_sub",
                        lambda n: mod if n == "camera" else None)
    r = _admin_client().get("/api/cam/status")
    assert r.status_code == 200
    reason = r.get_json()["reason"]
    assert "RuntimeError" in reason and "secret.dat" not in reason


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


# ── cam add / remove / list (config seams) ──────────────────────────────────

def _capture_console(monkeypatch):
    """Capture what the TUI verb printed."""
    out = []
    monkeypatch.setattr(netwatch, "add_console", lambda line="", *a, **k: out.append(line))
    return out


def _pro_cam(monkeypatch, mod, app_running=True):
    monkeypatch.setattr(netwatch, "tier_at_least", lambda t: True)
    monkeypatch.setattr(netwatch, "_pro_sub",
                        lambda n: mod if n == "camera" else None)
    # Inside the running app the sentry is hot-restarted; a one-shot CLI run
    # only writes the config (see _APP_RUNNING).
    monkeypatch.setattr(netwatch, "_APP_RUNNING", app_running)


def test_cam_add_blink_writes_and_restarts(monkeypatch):
    mod = _cam_mod()
    mod.add_source.return_value = {"id": 0, "kind": "blink", "source": "Front Door"}
    mod.restart_background.return_value = True
    _pro_cam(monkeypatch, mod)
    out = _capture_console(monkeypatch)
    netwatch._disp_cam(["cam", "add", "blink", "Front", "Door"])
    mod.add_source.assert_called_once_with("blink", "Front Door")  # name keeps its space
    mod.restart_background.assert_called_once()
    assert any("added cam0" in netwatch._ansi_strip(l) for l in out)


def test_cam_add_reports_a_rejected_source(monkeypatch):
    mod = _cam_mod()
    mod.add_source.side_effect = ValueError("camera already configured: Front Door")
    _pro_cam(monkeypatch, mod)
    out = _capture_console(monkeypatch)
    netwatch._disp_cam(["cam", "add", "blink", "Front Door"])
    assert any("already configured" in netwatch._ansi_strip(l) for l in out)
    mod.restart_background.assert_not_called()      # nothing changed, nothing restarted


def test_cam_add_without_args_shows_usage(monkeypatch):
    mod = _cam_mod()
    _pro_cam(monkeypatch, mod)
    out = _capture_console(monkeypatch)
    netwatch._disp_cam(["cam", "add", "blink"])
    assert any("usage: cam add" in netwatch._ansi_strip(l) for l in out)
    mod.add_source.assert_not_called()


def test_cam_remove_by_id(monkeypatch):
    mod = _cam_mod()
    mod.remove_source.return_value = {"id": 1, "source": "0"}
    mod.restart_background.return_value = False
    _pro_cam(monkeypatch, mod)
    out = _capture_console(monkeypatch)
    netwatch._disp_cam(["cam", "remove", "1"])
    mod.remove_source.assert_called_once_with(1)
    assert any("removed cam1" in netwatch._ansi_strip(l) for l in out)


def test_cam_remove_rejects_a_non_numeric_id(monkeypatch):
    mod = _cam_mod()
    _pro_cam(monkeypatch, mod)
    out = _capture_console(monkeypatch)
    netwatch._disp_cam(["cam", "remove", "front-door"])
    mod.remove_source.assert_not_called()
    assert out                                      # complained instead of raising


def test_cam_list_shows_ids_and_kinds(monkeypatch):
    mod = _cam_mod()
    mod.list_sources.return_value = [
        {"id": 0, "kind": "blink", "source": "Front Door", "valid": True},
        {"id": 1, "kind": "rtsp", "source": "rtsp://***@cam/stream", "valid": True},
    ]
    _pro_cam(monkeypatch, mod)
    out = _capture_console(monkeypatch)
    netwatch._disp_cam(["cam", "list"])
    text = " ".join(netwatch._ansi_strip(l) for l in out)
    assert "cam0" in text and "blink" in text and "Front Door" in text
    assert "cam1" in text and "rtsp" in text


def test_cam_blink_auth_points_at_the_terminal_command(monkeypatch):
    mod = _cam_mod()
    _pro_cam(monkeypatch, mod)
    out = _capture_console(monkeypatch)
    netwatch._disp_cam(["cam", "blink-auth"])
    text = " ".join(netwatch._ansi_strip(l) for l in out)
    assert "netwatch_pro.camera_blink auth" in text
    assert "password is never stored" in text.lower()


def test_cam_management_is_pro_gated(monkeypatch):
    mod = _cam_mod()
    monkeypatch.setattr(netwatch, "tier_at_least", lambda t: False)
    monkeypatch.setattr(netwatch, "_pro_sub",
                        lambda n: mod if n == "camera" else None)
    out = _capture_console(monkeypatch)
    netwatch._disp_cam(["cam", "add", "blink", "Front Door"])
    mod.add_source.assert_not_called()
    assert any("Pro feature" in netwatch._ansi_strip(l) for l in out)


def test_cam_restart_failure_is_reported_not_raised(monkeypatch):
    mod = _cam_mod()
    mod.add_source.return_value = {"id": 0, "kind": "usb", "source": "0"}
    mod.restart_background.side_effect = RuntimeError("OpenCV not installed")
    _pro_cam(monkeypatch, mod)
    out = _capture_console(monkeypatch)
    netwatch._disp_cam(["cam", "add", "usb", "0"])
    assert any("OpenCV not installed" in netwatch._ansi_strip(l) for l in out)


# ── cam tab panel ──────────────────────────────────────────────────────────

def test_section_cam_renders_the_real_status_schema(monkeypatch):
    """The panel was written against an imagined schema (dict events, a
    'status' key) and blew up on camera.py's actual payload."""
    mod = _cam_mod()
    _pro_cam(monkeypatch, mod)
    lines = netwatch._section_cam()
    text = " ".join(netwatch._ansi_strip(l) for l in lines)
    assert "cam0" in text and "live" in text and "frames 42" in text
    assert "ALERT camera_person" in text


def test_section_cam_shows_why_it_is_empty(monkeypatch):
    mod = _cam_mod()
    mod.status.return_value = {"running": False, "cameras": [], "events": [],
                               "configured": 1,
                               "reason": "RuntimeError: OpenCV not installed"}
    _pro_cam(monkeypatch, mod)
    text = " ".join(netwatch._ansi_strip(l) for l in netwatch._section_cam())
    assert "OpenCV not installed" in text
    assert "cam add blink" in text


def test_section_cam_offers_blink_auth_when_nothing_configured(monkeypatch):
    mod = _cam_mod()
    mod.status.return_value = {"running": False, "cameras": [], "events": [],
                               "configured": 0, "reason": "no cameras configured"}
    _pro_cam(monkeypatch, mod)
    text = " ".join(netwatch._ansi_strip(l) for l in netwatch._section_cam())
    assert "cam blink-auth" in text


def test_cam_status_verb_explains_a_stopped_sentry(monkeypatch):
    mod = _cam_mod()
    mod.status.return_value = {"running": False, "cameras": [], "events": [],
                               "configured": 0, "reason": "no cameras configured"}
    _pro_cam(monkeypatch, mod)
    out = _capture_console(monkeypatch)
    netwatch._disp_cam(["cam"])
    text = " ".join(netwatch._ansi_strip(l) for l in out)
    assert "no cameras configured" in text and "cam add blink" in text


def test_one_shot_cli_add_does_not_start_camera_threads(monkeypatch):
    """`netwatch cam add …` exits immediately — starting OpenCV watchers there
    aborts in native code at teardown and helps nobody."""
    mod = _cam_mod()
    mod.add_source.return_value = {"id": 0, "kind": "usb", "source": "0"}
    _pro_cam(monkeypatch, mod, app_running=False)
    out = _capture_console(monkeypatch)
    netwatch._disp_cam(["cam", "add", "usb", "0"])
    mod.add_source.assert_called_once()
    mod.restart_background.assert_not_called()
    assert "saved" in netwatch._ansi_strip(" ".join(out))


def test_exit_hook_stops_the_sentry(monkeypatch):
    mod = _cam_mod()
    monkeypatch.setattr(netwatch, "_pro_sub", lambda n: mod if n == "camera" else None)
    netwatch._stop_camera_sentry_at_exit()
    mod.stop_background.assert_called_once()


def test_exit_hook_is_silent_without_the_addon(monkeypatch):
    monkeypatch.setattr(netwatch, "_pro_sub", lambda n: None)
    netwatch._stop_camera_sentry_at_exit()        # must not raise
