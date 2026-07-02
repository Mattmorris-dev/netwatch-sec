"""Free-tier client-magnet tools: alerts webhook + exposure self-check.

Free tier ships a *basic* version of each tool; Pro unlocks the better one.
These tests exercise the free behaviour, the Pro gate, and — critically — the
fail-closed egress on the alert webhook (https-only + SSRF guard).
"""
import json
from unittest.mock import patch, MagicMock

import netwatch


def _console_tail(n=12):
    return "\n".join(list(netwatch.console_output)[-n:])


# ─── webhook kind detection ───────────────────────────────────────────────

def test_webhook_kind_detection():
    assert netwatch._webhook_kind("https://discord.com/api/webhooks/1/x") == "discord"
    assert netwatch._webhook_kind("https://discordapp.com/api/webhooks/1/x") == "discord"
    assert netwatch._webhook_kind("https://hooks.slack.com/services/A/B/C") == "slack"
    assert netwatch._webhook_kind("https://example.com/hook") == "generic"


# ─── egress fails closed ──────────────────────────────────────────────────

def test_send_webhook_rejects_non_https():
    with patch.object(netwatch, "req_lib", MagicMock()) as rl:
        assert netwatch._send_webhook("http://discord.com/api/webhooks/1/x", "t", "m") is False
        rl.post.assert_not_called()


def test_send_webhook_rejects_internal_host():
    # SSRF guard must block loopback / RFC1918 even over https.
    with patch.object(netwatch, "req_lib", MagicMock()) as rl:
        for url in ("https://127.0.0.1/x", "https://192.168.1.5/x",
                    "https://169.254.169.254/latest", "https://10.0.0.1/x"):
            assert netwatch._send_webhook(url, "t", "m") is False
        rl.post.assert_not_called()


def test_send_webhook_posts_when_host_allowed():
    resp = MagicMock(status_code=204)
    rl = MagicMock()
    rl.post.return_value = resp
    with patch.object(netwatch, "req_lib", rl), \
         patch.object(netwatch, "_resolve_safe", return_value=("93.184.216.34", "")):
        ok = netwatch._send_webhook("https://hooks.slack.com/services/A/B/C", "hi", "there")
    assert ok is True
    args, kwargs = rl.post.call_args
    # Slack payload disables markdown so attacker links/mentions don't render.
    assert kwargs["json"] == {"text": "🛰 NetWatch: hi — there", "mrkdwn": False}


def test_webhook_sanitizes_and_disables_mentions():
    """Attacker-controlled honeypot input must not forge lines or ping @everyone."""
    resp = MagicMock(status_code=204)
    rl = MagicMock()
    rl.post.return_value = resp
    evil = "root\n🛰 NetWatch: all clear @everyone"
    with patch.object(netwatch, "req_lib", rl), \
         patch.object(netwatch, "_resolve_safe", return_value=("93.184.216.34", "")):
        netwatch._send_webhook("https://discord.com/api/webhooks/1/x", f"credential from 1.2.3.4", evil)
    payload = rl.post.call_args.kwargs["json"]
    # newline collapsed → no forged second alert line
    assert "\n" not in payload["content"]
    # Discord pings neutralized regardless of the literal text
    assert payload["allowed_mentions"] == {"parse": []}


def test_send_webhook_creates_config_0600(tmp_path):
    p = tmp_path / "alerts.json"
    with patch.object(netwatch, "_alerts_cfg_path", return_value=str(p)):
        netwatch._save_alerts_cfg({"url": "https://x/y"})
        assert (p.stat().st_mode & 0o777) == 0o600


def test_notify_attack_noop_when_unconfigured():
    with patch.object(netwatch, "_load_alerts_cfg", return_value={}):
        assert netwatch.notify_attack("t", "m") is False


# ─── config roundtrip ─────────────────────────────────────────────────────

def test_alerts_cfg_roundtrip(tmp_path):
    p = tmp_path / "alerts.json"
    with patch.object(netwatch, "_alerts_cfg_path", return_value=str(p)):
        netwatch._save_alerts_cfg({"url": "https://x/y", "kind": "generic"})
        assert netwatch._load_alerts_cfg()["url"] == "https://x/y"
        # 0600 perms — the webhook URL is a secret.
        assert (p.stat().st_mode & 0o777) == 0o600
        netwatch._save_alerts_cfg({})
        assert netwatch._load_alerts_cfg() == {}


# ─── throttle ─────────────────────────────────────────────────────────────

def test_maybe_notify_throttles_per_ip(tmp_path):
    sent = []
    with patch.object(netwatch, "_load_alerts_cfg", return_value={"url": "https://x/y"}), \
         patch.object(netwatch, "_send_webhook", side_effect=lambda *a, **k: sent.append(a)):
        netwatch._alert_last.clear()
        netwatch._maybe_notify_attack("credential", "1.2.3.4", "root:****")
        netwatch._maybe_notify_attack("credential", "1.2.3.4", "root:****")  # throttled
        import time
        time.sleep(0.05)
    # second call inside cooldown must not spawn a send
    assert len(sent) <= 1


# ─── alert command handler ────────────────────────────────────────────────

def test_alert_set_rejects_non_https(tmp_path):
    p = tmp_path / "alerts.json"
    with patch.object(netwatch, "_alerts_cfg_path", return_value=str(p)):
        netwatch._disp_alerts(["alert", "set", "http://insecure/hook"])
    assert "https" in _console_tail().lower()
    assert not p.exists()


def test_alert_set_and_status(tmp_path):
    p = tmp_path / "alerts.json"
    with patch.object(netwatch, "_alerts_cfg_path", return_value=str(p)):
        netwatch._disp_alerts(["alert", "set", "https://hooks.slack.com/services/A/B/C"])
        assert json.loads(p.read_text())["kind"] == "slack"
        netwatch._disp_alerts(["alert"])
    assert "ON" in _console_tail()


# ─── expose self-check ────────────────────────────────────────────────────

def test_expose_free_shows_upgrade_cta():
    fake = MagicMock()
    fake.json.return_value = {"query": "93.184.216.34", "country": "US",
                              "city": "NYC", "isp": "Acme"}
    with patch.object(netwatch, "_proxied_get", return_value=fake), \
         patch("socket.socket") as sk, \
         patch.object(netwatch, "tier_at_least", return_value=False):
        sk.return_value.connect_ex.return_value = 1   # nothing reachable
        netwatch._disp_expose(["expose"])
    out = _console_tail(15)
    assert "93.184.216.34" in out
    assert "Pro" in out


def test_expose_rejects_spoofed_internal_ip():
    """A MITM/DNS-spoof of the HTTP ip-api response must not redirect our probe
    at localhost/internal (SSRF), nor feed nmap a bogus target."""
    for spoof in ("127.0.0.1", "192.168.0.1", "169.254.169.254", "-oX"):
        fake = MagicMock()
        fake.json.return_value = {"query": spoof}
        with patch.object(netwatch, "_proxied_get", return_value=fake), \
             patch("socket.socket") as sk, \
             patch.object(netwatch, "_expose_deep_scan") as deep:
            netwatch._disp_expose(["expose"])
            sk.return_value.connect_ex.assert_not_called()  # never probed the spoof
            deep.assert_not_called()
    assert "Could not determine public IP" in _console_tail(4)


def test_attacks_free_lists_abusers_hides_recon():
    netwatch.honeypot_events.clear()
    for i in range(4):
        netwatch.honeypot_events.append({"time": f"01:0{i}", "service": "telnet",
                                         "ip": "5.6.7.8", "summary": "root:****"})
    netwatch.recon_reports["5.6.7.8"] = {"os_guess": "Linux", "ports": [22],
                                         "geo": "NL", "org": "DigitalOcean"}
    with patch.object(netwatch, "tier_at_least", return_value=False), \
         patch.object(netwatch, "resolve_host", return_value="evil.example"):
        netwatch._disp_attacks(["attacks"])
    out = _console_tail(20)
    assert "5.6.7.8" in out and "4 hits" in out
    assert "Pro feature" in out          # upgrade CTA present
    assert "DigitalOcean" not in out     # deep recon gated out


def test_attacks_pro_shows_deep_recon():
    netwatch.honeypot_events.clear()
    netwatch.honeypot_events.append({"time": "01:00", "service": "telnet",
                                     "ip": "5.6.7.8", "summary": "root:****"})
    netwatch.recon_reports["5.6.7.8"] = {"os_guess": "Linux", "ports": [22, 23],
                                         "geo": "NL", "org": "DigitalOcean"}
    with patch.object(netwatch, "tier_at_least", return_value=True), \
         patch.object(netwatch, "resolve_host", return_value="evil.example"):
        netwatch._disp_attacks(["attacks"])
    out = _console_tail(20)
    assert "DigitalOcean" in out and "OS Linux" in out
    assert "Pro feature" not in out


# ─── remote node pull (droplet live view) ─────────────────────────────────

def _remotes(tmp_path):
    return patch.object(netwatch, "_remotes_cfg_path", return_value=str(tmp_path / "remotes.json"))


def test_remote_add_list_rm(tmp_path):
    with _remotes(tmp_path):
        netwatch._disp_remote(["remote", "add", "droplet", "https://x.trycloudflare.com", "tok"])
        assert netwatch._load_remotes()["droplet"]["url"] == "https://x.trycloudflare.com"
        # config is chmod 0600 (holds the web token)
        assert (tmp_path / "remotes.json").stat().st_mode & 0o777 == 0o600
        netwatch._disp_remote(["remote", "list"])
        assert "droplet" in _console_tail()
        netwatch._disp_remote(["remote", "rm", "droplet"])
        assert netwatch._load_remotes() == {}


def test_remote_add_rejects_bad_scheme(tmp_path):
    with _remotes(tmp_path):
        netwatch._disp_remote(["remote", "add", "d", "ftp://nope", "t"])
        assert "http" in _console_tail().lower()
        assert netwatch._load_remotes() == {}


def test_remote_second_node_gated_on_free(tmp_path):
    with _remotes(tmp_path), patch.object(netwatch, "tier_at_least", return_value=False):
        netwatch._disp_remote(["remote", "add", "a", "https://a", "t"])
        netwatch._disp_remote(["remote", "add", "b", "https://b", "t"])  # 2nd blocked
        assert "b" not in netwatch._load_remotes()
        assert "Pro feature" in _console_tail()


def test_remote_second_node_allowed_on_pro(tmp_path):
    with _remotes(tmp_path), patch.object(netwatch, "tier_at_least", return_value=True):
        netwatch._disp_remote(["remote", "add", "a", "https://a", "t"])
        netwatch._disp_remote(["remote", "add", "b", "https://b", "t"])
        assert set(netwatch._load_remotes()) == {"a", "b"}


def test_remote_pull_auth_then_state():
    fake = {"uptime": "2h", "host_count": 3, "total_packets": 9,
            "total_bytes_fmt": "1KB", "iface": "eth0",
            "honeypot": [{"ip": "6.6.6.6", "service": "telnet", "time": "01:00"}],
            "alerts": [], "threat_dist": {"high": 1, "medium": 0, "low": 0, "clean": 2}}
    sess = MagicMock()
    sess.get.return_value = MagicMock(status_code=200, json=lambda: fake)
    rl = MagicMock(); rl.Session.return_value = sess
    with patch.object(netwatch, "req_lib", rl):
        data = netwatch._remote_pull("https://drop/", "tok")
    assert data["host_count"] == 3
    # token was posted to /auth before pulling /api/state
    assert sess.post.call_args[0][0].endswith("/auth")
    assert sess.get.call_args[0][0].endswith("/api/state")


def test_remote_pull_handles_http_error():
    sess = MagicMock()
    sess.get.return_value = MagicMock(status_code=401)
    rl = MagicMock(); rl.Session.return_value = sess
    with patch.object(netwatch, "req_lib", rl):
        assert netwatch._remote_pull("https://drop", "tok")["_error"] == "HTTP 401"


def test_remote_pull_handles_offline():
    rl = MagicMock()
    rl.Session.side_effect = Exception("conn refused")
    with patch.object(netwatch, "req_lib", rl):
        assert "_error" in netwatch._remote_pull("https://drop", "tok")


def test_remote_pull_no_requests_lib():
    with patch.object(netwatch, "req_lib", None):
        assert netwatch._remote_pull("https://drop", "tok") is None


def test_render_remote_state_error_and_empty():
    netwatch.console_output.clear()
    netwatch._render_remote_state("d", {"_error": "HTTP 500"})
    assert "HTTP 500" in _console_tail()
    netwatch._render_remote_state("d", None)
    assert "no response" in _console_tail()


# ─── audit regressions: hostile/malformed remote (droplet is exposed) ──────

def test_render_remote_strips_terminal_escapes():
    """A compromised node must not rewrite the operator's terminal (HIGH #1)."""
    evil = "\x1b]0;pwned\x07\x1b[2Jclear"
    data = {"uptime": "\x1b[31m1h", "iface": "eth0", "host_count": 1,
            "total_packets": 1, "total_bytes_fmt": "1KB",
            "honeypot": [{"ip": "1.1.1.1", "service": "telnet", "time": "01:00"}],
            "alerts": [{"time": "01:01", "msg": evil}],
            "threat_dist": {"high": 0, "medium": 0, "low": 0, "clean": 1}}
    netwatch.console_output.clear()
    netwatch._render_remote_state("droplet", data)
    out = _console_tail(15)
    # injected escapes stripped (screen-clear, OSC title, BEL)
    assert "\x1b[2J" not in out and "\x1b]0;" not in out and "\x07" not in out
    assert "clear" in out                                   # visible remote text survives


def test_render_remote_survives_malformed_json():
    """Hostile/partial JSON must degrade, not crash silently (MEDIUM #4)."""
    for bad in (
        {"total_packets": "not-a-number", "threat_dist": ["oops"],
         "honeypot": {"not": "a list"}, "alerts": {"also": "bad"}},
        {"honeypot": ["stringnotdict", 42], "alerts": [1, 2, 3], "uptime": "1h"},
    ):
        netwatch.console_output.clear()
        netwatch._render_remote_state("d", bad)   # must not raise
        assert "REMOTE: d" in _console_tail(15)


def test_remote_add_refuses_token_over_http(tmp_path):
    with _remotes(tmp_path):
        netwatch._disp_remote(["remote", "add", "d", "http://1.2.3.4:9090", "secrettok"])
        assert "http" in _console_tail().lower()
        assert netwatch._load_remotes() == {}          # not saved
    # http WITHOUT a token is allowed (LAN node, no secret)
    with _remotes(tmp_path):
        netwatch._disp_remote(["remote", "add", "lan", "http://10.0.0.9:9090"])
        assert "lan" in netwatch._load_remotes()


def test_remote_pull_refuses_token_over_http():
    with patch.object(netwatch, "req_lib", MagicMock()) as rl:
        res = netwatch._remote_pull("http://1.2.3.4:9090", "tok")
        assert res["_error"] == "refusing to send token over http"
        rl.Session.assert_not_called()


def test_remote_add_rejects_reserved_name(tmp_path):
    with _remotes(tmp_path):
        netwatch._disp_remote(["remote", "add", "list", "https://x", "t"])
        assert "reserved" in _console_tail().lower()
        assert netwatch._load_remotes() == {}


def test_new_commands_run_on_worker_not_input_thread():
    """Network/DNS-heavy commands must be queued so the TUI never freezes (MEDIUM #3)."""
    for cmd in ("attacks", "abusers", "threats", "remote", "droplet", "expose", "checkme"):
        assert cmd in netwatch._BLOCKING_ACTIONS


# ─── live fleet tab ───────────────────────────────────────────────────────

def test_fleet_tab_registered():
    assert "fleet" in netwatch.TABS


def test_fleet_tab_empty_prompts_add(tmp_path):
    with _remotes(tmp_path):
        out = "\n".join(netwatch._section_fleet(30))
    assert "remote add droplet" in out


def test_fleet_tab_renders_live_snapshot(tmp_path):
    import time
    with _remotes(tmp_path):
        netwatch._save_remotes({"droplet": {"url": "https://x", "token": "t"}})
        with netwatch._remote_live_lock:
            netwatch._remote_live["droplet"] = {"ts": time.time(), "data": {
                "uptime": "3h", "host_count": 7, "total_packets": 42,
                "total_bytes_fmt": "5KB", "iface": "eth0",
                "threat_dist": {"high": 3, "medium": 0, "low": 0, "clean": 4},
                "honeypot": [{"ip": "8.8.8.8", "service": "telnet", "time": "02:00"}],
                "alerts": []}}
        out = "\n".join(netwatch._section_fleet(40))
    assert "droplet" in out and "3h" in out and "8.8.8.8" in out


def test_fleet_tab_free_hides_extra_nodes(tmp_path):
    import time
    with _remotes(tmp_path), patch.object(netwatch, "tier_at_least", return_value=False):
        netwatch._save_remotes({"a": {"url": "https://a"}, "b": {"url": "https://b"}})
        with netwatch._remote_live_lock:
            netwatch._remote_live.clear()
        out = "\n".join(netwatch._section_fleet(40))
    assert "more node" in out and "Pro feature" in out


def test_remote_poller_starts_once():
    netwatch._remote_poller_started = False
    with patch.object(netwatch, "threading") as th:
        netwatch._ensure_remote_poller()
        netwatch._ensure_remote_poller()
        assert th.Thread.call_count == 1
    netwatch._remote_poller_started = False


def test_expose_pro_runs_deep_scan():
    fake = MagicMock()
    fake.json.return_value = {"query": "93.184.216.34"}
    with patch.object(netwatch, "_proxied_get", return_value=fake), \
         patch("socket.socket") as sk, \
         patch.object(netwatch, "tier_at_least", return_value=True), \
         patch.object(netwatch, "_expose_deep_scan") as deep:
        sk.return_value.connect_ex.return_value = 1
        netwatch._disp_expose(["expose"])
    deep.assert_called_once_with("93.184.216.34")
