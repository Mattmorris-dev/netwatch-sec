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
