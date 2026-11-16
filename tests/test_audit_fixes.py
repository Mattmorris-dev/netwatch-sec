"""Regression tests for the 1.6.2 audit fixes: host scoring, eviction,
private ranges, scan detection, whitelist defaults, default subnet."""
import socket
import struct
from unittest.mock import patch

import pytest

import netwatch


@pytest.fixture(autouse=True)
def _clean_hosts():
    netwatch.hosts.clear()
    del netwatch.alerts[:]
    yield
    netwatch.hosts.clear()
    del netwatch.alerts[:]


def _run_maintenance(passes=5):
    """_maintain_hosts with lookups done inline (no threads, no DNS)."""
    class _Inline:
        def __init__(self, target=None, args=(), **_kw):
            self._t, self._a = target, args

        def start(self):
            self._t(*self._a)

    with patch("netwatch.resolve_host", return_value=""), \
            patch("netwatch.threading.Thread", _Inline):
        for _ in range(passes):
            netwatch._maintain_hosts()


class TestScoringCoversAllHosts:
    def test_every_host_is_enriched_not_only_the_first_20(self):
        for i in range(1, 61):
            netwatch.hosts[f"45.33.32.{i}"]["ports"] = {80}
        _run_maintenance()
        assert all(h.get("_enriched") for h in netwatch.hosts.values())

    def test_host_that_starts_to_scan_later_is_rescored(self):
        for i in range(1, 41):
            netwatch.hosts[f"45.33.32.{i}"]["ports"] = {80}
        _run_maintenance()
        for ip in ("45.33.32.5", "45.33.32.30"):       # inside and outside the old window
            assert netwatch.hosts[ip]["threat_score"] == 0
            netwatch.hosts[ip]["scan_ports"] = set(range(1, 201))
        _run_maintenance(passes=1)
        for ip in ("45.33.32.5", "45.33.32.30"):
            assert "SCANNER" in netwatch.hosts[ip]["tags"]
            assert netwatch.hosts[ip]["threat_score"] == 30

    def test_score_is_not_counted_twice(self):
        ip = "203.0.113.9"
        netwatch.hosts[ip]["scan_ports"] = set(range(100))
        netwatch.hosts[ip]["ports"] = {4444}
        _run_maintenance(passes=10)
        assert netwatch.hosts[ip]["threat_score"] == 50

    def test_enrich_keeps_existing_tags(self):
        ip = "203.0.113.10"
        netwatch.hosts[ip]["tags"].add("BRUTE")
        with patch("netwatch.resolve_host", return_value=""):
            netwatch.enrich_host(ip)
        assert "BRUTE" in netwatch.hosts[ip]["tags"]

    def test_slow_dns_does_not_pile_up_threads(self):
        for i in range(1, 201):
            netwatch.hosts[f"198.51.100.{i}"]["ports"] = {80}
        started = []

        class _Never:
            def __init__(self, target=None, args=(), **_kw):
                started.append(args)

            def start(self):
                pass

        with patch("netwatch.threading.Thread", _Never):
            for _ in range(20):
                netwatch._maintain_hosts()
        assert len(started) == netwatch._ENRICH_MAX_ACTIVE


class TestEviction:
    def test_oldest_by_epoch_goes_first_across_midnight(self):
        with patch.object(netwatch, "MAX_HOSTS", 1):
            old, new = netwatch.hosts["203.0.113.1"], netwatch.hosts["203.0.113.2"]
            old.update(last_seen="23:58:00", last_seen_ts=1000.0, _enriched=True)
            new.update(last_seen="00:01:00", last_seen_ts=1180.0, _enriched=True)
            netwatch._maintain_hosts()
        assert list(netwatch.hosts) == ["203.0.113.2"]


class TestPrivateRanges:
    @pytest.mark.parametrize("ip", [
        "10.1.2.3", "192.168.9.9", "172.16.0.1", "172.20.0.5", "172.31.255.254",
        "100.64.0.1", "100.127.255.254", "127.0.0.1", "169.254.1.1"])
    def test_private(self, ip):
        assert netwatch._is_private_ip(ip) is True
        assert netwatch._is_benign(ip) is True

    @pytest.mark.parametrize("ip", [
        "172.15.0.1", "172.32.0.1", "100.63.0.1", "100.128.0.1", "8.8.8.8",
        "11.0.0.1", "192.169.0.1", "172.x.0.1"])
    def test_public(self, ip):
        assert netwatch._is_private_ip(ip) is False

    def test_docker_range_host_is_not_scored(self):
        ip = "172.20.0.5"
        netwatch.hosts[ip]["scan_ports"] = set(range(200))
        netwatch.score_host(ip)
        assert netwatch.hosts[ip]["threat_score"] == 0


def _frame(src, dst, sport, dport, proto=6, flags=0x02):
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0, 0, 64, proto, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    if proto == 6:
        l4 = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 0x50, flags, 0, 0, 0)
    else:
        l4 = struct.pack("!HHHH", sport, dport, 8, 0)
    return b"\0" * 12 + b"\x08\x00" + ip + l4


class _Stop(BaseException):
    pass


def _sniff(frames):
    class _Sock:
        def __init__(self, *a):
            self._it = iter(frames)

        def bind(self, *a):
            pass

        def settimeout(self, *a):
            pass

        def recvfrom(self, _n):
            try:
                return next(self._it), None
            except StopIteration:
                raise _Stop from None

    with patch("netwatch.socket.socket", _Sock), \
            patch.object(netwatch.socket, "AF_PACKET", 17, create=True), \
            patch.object(netwatch, "LOCAL_IPS", {"192.0.2.10", "127.0.0.1"}):
        with pytest.raises(_Stop):
            netwatch.traffic_monitor()
        with patch("netwatch.threading.Thread"):
            netwatch._maintain_hosts()


class TestScanDetection:
    LOCAL = "192.0.2.10"

    def test_busy_server_replies_are_not_a_scan(self):
        server = "93.184.216.34"
        # 120 of OUR connections to one server: SYN out, SYN/ACK + data back
        frames = []
        for p in range(40000, 40120):
            frames.append(_frame(self.LOCAL, server, p, 443, flags=0x02))
            frames.append(_frame(server, self.LOCAL, 443, p, flags=0x12))
            frames.append(_frame(server, self.LOCAL, 443, p, flags=0x18))
        _sniff(frames)
        h = netwatch.hosts[server]
        assert len(h["scan_ports"]) == 0
        assert "SCANNER" not in h["tags"] and h["threat_score"] == 0
        assert not any("PORT SCAN" in a["msg"] for a in netwatch.alerts)

    def test_dns_replies_are_not_a_scan(self):
        resolver = "9.9.9.9"
        frames = [_frame(resolver, self.LOCAL, 53, p, proto=17) for p in range(40000, 40120)]
        _sniff(frames)
        assert len(netwatch.hosts[resolver]["scan_ports"]) == 0

    def test_syn_scan_is_detected(self):
        scanner = "45.33.32.156"
        _sniff([_frame(scanner, self.LOCAL, 55555, p, flags=0x02) for p in range(1, 121)])
        h = netwatch.hosts[scanner]
        assert len(h["scan_ports"]) == 120
        assert "SCANNER" in h["tags"] and h["threat_score"] == 30
        assert any("PORT SCAN" in a["msg"] for a in netwatch.alerts)

    def test_udp_scan_is_detected(self):
        scanner = "45.33.32.157"
        _sniff([_frame(scanner, self.LOCAL, 44444, p, proto=17) for p in range(1, 121)])
        assert "SCANNER" in netwatch.hosts[scanner]["tags"]

    def test_last_seen_epoch_is_recorded(self):
        _sniff([_frame("45.33.32.158", self.LOCAL, 1234, 80)])
        assert netwatch.hosts["45.33.32.158"]["last_seen_ts"] > 0
        assert len(netwatch.hosts["45.33.32.158"]["last_seen"]) == 8


class TestWhitelistDefaults:
    def test_no_site_specific_addresses_ship(self):
        import inspect
        src = inspect.getsource(netwatch)
        for needle in ("100.66.15.102", "100.85.81.110", "207.251.86.235", '"10.0.1.0/24"'):
            assert needle not in src

    def test_env_entries(self):
        scan, pref = set(netwatch.WHITELIST_SCAN), netwatch.WHITELIST_PREFIXES
        try:
            bad = netwatch._load_user_whitelist("198.51.100.7, 203.0.113., not-an-ip,,999.1.1.1")
            assert bad == ["not-an-ip", "999.1.1.1"]
            assert netwatch.is_whitelisted("198.51.100.7")
            assert netwatch.is_whitelisted("203.0.113.44")
            assert not netwatch.is_whitelisted("198.51.100.8")
        finally:
            netwatch.WHITELIST_SCAN.clear()
            netwatch.WHITELIST_SCAN.update(scan)
            netwatch.WHITELIST_PREFIXES = pref


class TestDefaultCidr:
    def _cidr(self, out):
        with patch("netwatch.subprocess.check_output", return_value=out):
            return netwatch._default_cidr()

    def test_home_lan(self):
        assert self._cidr("2: wlan0    inet 192.168.1.23/24 brd 192.168.1.255 scope global wlan0") == "192.168.1.0/24"

    def test_public_range_is_refused(self):
        assert self._cidr("2: eth0    inet 164.90.130.7/20 brd 164.90.143.255 scope global eth0") is None

    def test_cloud_shared_private_range_is_refused(self):
        assert self._cidr("2: eth0    inet 10.10.0.5/16 brd 10.10.255.255 scope global eth0") is None

    def test_no_interface(self):
        with patch("netwatch.subprocess.check_output", side_effect=OSError):
            assert netwatch._default_cidr() is None

    def test_subnet_command_without_lan_gives_usage(self):
        out = []
        with patch("netwatch._default_cidr", return_value=None), \
                patch("netwatch.add_console", side_effect=out.append), \
                patch("netwatch.threading.Thread") as th:
            netwatch._disp_subnet(["subnet"])
        assert not th.called and "Usage: subnet <cidr>" in out[0]


class TestFtpPassiveAddress:
    def test_uses_the_address_the_client_connected_to(self):
        import inspect
        src = inspect.getsource(netwatch.handle_ftp)
        assert "client.getsockname()" in src and '"10.0.1.9"' not in src


class TestSharedConfigPaths:
    """alerts.json / remotes.json live in the shared config dir, so the webhook
    that `netwatch alert set` saves is the one `sudo netwatch` reads."""

    def test_paths_follow_config_dir(self, tmp_path, monkeypatch):
        monkeypatch.setenv("NETWATCH_CONFIG_DIR", str(tmp_path))
        assert netwatch._alerts_cfg_path() == str(tmp_path / "alerts.json")
        assert netwatch._remotes_cfg_path() == str(tmp_path / "remotes.json")

    def test_set_as_one_user_is_read_as_another(self, tmp_path, monkeypatch):
        shared = tmp_path / "shared"
        monkeypatch.setenv("NETWATCH_CONFIG_DIR", str(shared))
        monkeypatch.setenv("HOME", str(tmp_path / "home-user"))
        netwatch._save_alerts_cfg({"url": "https://example.com/hook"})
        monkeypatch.setenv("HOME", str(tmp_path / "home-root"))      # now "sudo"
        assert netwatch._load_alerts_cfg()["url"] == "https://example.com/hook"

    def test_legacy_file_is_copied_once(self, tmp_path, monkeypatch):
        home, shared = tmp_path / "home", tmp_path / "shared"
        legacy = home / ".config" / "netwatch"
        legacy.mkdir(parents=True)
        (legacy / "alerts.json").write_text('{"url": "https://old.example/hook"}')
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setenv("NETWATCH_CONFIG_DIR", str(shared))
        assert netwatch._migrate_legacy_config() == ["alerts.json"]
        assert (shared / "alerts.json").stat().st_mode & 0o777 == 0o600
        assert netwatch._load_alerts_cfg()["url"] == "https://old.example/hook"
        (shared / "alerts.json").write_text('{"url": "https://new.example/hook"}')
        assert netwatch._migrate_legacy_config() == []               # never overwrites
        assert netwatch._load_alerts_cfg()["url"] == "https://new.example/hook"

    def test_same_dir_is_a_no_op(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("NETWATCH_CONFIG_DIR", str(tmp_path / ".config" / "netwatch"))
        assert netwatch._migrate_legacy_config() == []


class TestWebhookFailureReason:
    def _send(self, url, post=None, resolve=("93.184.216.34", "")):
        with patch("netwatch._resolve_safe", return_value=resolve), \
                patch.object(netwatch.req_lib, "post", post or (lambda *a, **k: None)):
            ok = netwatch._send_webhook(url, "t", "m")
        return ok, netwatch._last_webhook_error

    def test_not_https(self):
        assert self._send("http://example.com/hook") == (False, "the webhook URL is not https://")

    def test_blocked_host(self):
        ok, why = self._send("https://169.254.169.254/x", resolve=(None, "internal address"))
        assert not ok and "internal address" in why

    @pytest.mark.parametrize("code,hint", [(404, "deleted"), (401, "token"), (429, "rate limited"), (500, "HTTP 500")])
    def test_http_status(self, code, hint):
        class R:
            status_code = code
        ok, why = self._send("https://discord.com/api/webhooks/1/x", post=lambda *a, **k: R())
        assert not ok and hint in why

    def test_network_error(self):
        def boom(*a, **k):
            raise TimeoutError()
        ok, why = self._send("https://hooks.slack.com/services/A/B/C", post=boom)
        assert not ok and "timed out" in why

    def test_success_clears_the_reason(self):
        class R:
            status_code = 204
        netwatch._last_webhook_error = "old"
        assert self._send("https://discord.com/api/webhooks/1/x", post=lambda *a, **k: R()) == (True, "")

    def test_alert_test_prints_the_reason(self, tmp_path):
        class R:
            status_code = 404
        p = tmp_path / "alerts.json"
        p.write_text('{"url": "https://discord.com/api/webhooks/1/x"}')
        with patch.object(netwatch, "_alerts_cfg_path", return_value=str(p)), \
                patch("netwatch._resolve_safe", return_value=("162.159.128.233", "")), \
                patch.object(netwatch.req_lib, "post", lambda *a, **k: R()):
            netwatch._disp_alerts(["alert", "test"])
        out = "\n".join(netwatch.console_output)
        assert "failed: the service answered HTTP 404 (the webhook was deleted or the URL is wrong)" in out
