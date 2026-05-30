"""
Tests for netwatch.py utility/helper functions:
  _capped_append, _ansi_strip, format_bytes, threat_color, _is_benign,
  check_suspicious, _truncate_data, _rotate_log, is_whitelisted, get_local_ips,
  resolve_host, enrich_host
"""
import os
import json
import tempfile
import pytest
from unittest.mock import patch, MagicMock

import netwatch


# ═══════════════════════════════════════════════════════════
#  _capped_append
# ═══════════════════════════════════════════════════════════

class TestCappedAppend:
    def test_append_under_cap(self):
        lst = [1, 2, 3]
        netwatch._capped_append(lst, 4, 10)
        assert lst == [1, 2, 3, 4]

    def test_append_at_cap(self):
        lst = [1, 2, 3]
        netwatch._capped_append(lst, 4, 4)
        assert lst == [1, 2, 3, 4]

    def test_append_over_cap_trims_front(self):
        lst = [1, 2, 3]
        netwatch._capped_append(lst, 4, 3)
        assert lst == [2, 3, 4]

    def test_cap_of_one(self):
        lst = [1, 2, 3]
        netwatch._capped_append(lst, 99, 1)
        assert lst == [99]

    def test_empty_list(self):
        lst = []
        netwatch._capped_append(lst, "x", 5)
        assert lst == ["x"]

    def test_large_overshoot(self):
        lst = list(range(100))
        netwatch._capped_append(lst, 100, 10)
        assert len(lst) == 10
        assert lst[-1] == 100

    def test_cap_zero_empties(self):
        # Edge: cap=0 means delete everything after append
        lst = [1, 2]
        netwatch._capped_append(lst, 3, 0)
        # After append lst=[1,2,3], len=3 > 0, del lst[:3] = []
        assert lst == []

    def test_repeated_appends_never_exceed(self):
        lst = []
        for i in range(200):
            netwatch._capped_append(lst, i, 50)
        assert len(lst) == 50
        assert lst[-1] == 199

    @pytest.mark.parametrize("cap", [1, 5, 10, 50, 100])
    def test_various_caps(self, cap):
        lst = list(range(cap * 2))
        netwatch._capped_append(lst, 999, cap)
        assert len(lst) == cap
        assert lst[-1] == 999


# ═══════════════════════════════════════════════════════════
#  _ansi_strip
# ═══════════════════════════════════════════════════════════

class TestAnsiStrip:
    @pytest.mark.parametrize("input_str,expected", [
        ("hello", "hello"),
        ("\033[91mred\033[0m", "red"),
        ("\033[1m\033[94mbold blue\033[0m", "bold blue"),
        ("", ""),
        ("no escape here", "no escape here"),
        ("\x1b[2J\x1b[H", ""),  # clear screen + home
        ("\x1b[38;2;255;0;0mTrueColor\x1b[0m", "TrueColor"),
        ("line1\r\nline2", "line1\nline2"),  # carriage return stripped
        ("\x00\x01\x02hello\x7f", "hello"),  # C0 control chars
        ("\x1b]0;title\x07normal", "normal"),  # OSC sequence
        ("tab\there", "tab\there"),  # tab preserved
        ("new\nline", "new\nline"),  # newline preserved
    ])
    def test_strip_ansi(self, input_str, expected):
        assert netwatch._ansi_strip(input_str) == expected

    def test_strip_nested_ansi(self):
        s = "\033[1m\033[91m\033[4mhello\033[0m"
        assert netwatch._ansi_strip(s) == "hello"

    def test_unicode_preserved(self):
        assert netwatch._ansi_strip("hello ☃ world") == "hello ☃ world"

    def test_long_string_performance(self):
        s = "\033[91m" + "x" * 10000 + "\033[0m"
        result = netwatch._ansi_strip(s)
        assert len(result) == 10000

    def test_null_bytes_stripped(self):
        assert netwatch._ansi_strip("\x00\x00hello\x00") == "hello"

    def test_mixed_control_and_ansi(self):
        s = "\x1b[31m\x01\x02attack\x1b[0m\x03"
        assert netwatch._ansi_strip(s) == "attack"

    def test_bell_character_stripped(self):
        assert netwatch._ansi_strip("alert\x07!") == "alert!"

    def test_backspace_stripped(self):
        assert netwatch._ansi_strip("back\x08space") == "backspace"

    def test_form_feed_stripped(self):
        assert netwatch._ansi_strip("page\x0cbreak") == "pagebreak"


# ═══════════════════════════════════════════════════════════
#  format_bytes
# ═══════════════════════════════════════════════════════════

class TestFormatBytes:
    @pytest.mark.parametrize("input_val,expected", [
        (0, "0.0B"),
        (1, "1.0B"),
        (512, "512.0B"),
        (1023, "1023.0B"),
        (1024, "1.0KB"),
        (1536, "1.5KB"),
        (1048576, "1.0MB"),
        (1073741824, "1.0GB"),
        (1099511627776, "1.0TB"),
        (5368709120, "5.0GB"),
    ])
    def test_format(self, input_val, expected):
        assert netwatch.format_bytes(input_val) == expected

    def test_large_value(self):
        result = netwatch.format_bytes(10 * 1024**4)
        assert "TB" in result

    def test_fractional_kb(self):
        result = netwatch.format_bytes(2560)
        assert "KB" in result
        assert "2.5" in result


# ═══════════════════════════════════════════════════════════
#  threat_color
# ═══════════════════════════════════════════════════════════

class TestThreatColor:
    @pytest.mark.parametrize("score,expected_color", [
        (0, netwatch.WHITE),
        (5, netwatch.WHITE),
        (9, netwatch.WHITE),
        (10, netwatch.YELLOW),
        (15, netwatch.YELLOW),
        (29, netwatch.YELLOW),
        (30, netwatch.RED),
        (50, netwatch.RED),
        (100, netwatch.RED),
        (999, netwatch.RED),
    ])
    def test_threat_color(self, score, expected_color):
        assert netwatch.threat_color(score) == expected_color

    def test_negative_score(self):
        # Should return WHITE for below-threshold
        assert netwatch.threat_color(-1) == netwatch.WHITE


# ═══════════════════════════════════════════════════════════
#  is_whitelisted
# ═══════════════════════════════════════════════════════════

class TestIsWhitelisted:
    @pytest.mark.parametrize("ip,expected", [
        ("127.0.0.1", True),
        ("10.0.1.1", True),
        ("100.66.15.102", True),
        ("216.239.1.1", True),
        ("104.16.1.1", True),
        ("142.250.1.1", True),
        ("203.0.113.1", False),
        ("8.8.8.8", False),
        ("1.1.1.1", False),
        ("192.168.1.1", False),
        ("", False),
        ("100.85.81.110", True),
        ("207.251.86.235", True),
        ("18.238.1.1", True),
        ("108.138.1.1", True),
    ])
    def test_whitelist(self, ip, expected):
        assert netwatch.is_whitelisted(ip) == expected

    def test_prefix_match_not_exact(self):
        # "216.239." prefix match
        assert netwatch.is_whitelisted("216.239.255.255") == True
        assert netwatch.is_whitelisted("216.240.1.1") == False


# ═══════════════════════════════════════════════════════════
#  get_local_ips
# ═══════════════════════════════════════════════════════════

class TestGetLocalIps:
    @patch("netwatch.subprocess.check_output")
    def test_parses_ip_output(self, mock_check):
        mock_check.return_value = "    inet 192.168.1.5/24 brd\n    inet 10.0.0.1/8 brd\n    inet6 ::1/128\n"
        ips = netwatch.get_local_ips()
        assert "192.168.1.5" in ips
        assert "10.0.0.1" in ips

    @patch("netwatch.subprocess.check_output", side_effect=Exception("fail"))
    def test_fallback_on_error(self, mock_check):
        ips = netwatch.get_local_ips()
        assert "10.0.1.9" in ips

    @patch("netwatch.subprocess.check_output")
    def test_empty_output(self, mock_check):
        mock_check.return_value = ""
        ips = netwatch.get_local_ips()
        # No crash, returns set (may be empty)
        assert isinstance(ips, set)


# ═══════════════════════════════════════════════════════════
#  resolve_host
# ═══════════════════════════════════════════════════════════

class TestResolveHost:
    @patch("socket.gethostbyaddr")
    def test_successful_resolve(self, mock_resolve):
        mock_resolve.return_value = ("example.com", [], [])
        result = netwatch.resolve_host("93.184.216.34")
        assert result == "example.com"

    @patch("socket.gethostbyaddr")
    def test_cached_result(self, mock_resolve):
        netwatch.dns_cache["1.2.3.4"] = "cached.host"
        result = netwatch.resolve_host("1.2.3.4")
        assert result == "cached.host"
        mock_resolve.assert_not_called()

    @patch("socket.gethostbyaddr", side_effect=Exception("NXDOMAIN"))
    def test_failed_resolve(self, mock_resolve):
        result = netwatch.resolve_host("192.0.2.99")
        assert result == ""

    @patch("socket.gethostbyaddr")
    def test_truncates_long_hostname(self, mock_resolve):
        mock_resolve.return_value = ("a" * 100, [], [])
        result = netwatch.resolve_host("1.1.1.1")
        assert len(result) == 35

    @patch("socket.gethostbyaddr")
    def test_cache_eviction(self, mock_resolve):
        mock_resolve.return_value = ("new.host", [], [])
        # Fill cache over MAX
        for i in range(netwatch.MAX_DNS_CACHE + 5):
            netwatch.dns_cache[f"10.0.{i//256}.{i%256}"] = f"host{i}"
        netwatch.resolve_host("99.99.99.99")
        # Cache should have been trimmed
        assert len(netwatch.dns_cache) <= netwatch.MAX_DNS_CACHE + 1


# ═══════════════════════════════════════════════════════════
#  enrich_host
# ═══════════════════════════════════════════════════════════

class TestEnrichHost:
    @patch("netwatch.resolve_host", return_value="server.cloudfront.net")
    def test_tags_cdn(self, mock_resolve):
        netwatch.hosts["1.2.3.4"]["ports"] = set()
        netwatch.enrich_host("1.2.3.4")
        assert "CDN" in netwatch.hosts["1.2.3.4"]["tags"]

    @patch("netwatch.resolve_host", return_value="mail.google.com")
    def test_tags_google(self, mock_resolve):
        netwatch.hosts["8.8.8.8"]["ports"] = set()
        netwatch.enrich_host("8.8.8.8")
        assert "Google" in netwatch.hosts["8.8.8.8"]["tags"]

    @patch("netwatch.resolve_host", return_value="ec2.amazon.com")
    def test_tags_aws(self, mock_resolve):
        netwatch.hosts["3.3.3.3"]["ports"] = set()
        netwatch.enrich_host("3.3.3.3")
        assert "AWS" in netwatch.hosts["3.3.3.3"]["tags"]

    @patch("netwatch.resolve_host", return_value="")
    def test_scanner_detection(self, mock_resolve):
        ip = "203.0.113.99"
        netwatch.hosts[ip]["ports"] = set(range(100))  # over SCAN_THRESHOLD
        netwatch.enrich_host(ip)
        assert "SCANNER" in netwatch.hosts[ip]["tags"]
        assert netwatch.hosts[ip]["threat_score"] >= 30

    @patch("netwatch.resolve_host", return_value="")
    def test_sus_port_detection(self, mock_resolve):
        ip = "203.0.113.50"
        netwatch.hosts[ip]["ports"] = {4444, 80}
        netwatch.enrich_host(ip)
        assert "SUS-PORT" in netwatch.hosts[ip]["tags"]
        assert netwatch.hosts[ip]["threat_score"] >= 20

    @patch("netwatch.resolve_host", return_value="")
    def test_local_ip_skips_scoring(self, mock_resolve):
        ip = "10.0.1.5"
        netwatch.hosts[ip]["ports"] = set(range(200))
        netwatch.enrich_host(ip)
        assert netwatch.hosts[ip]["threat_score"] == 0

    @patch("netwatch.resolve_host", return_value="")
    def test_whitelisted_skips_scoring(self, mock_resolve):
        ip = "127.0.0.1"
        netwatch.hosts[ip]["ports"] = {4444, 1337}
        netwatch.enrich_host(ip)
        assert netwatch.hosts[ip]["threat_score"] == 0

    @patch("netwatch.resolve_host", return_value="")
    def test_already_enriched_skips(self, mock_resolve):
        ip = "203.0.113.77"
        netwatch.hosts[ip]["_enriched"] = True
        netwatch.hosts[ip]["ports"] = set(range(200))
        netwatch.enrich_host(ip)
        # Should not re-enrich
        mock_resolve.assert_not_called()

    @patch("netwatch.resolve_host", return_value="relay.telegram.org")
    def test_tags_telegram(self, mock_resolve):
        netwatch.hosts["5.5.5.5"]["ports"] = set()
        netwatch.enrich_host("5.5.5.5")
        assert "Telegram" in netwatch.hosts["5.5.5.5"]["tags"]

    @patch("netwatch.resolve_host", return_value="api.anthropic.com")
    def test_tags_claude(self, mock_resolve):
        netwatch.hosts["6.6.6.6"]["ports"] = set()
        netwatch.enrich_host("6.6.6.6")
        assert "Claude" in netwatch.hosts["6.6.6.6"]["tags"]

    @patch("netwatch.resolve_host", return_value="")
    def test_remote_access_tag(self, mock_resolve):
        ip = "203.0.113.60"
        netwatch.hosts[ip]["ports"] = {23, 3389}
        netwatch.enrich_host(ip)
        assert "REMOTE-ACCESS" in netwatch.hosts[ip]["tags"]


# ═══════════════════════════════════════════════════════════
#  _truncate_data
# ═══════════════════════════════════════════════════════════

class TestTruncateData:
    def test_short_string_unchanged(self):
        assert netwatch._truncate_data("hello") == "hello"

    def test_long_string_truncated(self):
        s = "x" * 1000
        result = netwatch._truncate_data(s)
        assert len(result) == netwatch.MAX_LOG_FIELD

    def test_dict_values_truncated(self):
        d = {"key": "a" * 500}
        result = netwatch._truncate_data(d)
        assert len(result["key"]) == netwatch.MAX_LOG_FIELD

    def test_nested_dict(self):
        d = {"outer": {"inner": "b" * 500}}
        result = netwatch._truncate_data(d)
        assert len(result["outer"]["inner"]) == netwatch.MAX_LOG_FIELD

    def test_list_truncated(self):
        lst = list(range(100))
        result = netwatch._truncate_data(lst)
        assert len(result) == 50  # max 50 items

    def test_integer_passthrough(self):
        assert netwatch._truncate_data(42) == 42

    def test_none_passthrough(self):
        assert netwatch._truncate_data(None) is None

    def test_custom_max_len(self):
        s = "x" * 100
        result = netwatch._truncate_data(s, max_len=10)
        assert len(result) == 10

    def test_empty_string(self):
        assert netwatch._truncate_data("") == ""

    def test_empty_dict(self):
        assert netwatch._truncate_data({}) == {}

    def test_empty_list(self):
        assert netwatch._truncate_data([]) == []

    def test_mixed_types_in_dict(self):
        d = {"s": "x" * 500, "n": 42, "l": [1, 2, 3]}
        result = netwatch._truncate_data(d)
        assert len(result["s"]) == netwatch.MAX_LOG_FIELD
        assert result["n"] == 42
        assert result["l"] == [1, 2, 3]


# ═══════════════════════════════════════════════════════════
#  _rotate_log
# ═══════════════════════════════════════════════════════════

class TestRotateLog:
    def test_no_rotation_if_small(self, tmp_path):
        f = tmp_path / "test.log"
        f.write_text("small content")
        netwatch._rotate_log(str(f))
        assert f.exists()

    def test_rotation_when_large(self, tmp_path):
        f = tmp_path / "test.log"
        f.write_bytes(b"x" * (netwatch.MAX_LOG_FILE_SIZE + 1))
        netwatch._rotate_log(str(f))
        rotated = tmp_path / "test.log.1"
        assert rotated.exists()
        assert not f.exists()

    def test_no_crash_nonexistent_file(self):
        netwatch._rotate_log("/nonexistent/path/file.log")

    def test_cascading_rotation(self, tmp_path):
        f = tmp_path / "test.log"
        f1 = tmp_path / "test.log.1"
        f2 = tmp_path / "test.log.2"
        f.write_bytes(b"x" * (netwatch.MAX_LOG_FILE_SIZE + 1))
        f1.write_text("old1")
        f2.write_text("old2")
        netwatch._rotate_log(str(f))
        f3 = tmp_path / "test.log.3"
        # old .2 -> .3, old .1 -> .2, current -> .1
        assert f3.exists()


# ═══════════════════════════════════════════════════════════
#  _is_benign
# ═══════════════════════════════════════════════════════════

class TestIsBenign:
    @pytest.mark.parametrize("ip,expected", [
        ("10.0.1.1", True),
        ("192.168.0.1", True),
        ("172.16.0.1", True),
        ("100.64.0.1", True),   # CGNAT range
        ("100.127.255.254", True),
        ("100.128.0.1", False),  # Outside CGNAT
        ("203.0.113.1", False),
        ("8.8.8.8", False),
    ])
    def test_is_benign(self, ip, expected):
        result = netwatch._is_benign(ip)
        assert result == expected, f"_is_benign({ip}) expected {expected}"

    def test_whitelisted_ip_benign(self):
        assert netwatch._is_benign("127.0.0.1") == True

    def test_known_infra_hostname_not_benign(self):
        netwatch.dns_cache["4.4.4.4"] = "server.google.com"
        assert netwatch._is_benign("4.4.4.4") == False

    def test_unknown_hostname_not_benign(self):
        netwatch.dns_cache["5.5.5.5"] = "evil.attacker.net"
        assert netwatch._is_benign("5.5.5.5") == False

    def test_empty_hostname_not_benign(self):
        netwatch.dns_cache["6.6.6.6"] = ""
        assert netwatch._is_benign("6.6.6.6") == False


# ═══════════════════════════════════════════════════════════
#  check_suspicious
# ═══════════════════════════════════════════════════════════

class TestCheckSuspicious:
    def test_benign_both_sides_no_alert(self):
        netwatch.check_suspicious("10.0.1.1", "192.168.0.1", 80, 443)
        assert len(netwatch.alerts) == 0

    def test_sus_port_generates_alert(self):
        netwatch.check_suspicious("203.0.113.1", "10.0.1.1", 4444, 80)
        assert any("SUS PORT" in a["msg"] for a in netwatch.alerts)

    def test_tor_port_no_sus_alert(self):
        # TOR_PORTS should NOT trigger SUS PORT alert
        netwatch.check_suspicious("203.0.113.1", "10.0.1.1", 9050, 80)
        assert not any("SUS PORT 9050" in a["msg"] for a in netwatch.alerts)

    def test_port_scan_detection(self):
        ip = "203.0.113.99"
        netwatch.hosts[ip]["ports"] = set(range(100))
        netwatch.check_suspicious(ip, "10.0.1.1", 80, 80)
        assert any("PORT SCAN" in a["msg"] for a in netwatch.alerts)

    def test_no_duplicate_alerts(self):
        netwatch.check_suspicious("203.0.113.1", "10.0.1.1", 4444, 80)
        netwatch.check_suspicious("203.0.113.1", "10.0.1.1", 4444, 80)
        sus_alerts = [a for a in netwatch.alerts if "SUS PORT" in a["msg"]]
        assert len(sus_alerts) == 1

    def test_multiple_sus_ports(self):
        netwatch.check_suspicious("203.0.113.1", "10.0.1.1", 4444, 1337)
        # Both ports should trigger (if not in TOR_PORTS)
        assert any("4444" in a["msg"] for a in netwatch.alerts)
        assert any("1337" in a["msg"] for a in netwatch.alerts)
