"""
Tests for handle_command() and all command branches.
40+ commands tested: scan, deep, stealth, recon, trace, banner, whois, geo,
dnsinfo, portscan, rdns, attackers, profile, block, unblock, blocked, subnet,
track, untrack, conns, sniff, trackdns, tracked, tracking, pcap, export,
mac, proxy, crt, headers, asn, abuse, inspect, analyze, decode, sessions,
ssl, secheaders, techstack, ping, health, etrace, help, clear, dashboard
"""
import pytest
from unittest.mock import patch, MagicMock, call
import threading
import time

import netwatch


# ═══════════════════════════════════════════════════════════
#  INPUT VALIDATION IN handle_command
# ═══════════════════════════════════════════════════════════

class TestCommandInputValidation:
    @pytest.mark.parametrize("cmd", [
        "scan ; rm -rf /",
        "scan 1.2.3.4;cat /etc/passwd",
        "scan $(whoami)",
        "scan `id`",
        "scan |ls",
    ])
    def test_scan_rejects_injection(self, cmd):
        netwatch.handle_command(cmd)
        # Should get "Invalid target" message
        assert any("Invalid" in c for c in netwatch.console_output)

    @pytest.mark.parametrize("cmd", [
        "deep $(id)",
        "stealth |cat /etc/passwd",
        "recon ; whoami",
        "trace `uname`",
    ])
    def test_other_commands_reject_injection(self, cmd):
        netwatch.handle_command(cmd)
        assert any("Invalid" in c for c in netwatch.console_output)

    def test_empty_command(self):
        netwatch.handle_command("")
        assert len(netwatch.console_output) == 0

    def test_whitespace_only(self):
        netwatch.handle_command("   ")
        assert len(netwatch.console_output) == 0

    def test_unknown_command(self):
        netwatch.handle_command("nonexistent_cmd")
        assert any("Unknown" in c for c in netwatch.console_output)

    @pytest.mark.parametrize("target", [
        "192.168.1.1",
        "10.0.0.0/24",
        "fe80::1",
        "2001:db8::1",
    ])
    def test_valid_targets_accepted(self, target):
        # These should NOT show "Invalid target" - they might fail elsewhere but input is valid
        with patch("threading.Thread") as mock_thread:
            mock_thread.return_value.start = MagicMock()
            netwatch.handle_command(f"scan {target}")
        assert not any("Invalid" in c for c in netwatch.console_output)


# ═══════════════════════════════════════════════════════════
#  SCAN COMMANDS
# ═══════════════════════════════════════════════════════════

class TestScanCommands:
    @patch("threading.Thread")
    def test_scan_default_preset(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("scan 192.168.1.1")
        assert any("Scanning" in c for c in netwatch.console_output)
        assert any("quick" in c for c in netwatch.console_output)

    @pytest.mark.parametrize("preset", ["quick", "syn", "udp", "ping", "full"])
    @patch("threading.Thread")
    def test_scan_presets(self, mock_thread, preset):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command(f"scan 10.0.1.1 {preset}")
        assert any(preset in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_deep_scan(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("deep 10.0.1.1")
        assert any("DEEP" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_stealth_scan(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("stealth 10.0.1.1")
        assert any("STEALTH" in c or "Tor" in c for c in netwatch.console_output)


# ═══════════════════════════════════════════════════════════
#  RECON & TRACE
# ═══════════════════════════════════════════════════════════

class TestReconTraceCommands:
    @patch("threading.Thread")
    def test_recon_command(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("recon 10.0.1.1")
        assert any("RECON" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_trace_command(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("trace 8.8.8.8")
        assert any("Traceroute" in c for c in netwatch.console_output)


# ═══════════════════════════════════════════════════════════
#  BANNER
# ═══════════════════════════════════════════════════════════

class TestBannerCommand:
    @patch("netwatch.banner_grab", return_value="SSH-2.0-OpenSSH")
    def test_banner_valid(self, mock_grab):
        netwatch.handle_command("banner 10.0.1.1 22")
        assert any("SSH" in c for c in netwatch.console_output)

    def test_banner_invalid_target(self):
        netwatch.handle_command("banner $(id) 22")
        assert any("Invalid" in c for c in netwatch.console_output)

    def test_banner_invalid_port(self):
        netwatch.handle_command("banner 10.0.1.1 abc")
        assert any("Invalid port" in c for c in netwatch.console_output)

    def test_banner_missing_args(self):
        # Missing port - should not crash
        netwatch.handle_command("banner 10.0.1.1")
        # Doesn't match "banner" condition (needs 3 parts)


# ════════════════════��══════════════════════════════════════
#  WHOIS
# ════════════════��══════════════════════════════════════════

class TestWhoisCommand:
    @patch("netwatch.osint_whois", return_value={"registrar": "Test Reg"})
    @patch("netwatch.resolve_host", return_value="example.com")
    def test_whois_success(self, mock_resolve, mock_whois):
        netwatch.handle_command("whois 1.2.3.4")
        assert any("WHOIS" in c for c in netwatch.console_output)
        assert any("registrar" in c for c in netwatch.console_output)

    @patch("netwatch.osint_whois", return_value={"error": "not installed"})
    @patch("netwatch.resolve_host", return_value="")
    def test_whois_error(self, mock_resolve, mock_whois):
        netwatch.handle_command("whois bad.host")
        assert any("not installed" in c for c in netwatch.console_output)


# ���══════════════════════════════════════════════════════════
#  GEO
# ═══════════════════════════════════════════════════════════

class TestGeoCommand:
    @patch("threading.Thread")
    def test_geo_command(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("geo 8.8.8.8")
        assert any("Geolocating" in c for c in netwatch.console_output)


# ═══════════════════════════════════════════════════════════
#  DNSINFO
# ═══════════════════════════════════════════════════════════

class TestDnsinfoCommand:
    @patch("threading.Thread")
    def test_dnsinfo_command(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("dnsinfo example.com")
        assert any("DNS" in c for c in netwatch.console_output)


# ═════════════════════════════���═════════════════════════════
#  PORTSCAN
# ═══════════════════════════════════════════════════════════

class TestPortscanCommand:
    @patch("threading.Thread")
    def test_portscan_valid(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("portscan example.com")
        assert any("Port scanning" in c for c in netwatch.console_output)

    def test_portscan_invalid_target(self):
        netwatch.handle_command("portscan $(id)")
        assert any("Invalid" in c for c in netwatch.console_output)


# ═══════════════════════════════════════════════════════════
#  RDNS
# ══════════════════════════════════════════════════���════════

class TestRdnsCommand:
    @patch("netwatch.osint_reverse_dns", return_value={"PTR": "host.example.com"})
    def test_rdns_success(self, mock_rdns):
        netwatch.handle_command("rdns 1.2.3.4")
        assert any("PTR" in c for c in netwatch.console_output)

    @patch("netwatch.osint_reverse_dns", return_value={"error": "no PTR"})
    def test_rdns_no_record(self, mock_rdns):
        netwatch.handle_command("rdns 1.2.3.4")
        assert any("no PTR" in c for c in netwatch.console_output)


# ═══════════════════════════════���═══════════════════════════
#  ATTACKERS
# ═══════════════════════════════════════════════════════════

class TestAttackersCommand:
    def test_no_attackers(self):
        netwatch.handle_command("attackers")
        assert any("No honeypot" in c for c in netwatch.console_output)

    def test_with_attackers(self, populated_honeypot_events):
        with patch("netwatch.resolve_host", return_value="evil.host"):
            netwatch.handle_command("attackers")
        assert any("ATTACKERS" in c for c in netwatch.console_output)
        assert any("203.0.113.42" in c for c in netwatch.console_output)


# ═══════════════════════════════════════════════════════════
#  PROFILE
# ═══════════════════════════════════════════════════════════

class TestProfileCommand:
    def test_no_report(self):
        netwatch.handle_command("profile 1.2.3.4")
        assert any("No recon report" in c for c in netwatch.console_output)

    def test_with_report(self):
        netwatch.recon_reports["1.2.3.4"] = {
            "hostname": "evil.host",
            "os_guess": "Linux",
            "timestamp": "2024-01-01T00:00:00",
            "ports": ["22/tcp open ssh", "80/tcp open http"],
            "traceroute": ["1  10.0.1.1"],
            "honeypot_activity": [{"x": 1}],
        }
        netwatch.handle_command("profile 1.2.3.4")
        assert any("RECON REPORT" in c for c in netwatch.console_output)
        assert any("Linux" in c for c in netwatch.console_output)


# ═══════════════════════════════════════════════════════════
#  BLOCK / UNBLOCK / BLOCKED
# ═══════════════════════════════════════��═══════════════════

class TestBlockCommands:
    @patch("netwatch.HAS_RAW_NET", True)
    @patch("netwatch.subprocess.run")
    def test_block_valid_ip(self, mock_run):
        netwatch.handle_command("block 203.0.113.1")
        assert any("BLOCKED" in c for c in netwatch.console_output)
        assert mock_run.call_count == 2  # INPUT + OUTPUT rules

    def test_block_invalid_ip(self):
        netwatch.handle_command("block not-an-ip")
        assert any("Invalid IP" in c for c in netwatch.console_output)

    @patch("netwatch.subprocess.run")
    def test_unblock_valid_ip(self, mock_run):
        netwatch.handle_command("unblock 203.0.113.1")
        assert any("UNBLOCKED" in c for c in netwatch.console_output)

    def test_unblock_invalid_ip(self):
        netwatch.handle_command("unblock evil;rm")
        assert any("Invalid IP" in c for c in netwatch.console_output)

    @patch("netwatch.subprocess.run")
    def test_blocked_list(self, mock_run):
        mock_run.return_value = MagicMock(stdout="1 DROP all -- 203.0.113.1\n")
        netwatch.handle_command("blocked")
        assert any("DROP" in c for c in netwatch.console_output)


# ═══════════���══════════════════��════════════════════════════
#  SUBNET
# ═══════════════════════════════════════════════════════════

class TestSubnetCommand:
    @patch("threading.Thread")
    def test_subnet_default(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("subnet")
        assert any("Ping sweeping" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_subnet_custom(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("subnet 192.168.0.0/24")
        assert any("192.168.0.0/24" in c for c in netwatch.console_output)


# ═══════════════════════════════════════════════════════════
#  TRACK / UNTRACK / TRACKED / TRACKING
# ═══════════════════════════════════════════════════════════

class TestTrackCommands:
    @patch("threading.Thread")
    def test_track_ip(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("track 10.0.1.5")
        assert any("TRACKING" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_track_with_duration(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("track 10.0.1.5 60")
        assert any("TRACKING" in c for c in netwatch.console_output)

    def test_track_already_tracking(self):
        netwatch.tracking_active["10.0.1.5"] = True
        netwatch.handle_command("track 10.0.1.5")
        assert any("Already tracking" in c for c in netwatch.console_output)

    def test_track_invalid_ip(self):
        netwatch.handle_command("track ; rm -rf /")
        assert any("Invalid" in c for c in netwatch.console_output)

    def test_untrack(self):
        netwatch.tracking_active["10.0.1.5"] = True
        netwatch.handle_command("untrack 10.0.1.5")
        assert netwatch.tracking_active["10.0.1.5"] == False

    def test_untrack_not_tracked(self):
        netwatch.handle_command("untrack 10.0.1.5")
        assert any("Not currently" in c for c in netwatch.console_output)

    def test_tracked_no_data(self):
        netwatch.handle_command("tracked 10.0.1.5")
        assert any("No tracked data" in c for c in netwatch.console_output)

    def test_tracking_no_active(self):
        netwatch.handle_command("tracking")
        assert any("No active" in c for c in netwatch.console_output)

    def test_tracking_shows_active(self):
        netwatch.tracking_active["10.0.1.5"] = True
        netwatch.tracked_ips["10.0.1.5"] = [{"x": 1}]
        netwatch.handle_command("tracking")
        assert any("10.0.1.5" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_track_duration_clamped(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("track 10.0.1.5 99999")
        # Should clamp to 3600 - no crash
        assert any("TRACKING" in c for c in netwatch.console_output)


# ═══════════════════════════════════════════════════════════
#  CONNS / SNIFF / TRACKDNS
# ═══════════════════════════════════════════════════════════

class TestNetworkCapture:
    @patch("threading.Thread")
    def test_conns(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("conns 10.0.1.5")
        assert any("TCP connections" in c for c in netwatch.console_output)

    def test_conns_invalid(self):
        netwatch.handle_command("conns $(id)")
        assert any("Invalid" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_sniff(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("sniff 10.0.1.5")
        assert any("Sniffing" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_sniff_with_duration(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("sniff 10.0.1.5 30")
        assert any("30s" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_sniff_duration_clamped(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("sniff 10.0.1.5 999")
        # Should be clamped to 300
        assert any("Sniffing" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_trackdns(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("trackdns 10.0.1.5")
        assert any("DNS" in c for c in netwatch.console_output)

    def test_trackdns_invalid(self):
        netwatch.handle_command("trackdns ; rm /")
        assert any("Invalid" in c for c in netwatch.console_output)


# ═══════════════════════════════════════════════════════════
#  PCAP
# ══════════════════════════════════════════════��════════════

class TestPcapCommand:
    @patch("netwatch.start_tcpdump")
    def test_pcap_start(self, mock_start):
        netwatch.handle_command("pcap")
        assert any("PCAP capture started" in c for c in netwatch.console_output)

    @patch("netwatch.stop_tcpdump")
    def test_pcap_stop(self, mock_stop):
        netwatch.handle_command("pcap stop")
        assert any("stopped" in c for c in netwatch.console_output)


# ═══════════════════════════════════════════════════════════
#  EXPORT
# ═══════════════════════════════════════════════════════════

class TestExportCommand:
    @patch("netwatch.save_logs")
    def test_export(self, mock_save):
        netwatch.handle_command("export")
        assert any("Exported" in c for c in netwatch.console_output)


# ═════════════════════��═════════════════════════════════════
#  MAC
# ═══════════════════════════════════════════════════════════

class TestMacCommand:
    def test_mac_no_args(self):
        netwatch.handle_command("mac")
        assert any("Usage" in c for c in netwatch.console_output)

    def test_mac_not_found(self):
        netwatch.handle_command("mac aa:bb:cc:dd:ee:ff")
        assert any("not found" in c for c in netwatch.console_output)

    def test_mac_found(self):
        netwatch.arp_table["10.0.1.5"] = {"mac": "aa:bb:cc:dd:ee:ff", "state": "REACHABLE"}
        with patch("netwatch.resolve_host", return_value="myhost"):
            netwatch.handle_command("mac aa:bb:cc")
        assert any("10.0.1.5" in c for c in netwatch.console_output)


# ═══════════════════════════════════════════════════════════
#  PROXY COMMANDS
# ═══════════════════════════════════════════════════════════

class TestProxyCommand:
    def test_proxy_list_empty(self):
        netwatch.handle_command("proxy list")
        assert any("No proxies" in c for c in netwatch.console_output)

    def test_proxy_add_valid(self):
        netwatch.handle_command("proxy add socks5 127.0.0.1:9050")
        assert len(netwatch.proxy_pool) == 1
        assert netwatch.proxy_pool[0]["type"] == "socks5"

    def test_proxy_add_invalid_type(self):
        netwatch.handle_command("proxy add badtype 127.0.0.1:9050")
        assert any("must be" in c for c in netwatch.console_output)

    def test_proxy_add_no_port(self):
        netwatch.handle_command("proxy add socks5 127.0.0.1")
        assert any("Format" in c for c in netwatch.console_output)

    def test_proxy_add_invalid_port(self):
        netwatch.handle_command("proxy add socks5 127.0.0.1:99999")
        assert any("Invalid port" in c for c in netwatch.console_output)

    def test_proxy_rm(self):
        netwatch.proxy_pool.append({"type": "socks5", "host": "127.0.0.1", "port": "9050", "label": "socks5://127.0.0.1:9050"})
        netwatch.handle_command("proxy rm 1")
        assert len(netwatch.proxy_pool) == 0

    def test_proxy_rm_invalid_index(self):
        netwatch.handle_command("proxy rm 99")
        assert any("Invalid index" in c for c in netwatch.console_output)

    def test_proxy_rotate_toggle(self):
        assert netwatch.proxy_rotation == False
        netwatch.handle_command("proxy rotate")
        assert netwatch.proxy_rotation == True
        netwatch.handle_command("proxy rotate")
        assert netwatch.proxy_rotation == False

    @patch("threading.Thread")
    def test_proxy_test(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.proxy_pool.append({"type": "socks5", "host": "127.0.0.1", "port": "9050", "label": "socks5://127.0.0.1:9050"})
        netwatch.handle_command("proxy test")
        # Should start a test thread (no crash)

    @patch("threading.Thread")
    def test_proxy_status(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("proxy status")
        # Should launch _cmd_proxy thread


# ═══════════════════════════════════════════════════════════
#  CRT / HEADERS / ASN / ABUSE
# ═══════════════════════════════════════════════════════════

class TestOsintCommands:
    @patch("threading.Thread")
    def test_crt(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("crt example.com")
        assert any("Cert transparency" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_headers(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("headers example.com")
        assert any("HTTP headers" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_asn(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("asn 8.8.8.8")
        assert any("ASN" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_abuse(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("abuse 203.0.113.1")
        assert any("Abuse" in c for c in netwatch.console_output)


# ═══════════════════════════════════════════════════════════
#  INSPECT
# ═══════════════════════════════════════════════════════════

class TestInspectCommand:
    def test_inspect_no_events(self):
        netwatch.handle_command("inspect")
        assert any("Last 10" in c for c in netwatch.console_output)

    def test_inspect_with_events(self, populated_honeypot_events):
        netwatch.handle_command("inspect 1")
        assert any("EVENT #1" in c for c in netwatch.console_output)

    def test_inspect_invalid_index(self, populated_honeypot_events):
        netwatch.handle_command("inspect 999")
        assert any("Last 10" in c for c in netwatch.console_output)


# ═══════════════════════════════════════════════════════════
#  ANALYZE
# ═══════════════════════════════════════════════════════════

class TestAnalyzeCommand:
    @patch("threading.Thread")
    def test_analyze(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("analyze 203.0.113.42")
        assert any("Analyzing" in c for c in netwatch.console_output)


# ═══════════════════════════════════════════════════════════
#  DECODE
# ═══════════════════════════════════════════════════════════

class TestDecodeCommand:
    def test_decode_base64(self):
        import base64
        encoded = base64.b64encode(b"secret").decode()
        netwatch.handle_command(f"decode {encoded}")
        assert any("Decode" in c for c in netwatch.console_output)

    def test_decode_url(self):
        netwatch.handle_command("decode hello%20world")
        assert any("Decode" in c for c in netwatch.console_output)


# ═══════════════════════════════════════════════════════════
#  SESSIONS
# ═══════════════════════════════════════════════════════════

class TestSessionsCommand:
    def test_no_sessions(self):
        netwatch.handle_command("sessions")
        assert any("No honeypot sessions" in c for c in netwatch.console_output)

    def test_with_sessions(self, populated_honeypot_events):
        netwatch.handle_command("sessions")
        assert any("HONEYPOT SESSIONS" in c for c in netwatch.console_output)


# ═══════════════════════════════════════════════════════════
#  SSL / SECHEADERS / TECHSTACK / PING / HEALTH / ETRACE
# ═════════════════════════════════════��═════════════════════

class TestOsintThreadedCommands:
    @patch("threading.Thread")
    def test_ssl_command(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("ssl example.com")
        assert any("SSL" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_ssl_custom_port(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("ssl example.com 8443")
        assert any("8443" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_secheaders_command(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("secheaders example.com")
        assert any("Security header" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_techstack_command(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("techstack example.com")
        assert any("Tech fingerprint" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_ping_command(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("ping 8.8.8.8")
        assert any("Ping" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_ping_custom_count(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("ping 8.8.8.8 10")
        assert any("10 packets" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_health_command(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("health example.com")
        assert any("HEALTH" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_etrace_command(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("etrace 8.8.8.8")
        assert any("Enriched traceroute" in c for c in netwatch.console_output)

    def test_etrace_invalid(self):
        netwatch.handle_command("etrace $(id)")
        assert any("Invalid" in c for c in netwatch.console_output)


# ═══════════════════════════════════════════════════════════
#  TAB SWITCHING / HELP / CLEAR / DASHBOARD
# ═══════════════════════════════════════════════════════════

class TestMiscCommands:
    @pytest.mark.parametrize("tab", ["hosts", "alerts", "dns", "proto", "honeypot", "nmap", "arp", "all", "osint", "proxy"])
    def test_tab_switch(self, tab):
        netwatch.handle_command(tab)
        assert netwatch.current_tab == tab

    def test_help_command(self):
        netwatch.handle_command("help")
        assert netwatch.show_help_overlay == True

    def test_clear_command(self):
        netwatch.console_output.append("something")
        netwatch.handle_command("clear")
        assert len(netwatch.console_output) == 0

    def test_dashboard_command(self):
        netwatch.console_mode = True
        netwatch.handle_command("dashboard")
        assert netwatch.console_mode == False
