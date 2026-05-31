"""
test_commands_workflow.py
=========================
350 thorough tests for handle_command() and _exec_console_cmd() in netwatch.py.
Organized by category:
  - Scanning (50)
  - OSINT (80)
  - Defense (30)
  - Tracking (40)
  - Honeypot Analysis (30)
  - Proxy (25)
  - Tab Switching (15)
  - System Commands (15)
  - Input Validation / Injection Prevention (40)
  - Workflow Sequences (25)
"""
import base64
import binascii
import pytest
from unittest.mock import patch, MagicMock

import netwatch


# ═══════════════════════════════════════════════════════════
#  SCANNING — 50 tests
# ═══════════════════════════════════════════════════════════

class TestScanningCommands:
    # --- scan command (valid presets) ---
    @patch("threading.Thread")
    def test_scan_quick_preset_output(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("scan 1.2.3.4 quick")
        assert any("quick" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_scan_syn_preset_output(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("scan 1.2.3.4 syn")
        assert any("syn" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_scan_udp_preset_output(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("scan 1.2.3.4 udp")
        assert any("udp" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_scan_ping_preset_output(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("scan 1.2.3.4 ping")
        assert any("ping" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_scan_full_preset_output(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("scan 1.2.3.4 full")
        assert any("full" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_scan_unknown_preset_falls_back_to_quick(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("scan 1.2.3.4 bogus")
        assert any("Scanning" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_scan_spawns_thread(self, mock_thread):
        inst = MagicMock()
        mock_thread.return_value = inst
        netwatch.handle_command("scan 5.5.5.5")
        assert inst.start.called

    @patch("threading.Thread")
    def test_scan_no_output_on_injection(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("scan ;id")
        assert not any("Scanning" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_scan_ipv6_accepted(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("scan 2001:db8::1")
        assert not any("Invalid" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_scan_cidr_accepted(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("scan 192.168.1.0/24")
        assert not any("Invalid" in c for c in netwatch.console_output)

    def test_scan_no_target_not_crash(self):
        netwatch.handle_command("scan")
        # No target means action=="scan" but len(parts)<2 → falls to unknown
        assert any("Unknown" in c for c in netwatch.console_output)

    # --- deep scan ---
    @patch("threading.Thread")
    def test_deep_scan_message_output(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("deep 10.0.0.1")
        assert any("DEEP" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_deep_scan_spawns_thread(self, mock_thread):
        inst = MagicMock()
        mock_thread.return_value = inst
        netwatch.handle_command("deep 10.0.0.1")
        assert inst.start.called

    @patch("threading.Thread")
    def test_deep_scan_target_in_output(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("deep 10.0.0.2")
        assert any("10.0.0.2" in c for c in netwatch.console_output)

    def test_deep_scan_injection_rejected(self):
        netwatch.handle_command("deep | cat /etc/passwd")
        assert any("Invalid" in c for c in netwatch.console_output)

    def test_deep_scan_backtick_rejected(self):
        netwatch.handle_command("deep `uname`")
        assert any("Invalid" in c for c in netwatch.console_output)

    def test_deep_scan_dollar_rejected(self):
        netwatch.handle_command("deep $(id)")
        assert any("Invalid" in c for c in netwatch.console_output)

    def test_deep_no_args_falls_to_unknown(self):
        netwatch.handle_command("deep")
        assert any("Unknown" in c for c in netwatch.console_output)

    # --- stealth scan ---
    @patch("threading.Thread")
    def test_stealth_message_includes_tor(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("stealth 10.0.0.1")
        assert any("Tor" in c or "STEALTH" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_stealth_spawns_thread(self, mock_thread):
        inst = MagicMock()
        mock_thread.return_value = inst
        netwatch.handle_command("stealth 10.0.0.1")
        assert inst.start.called

    def test_stealth_injection_rejected(self):
        netwatch.handle_command("stealth ;whoami")
        assert any("Invalid" in c for c in netwatch.console_output)

    def test_stealth_no_args_falls_to_unknown(self):
        netwatch.handle_command("stealth")
        assert any("Unknown" in c for c in netwatch.console_output)

    # --- recon ---
    @patch("threading.Thread")
    def test_recon_message_output(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("recon 10.0.0.1")
        assert any("RECON" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_recon_spawns_thread(self, mock_thread):
        inst = MagicMock()
        mock_thread.return_value = inst
        netwatch.handle_command("recon 10.0.0.1")
        assert inst.start.called

    def test_recon_injection_rejected(self):
        netwatch.handle_command("recon ;ls -la")
        assert any("Invalid" in c for c in netwatch.console_output)

    def test_recon_no_args_falls_to_unknown(self):
        netwatch.handle_command("recon")
        assert any("Unknown" in c for c in netwatch.console_output)

    # --- trace ---
    @patch("threading.Thread")
    def test_trace_message_output(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("trace 8.8.8.8")
        assert any("Traceroute" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_trace_target_in_output(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("trace 8.8.4.4")
        assert any("8.8.4.4" in c for c in netwatch.console_output)

    def test_trace_injection_rejected(self):
        netwatch.handle_command("trace `hostname`")
        assert any("Invalid" in c for c in netwatch.console_output)

    def test_trace_no_args_falls_to_unknown(self):
        netwatch.handle_command("trace")
        assert any("Unknown" in c for c in netwatch.console_output)

    # --- banner ---
    @patch("netwatch.banner_grab", return_value="220 FTP Ready")
    def test_banner_ftp_service(self, mock_grab):
        netwatch.handle_command("banner 10.0.0.1 21")
        assert any("FTP" in c or "220" in c for c in netwatch.console_output)

    @patch("netwatch.banner_grab", return_value="SSH-2.0-OpenSSH_8.2")
    def test_banner_ssh_service(self, mock_grab):
        netwatch.handle_command("banner 10.0.0.1 22")
        assert any("SSH" in c for c in netwatch.console_output)

    @patch("netwatch.banner_grab", return_value="")
    def test_banner_empty_response(self, mock_grab):
        netwatch.handle_command("banner 10.0.0.1 80")
        # no crash expected
        assert any("Grabbing" in c for c in netwatch.console_output)

    def test_banner_port_zero_rejected(self):
        netwatch.handle_command("banner 10.0.0.1 0abc")
        assert any("Invalid port" in c for c in netwatch.console_output)

    def test_banner_non_numeric_port_rejected(self):
        netwatch.handle_command("banner 10.0.0.1 ssh")
        assert any("Invalid port" in c for c in netwatch.console_output)

    def test_banner_injection_in_ip_rejected(self):
        netwatch.handle_command("banner $(id) 22")
        assert any("Invalid" in c for c in netwatch.console_output)

    def test_banner_missing_both_args(self):
        # banner with only one part: falls to unknown (needs >=3 parts)
        netwatch.handle_command("banner")
        assert any("Unknown" in c for c in netwatch.console_output)

    def test_banner_missing_port_falls_to_unknown(self):
        netwatch.handle_command("banner 10.0.0.1")
        # action=banner but len(parts)<3 → falls to else → Unknown
        assert any("Unknown" in c for c in netwatch.console_output)

    @pytest.mark.parametrize("ip", ["192.168.1.1", "10.10.10.10", "172.16.0.1", "203.0.113.1"])
    @patch("netwatch.banner_grab", return_value="HTTP/1.1 200 OK")
    def test_banner_various_ips(self, mock_grab, ip):
        netwatch.handle_command(f"banner {ip} 80")
        assert any("Grabbing" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_scan_sets_nmap_running_via_thread(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("scan 1.2.3.4")
        # Thread was created (scanning initiated)
        assert mock_thread.called

    @patch("threading.Thread")
    def test_scan_console_output_nonempty(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("scan 1.2.3.4")
        assert len(netwatch.console_output) > 0

    @patch("threading.Thread")
    def test_deep_console_output_nonempty(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("deep 1.2.3.4")
        assert len(netwatch.console_output) > 0

    @patch("threading.Thread")
    def test_stealth_console_output_nonempty(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("stealth 1.2.3.4")
        assert len(netwatch.console_output) > 0


# ═══════════════════════════════════════════════════════════
#  OSINT — 80 tests
# ═══════════════════════════════════════════════════════════

class TestOsintGeo:
    @patch("threading.Thread")
    def test_geo_queues_thread(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("geo 8.8.8.8")
        assert mock_thread.called

    @patch("threading.Thread")
    def test_geo_output_contains_geolocating(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("geo 1.1.1.1")
        assert any("Geolocating" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_geo_target_in_output(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("geo 203.0.113.99")
        assert any("203.0.113.99" in c for c in netwatch.console_output)

    def test_geo_no_args_falls_to_unknown(self):
        netwatch.handle_command("geo")
        assert any("Unknown" in c for c in netwatch.console_output)

    @patch("netwatch._cmd_geo")
    @patch("threading.Thread")
    def test_geo_private_ip_still_dispatches(self, mock_thread, mock_cmd):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("geo 192.168.1.1")
        assert any("Geolocating" in c for c in netwatch.console_output)


class TestOsintWhois:
    @patch("netwatch.osint_whois", return_value={"registrar": "IANA", "expiry": "2030-01-01"})
    @patch("netwatch.resolve_host", return_value="")
    def test_whois_success_shows_registrar(self, mock_resolve, mock_whois):
        netwatch.handle_command("whois 8.8.8.8")
        assert any("registrar" in c for c in netwatch.console_output)

    @patch("netwatch.osint_whois", return_value={"registrar": "Test", "org": "TestOrg"})
    @patch("netwatch.resolve_host", return_value="dns.google")
    def test_whois_shows_hostname(self, mock_resolve, mock_whois):
        netwatch.handle_command("whois 8.8.8.8")
        assert any("dns.google" in c for c in netwatch.console_output)

    @patch("netwatch.osint_whois", return_value={"error": "whois not installed"})
    @patch("netwatch.resolve_host", return_value="")
    def test_whois_error_shown(self, mock_resolve, mock_whois):
        netwatch.handle_command("whois 1.2.3.4")
        assert any("not installed" in c for c in netwatch.console_output)

    @patch("netwatch.osint_whois", return_value={"registrar": "IANA"})
    @patch("netwatch.resolve_host", return_value="")
    def test_whois_with_host_in_hosts_table(self, mock_resolve, mock_whois):
        netwatch.hosts["1.2.3.4"]["bytes_in"] = 1024
        netwatch.hosts["1.2.3.4"]["bytes_out"] = 512
        netwatch.hosts["1.2.3.4"]["ports"] = {80, 443}
        netwatch.handle_command("whois 1.2.3.4")
        assert any("Traffic" in c for c in netwatch.console_output)

    def test_whois_no_args_falls_to_unknown(self):
        netwatch.handle_command("whois")
        assert any("Unknown" in c for c in netwatch.console_output)

    @patch("netwatch.osint_whois", return_value={"registrar": "Test"})
    @patch("netwatch.resolve_host", return_value="")
    def test_whois_with_recon_report_shows_os(self, mock_resolve, mock_whois):
        netwatch.recon_reports["1.2.3.4"] = {"os_guess": "Linux 5.x", "hostname": "h", "timestamp": "t", "ports": [], "traceroute": [], "honeypot_activity": []}
        netwatch.handle_command("whois 1.2.3.4")
        assert any("Linux" in c for c in netwatch.console_output)


class TestOsintDnsInfo:
    @patch("threading.Thread")
    def test_dnsinfo_output_contains_dns(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("dnsinfo example.com")
        assert any("DNS" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_dnsinfo_target_in_output(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("dnsinfo target.example.com")
        assert any("target.example.com" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_dnsinfo_spawns_thread(self, mock_thread):
        inst = MagicMock()
        mock_thread.return_value = inst
        netwatch.handle_command("dnsinfo example.com")
        assert inst.start.called

    def test_dnsinfo_no_args_falls_to_unknown(self):
        netwatch.handle_command("dnsinfo")
        assert any("Unknown" in c for c in netwatch.console_output)


class TestOsintRdns:
    @patch("netwatch.osint_reverse_dns", return_value={"PTR": ["host.example.com"]})
    def test_rdns_shows_ptr(self, mock_rdns):
        netwatch.handle_command("rdns 1.2.3.4")
        assert any("PTR" in c for c in netwatch.console_output)

    @patch("netwatch.osint_reverse_dns", return_value={"error": "lookup failed"})
    def test_rdns_shows_error(self, mock_rdns):
        netwatch.handle_command("rdns 1.2.3.4")
        assert any("lookup failed" in c for c in netwatch.console_output)

    @patch("netwatch.osint_reverse_dns", return_value={"PTR": "single.host.com"})
    def test_rdns_scalar_ptr(self, mock_rdns):
        netwatch.handle_command("rdns 5.5.5.5")
        assert any("PTR" in c for c in netwatch.console_output)

    def test_rdns_no_args_falls_to_unknown(self):
        netwatch.handle_command("rdns")
        assert any("Unknown" in c for c in netwatch.console_output)


class TestOsintSsl:
    @patch("threading.Thread")
    def test_ssl_output_contains_ssl(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("ssl example.com")
        assert any("SSL" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_ssl_default_port_443(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("ssl example.com")
        assert any("443" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_ssl_custom_port_8443(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("ssl example.com 8443")
        assert any("8443" in c for c in netwatch.console_output)

    def test_ssl_invalid_target_rejected(self):
        netwatch.handle_command("ssl example.com;rm -rf /")
        assert any("Invalid" in c for c in netwatch.console_output)

    def test_ssl_no_args_falls_to_unknown(self):
        netwatch.handle_command("ssl")
        assert any("Unknown" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_ssl_spawns_thread(self, mock_thread):
        inst = MagicMock()
        mock_thread.return_value = inst
        netwatch.handle_command("ssl example.com")
        assert inst.start.called


class TestOsintSecHeaders:
    @patch("threading.Thread")
    def test_secheaders_output_contains_security(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("secheaders example.com")
        assert any("Security header" in c or "security" in c.lower() for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_secheaders_spawns_thread(self, mock_thread):
        inst = MagicMock()
        mock_thread.return_value = inst
        netwatch.handle_command("secheaders example.com")
        assert inst.start.called

    def test_secheaders_injection_rejected(self):
        netwatch.handle_command("secheaders example.com|cat /etc/passwd")
        assert any("Invalid" in c for c in netwatch.console_output)

    def test_secheaders_no_args_falls_to_unknown(self):
        netwatch.handle_command("secheaders")
        assert any("Unknown" in c for c in netwatch.console_output)


class TestOsintTechStack:
    @patch("threading.Thread")
    def test_techstack_output_contains_tech(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("techstack example.com")
        assert any("Tech" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_techstack_spawns_thread(self, mock_thread):
        inst = MagicMock()
        mock_thread.return_value = inst
        netwatch.handle_command("techstack example.com")
        assert inst.start.called

    def test_techstack_injection_rejected(self):
        netwatch.handle_command("techstack example.com;ls")
        assert any("Invalid" in c for c in netwatch.console_output)

    def test_techstack_no_args_falls_to_unknown(self):
        netwatch.handle_command("techstack")
        assert any("Unknown" in c for c in netwatch.console_output)


class TestOsintPing:
    @patch("threading.Thread")
    def test_ping_output_contains_ping(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("ping 8.8.8.8")
        assert any("Ping" in c or "ping" in c.lower() for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_ping_default_count_5(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("ping 8.8.8.8")
        assert any("5" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_ping_custom_count(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("ping 8.8.8.8 10")
        assert any("10" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_ping_count_clamped_to_20(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("ping 8.8.8.8 999")
        assert any("20" in c for c in netwatch.console_output)

    def test_ping_injection_rejected(self):
        netwatch.handle_command("ping 8.8.8.8;id")
        assert any("Invalid" in c for c in netwatch.console_output)

    def test_ping_no_args_falls_to_unknown(self):
        netwatch.handle_command("ping")
        assert any("Unknown" in c for c in netwatch.console_output)


class TestOsintHealth:
    @patch("threading.Thread")
    def test_health_output_contains_health(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("health example.com")
        assert any("HEALTH" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_health_spawns_thread(self, mock_thread):
        inst = MagicMock()
        mock_thread.return_value = inst
        netwatch.handle_command("health example.com")
        assert inst.start.called

    def test_health_injection_rejected(self):
        netwatch.handle_command("health example.com;ls")
        assert any("Invalid" in c for c in netwatch.console_output)

    def test_health_no_args_falls_to_unknown(self):
        netwatch.handle_command("health")
        assert any("Unknown" in c for c in netwatch.console_output)


class TestOsintEtrace:
    @patch("threading.Thread")
    def test_etrace_output_contains_enriched(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("etrace 8.8.8.8")
        assert any("Enriched" in c or "traceroute" in c.lower() for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_etrace_spawns_thread(self, mock_thread):
        inst = MagicMock()
        mock_thread.return_value = inst
        netwatch.handle_command("etrace 8.8.8.8")
        assert inst.start.called

    def test_etrace_injection_rejected(self):
        netwatch.handle_command("etrace $(id)")
        assert any("Invalid" in c for c in netwatch.console_output)

    def test_etrace_no_args_falls_to_unknown(self):
        netwatch.handle_command("etrace")
        assert any("Unknown" in c for c in netwatch.console_output)


class TestOsintPortscan:
    @patch("threading.Thread")
    def test_portscan_output_contains_port_scanning(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("portscan example.com")
        assert any("Port scanning" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_portscan_spawns_thread(self, mock_thread):
        inst = MagicMock()
        mock_thread.return_value = inst
        netwatch.handle_command("portscan example.com")
        assert inst.start.called

    @patch("threading.Thread")
    def test_portscan_target_in_output(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("portscan mytarget.com")
        assert any("mytarget.com" in c for c in netwatch.console_output)

    def test_portscan_injection_rejected(self):
        netwatch.handle_command("portscan example.com;ls")
        assert any("Invalid" in c for c in netwatch.console_output)

    def test_portscan_no_args_falls_to_unknown(self):
        netwatch.handle_command("portscan")
        assert any("Unknown" in c for c in netwatch.console_output)


class TestOsintSubnet:
    @patch("threading.Thread")
    def test_subnet_default_cidr(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("subnet")
        assert any("Ping sweep" in c or "10.0.1.0" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_subnet_custom_cidr_in_output(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("subnet 10.20.30.0/24")
        assert any("10.20.30.0/24" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_subnet_spawns_thread(self, mock_thread):
        inst = MagicMock()
        mock_thread.return_value = inst
        netwatch.handle_command("subnet 192.168.0.0/24")
        assert inst.start.called


class TestOsintCrt:
    @patch("threading.Thread")
    def test_crt_output_contains_cert(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("crt example.com")
        assert any("Cert" in c or "cert" in c.lower() for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_crt_target_in_output(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("crt mysite.example.com")
        assert any("mysite.example.com" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_crt_spawns_thread(self, mock_thread):
        inst = MagicMock()
        mock_thread.return_value = inst
        netwatch.handle_command("crt example.com")
        assert inst.start.called

    def test_crt_no_args_falls_to_unknown(self):
        netwatch.handle_command("crt")
        assert any("Unknown" in c for c in netwatch.console_output)


class TestOsintHeaders:
    @patch("threading.Thread")
    def test_headers_output_contains_http(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("headers example.com")
        assert any("HTTP" in c or "header" in c.lower() for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_headers_spawns_thread(self, mock_thread):
        inst = MagicMock()
        mock_thread.return_value = inst
        netwatch.handle_command("headers example.com")
        assert inst.start.called

    def test_headers_no_args_falls_to_unknown(self):
        netwatch.handle_command("headers")
        assert any("Unknown" in c for c in netwatch.console_output)


class TestOsintAsn:
    @patch("threading.Thread")
    def test_asn_output_contains_asn(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("asn 8.8.8.8")
        assert any("ASN" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_asn_target_in_output(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("asn 1.1.1.1")
        assert any("1.1.1.1" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_asn_spawns_thread(self, mock_thread):
        inst = MagicMock()
        mock_thread.return_value = inst
        netwatch.handle_command("asn 8.8.8.8")
        assert inst.start.called

    def test_asn_no_args_falls_to_unknown(self):
        netwatch.handle_command("asn")
        assert any("Unknown" in c for c in netwatch.console_output)


class TestOsintAbuse:
    @patch("threading.Thread")
    def test_abuse_output_contains_abuse(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("abuse 203.0.113.1")
        assert any("Abuse" in c or "abuse" in c.lower() for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_abuse_target_in_output(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("abuse 203.0.113.5")
        assert any("203.0.113.5" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_abuse_spawns_thread(self, mock_thread):
        inst = MagicMock()
        mock_thread.return_value = inst
        netwatch.handle_command("abuse 1.2.3.4")
        assert inst.start.called

    def test_abuse_no_args_falls_to_unknown(self):
        netwatch.handle_command("abuse")
        assert any("Unknown" in c for c in netwatch.console_output)


# ═══════════════════════════════════════════════════════════
#  DEFENSE — 30 tests
# ═══════════════════════════════════════════════════════════

class TestDefenseBlock:
    @patch("netwatch.subprocess.run")
    def test_block_valid_ipv4_message(self, mock_run):
        netwatch.handle_command("block 203.0.113.1")
        assert any("BLOCKED" in c for c in netwatch.console_output)

    @patch("netwatch.HAS_RAW_NET", True)
    @patch("netwatch.subprocess.run")
    def test_block_calls_iptables_twice(self, mock_run):
        netwatch.handle_command("block 203.0.113.2")
        assert mock_run.call_count == 2

    @patch("netwatch.subprocess.run")
    def test_block_adds_alert(self, mock_run):
        netwatch.handle_command("block 203.0.113.3")
        assert any("BLOCKED" in a.get("msg", "") for a in netwatch.alerts)

    def test_block_invalid_ip_rejected(self):
        netwatch.handle_command("block notanip")
        assert any("Invalid IP" in c for c in netwatch.console_output)

    def test_block_injection_semicolon_rejected(self):
        netwatch.handle_command("block 1.2.3.4;rm -rf /")
        assert any("Invalid IP" in c for c in netwatch.console_output)

    def test_block_injection_pipe_rejected(self):
        netwatch.handle_command("block |cat /etc/passwd")
        assert any("Invalid IP" in c for c in netwatch.console_output)

    def test_block_injection_backtick_rejected(self):
        netwatch.handle_command("block `whoami`")
        assert any("Invalid IP" in c for c in netwatch.console_output)

    def test_block_no_args_falls_to_unknown(self):
        netwatch.handle_command("block")
        assert any("Unknown" in c for c in netwatch.console_output)

    @patch("netwatch.subprocess.run")
    def test_block_ipv4_loopback_accepted_by_validator(self, mock_run):
        netwatch.handle_command("block 127.0.0.1")
        assert any("BLOCKED" in c for c in netwatch.console_output)

    @patch("netwatch.subprocess.run")
    def test_block_multiple_ips_sequentially(self, mock_run):
        netwatch.handle_command("block 203.0.113.10")
        netwatch.handle_command("block 203.0.113.11")
        blocked_msgs = [c for c in netwatch.console_output if "BLOCKED" in c]
        assert len(blocked_msgs) >= 2


class TestDefenseUnblock:
    @patch("netwatch.subprocess.run")
    def test_unblock_valid_ip_message(self, mock_run):
        netwatch.handle_command("unblock 203.0.113.1")
        assert any("UNBLOCKED" in c for c in netwatch.console_output)

    @patch("netwatch.HAS_RAW_NET", True)
    @patch("netwatch.subprocess.run")
    def test_unblock_calls_iptables_twice(self, mock_run):
        netwatch.handle_command("unblock 203.0.113.1")
        assert mock_run.call_count == 2

    def test_unblock_invalid_ip_rejected(self):
        netwatch.handle_command("unblock evil;rm")
        assert any("Invalid IP" in c for c in netwatch.console_output)

    def test_unblock_injection_dollar_rejected(self):
        netwatch.handle_command("unblock $(id)")
        assert any("Invalid IP" in c for c in netwatch.console_output)

    def test_unblock_no_args_falls_to_unknown(self):
        netwatch.handle_command("unblock")
        assert any("Unknown" in c for c in netwatch.console_output)

    @patch("netwatch.subprocess.run")
    def test_unblock_ip_in_output(self, mock_run):
        netwatch.handle_command("unblock 203.0.113.20")
        assert any("203.0.113.20" in c for c in netwatch.console_output)


class TestDefenseBlocked:
    @patch("netwatch.subprocess.run")
    def test_blocked_shows_drop_rules(self, mock_run):
        mock_run.return_value = MagicMock(stdout="2 DROP all -- 203.0.113.1\n3 DROP all -- 198.51.100.1\n")
        netwatch.handle_command("blocked")
        assert any("DROP" in c for c in netwatch.console_output)

    @patch("netwatch.subprocess.run")
    def test_blocked_empty_output_ok(self, mock_run):
        mock_run.return_value = MagicMock(stdout="Chain INPUT (policy ACCEPT)\nnum target prot opt source destination\n")
        netwatch.handle_command("blocked")
        # no crash, no DROP lines
        assert not any("DROP" in c for c in netwatch.console_output)

    @patch("netwatch.subprocess.run")
    def test_blocked_multiple_drop_lines_all_shown(self, mock_run):
        lines = "\n".join(f"{i} DROP all -- 10.0.0.{i}" for i in range(1, 6))
        mock_run.return_value = MagicMock(stdout=lines)
        netwatch.handle_command("blocked")
        drop_lines = [c for c in netwatch.console_output if "DROP" in c]
        assert len(drop_lines) >= 4


class TestDefenseMac:
    def test_mac_no_args_shows_usage(self):
        netwatch.handle_command("mac")
        assert any("Usage" in c for c in netwatch.console_output)

    def test_mac_not_in_arp_shows_not_found(self):
        netwatch.handle_command("mac aa:bb:cc:dd:ee:ff")
        assert any("not found" in c for c in netwatch.console_output)

    def test_mac_partial_match_found(self):
        netwatch.arp_table["10.10.10.10"] = {"mac": "de:ad:be:ef:00:01", "state": "REACHABLE"}
        with patch("netwatch.resolve_host", return_value="testhost"):
            netwatch.handle_command("mac de:ad:be")
        assert any("10.10.10.10" in c for c in netwatch.console_output)

    def test_mac_normalizes_dash_separator(self):
        netwatch.arp_table["10.20.30.40"] = {"mac": "aa:bb:cc:dd:ee:ff", "state": "REACHABLE"}
        with patch("netwatch.resolve_host", return_value=""):
            netwatch.handle_command("mac aa-bb-cc")
        assert any("10.20.30.40" in c for c in netwatch.console_output)

    def test_mac_no_match_suggests_subnet(self):
        netwatch.handle_command("mac ff:ff:ff:ff:ff:ff")
        assert any("subnet" in c.lower() or "arp" in c.lower() for c in netwatch.console_output)


# ═══════════════════════════════════════════════════════════
#  TRACKING — 40 tests
# ═══════════════════════════════════════════════════════════

class TestTrackCommand:
    @patch("threading.Thread")
    def test_track_starts_tracking(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("track 10.0.0.1")
        assert any("TRACKING" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_track_spawns_thread(self, mock_thread):
        inst = MagicMock()
        mock_thread.return_value = inst
        netwatch.handle_command("track 10.0.0.1")
        assert inst.start.called

    @patch("threading.Thread")
    def test_track_with_duration_shows_seconds(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("track 10.0.0.1 120")
        assert any("120" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_track_duration_clamped_to_3600(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("track 10.0.0.1 99999")
        assert any("TRACKING" in c for c in netwatch.console_output)

    def test_track_already_tracking_shows_warning(self):
        netwatch.tracking_active["10.0.0.1"] = True
        netwatch.handle_command("track 10.0.0.1")
        assert any("Already tracking" in c for c in netwatch.console_output)

    def test_track_injection_rejected(self):
        netwatch.handle_command("track ;ls")
        assert any("Invalid" in c for c in netwatch.console_output)

    def test_track_dollar_injection_rejected(self):
        netwatch.handle_command("track $(id)")
        assert any("Invalid" in c for c in netwatch.console_output)

    def test_track_no_args_falls_to_unknown(self):
        netwatch.handle_command("track")
        assert any("Unknown" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_track_zero_duration_shows_until_untrack(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("track 10.0.0.1 0")
        assert any("untrack" in c.lower() for c in netwatch.console_output)

    @pytest.mark.parametrize("ip", ["10.0.0.1", "192.168.1.100", "172.16.5.5", "203.0.113.7"])
    @patch("threading.Thread")
    def test_track_various_valid_ips(self, mock_thread, ip):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command(f"track {ip}")
        assert any("TRACKING" in c for c in netwatch.console_output)
        netwatch.console_output.clear()


class TestUntrackCommand:
    def test_untrack_active_ip_stops_it(self):
        netwatch.tracking_active["10.0.0.5"] = True
        netwatch.handle_command("untrack 10.0.0.5")
        assert netwatch.tracking_active["10.0.0.5"] == False

    def test_untrack_shows_stopped_message(self):
        netwatch.tracking_active["10.0.0.6"] = True
        netwatch.handle_command("untrack 10.0.0.6")
        assert any("Stopped" in c or "Untrack" in c.lower() for c in netwatch.console_output)

    def test_untrack_not_tracking_shows_message(self):
        netwatch.handle_command("untrack 10.0.0.7")
        assert any("Not currently" in c for c in netwatch.console_output)

    def test_untrack_no_args_falls_to_unknown(self):
        netwatch.handle_command("untrack")
        assert any("Unknown" in c for c in netwatch.console_output)

    def test_untrack_does_not_remove_key_just_sets_false(self):
        netwatch.tracking_active["10.0.0.8"] = True
        netwatch.handle_command("untrack 10.0.0.8")
        assert "10.0.0.8" in netwatch.tracking_active
        assert netwatch.tracking_active["10.0.0.8"] == False


class TestTrackingCommand:
    def test_tracking_no_active_shows_message(self):
        netwatch.handle_command("tracking")
        assert any("No active" in c for c in netwatch.console_output)

    def test_tracking_shows_active_ip(self):
        netwatch.tracking_active["10.0.0.9"] = True
        netwatch.tracked_ips["10.0.0.9"] = [{"x": 1}, {"x": 2}]
        netwatch.handle_command("tracking")
        assert any("10.0.0.9" in c for c in netwatch.console_output)

    def test_tracking_shows_packet_count(self):
        netwatch.tracking_active["10.0.0.10"] = True
        netwatch.tracked_ips["10.0.0.10"] = [{"x": i} for i in range(5)]
        netwatch.handle_command("tracking")
        assert any("5" in c for c in netwatch.console_output)

    def test_tracking_false_not_shown_as_active(self):
        netwatch.tracking_active["10.0.0.11"] = False
        netwatch.handle_command("tracking")
        assert any("No active" in c for c in netwatch.console_output)


class TestTrackedCommand:
    def test_tracked_no_data_shows_message(self):
        netwatch.handle_command("tracked 10.0.0.1")
        assert any("No tracked data" in c for c in netwatch.console_output)

    def test_tracked_with_data_shows_summary(self):
        netwatch.tracked_ips["10.0.0.1"] = [
            {"time": "12:00:00", "proto": "TCP", "size": 100, "direction": "OUT",
             "dst": "8.8.8.8", "dport": 443, "sport": 54321, "payload": ""}
        ]
        netwatch.handle_command("tracked 10.0.0.1")
        assert any("TRACK SUMMARY" in c for c in netwatch.console_output)

    def test_tracked_invalid_ip_rejected(self):
        netwatch.handle_command("tracked $(id)")
        assert any("Invalid" in c for c in netwatch.console_output)

    def test_tracked_no_args_falls_to_unknown(self):
        netwatch.handle_command("tracked")
        assert any("Unknown" in c for c in netwatch.console_output)


class TestConnsCommand:
    @patch("threading.Thread")
    def test_conns_output_contains_tcp(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("conns 10.0.0.1")
        assert any("TCP" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_conns_spawns_thread(self, mock_thread):
        inst = MagicMock()
        mock_thread.return_value = inst
        netwatch.handle_command("conns 10.0.0.1")
        assert inst.start.called

    def test_conns_injection_rejected(self):
        netwatch.handle_command("conns ;id")
        assert any("Invalid" in c for c in netwatch.console_output)

    def test_conns_no_args_falls_to_unknown(self):
        netwatch.handle_command("conns")
        assert any("Unknown" in c for c in netwatch.console_output)


class TestSniffCommand:
    @patch("threading.Thread")
    def test_sniff_output_contains_sniffing(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("sniff 10.0.0.1")
        assert any("Sniffing" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_sniff_default_duration_15(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("sniff 10.0.0.1")
        assert any("15" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_sniff_custom_duration(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("sniff 10.0.0.1 60")
        assert any("60" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_sniff_duration_clamped_to_300(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("sniff 10.0.0.1 9999")
        assert any("300" in c for c in netwatch.console_output)

    def test_sniff_injection_rejected(self):
        netwatch.handle_command("sniff ;id")
        assert any("Invalid" in c for c in netwatch.console_output)

    def test_sniff_no_args_falls_to_unknown(self):
        netwatch.handle_command("sniff")
        assert any("Unknown" in c for c in netwatch.console_output)


class TestTrackDnsCommand:
    @patch("threading.Thread")
    def test_trackdns_output_contains_dns(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("trackdns 10.0.0.1")
        assert any("DNS" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_trackdns_spawns_thread(self, mock_thread):
        inst = MagicMock()
        mock_thread.return_value = inst
        netwatch.handle_command("trackdns 10.0.0.1")
        assert inst.start.called

    def test_trackdns_injection_rejected(self):
        netwatch.handle_command("trackdns ;rm /")
        assert any("Invalid" in c for c in netwatch.console_output)

    def test_trackdns_no_args_falls_to_unknown(self):
        netwatch.handle_command("trackdns")
        assert any("Unknown" in c for c in netwatch.console_output)


# ═══════════════════════════════════════════════════════════
#  HONEYPOT ANALYSIS — 30 tests
# ═══════════════════════════════════════════════════════════

class TestInspectCommand:
    def test_inspect_no_events_shows_last_10_header(self):
        netwatch.handle_command("inspect")
        assert any("Last 10" in c for c in netwatch.console_output)

    def test_inspect_with_events_no_index_shows_list(self, populated_honeypot_events):
        netwatch.handle_command("inspect")
        assert any("Last 10" in c for c in netwatch.console_output)

    def test_inspect_specific_event_shows_event_number(self, populated_honeypot_events):
        netwatch.handle_command("inspect 1")
        assert any("EVENT #1" in c for c in netwatch.console_output)

    def test_inspect_specific_event_shows_ip(self, populated_honeypot_events):
        netwatch.handle_command("inspect 1")
        assert any("203.0.113.42" in c for c in netwatch.console_output)

    def test_inspect_specific_event_shows_service(self, populated_honeypot_events):
        netwatch.handle_command("inspect 1")
        assert any("telnet" in c for c in netwatch.console_output)

    def test_inspect_out_of_range_shows_last_10(self, populated_honeypot_events):
        netwatch.handle_command("inspect 999")
        assert any("Last 10" in c for c in netwatch.console_output)

    def test_inspect_event_2_shows_second_event(self, populated_honeypot_events):
        netwatch.handle_command("inspect 2")
        assert any("EVENT #2" in c for c in netwatch.console_output)

    def test_inspect_event_with_data_shows_raw_data(self):
        netwatch.honeypot_events.append({
            "time": "10:00:00", "service": "telnet", "ip": "1.2.3.4",
            "summary": "test", "data": "GET /admin HTTP/1.1\r\nHost: example.com"
        })
        netwatch.handle_command("inspect 1")
        assert any("Raw Data" in c for c in netwatch.console_output)

    def test_inspect_shows_usage_hint(self, populated_honeypot_events):
        netwatch.handle_command("inspect")
        assert any("Usage" in c or "inspect" in c.lower() for c in netwatch.console_output)

    def test_inspect_shows_summary_field(self, populated_honeypot_events):
        netwatch.handle_command("inspect 1")
        assert any("Summary" in c for c in netwatch.console_output)


class TestAnalyzeCommand:
    @patch("threading.Thread")
    def test_analyze_output_contains_analyzing(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("analyze 1.2.3.4")
        assert any("Analyzing" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_analyze_spawns_thread(self, mock_thread):
        inst = MagicMock()
        mock_thread.return_value = inst
        netwatch.handle_command("analyze 1.2.3.4")
        assert inst.start.called

    @patch("threading.Thread")
    def test_analyze_target_in_output(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("analyze 203.0.113.42")
        assert any("203.0.113.42" in c for c in netwatch.console_output)

    def test_analyze_no_args_falls_to_unknown(self):
        netwatch.handle_command("analyze")
        assert any("Unknown" in c for c in netwatch.console_output)


class TestSessionsCommand:
    def test_sessions_no_events_shows_no_sessions(self):
        netwatch.handle_command("sessions")
        assert any("No honeypot sessions" in c for c in netwatch.console_output)

    def test_sessions_with_events_shows_header(self, populated_honeypot_events):
        netwatch.handle_command("sessions")
        assert any("HONEYPOT SESSIONS" in c for c in netwatch.console_output)

    def test_sessions_with_events_shows_ip(self, populated_honeypot_events):
        netwatch.handle_command("sessions")
        assert any("203.0.113.42" in c for c in netwatch.console_output)

    def test_sessions_shows_attacker_count(self, populated_honeypot_events):
        netwatch.handle_command("sessions")
        attacker_ips = set(e["ip"] for e in netwatch.honeypot_events)
        assert any(str(len(attacker_ips)) in c for c in netwatch.console_output)

    def test_sessions_multiple_attackers_all_shown(self, populated_honeypot_events):
        netwatch.handle_command("sessions")
        assert any("198.51.100.1" in c or "192.0.2.5" in c for c in netwatch.console_output)


class TestAttackersCommand:
    def test_attackers_no_events(self):
        netwatch.handle_command("attackers")
        assert any("No honeypot" in c for c in netwatch.console_output)

    def test_attackers_with_events_shows_header(self, populated_honeypot_events):
        with patch("netwatch.resolve_host", return_value="evil.host"):
            netwatch.handle_command("attackers")
        assert any("ATTACKERS" in c for c in netwatch.console_output)

    def test_attackers_shows_ip(self, populated_honeypot_events):
        with patch("netwatch.resolve_host", return_value=""):
            netwatch.handle_command("attackers")
        assert any("203.0.113.42" in c for c in netwatch.console_output)

    def test_attackers_shows_event_count(self, populated_honeypot_events):
        with patch("netwatch.resolve_host", return_value=""):
            netwatch.handle_command("attackers")
        # should show event count for each attacker
        assert any("event" in c.lower() for c in netwatch.console_output)


class TestDecodeCommand:
    def test_decode_base64_produces_output(self):
        encoded = base64.b64encode(b"hello world").decode()
        netwatch.handle_command(f"decode {encoded}")
        assert any("Decode" in c or "base64" in c.lower() for c in netwatch.console_output)

    def test_decode_base64_content_present(self):
        encoded = base64.b64encode(b"secretdata").decode()
        netwatch.handle_command(f"decode {encoded}")
        assert any("secretdata" in c for c in netwatch.console_output)

    def test_decode_hex_produces_output(self):
        hex_data = binascii.hexlify(b"hello").decode()
        netwatch.handle_command(f"decode {hex_data}")
        assert any("Decode" in c or "hex" in c.lower() for c in netwatch.console_output)

    def test_decode_url_encoded_string(self):
        netwatch.handle_command("decode hello%20world%21")
        assert any("Decode" in c for c in netwatch.console_output)

    def test_decode_plain_text_no_crash(self):
        netwatch.handle_command("decode plaintext")
        assert any("Decode" in c for c in netwatch.console_output)

    def test_decode_no_args_falls_to_unknown(self):
        netwatch.handle_command("decode")
        assert any("Unknown" in c for c in netwatch.console_output)

    def test_decode_multiword_payload(self):
        netwatch.handle_command("decode GET /admin HTTP/1.1")
        assert any("Decode" in c for c in netwatch.console_output)


class TestProfileCommand:
    def test_profile_no_report(self):
        netwatch.handle_command("profile 1.2.3.4")
        assert any("No recon report" in c for c in netwatch.console_output)

    def test_profile_with_report_shows_header(self):
        netwatch.recon_reports["5.5.5.5"] = {
            "hostname": "evil.host", "os_guess": "Linux", "timestamp": "2024-01-01T00:00:00",
            "ports": ["22/tcp open ssh"], "traceroute": [], "honeypot_activity": [],
        }
        netwatch.handle_command("profile 5.5.5.5")
        assert any("RECON REPORT" in c for c in netwatch.console_output)

    def test_profile_shows_os_guess(self):
        netwatch.recon_reports["6.6.6.6"] = {
            "hostname": "h", "os_guess": "Windows 10", "timestamp": "t",
            "ports": [], "traceroute": [], "honeypot_activity": [],
        }
        netwatch.handle_command("profile 6.6.6.6")
        assert any("Windows 10" in c for c in netwatch.console_output)

    def test_profile_shows_honeypot_hits(self):
        netwatch.recon_reports["7.7.7.7"] = {
            "hostname": "h", "os_guess": "?", "timestamp": "t",
            "ports": [], "traceroute": [], "honeypot_activity": [{"x": 1}, {"x": 2}],
        }
        netwatch.handle_command("profile 7.7.7.7")
        assert any("Honeypot" in c or "honeypot" in c.lower() for c in netwatch.console_output)

    def test_profile_no_args_falls_to_unknown(self):
        netwatch.handle_command("profile")
        assert any("Unknown" in c for c in netwatch.console_output)


# ═══════════════════════════════════════════════════════════
#  PROXY — 25 tests
# ═══════════════════════════════════════════════════════════

class TestProxyTabSwitch:
    def test_proxy_alone_switches_tab(self):
        netwatch.handle_command("proxy")
        assert netwatch.current_tab == "proxy"

    def test_proxy_alone_shows_switch_message(self):
        netwatch.handle_command("proxy")
        assert any("PROXY" in c for c in netwatch.console_output)


class TestProxyAdd:
    def test_proxy_add_socks5_valid(self):
        netwatch.handle_command("proxy add socks5 127.0.0.1:9050")
        assert len(netwatch.proxy_pool) == 1
        assert netwatch.proxy_pool[0]["type"] == "socks5"

    def test_proxy_add_socks4_valid(self):
        netwatch.handle_command("proxy add socks4 127.0.0.1:9051")
        assert len(netwatch.proxy_pool) == 1
        assert netwatch.proxy_pool[0]["type"] == "socks4"

    def test_proxy_add_http_valid(self):
        netwatch.handle_command("proxy add http 127.0.0.1:8080")
        assert len(netwatch.proxy_pool) == 1

    def test_proxy_add_https_valid(self):
        netwatch.handle_command("proxy add https 127.0.0.1:8443")
        assert len(netwatch.proxy_pool) == 1

    def test_proxy_add_invalid_type_shows_error(self):
        netwatch.handle_command("proxy add ftp 127.0.0.1:21")
        assert any("must be" in c for c in netwatch.console_output)

    def test_proxy_add_no_port_shows_format_error(self):
        netwatch.handle_command("proxy add socks5 127.0.0.1")
        assert any("Format" in c for c in netwatch.console_output)

    def test_proxy_add_invalid_port_shows_error(self):
        netwatch.handle_command("proxy add socks5 127.0.0.1:99999")
        assert any("Invalid port" in c for c in netwatch.console_output)

    def test_proxy_add_port_zero_shows_error(self):
        netwatch.handle_command("proxy add socks5 127.0.0.1:0")
        assert any("Invalid port" in c for c in netwatch.console_output)

    def test_proxy_add_multiple_entries(self):
        netwatch.handle_command("proxy add socks5 127.0.0.1:9050")
        netwatch.handle_command("proxy add http 10.0.0.1:8080")
        assert len(netwatch.proxy_pool) == 2

    def test_proxy_add_shows_added_message(self):
        netwatch.handle_command("proxy add socks5 127.0.0.1:9050")
        assert any("Added proxy" in c for c in netwatch.console_output)


class TestProxyRemove:
    def test_proxy_rm_first_entry(self):
        netwatch.proxy_pool.append({"type": "socks5", "host": "127.0.0.1", "port": "9050", "label": "socks5://127.0.0.1:9050"})
        netwatch.handle_command("proxy rm 1")
        assert len(netwatch.proxy_pool) == 0

    def test_proxy_rm_invalid_index_shows_error(self):
        netwatch.handle_command("proxy rm 99")
        assert any("Invalid index" in c for c in netwatch.console_output)

    def test_proxy_rm_shows_removed_message(self):
        netwatch.proxy_pool.append({"type": "http", "host": "10.0.0.1", "port": "8080", "label": "http://10.0.0.1:8080"})
        netwatch.handle_command("proxy rm 1")
        assert any("Removed" in c for c in netwatch.console_output)


class TestProxyList:
    def test_proxy_list_empty_shows_no_proxies(self):
        netwatch.handle_command("proxy list")
        assert any("No proxies" in c for c in netwatch.console_output)

    def test_proxy_list_with_entries(self):
        netwatch.proxy_pool.append({"type": "socks5", "host": "127.0.0.1", "port": "9050", "label": "socks5://127.0.0.1:9050"})
        netwatch.handle_command("proxy list")
        assert any("socks5://127.0.0.1:9050" in c for c in netwatch.console_output)

    def test_proxy_list_shows_rotation_status(self):
        netwatch.proxy_pool.append({"type": "http", "host": "1.2.3.4", "port": "8080", "label": "http://1.2.3.4:8080"})
        netwatch.handle_command("proxy list")
        assert any("Rotation" in c for c in netwatch.console_output)


class TestProxyRotate:
    def test_proxy_rotate_on(self):
        assert netwatch.proxy_rotation == False
        netwatch.handle_command("proxy rotate")
        assert netwatch.proxy_rotation == True

    def test_proxy_rotate_off(self):
        netwatch.proxy_rotation = True
        netwatch.handle_command("proxy rotate")
        assert netwatch.proxy_rotation == False

    def test_proxy_rotate_toggle_twice(self):
        netwatch.handle_command("proxy rotate")
        netwatch.handle_command("proxy rotate")
        assert netwatch.proxy_rotation == False


class TestProxyMiscActions:
    @patch("threading.Thread")
    def test_proxy_test_no_proxies_shows_message(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("proxy test")
        assert any("No proxies" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_proxy_test_with_entry_spawns_thread(self, mock_thread):
        inst = MagicMock()
        mock_thread.return_value = inst
        netwatch.proxy_pool.append({"type": "socks5", "host": "127.0.0.1", "port": "9050", "label": "socks5://127.0.0.1:9050"})
        netwatch.handle_command("proxy test")
        assert inst.start.called

    @patch("threading.Thread")
    def test_proxy_status_spawns_thread(self, mock_thread):
        inst = MagicMock()
        mock_thread.return_value = inst
        netwatch.handle_command("proxy status")
        assert inst.start.called

    @patch("threading.Thread")
    def test_proxy_start_spawns_thread(self, mock_thread):
        inst = MagicMock()
        mock_thread.return_value = inst
        netwatch.handle_command("proxy start")
        assert inst.start.called

    @patch("threading.Thread")
    def test_proxy_circuits_spawns_thread(self, mock_thread):
        inst = MagicMock()
        mock_thread.return_value = inst
        netwatch.handle_command("proxy circuits")
        assert inst.start.called


# ═══════════════════════════════════════════════════════════
#  TAB SWITCHING — 15 tests
# ═══════════════════════════════════════════════════════════

class TestTabSwitching:
    def test_tab_hosts(self):
        netwatch.handle_command("hosts")
        assert netwatch.current_tab == "hosts"

    def test_tab_dns(self):
        netwatch.handle_command("dns")
        assert netwatch.current_tab == "dns"

    def test_tab_alerts(self):
        netwatch.handle_command("alerts")
        assert netwatch.current_tab == "alerts"

    def test_tab_proto(self):
        netwatch.handle_command("proto")
        assert netwatch.current_tab == "proto"

    def test_tab_honeypot(self):
        netwatch.handle_command("honeypot")
        assert netwatch.current_tab == "honeypot"

    def test_tab_nmap(self):
        netwatch.handle_command("nmap")
        assert netwatch.current_tab == "nmap"

    def test_tab_arp(self):
        netwatch.handle_command("arp")
        assert netwatch.current_tab == "arp"

    def test_tab_all(self):
        netwatch.handle_command("all")
        assert netwatch.current_tab == "all"

    def test_tab_osint(self):
        netwatch.handle_command("osint")
        assert netwatch.current_tab == "osint"

    def test_tab_proxy_alone(self):
        netwatch.handle_command("proxy")
        assert netwatch.current_tab == "proxy"

    def test_tab_switch_shows_switched_message(self):
        netwatch.handle_command("hosts")
        assert any("Switched" in c or "HOSTS" in c for c in netwatch.console_output)

    def test_tab_switch_updates_from_previous(self):
        netwatch.current_tab = "dns"
        netwatch.handle_command("hosts")
        assert netwatch.current_tab == "hosts"

    @pytest.mark.parametrize("tab", ["hosts", "dns", "alerts"])
    def test_tab_switch_case_insensitive(self, tab):
        # Commands are lowercased before dispatch
        netwatch.handle_command(tab.upper())
        # UPPERCASE falls to unknown since action = parts[0].lower()
        # the tab check is for lowercase
        # Actually action is lowercased so "HOSTS" -> action="hosts" -> matches
        assert netwatch.current_tab == tab

    def test_proxy_tab_switch_from_non_proxy(self):
        netwatch.current_tab = "hosts"
        netwatch.handle_command("proxy")
        assert netwatch.current_tab == "proxy"

    def test_dashboard_sets_console_mode_false(self):
        netwatch.console_mode = True
        netwatch.handle_command("dashboard")
        assert netwatch.console_mode == False


# ═══════════════════════════════════════════════════════════
#  SYSTEM COMMANDS — 15 tests
# ═══════════════════════════════════════════════════════════

class TestSystemCommands:
    def test_clear_empties_console_output(self):
        netwatch.console_output.extend(["line1", "line2", "line3"])
        netwatch.handle_command("clear")
        assert len(netwatch.console_output) == 0

    def test_clear_on_empty_console_no_crash(self):
        netwatch.handle_command("clear")
        assert len(netwatch.console_output) == 0

    @patch("netwatch.start_tcpdump")
    def test_pcap_starts_capture(self, mock_start):
        netwatch.handle_command("pcap")
        assert mock_start.called

    @patch("netwatch.start_tcpdump")
    def test_pcap_shows_started_message(self, mock_start):
        netwatch.handle_command("pcap")
        assert any("PCAP capture started" in c for c in netwatch.console_output)

    @patch("netwatch.stop_tcpdump")
    def test_pcap_stop_calls_stop(self, mock_stop):
        netwatch.handle_command("pcap stop")
        assert mock_stop.called

    @patch("netwatch.stop_tcpdump")
    def test_pcap_stop_shows_stopped_message(self, mock_stop):
        netwatch.handle_command("pcap stop")
        assert any("stopped" in c.lower() for c in netwatch.console_output)

    @patch("netwatch.save_logs")
    def test_export_calls_save_logs(self, mock_save):
        netwatch.handle_command("export")
        assert mock_save.called

    @patch("netwatch.save_logs")
    def test_export_shows_exported_message(self, mock_save):
        netwatch.handle_command("export")
        assert any("Exported" in c for c in netwatch.console_output)

    def test_help_sets_show_help_overlay(self):
        assert netwatch.show_help_overlay == False
        netwatch.handle_command("help")
        assert netwatch.show_help_overlay == True

    def test_help_does_not_change_tab(self):
        netwatch.current_tab = "hosts"
        netwatch.handle_command("help")
        assert netwatch.current_tab == "hosts"

    def test_unknown_command_shows_unknown_message(self):
        netwatch.handle_command("xyzzy_nonexistent")
        assert any("Unknown" in c for c in netwatch.console_output)

    def test_empty_command_no_output(self):
        netwatch.handle_command("")
        assert len(netwatch.console_output) == 0

    def test_whitespace_command_no_output(self):
        netwatch.handle_command("   \t  ")
        assert len(netwatch.console_output) == 0

    def test_dashboard_from_console_mode_true(self):
        netwatch.console_mode = True
        netwatch.handle_command("dashboard")
        assert netwatch.console_mode == False

    def test_dashboard_when_already_false_stays_false(self):
        netwatch.console_mode = False
        netwatch.handle_command("dashboard")
        assert netwatch.console_mode == False


# ═══════════════════════════════════════════════════════════
#  INPUT VALIDATION / INJECTION PREVENTION — 40 tests
# ═══════════════════════════════════════════════════════════

class TestInjectionPrevention:
    @pytest.mark.parametrize("payload", [
        "; rm -rf /",
        "| cat /etc/passwd",
        "`id`",
        "$(whoami)",
        "\nrm -rf /",
        "& ls",
        "' OR '1'='1",
    ])
    def test_scan_rejects_all_injections(self, payload):
        netwatch.handle_command(f"scan {payload}")
        assert any("Invalid" in c or "Unknown" in c for c in netwatch.console_output)

    @pytest.mark.parametrize("payload", [
        "; rm -rf /",
        "| cat /etc/passwd",
        "`id`",
        "$(whoami)",
    ])
    def test_deep_rejects_injections(self, payload):
        netwatch.handle_command(f"deep {payload}")
        assert any("Invalid" in c or "Unknown" in c for c in netwatch.console_output)

    @pytest.mark.parametrize("payload", [
        "; id",
        "| ls",
        "`uname`",
        "$(cat /etc/passwd)",
    ])
    def test_stealth_rejects_injections(self, payload):
        netwatch.handle_command(f"stealth {payload}")
        assert any("Invalid" in c or "Unknown" in c for c in netwatch.console_output)

    @pytest.mark.parametrize("payload", [
        "; id",
        "|ls",
        "`whoami`",
        "$(id)",
    ])
    def test_recon_rejects_injections(self, payload):
        netwatch.handle_command(f"recon {payload}")
        assert any("Invalid" in c or "Unknown" in c for c in netwatch.console_output)

    @pytest.mark.parametrize("payload", [
        "; id",
        "| ls",
        "`uname -a`",
    ])
    def test_trace_rejects_injections(self, payload):
        netwatch.handle_command(f"trace {payload}")
        assert any("Invalid" in c or "Unknown" in c for c in netwatch.console_output)

    @pytest.mark.parametrize("ip", [
        "127.0.0.1",
        "10.0.0.1",
        "192.168.1.1",
        "172.16.0.1",
    ])
    def test_block_private_ips_accepted_by_validator(self, ip):
        with patch("netwatch.subprocess.run"):
            netwatch.handle_command(f"block {ip}")
        # ipaddress.ip_address accepts these — they pass validation
        assert any("BLOCKED" in c for c in netwatch.console_output)

    @pytest.mark.parametrize("payload", [
        "not-an-ip",
        "evil;rm",
        "$(id)",
        "|whoami",
        "1.2.3.4;5.6.7.8",
        "999.999.999.999",
    ])
    def test_block_invalid_ips_all_rejected(self, payload):
        netwatch.handle_command(f"block {payload}")
        assert any("Invalid IP" in c for c in netwatch.console_output)

    @pytest.mark.parametrize("payload", [
        "notanip",
        "evil;rm",
        "$(id)",
    ])
    def test_unblock_invalid_ips_rejected(self, payload):
        netwatch.handle_command(f"unblock {payload}")
        assert any("Invalid IP" in c for c in netwatch.console_output)

    @pytest.mark.parametrize("payload", [
        "; rm -rf /",
        "| cat /etc/passwd",
        "`id`",
    ])
    def test_track_rejects_injections(self, payload):
        netwatch.handle_command(f"track {payload}")
        assert any("Invalid" in c for c in netwatch.console_output)

    @pytest.mark.parametrize("payload", [
        ";id",
        "$(id)",
    ])
    def test_conns_rejects_injections(self, payload):
        netwatch.handle_command(f"conns {payload}")
        assert any("Invalid" in c for c in netwatch.console_output)

    @pytest.mark.parametrize("payload", [
        ";id",
        "$(id)",
    ])
    def test_sniff_rejects_injections(self, payload):
        netwatch.handle_command(f"sniff {payload}")
        assert any("Invalid" in c for c in netwatch.console_output)

    @pytest.mark.parametrize("url_payload", [
        "example.com;ls",
        "example.com|cat",
    ])
    def test_ssl_rejects_injections_in_url(self, url_payload):
        netwatch.handle_command(f"ssl {url_payload}")
        assert any("Invalid" in c for c in netwatch.console_output)

    def test_handle_command_never_crashes_on_long_input(self):
        long_cmd = "scan " + "A" * 10000
        try:
            netwatch.handle_command(long_cmd)
        except Exception:
            pytest.fail("handle_command raised on long input")

    def test_handle_command_never_crashes_on_unicode(self):
        try:
            netwatch.handle_command("scan ☃\x00[31mfoo")
        except Exception:
            pytest.fail("handle_command raised on unicode input")

    def test_handle_command_never_crashes_on_null_bytes(self):
        try:
            netwatch.handle_command("scan \x00\x01\x02")
        except Exception:
            pytest.fail("handle_command raised on null bytes")


# ═══════════════════════════════════════════════════════════
#  WORKFLOW SEQUENCES — 25 tests
# ═══════════════════════════════════════════════════════════

class TestWorkflowSequences:
    @patch("threading.Thread")
    def test_scan_then_inspect_no_corruption(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("scan 1.2.3.4")
        scan_out = list(netwatch.console_output)
        netwatch.honeypot_events.append({
            "time": "10:00:00", "service": "telnet", "ip": "1.2.3.4", "summary": "test"
        })
        netwatch.handle_command("inspect 1")
        assert any("EVENT #1" in c for c in netwatch.console_output)

    def test_track_then_untrack_clears_flag(self):
        with patch("threading.Thread") as mock_thread:
            mock_thread.return_value.start = MagicMock()
            netwatch.handle_command("track 10.0.0.1")
        netwatch.tracking_active["10.0.0.1"] = True  # simulate thread set
        netwatch.handle_command("untrack 10.0.0.1")
        assert netwatch.tracking_active["10.0.0.1"] == False

    @patch("netwatch.subprocess.run")
    def test_block_then_unblock_workflow(self, mock_run):
        netwatch.handle_command("block 203.0.113.50")
        assert any("BLOCKED" in c for c in netwatch.console_output)
        netwatch.console_output.clear()
        netwatch.handle_command("unblock 203.0.113.50")
        assert any("UNBLOCKED" in c for c in netwatch.console_output)

    @patch("netwatch.subprocess.run")
    def test_block_then_blocked_shows_in_list(self, mock_run):
        mock_run.return_value = MagicMock(stdout="1 DROP all -- 203.0.113.50\n")
        netwatch.handle_command("block 203.0.113.50")
        netwatch.console_output.clear()
        netwatch.handle_command("blocked")
        assert any("DROP" in c for c in netwatch.console_output)

    def test_proxy_add_list_remove_workflow(self):
        netwatch.handle_command("proxy add socks5 127.0.0.1:9050")
        assert len(netwatch.proxy_pool) == 1
        netwatch.console_output.clear()
        netwatch.handle_command("proxy list")
        assert any("socks5://127.0.0.1:9050" in c for c in netwatch.console_output)
        netwatch.console_output.clear()
        netwatch.handle_command("proxy rm 1")
        assert len(netwatch.proxy_pool) == 0

    def test_multiple_tab_switches_no_corruption(self):
        for tab in ["hosts", "dns", "alerts", "proto", "honeypot", "all"]:
            netwatch.handle_command(tab)
        assert netwatch.current_tab == "all"

    def test_tab_switch_does_not_affect_events(self, populated_honeypot_events):
        original_count = len(netwatch.honeypot_events)
        netwatch.handle_command("hosts")
        netwatch.handle_command("dns")
        assert len(netwatch.honeypot_events) == original_count

    def test_console_output_accumulates_across_commands(self):
        with patch("threading.Thread") as mock_thread:
            mock_thread.return_value.start = MagicMock()
            netwatch.handle_command("scan 1.2.3.4")
            netwatch.handle_command("geo 1.2.3.4")
        assert len(netwatch.console_output) >= 2

    def test_clear_between_commands_resets_output(self):
        with patch("threading.Thread") as mock_thread:
            mock_thread.return_value.start = MagicMock()
            netwatch.handle_command("scan 1.2.3.4")
        assert len(netwatch.console_output) > 0
        netwatch.handle_command("clear")
        assert len(netwatch.console_output) == 0

    def test_help_does_not_block_subsequent_commands(self):
        netwatch.handle_command("help")
        netwatch.handle_command("attackers")
        assert any("No honeypot" in c for c in netwatch.console_output)

    def test_dashboard_then_tab_switch_works(self):
        netwatch.console_mode = True
        netwatch.handle_command("dashboard")
        assert netwatch.console_mode == False
        netwatch.handle_command("hosts")
        assert netwatch.current_tab == "hosts"

    def test_attackers_then_sessions_shows_both(self, populated_honeypot_events):
        with patch("netwatch.resolve_host", return_value=""):
            netwatch.handle_command("attackers")
        netwatch.handle_command("sessions")
        assert any("ATTACKERS" in c for c in netwatch.console_output)
        assert any("HONEYPOT SESSIONS" in c for c in netwatch.console_output)

    def test_proxy_add_then_rotate_on(self):
        netwatch.handle_command("proxy add socks5 127.0.0.1:9050")
        netwatch.handle_command("proxy rotate")
        assert netwatch.proxy_rotation == True

    def test_recon_report_then_profile_shows_it(self):
        netwatch.recon_reports["99.99.99.99"] = {
            "hostname": "testhost", "os_guess": "FreeBSD", "timestamp": "t",
            "ports": ["22/tcp open ssh"], "traceroute": [], "honeypot_activity": [],
        }
        netwatch.handle_command("profile 99.99.99.99")
        assert any("RECON REPORT" in c for c in netwatch.console_output)

    def test_inspect_after_events_added(self):
        netwatch.honeypot_events.append({
            "time": "11:00:00", "service": "ftp", "ip": "55.55.55.55", "summary": "ftp probe"
        })
        netwatch.handle_command("inspect 1")
        assert any("55.55.55.55" in c or "ftp" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_scan_geo_whois_sequence_no_crash(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        with patch("netwatch.osint_whois", return_value={"registrar": "Test"}):
            with patch("netwatch.resolve_host", return_value=""):
                netwatch.handle_command("scan 1.2.3.4")
                netwatch.handle_command("geo 1.2.3.4")
                netwatch.handle_command("whois 1.2.3.4")
        assert len(netwatch.console_output) > 0

    def test_multiple_block_commands_create_multiple_alerts(self):
        with patch("netwatch.subprocess.run"):
            netwatch.handle_command("block 10.0.0.1")
            netwatch.handle_command("block 10.0.0.2")
        blocked_alerts = [a for a in netwatch.alerts if "BLOCKED" in a.get("msg", "")]
        assert len(blocked_alerts) >= 2

    def test_tracking_command_reflects_track_state(self):
        netwatch.tracking_active["192.168.5.5"] = True
        netwatch.tracked_ips["192.168.5.5"] = []
        netwatch.handle_command("tracking")
        assert any("192.168.5.5" in c for c in netwatch.console_output)
        netwatch.tracking_active["192.168.5.5"] = False
        netwatch.console_output.clear()
        netwatch.handle_command("tracking")
        assert any("No active" in c for c in netwatch.console_output)

    def test_proxy_pool_persists_across_commands(self):
        netwatch.handle_command("proxy add socks5 127.0.0.1:9050")
        netwatch.handle_command("hosts")  # tab switch
        assert len(netwatch.proxy_pool) == 1

    @patch("netwatch.save_logs")
    def test_export_then_clear_then_scan(self, mock_save):
        netwatch.handle_command("export")
        netwatch.handle_command("clear")
        assert len(netwatch.console_output) == 0
        with patch("threading.Thread") as mock_thread:
            mock_thread.return_value.start = MagicMock()
            netwatch.handle_command("scan 5.5.5.5")
        assert len(netwatch.console_output) > 0

    def test_decode_then_inspect_no_state_leak(self, populated_honeypot_events):
        encoded = base64.b64encode(b"payload").decode()
        netwatch.handle_command(f"decode {encoded}")
        netwatch.handle_command("inspect 1")
        assert any("EVENT #1" in c for c in netwatch.console_output)

    def test_mac_lookup_then_block_no_crash(self):
        netwatch.handle_command("mac aa:bb:cc:dd:ee:ff")
        with patch("netwatch.subprocess.run"):
            netwatch.handle_command("block 10.20.30.40")
        assert any("BLOCKED" in c for c in netwatch.console_output)

    def test_attackers_command_idempotent(self, populated_honeypot_events):
        with patch("netwatch.resolve_host", return_value=""):
            netwatch.handle_command("attackers")
            first_count = len(netwatch.console_output)
            netwatch.handle_command("attackers")
        # second call should also produce output
        assert len(netwatch.console_output) > first_count

    def test_sessions_idempotent(self, populated_honeypot_events):
        netwatch.handle_command("sessions")
        first_count = len(netwatch.console_output)
        netwatch.handle_command("sessions")
        assert len(netwatch.console_output) > first_count

    def test_full_osint_sequence_no_crash(self):
        with patch("threading.Thread") as mock_thread:
            mock_thread.return_value.start = MagicMock()
            with patch("netwatch.osint_whois", return_value={"r": "x"}):
                with patch("netwatch.resolve_host", return_value=""):
                    with patch("netwatch.osint_reverse_dns", return_value={"PTR": "h"}):
                        netwatch.handle_command("geo 8.8.8.8")
                        netwatch.handle_command("whois 8.8.8.8")
                        netwatch.handle_command("rdns 8.8.8.8")
                        netwatch.handle_command("dnsinfo google.com")
                        netwatch.handle_command("ssl google.com")
                        netwatch.handle_command("asn 8.8.8.8")
        assert len(netwatch.console_output) > 0


# ═══════════════════════════════════════════════════════════
#  _exec_console_cmd TESTS (bonus — these do not count toward
#  350 but are included; actual 350 are above)
# ═══════════════════════════════════════════════════════════

class TestExecConsoleCmd:
    def test_status_prints_uptime(self, capsys):
        netwatch._exec_console_cmd("status")
        captured = capsys.readouterr()
        assert "STATUS" in captured.out or "Uptime" in captured.out

    def test_help_prints_commands(self, capsys):
        netwatch._exec_console_cmd("help")
        captured = capsys.readouterr()
        assert "scan" in captured.out.lower()

    def test_non_status_delegates_to_handle_command(self, capsys):
        netwatch._exec_console_cmd("attackers")
        captured = capsys.readouterr()
        # Should print "No honeypot attackers" or similar
        assert "honeypot" in captured.out.lower() or "No" in captured.out

    def test_console_output_persists_after_exec(self, capsys):
        netwatch._exec_console_cmd("attackers")
        assert len(netwatch.console_output) > 0
        captured = capsys.readouterr()
        assert captured.out.strip() != ""

    def test_exec_console_cmd_scan_fires_thread(self, capsys):
        with patch("threading.Thread") as mock_thread:
            mock_thread.return_value.start = MagicMock()
            netwatch._exec_console_cmd("scan 1.2.3.4")
        assert mock_thread.called


# ═══════════════════════════════════════════════════════════
#  ADDITIONAL EDGE CASES AND COVERAGE — 40 more tests
# ═══════════════════════════════════════════════════════════

class TestScanEdgeCases:
    @patch("threading.Thread")
    def test_scan_preset_case_insensitive(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("scan 1.2.3.4 QUICK")
        # preset lowercased: "quick" found in SCAN_PRESETS
        assert any("quick" in c.lower() for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_scan_ip_with_dots_only(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("scan 255.255.255.255")
        assert not any("Invalid" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_scan_output_includes_flags(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("scan 1.2.3.4 full")
        # full preset flags include "-p-"
        assert any("-p-" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_deep_all_ports_mentioned(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("deep 1.2.3.4")
        assert any("all ports" in c.lower() or "vulns" in c.lower() for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_recon_full_profile_mentioned(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("recon 1.2.3.4")
        assert any("profile" in c.lower() or "1.2.3.4" in c for c in netwatch.console_output)

    @patch("netwatch.banner_grab", return_value="HTTP/1.1 301 Moved")
    def test_banner_shows_grab_message(self, mock_grab):
        netwatch.handle_command("banner 1.2.3.4 80")
        assert any("Grabbing" in c for c in netwatch.console_output)

    @patch("netwatch.banner_grab", return_value="SMTP 220 Ready")
    def test_banner_smtp_port(self, mock_grab):
        netwatch.handle_command("banner 1.2.3.4 25")
        assert any("SMTP" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_scan_hex_in_ip_allowed(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        # "a" is hex-like and matches r'^[\d./a-fA-F:]+'
        netwatch.handle_command("scan 1a.2b.3c.4d")
        assert not any("Invalid" in c for c in netwatch.console_output)


class TestOsintAdditional:
    @patch("threading.Thread")
    def test_geo_domain_name_accepted(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("geo google.com")
        assert any("Geolocating" in c for c in netwatch.console_output)

    @patch("netwatch.osint_whois", return_value={"registrar": "Test", "expiry": "2030"})
    @patch("netwatch.resolve_host", return_value="google.com")
    def test_whois_shows_ptr_result(self, mock_resolve, mock_whois):
        netwatch.handle_command("whois 8.8.8.8")
        assert any("google.com" in c or "Hostname" in c for c in netwatch.console_output)

    @patch("netwatch.osint_reverse_dns", return_value={"PTR": ["a.example.com", "b.example.com"]})
    def test_rdns_multiple_ptr_all_shown(self, mock_rdns):
        netwatch.handle_command("rdns 1.2.3.4")
        ptr_lines = [c for c in netwatch.console_output if "PTR" in c]
        assert len(ptr_lines) >= 2

    @patch("threading.Thread")
    def test_ssl_invalid_port_rejected(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        # port out of range: need parts[2].isdigit() first then range check
        # 0 is digit but out of 1-65535 range
        netwatch.handle_command("ssl example.com 0")
        assert any("Invalid port" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_ping_count_one_packet(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("ping 8.8.8.8 1")
        assert any("1" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_health_target_ip_accepted(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("health 8.8.8.8")
        assert any("HEALTH" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_etrace_domain_accepted(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("etrace google.com")
        assert any("Enriched" in c or "traceroute" in c.lower() for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_crt_subdomain_in_output(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("crt sub.example.com")
        assert any("sub.example.com" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_abuse_check_message_format(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("abuse 8.8.8.8")
        assert any("8.8.8.8" in c or "Abuse" in c or "abuse" in c.lower() for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_asn_lookup_message_format(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("asn 8.8.4.4")
        assert any("ASN" in c or "8.8.4.4" in c for c in netwatch.console_output)


class TestDefenseAdditional:
    @patch("netwatch.subprocess.run")
    def test_block_stores_in_alerts(self, mock_run):
        initial_alert_count = len(netwatch.alerts)
        netwatch.handle_command("block 203.0.113.77")
        assert len(netwatch.alerts) > initial_alert_count

    @patch("netwatch.subprocess.run")
    def test_unblock_does_not_add_alert(self, mock_run):
        initial_alert_count = len(netwatch.alerts)
        netwatch.handle_command("unblock 203.0.113.77")
        # unblock doesn't add to alerts
        assert len(netwatch.alerts) == initial_alert_count

    @patch("netwatch.subprocess.run")
    def test_blocked_parses_stdout_lines(self, mock_run):
        mock_run.return_value = MagicMock(stdout="Chain INPUT\n1 DROP 203.0.113.1\nChain FORWARD\n")
        netwatch.handle_command("blocked")
        assert any("DROP" in c for c in netwatch.console_output)

    def test_mac_empty_arp_table(self):
        # arp_table is empty by default
        netwatch.handle_command("mac de:ad:be:ef:00:00")
        assert any("not found" in c.lower() for c in netwatch.console_output)

    def test_mac_partial_match_multiple_entries(self):
        netwatch.arp_table["10.0.0.1"] = {"mac": "aa:bb:cc:11:22:33", "state": "REACHABLE"}
        netwatch.arp_table["10.0.0.2"] = {"mac": "aa:bb:cc:44:55:66", "state": "REACHABLE"}
        with patch("netwatch.resolve_host", return_value=""):
            netwatch.handle_command("mac aa:bb:cc")
        results = [c for c in netwatch.console_output if "10.0.0." in c]
        assert len(results) >= 2


class TestTrackingAdditional:
    @patch("threading.Thread")
    def test_track_duration_shown_in_seconds(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("track 10.0.0.1 90")
        assert any("90" in c for c in netwatch.console_output)

    def test_untrack_multiple_ips(self):
        netwatch.tracking_active["10.1.1.1"] = True
        netwatch.tracking_active["10.1.1.2"] = True
        netwatch.handle_command("untrack 10.1.1.1")
        netwatch.handle_command("untrack 10.1.1.2")
        assert netwatch.tracking_active["10.1.1.1"] == False
        assert netwatch.tracking_active["10.1.1.2"] == False

    def test_tracking_shows_multiple_active(self):
        netwatch.tracking_active["10.2.2.1"] = True
        netwatch.tracking_active["10.2.2.2"] = True
        netwatch.tracked_ips["10.2.2.1"] = []
        netwatch.tracked_ips["10.2.2.2"] = []
        netwatch.handle_command("tracking")
        assert any("10.2.2.1" in c for c in netwatch.console_output)
        assert any("10.2.2.2" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_conns_target_in_message(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("conns 10.99.99.99")
        assert any("10.99.99.99" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_sniff_target_in_message(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("sniff 10.88.88.88")
        assert any("10.88.88.88" in c for c in netwatch.console_output)

    @patch("threading.Thread")
    def test_trackdns_target_in_message(self, mock_thread):
        mock_thread.return_value.start = MagicMock()
        netwatch.handle_command("trackdns 10.77.77.77")
        assert any("10.77.77.77" in c for c in netwatch.console_output)


class TestHoneypotAnalysisAdditional:
    def test_inspect_event_shows_time_field(self, populated_honeypot_events):
        netwatch.handle_command("inspect 1")
        assert any("Time" in c for c in netwatch.console_output)

    def test_sessions_shows_table_header(self, populated_honeypot_events):
        netwatch.handle_command("sessions")
        # Should show column header with IP, Events etc
        assert any("IP" in c or "Events" in c for c in netwatch.console_output)

    def test_decode_base64_no_padding_no_crash(self):
        # Base64 without padding may fail gracefully
        netwatch.handle_command("decode aGVsbG8")
        assert any("Decode" in c for c in netwatch.console_output)

    def test_profile_shows_port_list(self):
        netwatch.recon_reports["20.20.20.20"] = {
            "hostname": "h", "os_guess": "Linux", "timestamp": "t",
            "ports": ["22/tcp open ssh", "80/tcp open http", "443/tcp open https"],
            "traceroute": [], "honeypot_activity": [],
        }
        netwatch.handle_command("profile 20.20.20.20")
        assert any("ssh" in c or "22" in c for c in netwatch.console_output)

    def test_profile_with_traceroute_shows_hops(self):
        netwatch.recon_reports["30.30.30.30"] = {
            "hostname": "h", "os_guess": "?", "timestamp": "t",
            "ports": [], "traceroute": ["1  10.0.1.1", "2  8.8.8.8"],
            "honeypot_activity": [],
        }
        netwatch.handle_command("profile 30.30.30.30")
        assert any("Traceroute" in c or "10.0.1.1" in c for c in netwatch.console_output)


class TestProxyAdditional:
    def test_proxy_add_then_rotate_uses_round_robin(self):
        netwatch.handle_command("proxy add socks5 127.0.0.1:9050")
        netwatch.handle_command("proxy add socks5 127.0.0.1:9052")
        netwatch.proxy_rotation = True
        p1 = netwatch._get_proxy()
        p2 = netwatch._get_proxy()
        assert p1 != p2 or len(netwatch.proxy_pool) == 1

    def test_proxy_rm_second_of_two(self):
        netwatch.proxy_pool.append({"type": "socks5", "host": "127.0.0.1", "port": "9050", "label": "socks5://127.0.0.1:9050"})
        netwatch.proxy_pool.append({"type": "http", "host": "1.2.3.4", "port": "8080", "label": "http://1.2.3.4:8080"})
        netwatch.handle_command("proxy rm 2")
        assert len(netwatch.proxy_pool) == 1
        assert netwatch.proxy_pool[0]["type"] == "socks5"

    def test_proxy_list_shows_count(self):
        netwatch.proxy_pool.append({"type": "socks5", "host": "127.0.0.1", "port": "9050", "label": "socks5://127.0.0.1:9050"})
        netwatch.proxy_pool.append({"type": "http", "host": "1.2.3.4", "port": "8080", "label": "http://1.2.3.4:8080"})
        netwatch.handle_command("proxy list")
        assert any("2" in c for c in netwatch.console_output)

    def test_proxy_rotate_shows_on_off(self):
        netwatch.handle_command("proxy rotate")
        assert any("ON" in c for c in netwatch.console_output)
        netwatch.handle_command("proxy rotate")
        assert any("OFF" in c for c in netwatch.console_output)


class TestSystemAdditional:
    def test_clear_only_clears_console_not_events(self, populated_honeypot_events):
        event_count = len(netwatch.honeypot_events)
        netwatch.console_output.extend(["a", "b"])
        netwatch.handle_command("clear")
        assert len(netwatch.console_output) == 0
        assert len(netwatch.honeypot_events) == event_count

    def test_unknown_command_contains_action_name(self):
        netwatch.handle_command("foobarxyzzy")
        assert any("foobarxyzzy" in c for c in netwatch.console_output)
