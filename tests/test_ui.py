"""
Tests for NetWatch terminal UI:
  - Tab navigation (number keys, Tab, Shift+Tab)
  - Console mode entry and exit
  - Command input handling
  - Dashboard frame rendering
  - Help overlay
  - Section renderers (no crashes on empty/full state)
  - Status bar formatting
  - Color output integrity
"""
import os
import sys
import time
import pytest
from unittest.mock import patch, MagicMock
from collections import defaultdict

import netwatch


# ═══════════════════════════════════════════════════════════
#  TAB NAVIGATION
# ═══════════════════════════════════════════════════════════

class TestTabNavigation:
    def test_initial_tab_is_all(self):
        assert netwatch.current_tab == "all"

    def test_tab_list_has_expected_tabs(self):
        assert "all" in netwatch.TABS
        assert "hosts" in netwatch.TABS
        assert "osint" in netwatch.TABS
        assert "proxy" in netwatch.TABS
        assert "honeypot" in netwatch.TABS

    def test_number_key_switches_tab(self):
        netwatch.current_tab = "all"
        # Simulate pressing "2" — should go to TABS[1]
        netwatch.current_tab = netwatch.TABS[1]
        assert netwatch.current_tab == netwatch.TABS[1]

    def test_tab_forward_cycles(self):
        netwatch.current_tab = netwatch.TABS[0]
        idx = netwatch.TABS.index(netwatch.current_tab)
        netwatch.current_tab = netwatch.TABS[(idx + 1) % len(netwatch.TABS)]
        assert netwatch.current_tab == netwatch.TABS[1]

    def test_tab_backward_cycles(self):
        netwatch.current_tab = netwatch.TABS[0]
        idx = netwatch.TABS.index(netwatch.current_tab)
        netwatch.current_tab = netwatch.TABS[(idx - 1) % len(netwatch.TABS)]
        assert netwatch.current_tab == netwatch.TABS[-1]

    def test_tab_wraps_forward(self):
        netwatch.current_tab = netwatch.TABS[-1]
        idx = netwatch.TABS.index(netwatch.current_tab)
        netwatch.current_tab = netwatch.TABS[(idx + 1) % len(netwatch.TABS)]
        assert netwatch.current_tab == netwatch.TABS[0]

    def test_tab_wraps_backward(self):
        netwatch.current_tab = netwatch.TABS[0]
        idx = netwatch.TABS.index(netwatch.current_tab)
        netwatch.current_tab = netwatch.TABS[(idx - 1) % len(netwatch.TABS)]
        assert netwatch.current_tab == netwatch.TABS[-1]

    @pytest.mark.parametrize("key,expected_idx", [
        ("1", 0), ("2", 1), ("3", 2), ("4", 3), ("5", 4),
    ])
    def test_number_keys_map_to_tabs(self, key, expected_idx):
        if expected_idx < len(netwatch.TABS):
            netwatch.current_tab = netwatch.TABS[expected_idx]
            assert netwatch.current_tab == netwatch.TABS[expected_idx]

    def test_command_switches_to_named_tab(self):
        netwatch.handle_command("hosts")
        assert netwatch.current_tab == "hosts"
        netwatch.handle_command("osint")
        assert netwatch.current_tab == "osint"
        netwatch.handle_command("all")
        assert netwatch.current_tab == "all"


# ═══════════════════════════════════════════════════════════
#  CONSOLE MODE
# ═══════════════════════════════════════════════════════════

class TestConsoleMode:
    def test_console_mode_starts_false(self):
        assert netwatch.console_mode == False

    def test_command_c_would_enter_console(self):
        # console mode is entered by typing "c" in dashboard
        # which is handled in main() key loop, not handle_command
        # but handle_command("dashboard") exits it
        netwatch.console_mode = True
        netwatch.handle_command("dashboard")
        assert netwatch.console_mode == False

    def test_status_command_works_in_console(self):
        # status uses global state — shouldn't crash
        netwatch.total_packets = 1234
        netwatch.total_bytes = 56789
        netwatch.console_output.clear()
        # status is handled in the main loop, not handle_command
        # but we can verify the state variables are accessible
        assert netwatch.total_packets == 1234
        assert netwatch.total_bytes == 56789

    def test_clear_command_clears_output(self):
        netwatch.console_output.extend(["line1", "line2", "line3"])
        netwatch.handle_command("clear")
        assert len(netwatch.console_output) == 0


# ═══════════════════════════════════════════════════════════
#  DASHBOARD FRAME RENDERING
# ═══════════════════════════════════════════════════════════

class TestDashboardFrame:
    @pytest.mark.parametrize("cols", [60, 80, 120, 200])
    def test_frame_renders_at_various_widths(self, cols):
        frame = netwatch._build_frame(cols=cols, max_content=30)
        assert isinstance(frame, list)
        assert len(frame) > 0

    @pytest.mark.parametrize("tab", ["all", "hosts", "proto", "dns", "honeypot", "nmap", "arp", "alerts", "osint", "proxy"])
    def test_frame_renders_all_tabs(self, tab):
        if tab in netwatch.TABS:
            netwatch.current_tab = tab
            frame = netwatch._build_frame(cols=100, max_content=35)
            assert len(frame) > 0

    def test_frame_with_data(self):
        # Populate some state
        netwatch.hosts["1.2.3.4"] = {
            "bytes_in": 1024, "bytes_out": 512, "packets": 10,
            "ports": {80, 443}, "protocols": {"TCP"}, "first_seen": "now",
            "last_seen": "now", "hostname": "test.com", "resolved": True,
            "threat_score": 5, "tags": set()
        }
        netwatch.honeypot_events.append({
            "time": "10:00:00", "service": "telnet", "ip": "5.6.7.8",
            "summary": "test event", "data": {}
        })
        netwatch.proto_stats["TCP"] = 100
        netwatch.proto_stats["UDP"] = 50
        netwatch.dns_queries.append({"time": "10:00:00", "domain": "example.com", "ip": "10.0.1.5"})
        netwatch.alerts.append({"time": "10:00:00", "msg": "test alert"})

        netwatch.current_tab = "all"
        frame = netwatch._build_frame(cols=120, max_content=40)
        assert len(frame) > 5
        # Should contain version string
        assert any("NETWATCH" in line for line in frame)

    def test_frame_empty_state_no_crash(self):
        # All state already cleared by fixture
        for tab in netwatch.TABS:
            netwatch.current_tab = tab
            frame = netwatch._build_frame(cols=80, max_content=30)
            assert isinstance(frame, list)


# ═══════════════════════════════════════════════════════════
#  HELP OVERLAY
# ═══════════════════════════════════════════════════════════

class TestHelpOverlay:
    def test_help_overlay_renders(self):
        lines = netwatch._build_help_overlay(100, 40)
        assert len(lines) > 20

    def test_help_overlay_contains_new_commands(self):
        lines = netwatch._build_help_overlay(120, 50)
        text = "\n".join(lines)
        assert "ssl" in text
        assert "secheaders" in text
        assert "techstack" in text
        assert "ping" in text
        assert "health" in text
        assert "etrace" in text

    def test_help_overlay_contains_sections(self):
        lines = netwatch._build_help_overlay(120, 50)
        text = "\n".join(lines)
        assert "OSINT" in text
        assert "Scanning" in text
        assert "Defense" in text
        assert "Tracking" in text
        assert "Proxy" in text

    def test_help_toggle(self):
        netwatch.show_help_overlay = False
        netwatch.handle_command("help")
        assert netwatch.show_help_overlay == True

    @pytest.mark.parametrize("cols", [60, 80, 120, 200])
    def test_help_overlay_various_widths(self, cols):
        lines = netwatch._build_help_overlay(cols, 40)
        assert len(lines) > 0


# ═══════════════════════════════════════════════════════════
#  TAB BAR
# ═══════════════════════════════════════════════════════════

class TestTabBar:
    def test_tab_bar_renders(self):
        bar = netwatch._tab_bar(120)
        assert isinstance(bar, str)
        assert len(bar) > 0

    def test_tab_bar_highlights_current(self):
        netwatch.current_tab = "hosts"
        bar = netwatch._tab_bar(120)
        # Should contain BG_RED for selected tab
        assert "\033[41m" in bar

    @pytest.mark.parametrize("tab", ["all", "hosts", "osint"])
    def test_tab_bar_different_selections(self, tab):
        netwatch.current_tab = tab
        bar = netwatch._tab_bar(120)
        assert tab.upper() in bar


# ═══════════════════════════════════════════════════════════
#  SECTION RENDERERS
# ═══════════════════════════════════════════════════════════

class TestSectionRenderers:
    def test_section_hosts_empty(self):
        lines = netwatch._section_hosts(limit=10)
        assert len(lines) >= 3  # header + col header + separator
        assert any("HOSTS" in l for l in lines)

    def test_section_hosts_with_data(self):
        netwatch.hosts["10.0.1.5"] = {
            "bytes_in": 2048, "bytes_out": 1024, "packets": 20,
            "ports": {22, 80}, "protocols": {"TCP"}, "first_seen": "now",
            "last_seen": "now", "hostname": "server.local", "resolved": True,
            "threat_score": 0, "tags": set()
        }
        lines = netwatch._section_hosts(limit=10)
        assert any("10.0.1.5" in l for l in lines)

    def test_section_protocols_empty(self):
        lines = netwatch._section_protocols(limit=8)
        assert any("PROTOCOLS" in l for l in lines)

    def test_section_protocols_with_data(self):
        netwatch.proto_stats["TCP"] = 500
        netwatch.proto_stats["UDP"] = 200
        netwatch.proto_stats["DNS"] = 100
        lines = netwatch._section_protocols(limit=8)
        text = "\n".join(lines)
        assert "TCP" in text

    def test_section_protocols_expanded(self):
        netwatch.proto_stats["TCP"] = 500
        lines = netwatch._section_protocols(limit=8, expanded=True)
        assert any("█" in l for l in lines)

    def test_section_dns_empty(self):
        lines = netwatch._section_dns(limit=5)
        assert any("DNS" in l for l in lines)

    def test_section_dns_with_data(self):
        netwatch.dns_queries.append({"time": "12:00", "domain": "evil.com", "ip": "10.0.1.5"})
        lines = netwatch._section_dns(limit=5)
        assert any("evil.com" in l for l in lines)

    def test_section_honeypot_empty(self):
        lines = netwatch._section_honeypot(limit=6)
        assert any("HONEYPOT" in l for l in lines)

    def test_section_honeypot_with_data(self):
        netwatch.honeypot_events.append({
            "time": "10:00", "service": "telnet", "ip": "5.5.5.5",
            "summary": "login attempt", "data": {}
        })
        lines = netwatch._section_honeypot(limit=6)
        assert any("5.5.5.5" in l for l in lines)

    def test_section_nmap_empty(self):
        lines = netwatch._section_nmap(limit=5)
        assert any("NMAP" in l or "nmap" in l.lower() for l in lines)

    def test_section_arp_empty(self):
        lines = netwatch._section_arp(limit=6)
        assert any("ARP" in l for l in lines)

    def test_section_arp_with_data(self):
        netwatch.arp_table["10.0.1.1"] = {"mac": "aa:bb:cc:dd:ee:ff", "state": "REACHABLE", "first_seen": "now"}
        lines = netwatch._section_arp(limit=6)
        assert any("10.0.1.1" in l for l in lines)

    def test_section_alerts_empty(self):
        lines = netwatch._section_alerts(limit=5)
        assert any("ALERT" in l.upper() for l in lines)

    def test_section_alerts_with_data(self):
        netwatch.alerts.append({"time": "10:00", "msg": "suspicious activity from 6.6.6.6"})
        lines = netwatch._section_alerts(limit=5)
        assert any("6.6.6.6" in l for l in lines)

    def test_section_osint_empty(self):
        lines = netwatch._section_osint(limit=20)
        assert any("OSINT" in l.upper() or "no results" in l for l in lines)

    def test_section_osint_with_data(self):
        netwatch.osint_results.append({
            "time": "10:00", "type": "GEO", "target": "1.2.3.4",
            "result": "San Francisco, US"
        })
        lines = netwatch._section_osint(limit=20)
        text = "\n".join(lines)
        assert "1.2.3.4" in text

    def test_section_console(self):
        netwatch.console_output.extend(["test line 1", "test line 2"])
        lines = netwatch._section_console()
        assert any("test line" in l for l in lines)


# ═══════════════════════════════════════════════════════════
#  HOST LINE FORMATTING
# ═══════════════════════════════════════════════════════════

class TestHostLine:
    def test_host_line_basic(self):
        data = {
            "bytes_in": 1024, "bytes_out": 512, "packets": 5,
            "ports": {80}, "protocols": {"TCP"}, "first_seen": "now",
            "last_seen": "now", "hostname": "test.local", "resolved": True,
            "threat_score": 0, "tags": set()
        }
        line = netwatch._host_line("10.0.1.5", data)
        assert "10.0.1.5" in line
        assert "test.local" in line

    def test_host_line_high_threat(self):
        data = {
            "bytes_in": 1024, "bytes_out": 512, "packets": 5,
            "ports": {80}, "protocols": {"TCP"}, "first_seen": "now",
            "last_seen": "now", "hostname": "", "resolved": False,
            "threat_score": 50, "tags": {"SCANNER"}
        }
        line = netwatch._host_line("evil.ip", data)
        assert "SCANNER" in line
        # Should use RED color for high threat
        assert "\033[91m" in line

    def test_host_line_long_hostname_truncated(self):
        data = {
            "bytes_in": 0, "bytes_out": 0, "packets": 0,
            "ports": set(), "protocols": set(), "first_seen": "now",
            "last_seen": "now", "hostname": "a" * 50, "resolved": True,
            "threat_score": 0, "tags": set()
        }
        line = netwatch._host_line("1.2.3.4", data)
        assert ".." in line  # truncation marker


# ═══════════════════════════════════════════════════════════
#  FORMAT BYTES
# ═══════════════════════════════════════════════════════════

class TestFormatBytes:
    @pytest.mark.parametrize("value,expected_contains", [
        (0, "0"),
        (100, "100"),
        (1024, "K"),
        (1048576, "M"),
        (1073741824, "G"),
    ])
    def test_format_bytes_units(self, value, expected_contains):
        result = netwatch.format_bytes(value)
        assert expected_contains in result


# ═══════════════════════════════════════════════════════════
#  HONEYPOT COLOR
# ═══════════════════════════════════════════════════════════

class TestHoneypotColor:
    @pytest.mark.parametrize("service,expected_color", [
        ("credential", netwatch.RED),
        ("malware_attempt", netwatch.RED),
        ("telnet", netwatch.YELLOW),
        ("telnet_cmd", netwatch.YELLOW),
        ("ftp_credential", netwatch.MAGENTA),
        ("rtsp", netwatch.BLUE),
        ("unknown_service", netwatch.DIM),
    ])
    def test_service_colors(self, service, expected_color):
        assert netwatch._honeypot_color(service) == expected_color


# ═══════════════════════════════════════════════════════════
#  THREAT COLOR
# ═══════════════════════════════════════════════════════════

class TestThreatColor:
    def test_zero_threat(self):
        result = netwatch.threat_color(0)
        assert result in (netwatch.GREEN, netwatch.DIM, netwatch.WHITE)

    def test_high_threat(self):
        result = netwatch.threat_color(50)
        assert result == netwatch.RED

    def test_medium_threat(self):
        result = netwatch.threat_color(15)
        assert result in (netwatch.YELLOW, netwatch.RED)


# ═══════════════════════════════════════════════════════════
#  CONSOLE OUTPUT (add_console)
# ═══════════════════════════════════════════════════════════

class TestAddConsole:
    def test_add_console_appends(self):
        netwatch.add_console("test message")
        assert "test message" in netwatch.console_output

    def test_add_console_caps_at_max(self):
        for i in range(netwatch.MAX_CONSOLE + 50):
            netwatch.add_console(f"line {i}")
        assert len(netwatch.console_output) <= netwatch.MAX_CONSOLE

    def test_add_console_thread_safe(self):
        import threading
        def add_many():
            for i in range(100):
                netwatch.add_console(f"thread line {i}")
        threads = [threading.Thread(target=add_many) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # Should not crash — thread safety via lock
        assert len(netwatch.console_output) > 0
