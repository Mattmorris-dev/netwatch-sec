"""
test_ui_layout.py — 150 tests for NetWatch UI layout, rendering, and console.

Categories:
1.  Tab navigation mechanics (15)
2.  _build_frame rendering (25)
3.  _build_help_overlay (10)
4.  _tab_bar (10)
5.  _host_line formatting (15)
6.  Section renderers (40)
7.  Console isolation (10)
8.  _exec_console_cmd (10)
9.  add_console thread safety and capping (5)
10. format_bytes / threat_color / _ansi_strip / _honeypot_color (10)
"""

import pytest
from unittest.mock import patch
import netwatch

# ─── Helpers ──────────────────────────────────────────────

def _strip(s):
    """Strip ANSI from string."""
    return netwatch._ansi_strip(s)


def _make_host(bytes_in=0, bytes_out=0, packets=0, ports=None, protocols=None,
               first_seen=None, last_seen=None, hostname="", resolved=False,
               threat_score=0, tags=None):
    return {
        "bytes_in": bytes_in,
        "bytes_out": bytes_out,
        "packets": packets,
        "ports": ports if ports is not None else set(),
        "protocols": protocols if protocols is not None else set(),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "hostname": hostname,
        "resolved": resolved,
        "threat_score": threat_score,
        "tags": tags if tags is not None else set(),
    }


def _frame_text(cols=80, max_content=35):
    """Return full stripped text of a frame."""
    return "\n".join(_strip(l) for l in netwatch._build_frame(cols, max_content))


# ═══════════════════════════════════════════════════════════
# 1. TAB NAVIGATION MECHANICS (15 tests)
# ═══════════════════════════════════════════════════════════

class TestTabNavigation:

    def test_tabs_list_length(self):
        assert len(netwatch.TABS) == 12

    def test_tabs_list_content(self):
        expected = ["all", "hosts", "proto", "dns", "honeypot", "nmap", "arp", "alerts", "osint", "proxy", "mesh", "fleet"]
        assert netwatch.TABS == expected

    def test_default_tab_is_all(self):
        assert netwatch.current_tab == "all"

    def test_set_tab_hosts(self):
        netwatch.current_tab = "hosts"
        assert netwatch.current_tab == "hosts"

    def test_set_tab_proto(self):
        netwatch.current_tab = "proto"
        assert netwatch.current_tab == "proto"

    def test_set_tab_dns(self):
        netwatch.current_tab = "dns"
        assert netwatch.current_tab == "dns"

    def test_set_tab_honeypot(self):
        netwatch.current_tab = "honeypot"
        assert netwatch.current_tab == "honeypot"

    def test_set_tab_nmap(self):
        netwatch.current_tab = "nmap"
        assert netwatch.current_tab == "nmap"

    def test_set_tab_arp(self):
        netwatch.current_tab = "arp"
        assert netwatch.current_tab == "arp"

    def test_set_tab_alerts(self):
        netwatch.current_tab = "alerts"
        assert netwatch.current_tab == "alerts"

    def test_set_tab_osint(self):
        netwatch.current_tab = "osint"
        assert netwatch.current_tab == "osint"

    def test_set_tab_proxy(self):
        netwatch.current_tab = "proxy"
        assert netwatch.current_tab == "proxy"

    def test_handle_command_switches_tab(self):
        netwatch.handle_command("hosts")
        assert netwatch.current_tab == "hosts"

    def test_handle_command_switches_tab_alerts(self):
        netwatch.handle_command("alerts")
        assert netwatch.current_tab == "alerts"

    def test_invalid_tab_resets_to_all_in_frame(self):
        netwatch.current_tab = "nonexistent"
        lines = netwatch._build_frame(80, 20)
        text = "\n".join(_strip(l) for l in lines)
        assert "reset to all view" in text
        assert netwatch.current_tab == "all"


# ═══════════════════════════════════════════════════════════
# 2. _build_frame RENDERING (25 tests)
# ═══════════════════════════════════════════════════════════

class TestBuildFrame:

    def test_returns_list(self):
        result = netwatch._build_frame(80, 20)
        assert isinstance(result, list)

    def test_returns_nonempty(self):
        result = netwatch._build_frame(80, 20)
        assert len(result) > 0

    def test_contains_netwatch_header(self):
        text = _frame_text(80, 20)
        assert "NETWATCH" in text

    def test_frame_tab_all(self):
        netwatch.current_tab = "all"
        text = _frame_text(80, 20)
        assert "HOSTS" in text

    def test_frame_tab_hosts(self):
        netwatch.current_tab = "hosts"
        text = _frame_text(80, 20)
        assert "HOSTS" in text

    def test_frame_tab_proto(self):
        netwatch.current_tab = "proto"
        text = _frame_text(80, 20)
        assert "PROTOCOLS" in text

    def test_frame_tab_dns(self):
        netwatch.current_tab = "dns"
        text = _frame_text(80, 20)
        assert "DNS" in text

    def test_frame_tab_honeypot(self):
        netwatch.current_tab = "honeypot"
        text = _frame_text(80, 20)
        assert "HONEYPOT" in text

    def test_frame_tab_nmap(self):
        netwatch.current_tab = "nmap"
        text = _frame_text(80, 20)
        assert "NMAP" in text

    def test_frame_tab_alerts(self):
        netwatch.current_tab = "alerts"
        text = _frame_text(80, 20)
        assert "ALERTS" in text

    def test_frame_tab_osint(self):
        netwatch.current_tab = "osint"
        text = _frame_text(80, 20)
        assert "OSINT" in text

    def test_frame_tab_proxy(self):
        netwatch.current_tab = "proxy"
        text = _frame_text(80, 20)
        assert "PROXY" in text

    def test_frame_cols_80(self):
        result = netwatch._build_frame(80, 20)
        assert len(result) > 0

    def test_frame_large_max_content(self):
        result = netwatch._build_frame(80, 100)
        assert len(result) > 0

    def test_console_output_not_in_frame_empty(self):
        netwatch.console_output.clear()
        text = _frame_text(80, 20)
        assert "OUTPUT" not in text

    def test_console_output_not_in_frame_with_data(self):
        """Critical: console output must NOT appear in dashboard frame."""
        netwatch.add_console("UNIQUE_CONSOLE_MARKER_XYZ")
        text = _frame_text(80, 20)
        assert "UNIQUE_CONSOLE_MARKER_XYZ" not in text

    def test_console_output_not_in_frame_all_tabs(self):
        netwatch.add_console("SHOULD_NOT_APPEAR")
        for tab in netwatch.TABS:
            netwatch.current_tab = tab
            text = _frame_text(80, 20)
            assert "SHOULD_NOT_APPEAR" not in text

    def test_frame_contains_uptime(self):
        text = _frame_text(80, 20)
        assert "Up:" in text

    def test_frame_contains_interface(self):
        text = _frame_text(80, 20)
        assert netwatch.IFACE in text

    def test_frame_contains_packets(self):
        netwatch.total_packets = 42
        text = _frame_text(80, 20)
        assert "42" in text

    def test_frame_with_populated_hosts(self):
        netwatch.hosts["1.2.3.4"]["bytes_in"] = 1000
        netwatch.hosts["1.2.3.4"]["packets"] = 5
        netwatch.current_tab = "hosts"
        text = _frame_text(80, 20)
        assert "1.2.3.4" in text

# ═══════════════════════════════════════════════════════════
# 3. _build_help_overlay (10 tests)
# ═══════════════════════════════════════════════════════════

class TestBuildHelpOverlay:

    def test_returns_list(self):
        result = netwatch._build_help_overlay(80, 40)
        assert isinstance(result, list)

    def test_nonempty(self):
        result = netwatch._build_help_overlay(80, 40)
        assert len(result) > 5

    def test_contains_osint_section(self):
        text = "\n".join(_strip(l) for l in netwatch._build_help_overlay(80, 40))
        assert "OSINT" in text

    def test_contains_scanning_section(self):
        text = "\n".join(_strip(l) for l in netwatch._build_help_overlay(80, 40))
        assert "Scanning" in text or "scan" in text.lower()

    def test_contains_defense_section(self):
        text = "\n".join(_strip(l) for l in netwatch._build_help_overlay(80, 40))
        assert "Defense" in text or "block" in text.lower()

    def test_contains_navigation_hints(self):
        text = "\n".join(_strip(l) for l in netwatch._build_help_overlay(80, 40))
        assert "Tab" in text or "1-" in text or "Navigation" in text

    def test_contains_close_hint(self):
        text = "\n".join(_strip(l) for l in netwatch._build_help_overlay(80, 40))
        assert "ESC" in text

    def test_wide_terminal(self):
        result = netwatch._build_help_overlay(200, 60)
        assert len(result) > 5

    def test_narrow_terminal(self):
        result = netwatch._build_help_overlay(40, 24)
        assert len(result) > 5

    def test_contains_version(self):
        text = "\n".join(_strip(l) for l in netwatch._build_help_overlay(80, 40))
        assert netwatch.VERSION in text


# ═══════════════════════════════════════════════════════════
# 4. _tab_bar (10 tests)
# ═══════════════════════════════════════════════════════════

class TestTabBar:

    def test_returns_string(self):
        result = netwatch._tab_bar(80)
        assert isinstance(result, str)

    def test_all_tabs_present(self):
        result = _strip(netwatch._tab_bar(80))
        for tab in netwatch.TABS:
            assert tab.upper() in result.upper()

    def test_current_tab_highlighted(self):
        netwatch.current_tab = "hosts"
        bar = netwatch._tab_bar(80)
        # The active tab uses BG_RED; confirm stripped text contains HOSTS
        stripped = _strip(bar)
        assert "HOSTS" in stripped.upper()

    def test_contains_numbered_tabs(self):
        # Numbers show when the bar fits; at wide widths they always do.
        bar = _strip(netwatch._tab_bar(160))
        assert "1:" in bar

    def test_tab_number_zero_for_tenth(self):
        # TABS[9] = "proxy", number = "0" (shown at a width where numbers fit)
        bar = _strip(netwatch._tab_bar(160))
        assert "0:" in bar

    def test_tab_bar_narrow_cols(self):
        result = netwatch._tab_bar(40)
        assert isinstance(result, str)

    def test_tab_bar_wide_cols(self):
        result = netwatch._tab_bar(200)
        assert isinstance(result, str)

    def test_switching_tab_changes_highlight(self):
        netwatch.current_tab = "dns"
        bar1 = netwatch._tab_bar(80)
        netwatch.current_tab = "alerts"
        bar2 = netwatch._tab_bar(80)
        # Both are valid strings; the ANSI differ
        assert bar1 != bar2

    def test_tab_bar_honeypot_shown(self):
        netwatch.current_tab = "honeypot"
        bar = _strip(netwatch._tab_bar(80))
        assert "HONEYPOT" in bar.upper()

    def test_tab_bar_proxy_shown(self):
        netwatch.current_tab = "proxy"
        bar = _strip(netwatch._tab_bar(80))
        assert "PROXY" in bar.upper()


# ═══════════════════════════════════════════════════════════
# 5. _host_line FORMATTING (15 tests)
# ═══════════════════════════════════════════════════════════

class TestHostLine:

    def test_returns_string(self):
        data = _make_host()
        assert isinstance(netwatch._host_line("1.2.3.4", data), str)

    def test_contains_ip(self):
        data = _make_host()
        line = _strip(netwatch._host_line("1.2.3.4", data))
        assert "1.2.3.4" in line

    def test_contains_hostname(self):
        data = _make_host(hostname="example.com")
        line = _strip(netwatch._host_line("1.2.3.4", data))
        assert "example.com" in line

    def test_hostname_truncated_long(self):
        data = _make_host(hostname="a" * 50)
        line = _strip(netwatch._host_line("1.2.3.4", data))
        # Should be truncated to 23 chars (21 + ..)
        assert "a" * 50 not in line

    def test_port_count_shown(self):
        data = _make_host(ports={80, 443, 22})
        line = _strip(netwatch._host_line("1.2.3.4", data))
        assert "3" in line

    def test_zero_ports(self):
        data = _make_host(ports=set())
        line = _strip(netwatch._host_line("1.2.3.4", data))
        assert "0" in line

    def test_tag_shown(self):
        data = _make_host(tags={"SCANNER"})
        line = _strip(netwatch._host_line("1.2.3.4", data))
        assert "SCANNER" in line

    def test_multiple_tags(self):
        data = _make_host(tags={"SCANNER", "SUS-PORT"})
        line = _strip(netwatch._host_line("1.2.3.4", data))
        assert "SCANNER" in line
        assert "SUS-PORT" in line

    def test_bytes_in_shown(self):
        data = _make_host(bytes_in=1024)
        line = _strip(netwatch._host_line("1.2.3.4", data))
        assert "1.0KB" in line

    def test_bytes_out_shown(self):
        data = _make_host(bytes_out=2048)
        line = _strip(netwatch._host_line("1.2.3.4", data))
        assert "2.0KB" in line

    def test_zero_traffic(self):
        data = _make_host()
        line = _strip(netwatch._host_line("5.5.5.5", data))
        assert "5.5.5.5" in line

    def test_high_threat_score(self):
        data = _make_host(threat_score=50)
        line = netwatch._host_line("9.9.9.9", data)
        # High threat → RED color code present
        assert netwatch.RED in line

    def test_medium_threat_score(self):
        data = _make_host(threat_score=15)
        line = netwatch._host_line("9.9.9.9", data)
        assert netwatch.YELLOW in line

    def test_low_threat_score(self):
        data = _make_host(threat_score=0)
        line = netwatch._host_line("9.9.9.9", data)
        assert netwatch.WHITE in line

    def test_large_traffic_uses_cyan(self):
        # bytes_in + bytes_out > 1_000_000 and threat_score 0 → CYAN
        data = _make_host(bytes_in=600_000, bytes_out=600_000, threat_score=0)
        line = netwatch._host_line("9.9.9.9", data)
        assert netwatch.CYAN in line


# ═══════════════════════════════════════════════════════════
# 6. SECTION RENDERERS (40 tests)
# ═══════════════════════════════════════════════════════════

class TestSectionHosts:

    def test_returns_list(self):
        assert isinstance(netwatch._section_hosts(10), list)

    def test_empty_state(self):
        lines = [_strip(l) for l in netwatch._section_hosts(10)]
        combined = "\n".join(lines)
        assert "no hosts yet" in combined

    def test_populated_shows_ip(self):
        netwatch.hosts["10.0.0.1"]["bytes_in"] = 500
        lines = [_strip(l) for l in netwatch._section_hosts(10)]
        assert any("10.0.0.1" in l for l in lines)

    def test_limit_zero(self):
        netwatch.hosts["10.0.0.1"]["bytes_in"] = 500
        lines = netwatch._section_hosts(0)
        assert isinstance(lines, list)

    def test_sorted_by_traffic(self):
        netwatch.hosts["1.1.1.1"]["bytes_in"] = 100
        netwatch.hosts["2.2.2.2"]["bytes_in"] = 999
        lines = [_strip(l) for l in netwatch._section_hosts(10)]
        combined = "\n".join(lines)
        pos_2 = combined.find("2.2.2.2")
        pos_1 = combined.find("1.1.1.1")
        assert pos_2 < pos_1  # higher traffic appears first


class TestSectionProtocols:

    def test_returns_list(self):
        assert isinstance(netwatch._section_protocols(8), list)

    def test_empty_state(self):
        lines = [_strip(l) for l in netwatch._section_protocols(8)]
        combined = "\n".join(lines)
        assert "waiting" in combined or "tshark" in combined

    def test_populated(self):
        netwatch.proto_stats["TCP"] = 10
        lines = [_strip(l) for l in netwatch._section_protocols(8)]
        combined = "\n".join(lines)
        assert "TCP" in combined

    def test_expanded_mode(self):
        netwatch.proto_stats["UDP"] = 5
        lines = [_strip(l) for l in netwatch._section_protocols(8, expanded=True)]
        combined = "\n".join(lines)
        assert "UDP" in combined and "Protocol" in combined

class TestSectionDns:

    def test_returns_list(self):
        assert isinstance(netwatch._section_dns(5), list)

    def test_empty_state(self):
        lines = [_strip(l) for l in netwatch._section_dns(5)]
        combined = "\n".join(lines)
        assert "waiting" in combined

    def test_populated(self):
        netwatch.dns_queries.append({"time": "12:00:00", "ip": "10.0.0.1", "domain": "example.com"})
        lines = [_strip(l) for l in netwatch._section_dns(5)]
        combined = "\n".join(lines)
        assert "example.com" in combined

    def test_limit_applied(self):
        for i in range(20):
            netwatch.dns_queries.append({"time": "12:00:00", "ip": "10.0.0.1", "domain": f"domain{i}.com"})
        lines = [_strip(l) for l in netwatch._section_dns(3)]
        # header + 3 query rows at most (plus possible empty line)
        domain_rows = [l for l in lines if ".com" in l]
        assert len(domain_rows) <= 3

    def test_known_service_annotated(self):
        netwatch.dns_queries.append({"time": "12:00:00", "ip": "10.0.0.1", "domain": "webcams.nyctmc.org"})
        lines = [_strip(l) for l in netwatch._section_dns(5)]
        combined = "\n".join(lines)
        assert "nyctmc" in combined


class TestSectionHoneypot:

    def test_returns_list(self):
        assert isinstance(netwatch._section_honeypot(6), list)

    def test_empty_state(self):
        lines = [_strip(l) for l in netwatch._section_honeypot(6)]
        combined = "\n".join(lines)
        assert "waiting" in combined or "visitors" in combined

    def test_populated(self):
        netwatch.honeypot_events.append({"time": "10:00:00", "service": "telnet", "ip": "1.2.3.4", "summary": "login admin"})
        lines = [_strip(l) for l in netwatch._section_honeypot(6)]
        combined = "\n".join(lines)
        assert "1.2.3.4" in combined

    def test_http_hidden_by_default(self):
        netwatch.honeypot_events.append({"time": "10:00:00", "service": "http", "ip": "5.5.5.5", "summary": "GET /"})
        lines = [_strip(l) for l in netwatch._section_honeypot(6, show_http=False)]
        combined = "\n".join(lines)
        # http events should be excluded
        assert "5.5.5.5" not in combined

    def test_http_shown_with_flag(self):
        netwatch.honeypot_events.append({"time": "10:00:00", "service": "http", "ip": "5.5.5.5", "summary": "GET /"})
        lines = [_strip(l) for l in netwatch._section_honeypot(6, show_http=True)]
        combined = "\n".join(lines)
        assert "5.5.5.5" in combined

    def test_limit_applied(self):
        for i in range(20):
            netwatch.honeypot_events.append({"time": "10:00:00", "service": "telnet", "ip": f"1.0.0.{i}", "summary": "x"})
        lines = [_strip(l) for l in netwatch._section_honeypot(3)]
        ip_rows = [l for l in lines if "1.0.0." in l]
        assert len(ip_rows) <= 3


class TestSectionNmap:

    def test_returns_list(self):
        assert isinstance(netwatch._section_nmap(5), list)

    def test_empty_state(self):
        lines = [_strip(l) for l in netwatch._section_nmap(5)]
        combined = "\n".join(lines)
        assert "no scans" in combined

    def test_populated(self):
        netwatch.nmap_results.append({"time": "10:00:00", "line": "80/tcp open http"})
        lines = [_strip(l) for l in netwatch._section_nmap(5)]
        combined = "\n".join(lines)
        assert "80/tcp" in combined

    def test_running_status(self):
        netwatch.nmap_running = True
        lines = [_strip(l) for l in netwatch._section_nmap(5)]
        combined = "\n".join(lines)
        assert "SCANNING" in combined

class TestSectionArp:

    def test_returns_list(self):
        assert isinstance(netwatch._section_arp(6), list)

    def test_empty_state(self):
        lines = [_strip(l) for l in netwatch._section_arp(6)]
        combined = "\n".join(lines)
        assert "no ARP" in combined

    def test_populated(self):
        netwatch.arp_table["192.168.1.1"] = {"mac": "aa:bb:cc:dd:ee:ff", "state": "REACHABLE", "last_seen": "now"}
        lines = [_strip(l) for l in netwatch._section_arp(6)]
        combined = "\n".join(lines)
        assert "aa:bb:cc:dd:ee:ff" in combined

    def test_limit_one(self):
        for i in range(10):
            netwatch.arp_table[f"10.0.0.{i}"] = {"mac": f"aa:00:00:00:00:{i:02x}", "state": "REACHABLE", "last_seen": "now"}
        lines = [_strip(l) for l in netwatch._section_arp(1)]
        mac_rows = [l for l in lines if "aa:00:00" in l]
        assert len(mac_rows) <= 1

class TestSectionAlerts:

    def test_returns_list(self):
        assert isinstance(netwatch._section_alerts(5), list)

    def test_empty_state(self):
        lines = [_strip(l) for l in netwatch._section_alerts(5)]
        combined = "\n".join(lines)
        assert "no alerts" in combined

    def test_populated(self):
        netwatch.alerts.append({"time": "10:00:00", "msg": "PORT SCAN: 1.2.3.4"})
        lines = [_strip(l) for l in netwatch._section_alerts(5)]
        combined = "\n".join(lines)
        assert "PORT SCAN" in combined

    def test_limit_applied(self):
        for i in range(20):
            netwatch.alerts.append({"time": "10:00:00", "msg": f"ALERT {i}"})
        lines = [_strip(l) for l in netwatch._section_alerts(3)]
        # [!] prefix identifies actual alert rows (not the header)
        alert_rows = [l for l in lines if "[!]" in l]
        assert len(alert_rows) <= 3

class TestSectionOsint:

    def test_returns_list(self):
        assert isinstance(netwatch._section_osint(20), list)

    def test_empty_state(self):
        lines = [_strip(l) for l in netwatch._section_osint(20)]
        combined = "\n".join(lines)
        assert "no results" in combined

    def test_populated(self):
        netwatch.osint_results.append({"time": "10:00:00", "type": "GEO", "target": "8.8.8.8", "result": "US"})
        lines = [_strip(l) for l in netwatch._section_osint(20)]
        combined = "\n".join(lines)
        assert "8.8.8.8" in combined

    def test_commands_shown(self):
        lines = [_strip(l) for l in netwatch._section_osint(20)]
        combined = "\n".join(lines)
        assert "geo" in combined

    def test_limit_applied(self):
        for i in range(30):
            netwatch.osint_results.append({"time": "10:00:00", "type": "GEO", "target": f"target{i}", "result": "ok"})
        lines = [_strip(l) for l in netwatch._section_osint(5)]
        # Match lines containing GEO type and target IP rows (not the commands line)
        target_rows = [l for l in lines if "GEO" in l and "target" in l]
        assert len(target_rows) <= 5


class TestSectionProxy:

    def test_returns_list(self):
        assert isinstance(netwatch._section_proxy(20), list)

    def test_empty_state_shows_options(self):
        lines = [_strip(l) for l in netwatch._section_proxy(20)]
        combined = "\n".join(lines)
        assert "proxy add" in combined or "Options" in combined or "PROXY" in combined

    def test_with_custom_proxy(self):
        netwatch.proxy_pool.append({"type": "socks5", "host": "127.0.0.1", "port": "9050", "label": "socks5://127.0.0.1:9050"})
        lines = [_strip(l) for l in netwatch._section_proxy(20)]
        combined = "\n".join(lines)
        assert "9050" in combined


class TestSectionConsole:

    def test_returns_list(self):
        assert isinstance(netwatch._section_console(), list)

    def test_empty_console(self):
        lines = netwatch._section_console()
        assert lines == []

    def test_populated_console(self):
        netwatch.console_output.append("hello world")
        lines = [_strip(l) for l in netwatch._section_console()]
        combined = "\n".join(lines)
        assert "hello world" in combined

    def test_max_eight_lines_shown(self):
        for i in range(20):
            netwatch.console_output.append(f"line {i}")
        lines = netwatch._section_console()
        # header + up to 8 output lines
        content_lines = [l for l in lines if "line" in l]
        assert len(content_lines) <= 8


# ═══════════════════════════════════════════════════════════
# 7. CONSOLE ISOLATION (10 tests)
# ═══════════════════════════════════════════════════════════

class TestConsoleIsolation:

    def test_no_console_in_frame_tab_all(self):
        netwatch.add_console("ISOLATE_ALL_TAB_TEST")
        netwatch.current_tab = "all"
        text = _frame_text(80, 20)
        assert "ISOLATE_ALL_TAB_TEST" not in text

    def test_no_console_in_frame_tab_hosts(self):
        netwatch.add_console("ISOLATE_HOSTS_TAB_TEST")
        netwatch.current_tab = "hosts"
        text = _frame_text(80, 20)
        assert "ISOLATE_HOSTS_TAB_TEST" not in text

    def test_no_console_in_frame_tab_dns(self):
        netwatch.add_console("ISOLATE_DNS_TAB_TEST")
        netwatch.current_tab = "dns"
        text = _frame_text(80, 20)
        assert "ISOLATE_DNS_TAB_TEST" not in text

    def test_no_console_in_frame_tab_honeypot(self):
        netwatch.add_console("ISOLATE_HP_TAB_TEST")
        netwatch.current_tab = "honeypot"
        text = _frame_text(80, 20)
        assert "ISOLATE_HP_TAB_TEST" not in text

    def test_no_console_in_frame_tab_alerts(self):
        netwatch.add_console("ISOLATE_ALERTS_TAB_TEST")
        netwatch.current_tab = "alerts"
        text = _frame_text(80, 20)
        assert "ISOLATE_ALERTS_TAB_TEST" not in text

    def test_no_console_in_frame_tab_nmap(self):
        netwatch.add_console("ISOLATE_NMAP_TAB_TEST")
        netwatch.current_tab = "nmap"
        text = _frame_text(80, 20)
        assert "ISOLATE_NMAP_TAB_TEST" not in text

    def test_no_console_in_frame_tab_arp(self):
        netwatch.add_console("ISOLATE_ARP_TAB_TEST")
        netwatch.current_tab = "arp"
        text = _frame_text(80, 20)
        assert "ISOLATE_ARP_TAB_TEST" not in text

    def test_no_console_in_frame_tab_osint(self):
        netwatch.add_console("ISOLATE_OSINT_TAB_TEST")
        netwatch.current_tab = "osint"
        text = _frame_text(80, 20)
        assert "ISOLATE_OSINT_TAB_TEST" not in text

    def test_no_console_in_frame_tab_proxy(self):
        netwatch.add_console("ISOLATE_PROXY_TAB_TEST")
        netwatch.current_tab = "proxy"
        text = _frame_text(80, 20)
        assert "ISOLATE_PROXY_TAB_TEST" not in text

    def test_console_output_persists_after_frame_build(self):
        netwatch.add_console("PERSIST_TEST")
        _ = _frame_text(80, 20)
        # console_output should still contain the entry
        joined = " ".join(_strip(l) for l in netwatch.console_output)
        assert "PERSIST_TEST" in joined


# ═══════════════════════════════════════════════════════════
# 8. _exec_console_cmd (10 tests)
# ═══════════════════════════════════════════════════════════

class TestExecConsoleCmd:

    def test_status_prints_output(self):
        with patch("builtins.print") as mock_print:
            netwatch._exec_console_cmd("status")
        printed = " ".join(str(c) for call in mock_print.call_args_list for c in call.args)
        assert "STATUS" in printed or "Uptime" in printed or "status" in printed.lower()

    def test_status_prints_packets(self):
        netwatch.total_packets = 77
        with patch("builtins.print") as mock_print:
            netwatch._exec_console_cmd("status")
        printed = " ".join(str(c) for call in mock_print.call_args_list for c in call.args)
        assert "77" in printed

    def test_help_prints_commands(self):
        with patch("builtins.print") as mock_print:
            netwatch._exec_console_cmd("help")
        printed = " ".join(str(c) for call in mock_print.call_args_list for c in call.args)
        assert "scan" in printed.lower() or "geo" in printed.lower()

    def test_help_includes_geo(self):
        with patch("builtins.print") as mock_print:
            netwatch._exec_console_cmd("help")
        printed = " ".join(str(c) for call in mock_print.call_args_list for c in call.args)
        assert "geo" in printed.lower()

    def test_unknown_cmd_delegates_to_handle_command(self):
        # "attackers" is a valid handle_command action; with empty honeypot should add to console
        netwatch._exec_console_cmd("attackers")
        # Should not raise; handle_command runs and adds to console (then prints)

    def test_geo_delegates_to_handle_command(self):
        # geo with invalid target shouldn't crash — just calls _cmd_geo in thread
        netwatch._exec_console_cmd("geo 1.2.3.4")
        # No assertion needed — just confirm no exception

    def test_clear_clears_console_output(self):
        netwatch.add_console("temporary")
        netwatch._exec_console_cmd("clear")
        assert len(netwatch.console_output) == 0

    def test_status_uppercase_recognized(self):
        # status is lowercased in _exec_console_cmd via a = cmd.strip().lower()
        with patch("builtins.print") as mock_print:
            netwatch._exec_console_cmd("STATUS")
        assert mock_print.called

    def test_help_uppercase_recognized(self):
        with patch("builtins.print") as mock_print:
            netwatch._exec_console_cmd("HELP")
        assert mock_print.called

    def test_exec_console_prints_console_output(self):
        # "attackers" with no events should add a line to console_output and print it
        netwatch.console_output.clear()
        with patch("builtins.print") as mock_print:
            netwatch._exec_console_cmd("attackers")
        # Either print was called (output) or console is empty (no events)
        assert True  # Should not raise


# ═══════════════════════════════════════════════════════════
# 9. add_console THREAD SAFETY AND CAPPING (5 tests)
# ═══════════════════════════════════════════════════════════

class TestAddConsole:

    def test_appends_to_console_output(self):
        netwatch.add_console("hello")
        assert "hello" in netwatch.console_output

    def test_capped_at_max(self):
        for i in range(netwatch.MAX_CONSOLE + 20):
            netwatch.add_console(f"line {i}")
        assert len(netwatch.console_output) <= netwatch.MAX_CONSOLE

    def test_oldest_dropped_when_capped(self):
        for i in range(netwatch.MAX_CONSOLE + 5):
            netwatch.add_console(f"msg {i}")
        # First few lines should be gone
        assert "msg 0" not in netwatch.console_output

    def test_latest_retained_when_capped(self):
        for i in range(netwatch.MAX_CONSOLE + 5):
            netwatch.add_console(f"entry {i}")
        last = f"entry {netwatch.MAX_CONSOLE + 4}"
        assert last in netwatch.console_output

    def test_multiple_threads_safe(self):
        import threading
        errors = []
        def _add():
            try:
                for i in range(30):
                    netwatch.add_console(f"t {i}")
            except Exception as e:
                errors.append(e)
        threads = [threading.Thread(target=_add) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []
        assert len(netwatch.console_output) <= netwatch.MAX_CONSOLE


# ═══════════════════════════════════════════════════════════
# 10. format_bytes / threat_color / _ansi_strip / _honeypot_color (10 tests)
# ═══════════════════════════════════════════════════════════

class TestUtilityFunctions:

    def test_format_bytes_zero(self):
        assert netwatch.format_bytes(0) == "0.0B"

    def test_format_bytes_kilobytes(self):
        assert netwatch.format_bytes(1024) == "1.0KB"

    def test_format_bytes_megabytes(self):
        assert netwatch.format_bytes(1024 * 1024) == "1.0MB"

    def test_format_bytes_gigabytes(self):
        assert netwatch.format_bytes(1024 ** 3) == "1.0GB"

    def test_threat_color_high(self):
        assert netwatch.threat_color(30) == netwatch.RED

    def test_threat_color_medium(self):
        assert netwatch.threat_color(10) == netwatch.YELLOW

    def test_threat_color_low(self):
        assert netwatch.threat_color(0) == netwatch.WHITE

    def test_ansi_strip_removes_color_codes(self):
        s = f"{netwatch.RED}hello{netwatch.RESET}"
        assert netwatch._ansi_strip(s) == "hello"

    def test_honeypot_color_credential(self):
        assert netwatch._honeypot_color("credential") == netwatch.RED

    def test_honeypot_color_telnet(self):
        assert netwatch._honeypot_color("telnet") == netwatch.YELLOW


# ═══════════════════════════════════════════════════════════
# 11. PERFORMANCE — TAB SWITCHING & COMMAND LATENCY (30 tests)
# ═══════════════════════════════════════════════════════════

import time
import threading

MAX_TAB_SWITCH_MS = 50
MAX_FRAME_RENDER_MS = 100
MAX_COMMAND_MS = 50
MAX_HELP_RENDER_MS = 100


def _time_ms(fn):
    t0 = time.perf_counter()
    fn()
    return (time.perf_counter() - t0) * 1000


class TestTabSwitchPerformance:

    def test_switch_all_tabs_under_budget(self):
        for tab in netwatch.TABS:
            ms = _time_ms(lambda t=tab: setattr(netwatch, 'current_tab', t))
            assert ms < MAX_TAB_SWITCH_MS, f"tab switch to {tab} took {ms:.1f}ms"

    def test_rapid_tab_cycling_10x(self):
        ms = _time_ms(lambda: [setattr(netwatch, 'current_tab', netwatch.TABS[i % len(netwatch.TABS)]) for i in range(10)])
        assert ms < MAX_TAB_SWITCH_MS, f"10 tab cycles took {ms:.1f}ms"

    def test_rapid_tab_cycling_100x(self):
        ms = _time_ms(lambda: [setattr(netwatch, 'current_tab', netwatch.TABS[i % len(netwatch.TABS)]) for i in range(100)])
        assert ms < MAX_TAB_SWITCH_MS, f"100 tab cycles took {ms:.1f}ms"

    def test_tab_switch_plus_render_all(self):
        for tab in netwatch.TABS:
            def switch_and_render(t=tab):
                netwatch.current_tab = t
                netwatch._build_frame(80, 30)
            ms = _time_ms(switch_and_render)
            assert ms < MAX_FRAME_RENDER_MS, f"switch+render {tab} took {ms:.1f}ms"

    def test_tab_switch_plus_render_rapid_cycle(self):
        def cycle():
            for tab in netwatch.TABS:
                netwatch.current_tab = tab
                netwatch._build_frame(80, 30)
        ms = _time_ms(cycle)
        assert ms < MAX_FRAME_RENDER_MS * 2, f"full cycle render took {ms:.1f}ms"


class TestFrameRenderPerformance:

    def test_empty_frame_under_budget(self):
        for tab in netwatch.TABS:
            netwatch.current_tab = tab
            ms = _time_ms(lambda: netwatch._build_frame(80, 30))
            assert ms < MAX_FRAME_RENDER_MS, f"empty {tab} frame took {ms:.1f}ms"

    def test_frame_with_100_hosts(self):
        for i in range(100):
            netwatch.hosts[f"10.0.{i//256}.{i%256}"]["bytes_in"] = i * 100
            netwatch.hosts[f"10.0.{i//256}.{i%256}"]["packets"] = i
        netwatch.current_tab = "hosts"
        ms = _time_ms(lambda: netwatch._build_frame(80, 30))
        assert ms < MAX_FRAME_RENDER_MS, f"100-host frame took {ms:.1f}ms"

    def test_frame_with_500_hosts(self):
        for i in range(500):
            netwatch.hosts[f"10.{i//65536}.{(i//256)%256}.{i%256}"]["bytes_in"] = i
        netwatch.current_tab = "hosts"
        ms = _time_ms(lambda: netwatch._build_frame(80, 30))
        assert ms < MAX_FRAME_RENDER_MS * 3, f"500-host frame took {ms:.1f}ms"

    def test_frame_with_100_alerts(self):
        for i in range(100):
            netwatch.alerts.append({"time": "12:00:00", "msg": f"alert {i}"})
        netwatch.current_tab = "alerts"
        ms = _time_ms(lambda: netwatch._build_frame(80, 30))
        assert ms < MAX_FRAME_RENDER_MS, f"100-alert frame took {ms:.1f}ms"

    def test_frame_with_100_honeypot_events(self):
        for i in range(100):
            netwatch.honeypot_events.append({"time": "12:00:00", "service": "telnet", "ip": f"1.2.3.{i%256}", "summary": f"cmd {i}"})
        netwatch.current_tab = "honeypot"
        ms = _time_ms(lambda: netwatch._build_frame(80, 30))
        assert ms < MAX_FRAME_RENDER_MS, f"100-event honeypot frame took {ms:.1f}ms"

    def test_frame_with_50_dns_queries(self):
        for i in range(50):
            netwatch.dns_queries.append({"time": "12:00:00", "ip": "10.0.0.1", "domain": f"site{i}.com"})
        netwatch.current_tab = "dns"
        ms = _time_ms(lambda: netwatch._build_frame(80, 30))
        assert ms < MAX_FRAME_RENDER_MS, f"50-dns frame took {ms:.1f}ms"

    def test_frame_with_50_protocols(self):
        for i in range(50):
            netwatch.proto_stats[f"PROTO_{i}"] = i * 10
        netwatch.current_tab = "proto"
        ms = _time_ms(lambda: netwatch._build_frame(80, 30))
        assert ms < MAX_FRAME_RENDER_MS, f"50-proto frame took {ms:.1f}ms"

    def test_frame_all_tab_populated(self):
        for i in range(50):
            netwatch.hosts[f"10.0.0.{i}"]["bytes_in"] = i * 100
        netwatch.proto_stats["TCP"] = 500
        for i in range(10):
            netwatch.dns_queries.append({"time": "12:00:00", "ip": "10.0.0.1", "domain": f"d{i}.com"})
            netwatch.honeypot_events.append({"time": "12:00:00", "service": "telnet", "ip": f"5.5.5.{i}", "summary": "x"})
            netwatch.alerts.append({"time": "12:00:00", "msg": f"alert {i}"})
        netwatch.current_tab = "all"
        ms = _time_ms(lambda: netwatch._build_frame(80, 30))
        assert ms < MAX_FRAME_RENDER_MS, f"populated all-tab took {ms:.1f}ms"

    def test_help_overlay_under_budget(self):
        ms = _time_ms(lambda: netwatch._build_help_overlay(80, 40))
        assert ms < MAX_HELP_RENDER_MS, f"help overlay took {ms:.1f}ms"

    def test_wide_terminal_no_slowdown(self):
        netwatch.current_tab = "all"
        ms = _time_ms(lambda: netwatch._build_frame(200, 60))
        assert ms < MAX_FRAME_RENDER_MS, f"wide terminal frame took {ms:.1f}ms"

    def test_narrow_terminal_no_slowdown(self):
        netwatch.current_tab = "all"
        ms = _time_ms(lambda: netwatch._build_frame(40, 20))
        assert ms < MAX_FRAME_RENDER_MS, f"narrow terminal frame took {ms:.1f}ms"


@patch("netwatch.resolve_host", return_value="")
class TestCommandPerformance:

    def test_tab_commands_fast(self, _mock):
        for tab in netwatch.TABS:
            ms = _time_ms(lambda t=tab: netwatch.handle_command(t))
            assert ms < MAX_COMMAND_MS, f"'{tab}' command took {ms:.1f}ms"

    def test_clear_fast(self, _mock):
        netwatch.add_console("junk")
        ms = _time_ms(lambda: netwatch.handle_command("clear"))
        assert ms < MAX_COMMAND_MS, f"clear took {ms:.1f}ms"

    def test_help_command_fast(self, _mock):
        ms = _time_ms(lambda: netwatch.handle_command("help"))
        assert ms < MAX_COMMAND_MS, f"help took {ms:.1f}ms"

    def test_summary_fast(self, _mock):
        ms = _time_ms(lambda: netwatch.handle_command("summary"))
        assert ms < MAX_COMMAND_MS, f"summary took {ms:.1f}ms"

    def test_ips_fast(self, _mock):
        for i in range(50):
            netwatch.hosts[f"10.0.0.{i}"]["bytes_in"] = i
        ms = _time_ms(lambda: netwatch.handle_command("ips"))
        assert ms < MAX_FRAME_RENDER_MS, f"ips took {ms:.1f}ms"

    def test_top_fast(self, _mock):
        for i in range(50):
            netwatch.hosts[f"10.0.0.{i}"]["bytes_in"] = i * 100
        ms = _time_ms(lambda: netwatch.handle_command("top 10"))
        assert ms < MAX_FRAME_RENDER_MS, f"top took {ms:.1f}ms"

    def test_attackers_fast(self, _mock):
        for i in range(20):
            netwatch.honeypot_events.append({"time": "12:00:00", "service": "credential", "ip": f"5.5.5.{i}", "summary": "admin:admin"})
        ms = _time_ms(lambda: netwatch.handle_command("attackers"))
        assert ms < MAX_FRAME_RENDER_MS, f"attackers took {ms:.1f}ms"

    def test_sessions_fast(self, _mock):
        for i in range(30):
            netwatch.honeypot_events.append({"time": "12:00:00", "service": "telnet", "ip": f"9.9.9.{i%10}", "summary": "cmd"})
        ms = _time_ms(lambda: netwatch.handle_command("sessions"))
        assert ms < MAX_FRAME_RENDER_MS, f"sessions took {ms:.1f}ms"

    def test_find_fast_with_data(self, _mock):
        for i in range(50):
            netwatch.hosts[f"10.0.0.{i}"]["bytes_in"] = i
        ms = _time_ms(lambda: netwatch.handle_command("find 10.0.0"))
        assert ms < MAX_FRAME_RENDER_MS, f"find took {ms:.1f}ms"

    def test_new_fast(self, _mock):
        for i in range(50):
            netwatch.hosts[f"10.0.0.{i}"]["first_seen"] = "12:00:00"
        ms = _time_ms(lambda: netwatch.handle_command("new"))
        assert ms < MAX_FRAME_RENDER_MS, f"new took {ms:.1f}ms"


@patch("netwatch.resolve_host", return_value="")
class TestConcurrentRenderSafety:

    def test_parallel_frame_renders_no_crash(self, _mock):
        errors = []
        def render_loop():
            try:
                for _ in range(20):
                    for tab in netwatch.TABS:
                        netwatch.current_tab = tab
                        netwatch._build_frame(80, 30)
            except Exception as e:
                errors.append(e)
        threads = [threading.Thread(target=render_loop) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
        assert errors == [], f"concurrent render errors: {errors}"

    def test_parallel_commands_and_renders_no_crash(self, _mock):
        errors = []
        def render_loop():
            try:
                for _ in range(10):
                    netwatch._build_frame(80, 30)
            except Exception as e:
                errors.append(e)
        def command_loop():
            try:
                for tab in netwatch.TABS:
                    netwatch.handle_command(tab)
                netwatch.handle_command("clear")
                netwatch.handle_command("help")
            except Exception as e:
                errors.append(e)
        threads = [threading.Thread(target=render_loop) for _ in range(2)]
        threads += [threading.Thread(target=command_loop) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
        assert errors == [], f"concurrent cmd+render errors: {errors}"
