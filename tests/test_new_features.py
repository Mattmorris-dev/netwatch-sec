"""Tests for NetWatch v1.1 features: time-series, mesh, GraphQL, web UI, TUI fixes."""
import sys
import os
import json
import time
import threading
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
with patch("subprocess.check_output", return_value="inet 10.0.1.9/24 scope global\ninet 127.0.0.1/8 scope host"):
    with patch.dict(os.environ, {"WERKZEUG_RUN_MAIN": "true"}):
        import netwatch


# ═══════════════════════════════════════════════════════════
#  TIME-SERIES
# ═══════════════════════════════════════════════════════════

class TestTimeSeries:

    def setup_method(self):
        netwatch._ts_samples.clear()

    def test_ts_samples_initially_empty(self):
        assert netwatch._ts_samples == []

    def test_ts_max_constant(self):
        assert netwatch._TS_MAX == 360

    def test_ts_samples_bounded(self):
        for i in range(400):
            netwatch._ts_samples.append({"ts": i, "packets": i, "bytes": i * 100, "protos": {}})
        with netwatch._ts_lock:
            if len(netwatch._ts_samples) > netwatch._TS_MAX:
                del netwatch._ts_samples[:len(netwatch._ts_samples) - netwatch._TS_MAX]
        assert len(netwatch._ts_samples) <= netwatch._TS_MAX

    def test_ts_sample_structure(self):
        sample = {"ts": int(time.time()), "packets": 100, "bytes": 5000, "protos": {"TCP": 50}}
        netwatch._ts_samples.append(sample)
        assert netwatch._ts_samples[0]["packets"] == 100
        assert netwatch._ts_samples[0]["protos"]["TCP"] == 50

    def test_ts_api_endpoint_exists(self):
        netwatch.web_app.config["TESTING"] = True
        old_token = netwatch.WEB_TOKEN
        netwatch.WEB_TOKEN = ""
        try:
            with netwatch.web_app.test_client() as c:
                netwatch._ts_samples.append({"ts": 1, "packets": 0, "bytes": 0, "protos": {}})
                resp = c.get("/api/timeseries")
                assert resp.status_code == 200
                data = json.loads(resp.data)
                assert isinstance(data, list)
                assert len(data) == 1
        finally:
            netwatch.WEB_TOKEN = old_token


# ═══════════════════════════════════════════════════════════
#  MESHTASTIC
# ═══════════════════════════════════════════════════════════

class TestMeshtastic:

    def setup_method(self):
        netwatch.mesh_messages.clear()
        netwatch.mesh_nodes.clear()
        netwatch.mesh_interface = None
        netwatch.mesh_alert_fwd = True

    def test_mesh_messages_initially_empty(self):
        assert netwatch.mesh_messages == []

    def test_mesh_nodes_initially_empty(self):
        assert netwatch.mesh_nodes == {}

    def test_mesh_send_fails_without_interface(self):
        assert netwatch.mesh_send("test") is False

    def test_mesh_send_succeeds_with_interface(self):
        mock_iface = MagicMock()
        netwatch.mesh_interface = mock_iface
        result = netwatch.mesh_send("hello mesh")
        assert result is True
        mock_iface.sendText.assert_called_once_with("hello mesh")
        assert len(netwatch.mesh_messages) == 1
        assert netwatch.mesh_messages[0]["text"] == "hello mesh"
        assert netwatch.mesh_messages[0]["type"] == "sent"
        netwatch.mesh_interface = None

    def test_mesh_forward_alert_sends(self):
        mock_iface = MagicMock()
        netwatch.mesh_interface = mock_iface
        netwatch._mesh_forward_alert("test alert from 10.0.1.5")
        mock_iface.sendText.assert_called_once()
        call_args = mock_iface.sendText.call_args[0][0]
        assert "[NW]" in call_args
        netwatch.mesh_interface = None

    def test_mesh_forward_alert_truncates_long_messages(self):
        mock_iface = MagicMock()
        netwatch.mesh_interface = mock_iface
        long_msg = "A" * 500
        netwatch._mesh_forward_alert(long_msg)
        call_args = mock_iface.sendText.call_args[0][0]
        assert len(call_args) <= 210
        netwatch.mesh_interface = None

    def test_mesh_forward_disabled(self):
        mock_iface = MagicMock()
        netwatch.mesh_interface = mock_iface
        netwatch.mesh_alert_fwd = False
        netwatch._mesh_forward_alert("test")
        mock_iface.sendText.assert_not_called()
        netwatch.mesh_interface = None

    def test_mesh_on_recv_stores_message(self):
        packet = {
            "decoded": {"text": "incoming message"},
            "fromId": "!abc123",
            "from": "Node1",
            "snr": 5.5,
        }
        netwatch._on_mesh_recv(packet)
        assert len(netwatch.mesh_messages) == 1
        assert netwatch.mesh_messages[0]["text"] == "incoming message"
        assert netwatch.mesh_messages[0]["type"] == "recv"
        assert "!abc123" in netwatch.mesh_nodes

    def test_mesh_on_recv_ignores_empty_text(self):
        packet = {"decoded": {}, "fromId": "!abc123"}
        netwatch._on_mesh_recv(packet)
        assert len(netwatch.mesh_messages) == 0

    def test_mesh_messages_bounded(self):
        netwatch.mesh_interface = MagicMock()
        for i in range(250):
            netwatch.mesh_messages.append({"ts": "00:00", "from": "x", "text": str(i), "type": "recv"})
        with netwatch.lock:
            if len(netwatch.mesh_messages) > netwatch._MESH_MAX_MSGS:
                del netwatch.mesh_messages[:len(netwatch.mesh_messages) - netwatch._MESH_MAX_MSGS]
        assert len(netwatch.mesh_messages) <= netwatch._MESH_MAX_MSGS
        netwatch.mesh_interface = None

    def test_mesh_command_switches_tab(self):
        netwatch.current_tab = "all"
        netwatch.handle_command("mesh")
        assert netwatch.current_tab == "mesh"

    def test_mesh_status_command(self):
        netwatch.console_output.clear()
        netwatch.handle_command("mesh status")
        output = " ".join(netwatch.console_output)
        assert "not connected" in output.lower() or "mesh" in output.lower()

    def test_mesh_alert_toggle(self):
        netwatch.handle_command("mesh alert off")
        assert netwatch.mesh_alert_fwd is False
        netwatch.handle_command("mesh alert on")
        assert netwatch.mesh_alert_fwd is True

    def test_mesh_send_command_no_interface(self):
        netwatch.console_output.clear()
        netwatch.handle_command("mesh send hello world")
        output = " ".join(netwatch.console_output)
        assert "not connected" in output.lower()

    def test_mesh_api_endpoint(self):
        netwatch.web_app.config["TESTING"] = True
        old_token = netwatch.WEB_TOKEN
        netwatch.WEB_TOKEN = ""
        try:
            with netwatch.web_app.test_client() as c:
                resp = c.get("/api/mesh")
                assert resp.status_code == 200
                data = json.loads(resp.data)
                assert "connected" in data
                assert "messages" in data
                assert "nodes" in data
        finally:
            netwatch.WEB_TOKEN = old_token

    def test_mesh_send_api_empty_rejected(self):
        netwatch.web_app.config["TESTING"] = True
        old_token = netwatch.WEB_TOKEN
        netwatch.WEB_TOKEN = ""
        try:
            with netwatch.web_app.test_client() as c:
                resp = c.post("/api/mesh/send",
                    data=json.dumps({"text": ""}),
                    content_type="application/json",
                    headers={"Origin": f"http://localhost:{netwatch.WEB_PORT}"})
                assert resp.status_code == 200
                data = json.loads(resp.data)
                assert "error" in data
        finally:
            netwatch.WEB_TOKEN = old_token

    def test_mesh_send_api_too_long_rejected(self):
        netwatch.web_app.config["TESTING"] = True
        old_token = netwatch.WEB_TOKEN
        netwatch.WEB_TOKEN = ""
        try:
            with netwatch.web_app.test_client() as c:
                resp = c.post("/api/mesh/send",
                    data=json.dumps({"text": "A" * 300}),
                    content_type="application/json",
                    headers={"Origin": f"http://localhost:{netwatch.WEB_PORT}"})
                data = json.loads(resp.data)
                assert "error" in data
        finally:
            netwatch.WEB_TOKEN = old_token


# ═══════════════════════════════════════════════════════════
#  TUI RENDER FIX
# ═══════════════════════════════════════════════════════════

class TestTUIRenderFix:

    def test_redraw_event_exists(self):
        assert hasattr(netwatch, '_redraw_event')

    def test_redraw_event_is_threading_event(self):
        assert isinstance(netwatch._redraw_event, threading.Event)

    def test_mesh_tab_in_tabs(self):
        assert "mesh" in netwatch.TABS

    def test_section_mesh_no_crash_without_device(self):
        lines = netwatch._section_mesh()
        assert isinstance(lines, list)
        assert len(lines) > 0

    def test_section_mesh_with_messages(self):
        netwatch.mesh_interface = MagicMock()
        netwatch.mesh_messages.append({
            "ts": "12:00", "from": "Node1", "text": "test", "type": "recv"
        })
        netwatch.mesh_nodes["!abc"] = {"name": "Node1", "snr": 5.0, "last_heard": "12:00"}
        lines = netwatch._section_mesh()
        text = " ".join(lines)
        assert "Node1" in text
        netwatch.mesh_interface = None


# ═══════════════════════════════════════════════════════════
#  WEB UI CLICKABLE IPS
# ═══════════════════════════════════════════════════════════

class TestWebUIClickable:

    def test_ip_click_class_in_html(self):
        assert "ip-click" in netwatch.WEB_DASHBOARD_HTML

    def test_ctx_menu_in_html(self):
        assert "ctx-menu" in netwatch.WEB_DASHBOARD_HTML

    def test_ctx_actions_in_html(self):
        assert "CTX_ACTIONS" in netwatch.WEB_DASHBOARD_HTML

    def test_output_panel_in_html(self):
        assert "output-panel" in netwatch.WEB_DASHBOARD_HTML

    def test_chart_js_included(self):
        assert "chart.js" in netwatch.WEB_DASHBOARD_HTML or "Chart" in netwatch.WEB_DASHBOARD_HTML

    def test_mesh_tab_in_web_tabs(self):
        assert '"mesh"' in netwatch.WEB_DASHBOARD_HTML

    def test_chart_canvas_elements(self):
        assert "chart-traffic" in netwatch.WEB_DASHBOARD_HTML
        assert "chart-proto" in netwatch.WEB_DASHBOARD_HTML
        assert "chart-threat" in netwatch.WEB_DASHBOARD_HTML

    def test_context_menu_has_scan(self):
        assert '"scan"' in netwatch.WEB_DASHBOARD_HTML

    def test_context_menu_has_geo(self):
        assert '"geo"' in netwatch.WEB_DASHBOARD_HTML

    def test_context_menu_has_fullrecon(self):
        assert '"fullrecon"' in netwatch.WEB_DASHBOARD_HTML

    def test_mesh_send_function_in_html(self):
        assert "sendMesh" in netwatch.WEB_DASHBOARD_HTML

    def test_render_mesh_function_in_html(self):
        assert "renderMesh" in netwatch.WEB_DASHBOARD_HTML


# ═══════════════════════════════════════════════════════════
#  STATE SNAPSHOT
# ═══════════════════════════════════════════════════════════

class TestStateSnapshot:

    def test_snapshot_has_threat_dist(self):
        snap = netwatch._state_snapshot()
        assert "threat_dist" in snap
        td = snap["threat_dist"]
        assert "clean" in td
        assert "low" in td
        assert "medium" in td
        assert "high" in td

    def test_snapshot_has_mesh_fields(self):
        snap = netwatch._state_snapshot()
        assert "mesh_connected" in snap
        assert "mesh_msgs" in snap
        assert "mesh_nodes" in snap

    def test_threat_dist_counts_correctly(self):
        netwatch.hosts["1.1.1.1"] = {
            "bytes_in": 0, "bytes_out": 0, "packets": 1, "ports": set(),
            "hostname": "", "threat_score": 0, "tags": set(),
            "first_seen": "00:00", "last_seen": "00:00",
        }
        netwatch.hosts["2.2.2.2"] = {
            "bytes_in": 0, "bytes_out": 0, "packets": 1, "ports": set(),
            "hostname": "", "threat_score": 35, "tags": set(),
            "first_seen": "00:00", "last_seen": "00:00",
        }
        snap = netwatch._state_snapshot()
        assert snap["threat_dist"]["clean"] >= 1
        assert snap["threat_dist"]["high"] >= 1


# ═══════════════════════════════════════════════════════════
#  GRAPHQL (conditional)
# ═══════════════════════════════════════════════════════════

class TestGraphQL:

    def test_gql_flag_exists(self):
        assert hasattr(netwatch, '_HAS_GQL')

    def test_gql_graceful_when_not_installed(self):
        if not netwatch._HAS_GQL:
            assert not hasattr(netwatch, '_gql_schema')
