"""
Shared fixtures and mocks for NetWatch test suite.
All external I/O is mocked: subprocess, socket, requests, filesystem.
"""
import sys
import os
import json
import struct
import socket
import pytest
from unittest.mock import patch, MagicMock, PropertyMock
from collections import defaultdict
from datetime import datetime

# Ensure netwatch module is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Patch heavy imports before importing netwatch
# We need to prevent netwatch from opening raw sockets or binding ports on import
with patch("subprocess.check_output", return_value="inet 10.0.1.9/24 scope global\ninet 127.0.0.1/8 scope host"):
    with patch.dict(os.environ, {"WERKZEUG_RUN_MAIN": "true"}):
        import netwatch


@pytest.fixture(autouse=True)
def reset_global_state():
    """Reset all mutable global state between tests."""
    netwatch.honeypot_events.clear()
    netwatch.dns_queries.clear()
    netwatch.alerts.clear()
    netwatch.nmap_results.clear()
    netwatch.console_output.clear()
    netwatch.hosts.clear()
    netwatch.dns_cache.clear()
    netwatch.proto_stats.clear()
    netwatch.tshark_conversations.clear()
    netwatch.arp_table.clear()
    netwatch.tracked_ips.clear()
    netwatch.tracking_active.clear()
    netwatch.recon_reports.clear()
    netwatch.osint_results.clear()
    netwatch._session_store.clear()
    netwatch._service_conns.clear()
    netwatch.proxy_pool.clear()
    netwatch.proxy_rotate_idx = 0
    netwatch.proxy_rotation = False
    netwatch.total_packets = 0
    netwatch.total_bytes = 0
    netwatch.nmap_running = False
    netwatch.console_mode = False
    netwatch._input_active = False
    netwatch._redraw_event.clear()
    netwatch.current_tab = "all"
    netwatch.show_help_overlay = False
    netwatch.ip_tags.clear()
    netwatch.ip_notes.clear()
    netwatch.watchlist.clear()
    netwatch._ts_samples.clear()
    netwatch.mesh_messages.clear()
    netwatch.mesh_nodes.clear()
    netwatch.mesh_interface = None
    netwatch.mesh_alert_fwd = True
    netwatch._cmd_history.clear()
    netwatch._output_scroll = 0
    yield


@pytest.fixture(autouse=True)
def _isolate_log_dir(tmp_path, monkeypatch):
    """Redirect LOG_DIR/PCAP_DIR to a per-test tmp dir so tests never write to
    the real logs/ (which can hold root-owned files from a prior `sudo netwatch`
    run — an unwritable all_events.json then fails every test that logs an event).
    Mirrors the explicit `patch.object(netwatch, "LOG_DIR", tmp_path)` that many
    tests already do; here it is applied to every test uniformly."""
    d = tmp_path / "nwlogs"
    (d / "pcaps").mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(netwatch, "LOG_DIR", str(d))
    monkeypatch.setattr(netwatch, "PCAP_DIR", str(d / "pcaps"))
    yield


@pytest.fixture(autouse=True)
def mock_getaddrinfo(request):
    """Return a public IP for any DNS lookup so SSRF validators pass in tests."""
    if "integration" in (request.node.get_closest_marker("skipif") and "network" or ""):
        yield
        return
    if "IntegrationNetwork" in request.node.nodeid:
        yield
        return
    with patch("socket.getaddrinfo", return_value=[(2, 1, 6, '', ("93.184.216.34", 0))]):
        yield


@pytest.fixture
def flask_client():
    """Flask test client for honeypot HTTP routes."""
    netwatch.app.config["TESTING"] = True
    with netwatch.app.test_client() as client:
        yield client


@pytest.fixture
def sample_ip():
    return "203.0.113.42"


@pytest.fixture
def sample_local_ip():
    return "10.0.1.9"


@pytest.fixture
def mock_subprocess_run():
    """Mock subprocess.run returning configurable output."""
    with patch("netwatch.subprocess.run") as mock_run:
        result = MagicMock()
        result.stdout = ""
        result.stderr = ""
        result.returncode = 0
        mock_run.return_value = result
        yield mock_run


@pytest.fixture
def mock_requests():
    """Mock _proxied_get for OSINT functions."""
    with patch("netwatch._proxied_get") as mock_get:
        yield mock_get


@pytest.fixture
def mock_socket_connect():
    """Mock socket connections."""
    with patch("socket.socket") as mock_sock:
        instance = MagicMock()
        mock_sock.return_value = instance
        instance.__enter__ = MagicMock(return_value=instance)
        instance.__exit__ = MagicMock(return_value=False)
        yield instance


@pytest.fixture
def sample_geo_response():
    return {
        "status": "success",
        "country": "United States",
        "countryCode": "US",
        "region": "CA",
        "regionName": "California",
        "city": "San Francisco",
        "zip": "94102",
        "lat": 37.7749,
        "lon": -122.4194,
        "isp": "Example ISP",
        "org": "Example Org",
        "as": "AS12345 Example",
        "query": "203.0.113.42",
    }


@pytest.fixture
def sample_nmap_output():
    return """Starting Nmap 7.93 ( https://nmap.org ) at 2024-01-01 00:00 UTC
Nmap scan report for 203.0.113.42
Host is up (0.010s latency).
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.9
80/tcp  open  http    nginx 1.22
443/tcp open  https   nginx 1.22
Nmap done: 1 IP address (1 host up) scanned in 5.23 seconds"""


@pytest.fixture
def sample_ethernet_frame():
    """Build a valid Ethernet + IPv4 + TCP frame."""
    # Ethernet: dst(6) + src(6) + type(2) = 14 bytes
    eth = b'\xff\xff\xff\xff\xff\xff' + b'\x00\x11\x22\x33\x44\x55' + struct.pack("!H", 0x0800)
    # IP: version/IHL=0x45, TOS, total_len, ID, flags/frag, TTL, proto(TCP=6), checksum, src, dst
    ip_header = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, 40, 1, 0, 64, 6, 0,
        socket.inet_aton("192.168.1.100"),
        socket.inet_aton("203.0.113.42"))
    # TCP: src_port, dst_port, seq, ack, offset/flags, window, checksum, urgent
    tcp_header = struct.pack("!HHIIBBHHH", 54321, 80, 0, 0, 0x50, 0x02, 8192, 0, 0)
    return eth + ip_header + tcp_header


@pytest.fixture
def sample_dns_frame():
    """Build Ethernet + IP + UDP + DNS query frame."""
    eth = b'\xff\xff\xff\xff\xff\xff' + b'\x00\x11\x22\x33\x44\x55' + struct.pack("!H", 0x0800)
    ip_header = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, 60, 1, 0, 64, 17, 0,
        socket.inet_aton("10.0.1.9"),
        socket.inet_aton("8.8.8.8"))
    # UDP: src_port, dst_port, length, checksum
    udp_header = struct.pack("!HHHH", 12345, 53, 30, 0)
    # DNS query for "example.com"
    dns_payload = b'\x00\x01' + b'\x01\x00' + b'\x00\x01' + b'\x00\x00' + b'\x00\x00' + b'\x00\x00'
    dns_payload += b'\x07example\x03com\x00' + b'\x00\x01\x00\x01'
    return eth + ip_header + udp_header + dns_payload


@pytest.fixture
def mock_whois_lib():
    """Mock whois library."""
    with patch.object(netwatch, "whois_lib") as mock_lib:
        mock_lib.whois.return_value = MagicMock(
            domain_name="example.com",
            registrar="Example Registrar",
            creation_date="2020-01-01",
            expiration_date="2025-01-01",
            name_servers=["ns1.example.com", "ns2.example.com"],
            org="Example Org",
            country="US",
            whois_server=None,
            state=None,
            city=None,
            emails=None,
            dnssec=None,
        )
        yield mock_lib


@pytest.fixture
def mock_dns_lib():
    """Mock dnspython."""
    with patch.object(netwatch, "dns") as mock_dns:
        mock_resolver = MagicMock()
        mock_dns.resolver = mock_resolver
        mock_dns.reversename = MagicMock()
        yield mock_dns


@pytest.fixture
def populated_honeypot_events():
    """Pre-populate honeypot events for testing."""
    events = [
        {"time": "10:00:01", "service": "telnet", "ip": "203.0.113.42", "summary": "login admin/1234"},
        {"time": "10:00:05", "service": "credential", "ip": "203.0.113.42", "summary": "admin:password"},
        {"time": "10:00:10", "service": "telnet_cmd", "ip": "203.0.113.42", "summary": "cmd: wget"},
        {"time": "10:01:00", "service": "rtsp", "ip": "198.51.100.1", "summary": "RTSP probe"},
        {"time": "10:02:00", "service": "scan_probe", "ip": "192.0.2.5", "summary": "GET /admin"},
    ]
    netwatch.honeypot_events.extend(events)
    return events
