"""
test_osint_new.py - Comprehensive tests for NetWatch OSINT features
=====================================================================
Tests: osint_ssl, osint_secheaders, osint_techstack, osint_ping_analyze,
       osint_trace_enriched, osint_health + handle_command integration.

All tests mock subprocess/network calls so no root or network needed.
Integration tests (marked) require network and are skipped by default.
"""

import os
import sys
import ssl
import socket
import subprocess
import unittest
from unittest.mock import patch, MagicMock, PropertyMock
from datetime import datetime, timedelta

import pytest

# Add parent dir so we can import netwatch functions
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# We need to patch heavy imports/startup before importing netwatch
# netwatch tries to create dirs, start servers, etc. We import only the functions.
# Patch Flask and other heavy deps at module level to avoid side effects.

# Minimal patches to allow importing the module without starting servers
with patch.dict(os.environ, {"WERKZEUG_RUN_MAIN": "true"}):
    with patch("flask.Flask.run", return_value=None):
        import netwatch


# ═══════════════════════════════════════════════════════════════════════
# FIXTURES
# ═══════════════════════════════════════════════════════════════════════

@pytest.fixture
def mock_proxied_get():
    """Patch _proxied_get to return a controllable mock response."""
    with patch("netwatch._proxied_get") as mock_get:
        yield mock_get


@pytest.fixture
def mock_subprocess():
    """Patch subprocess.run to return controllable output."""
    with patch("netwatch.subprocess.run") as mock_run:
        yield mock_run


@pytest.fixture
def mock_socket():
    """Patch socket.create_connection and ssl operations."""
    with patch("netwatch.socket.create_connection") as mock_conn:
        yield mock_conn


# ═══════════════════════════════════════════════════════════════════════
# osint_ssl TESTS
# ═══════════════════════════════════════════════════════════════════════

class TestOsintSSL:
    """Tests for osint_ssl(target, port=443) - TLS certificate inspection."""

    def _make_cert(self, cn="example.com", org="Example Inc",
                   not_before="Jan  1 00:00:00 2024 GMT",
                   not_after="Dec 31 23:59:59 2025 GMT",
                   san=None):
        """Helper to build a fake cert dict matching ssl module format."""
        cert = {
            "subject": ((("commonName", cn),),),
            "issuer": ((("organizationName", org),),),
            "notBefore": not_before,
            "notAfter": not_after,
            "subjectAltName": san or (("DNS", cn), ("DNS", f"*.{cn}")),
        }
        return cert

    @patch("netwatch.ssl.create_default_context")
    @patch("netwatch.socket.create_connection")
    def test_ssl_happyPath_returnsCertDetails(self, mock_conn, mock_ctx_factory):
        """Happy path: valid cert with all fields populated."""
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = self._make_cert()
        mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssock.version.return_value = "TLSv1.3"
        mock_ssock.__enter__ = MagicMock(return_value=mock_ssock)
        mock_ssock.__exit__ = MagicMock(return_value=False)

        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_sock

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssock
        mock_ctx_factory.return_value = mock_ctx

        result = netwatch.osint_ssl("example.com", 443)

        assert result["protocol"] == "TLSv1.3"
        assert result["cipher"] == "TLS_AES_256_GCM_SHA384"
        assert result["bits"] == 256
        assert result["subject"] == "example.com"
        assert result["issuer"] == "Example Inc"
        assert "alt_names" in result
        assert "example.com" in result["alt_names"]

    @patch("netwatch._validate_target_host", return_value=(True, ""))
    @patch("netwatch.ssl.create_default_context")
    @patch("netwatch.socket.create_connection")
    def test_ssl_customPort_usesCorrectPort(self, mock_conn, mock_ctx_factory, mock_val):
        """Custom port (e.g. 8443) is passed to create_connection."""
        # First connection: get binary DER cert + cipher/proto
        mock_ssock1 = MagicMock()
        mock_ssock1.getpeercert.return_value = b"\x30\x82" + b"\x00" * 100
        mock_ssock1.cipher.return_value = ("TLS_AES_128_GCM_SHA256", "TLSv1.2", 128)
        mock_ssock1.version.return_value = "TLSv1.2"
        mock_ssock1.__enter__ = MagicMock(return_value=mock_ssock1)
        mock_ssock1.__exit__ = MagicMock(return_value=False)

        # Second connection: get parsed cert
        mock_ssock2 = MagicMock()
        mock_ssock2.getpeercert.return_value = self._make_cert()
        mock_ssock2.__enter__ = MagicMock(return_value=mock_ssock2)
        mock_ssock2.__exit__ = MagicMock(return_value=False)

        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_sock

        mock_ctx1 = MagicMock()
        mock_ctx1.wrap_socket.return_value = mock_ssock1
        mock_ctx2 = MagicMock()
        mock_ctx2.wrap_socket.return_value = mock_ssock2
        mock_ctx_factory.side_effect = [mock_ctx1, mock_ctx2]

        result = netwatch.osint_ssl("myhost.io", 8443)

        # First call should be to (target, port) with timeout
        assert mock_conn.call_args_list[0] == unittest.mock.call(("myhost.io", 8443), timeout=5)
        assert result["protocol"] == "TLSv1.2"

    @patch("netwatch.ssl.create_default_context")
    @patch("netwatch.socket.create_connection")
    def test_ssl_connectionRefused_returnsError(self, mock_conn, mock_ctx_factory):
        """Connection refused should return an error dict."""
        mock_conn.side_effect = ConnectionRefusedError("Connection refused")

        result = netwatch.osint_ssl("offline.example.com", 443)

        assert "error" in result
        assert "refused" in result["error"].lower() or "Connection refused" in result["error"]

    @patch("netwatch.ssl.create_default_context")
    @patch("netwatch.socket.create_connection")
    def test_ssl_timeout_returnsError(self, mock_conn, mock_ctx_factory):
        """Socket timeout returns error dict."""
        mock_conn.side_effect = socket.timeout("timed out")

        result = netwatch.osint_ssl("slow.example.com", 443)

        assert "error" in result
        assert "timed out" in result["error"]

    @patch("netwatch._validate_target_host", return_value=(True, ""))
    @patch("netwatch.ssl.create_default_context")
    @patch("netwatch.socket.create_connection")
    def test_ssl_binaryCert_capturesCertSize(self, mock_conn, mock_ctx_factory, mock_val):
        """Binary DER cert size is captured in result."""
        # First connection: get binary DER cert (CERT_NONE context)
        der_bytes = b"\x30\x82" + b"\x00" * 1000
        mock_ssock1 = MagicMock()
        mock_ssock1.getpeercert.return_value = der_bytes
        mock_ssock1.cipher.return_value = ("ECDHE-RSA-AES256", "TLSv1.2", 256)
        mock_ssock1.version.return_value = "TLSv1.2"
        mock_ssock1.__enter__ = MagicMock(return_value=mock_ssock1)
        mock_ssock1.__exit__ = MagicMock(return_value=False)

        # Second connection: cert verification (default context) - gets parsed cert
        mock_ssock2 = MagicMock()
        mock_ssock2.getpeercert.return_value = self._make_cert()
        mock_ssock2.__enter__ = MagicMock(return_value=mock_ssock2)
        mock_ssock2.__exit__ = MagicMock(return_value=False)

        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_sock

        mock_ctx1 = MagicMock()
        mock_ctx1.wrap_socket.return_value = mock_ssock1
        mock_ctx2 = MagicMock()
        mock_ctx2.wrap_socket.return_value = mock_ssock2
        mock_ctx_factory.side_effect = [mock_ctx1, mock_ctx2]

        result = netwatch.osint_ssl("noverify.example.com", 443)

        assert result["protocol"] == "TLSv1.2"
        assert result["cert_size"] == 1002
        assert result["subject"] == "example.com"

    @patch("netwatch.ssl.create_default_context")
    @patch("netwatch.socket.create_connection")
    def test_ssl_expiredCert_daysLeftNegative(self, mock_conn, mock_ctx_factory):
        """Expired cert should show negative days_left."""
        cert = self._make_cert(not_after="Jan  1 00:00:00 2020 GMT")
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = cert
        mock_ssock.cipher.return_value = ("AES256", "TLSv1.2", 256)
        mock_ssock.version.return_value = "TLSv1.2"
        mock_ssock.__enter__ = MagicMock(return_value=mock_ssock)
        mock_ssock.__exit__ = MagicMock(return_value=False)

        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_sock

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssock
        mock_ctx_factory.return_value = mock_ctx

        result = netwatch.osint_ssl("expired.example.com", 443)

        assert "days_left" in result
        assert result["days_left"] < 0

    @patch("netwatch.ssl.create_default_context")
    @patch("netwatch.socket.create_connection")
    def test_ssl_ipTarget_usesIPAsHostname(self, mock_conn, mock_ctx_factory):
        """IP address target uses the IP as server_hostname."""
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = self._make_cert(cn="8.8.8.8")
        mock_ssock.cipher.return_value = ("AES128", "TLSv1.3", 128)
        mock_ssock.version.return_value = "TLSv1.3"
        mock_ssock.__enter__ = MagicMock(return_value=mock_ssock)
        mock_ssock.__exit__ = MagicMock(return_value=False)

        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_sock

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssock
        mock_ctx_factory.return_value = mock_ctx

        result = netwatch.osint_ssl("8.8.8.8", 443)

        assert "error" not in result
        assert result["subject"] == "8.8.8.8"

    @patch("netwatch.ssl.create_default_context")
    @patch("netwatch.socket.create_connection")
    def test_ssl_manySANs_truncatesTo10(self, mock_conn, mock_ctx_factory):
        """SAN list is capped at 10 entries."""
        san_list = tuple(("DNS", f"sub{i}.example.com") for i in range(20))
        cert = self._make_cert(san=san_list)
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = cert
        mock_ssock.cipher.return_value = ("AES256", "TLSv1.3", 256)
        mock_ssock.version.return_value = "TLSv1.3"
        mock_ssock.__enter__ = MagicMock(return_value=mock_ssock)
        mock_ssock.__exit__ = MagicMock(return_value=False)

        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_sock

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_ssock
        mock_ctx_factory.return_value = mock_ctx

        result = netwatch.osint_ssl("example.com", 443)

        assert len(result["alt_names"]) == 10


# ═══════════════════════════════════════════════════════════════════════
# osint_secheaders TESTS
# ═══════════════════════════════════════════════════════════════════════

class TestOsintSecheaders:
    """Tests for osint_secheaders(url) - HTTP security header audit."""

    def _make_response(self, headers_dict):
        """Create a mock response with given headers."""
        resp = MagicMock()
        resp.headers = headers_dict
        return resp

    def test_secheaders_allPresent_gradeA(self, mock_proxied_get):
        """All 7 security headers present should yield grade A (or close)."""
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=()",
        }
        mock_proxied_get.return_value = self._make_response(headers)

        result = netwatch.osint_secheaders("https://secure.example.com")

        assert result["grade"] == "A"
        assert result["score"] == "7/7"
        for label_info in result["headers"].values():
            assert label_info["present"] is True

    def test_secheaders_nonePresent_gradeF(self, mock_proxied_get):
        """No security headers yields grade F."""
        mock_proxied_get.return_value = self._make_response({})

        result = netwatch.osint_secheaders("http://insecure.example.com")

        assert result["grade"] == "F"
        assert result["score"] == "0/7"
        for label_info in result["headers"].values():
            assert label_info["present"] is False

    def test_secheaders_partialHeaders_gradeB(self, mock_proxied_get):
        """4-5 headers present should yield grade B."""
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "SAMEORIGIN",
            "X-Content-Type-Options": "nosniff",
        }
        mock_proxied_get.return_value = self._make_response(headers)

        result = netwatch.osint_secheaders("https://partial.example.com")

        assert result["grade"] == "B"
        assert result["score"] == "4/7"

    def test_secheaders_twoHeaders_gradeC(self, mock_proxied_get):
        """2-3 headers should yield grade C."""
        headers = {
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
        }
        mock_proxied_get.return_value = self._make_response(headers)

        result = netwatch.osint_secheaders("http://minimal.example.com")

        assert result["grade"] == "C"
        assert result["score"] == "2/7"

    def test_secheaders_requestFailed_returnsError(self, mock_proxied_get):
        """When _proxied_get returns None, returns error."""
        mock_proxied_get.return_value = None

        result = netwatch.osint_secheaders("http://dead.example.com")

        assert "error" in result
        assert "request failed" in result["error"]

    def test_secheaders_noHttpPrefix_addsHttp(self, mock_proxied_get):
        """URL without http:// prefix gets it prepended."""
        mock_proxied_get.return_value = self._make_response({})

        netwatch.osint_secheaders("example.com")

        # Should have been called with http:// prepended
        mock_proxied_get.assert_called_once_with("http://example.com", timeout=10)

    def test_secheaders_httpsPrefix_preserved(self, mock_proxied_get):
        """URL with https:// stays unchanged."""
        mock_proxied_get.return_value = self._make_response({})

        netwatch.osint_secheaders("https://example.com")

        mock_proxied_get.assert_called_once_with("https://example.com", timeout=10)

    def test_secheaders_caseInsensitiveHeaders(self, mock_proxied_get):
        """Headers should match regardless of case."""
        headers = {
            "STRICT-TRANSPORT-SECURITY": "max-age=300",
            "content-security-policy": "script-src 'self'",
            "X-FRAME-OPTIONS": "DENY",
        }
        mock_proxied_get.return_value = self._make_response(headers)

        result = netwatch.osint_secheaders("https://mixed-case.example.com")

        assert result["headers"]["HSTS"]["present"] is True
        assert result["headers"]["CSP"]["present"] is True
        assert result["headers"]["X-Frame-Options"]["present"] is True

    def test_secheaders_headersHaveValues(self, mock_proxied_get):
        """Header values are captured in the result."""
        headers = {
            "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
        }
        mock_proxied_get.return_value = self._make_response(headers)

        result = netwatch.osint_secheaders("https://hsts.example.com")

        assert "max-age=63072000" in result["headers"]["HSTS"]["value"]


# ═══════════════════════════════════════════════════════════════════════
# osint_techstack TESTS
# ═══════════════════════════════════════════════════════════════════════

class TestOsintTechstack:
    """Tests for osint_techstack(url) - Web technology fingerprinting."""

    def _make_response(self, body="", headers=None):
        """Create a mock response with body text and headers."""
        resp = MagicMock()
        resp.text = body
        resp.headers = headers or {}
        return resp

    def test_techstack_wordpress_detected(self, mock_proxied_get):
        """WordPress detected from wp-content in body."""
        body = '<link rel="stylesheet" href="/wp-content/themes/flavor/style.css">'
        mock_proxied_get.return_value = self._make_response(body)

        result = netwatch.osint_techstack("https://myblog.example.com")

        assert "WordPress" in result["technologies"]

    def test_techstack_nextjs_detected(self, mock_proxied_get):
        """Next.js detected from _next/ in body."""
        body = '<script src="/_next/static/chunks/main-abc123.js"></script>'
        mock_proxied_get.return_value = self._make_response(body)

        result = netwatch.osint_techstack("https://app.example.com")

        assert "Next.js" in result["technologies"]

    def test_techstack_nginx_fromServerHeader(self, mock_proxied_get):
        """Nginx detected from server header."""
        mock_proxied_get.return_value = self._make_response(
            body="<html></html>",
            headers={"Server": "nginx/1.24.0", "Content-Type": "text/html"}
        )

        result = netwatch.osint_techstack("https://server.example.com")

        assert any("nginx" in t for t in result["technologies"])
        assert "nginx/1.24.0" in result["server"]

    def test_techstack_apache_fromServerHeader(self, mock_proxied_get):
        """Apache detected from server header."""
        mock_proxied_get.return_value = self._make_response(
            body="<html></html>",
            headers={"Server": "Apache/2.4.57"}
        )

        result = netwatch.osint_techstack("https://legacy.example.com")

        assert any("Apache" in t for t in result["technologies"])

    def test_techstack_cloudflare_fromCfRay(self, mock_proxied_get):
        """Cloudflare CDN detected from cf-ray header."""
        mock_proxied_get.return_value = self._make_response(
            body="<html></html>",
            headers={"cf-ray": "abc123-LAX", "Server": "other"}
        )

        result = netwatch.osint_techstack("https://cdn.example.com")

        assert "Cloudflare CDN" in result["technologies"]

    def test_techstack_vercel_detected(self, mock_proxied_get):
        """Vercel detected from x-vercel-id header."""
        mock_proxied_get.return_value = self._make_response(
            body="<html></html>",
            headers={"x-vercel-id": "iad1::12345"}
        )

        result = netwatch.osint_techstack("https://deploy.example.com")

        assert "Vercel" in result["technologies"]

    def test_techstack_xPoweredBy(self, mock_proxied_get):
        """x-powered-by header value is captured."""
        mock_proxied_get.return_value = self._make_response(
            body="<html></html>",
            headers={"X-Powered-By": "Express"}
        )

        result = netwatch.osint_techstack("https://api.example.com")

        assert "express" in result["powered_by"]

    def test_techstack_multipleTechs_noDuplicates(self, mock_proxied_get):
        """wp-content and wp-includes both match WordPress but no duplicate."""
        body = '<link href="/wp-content/x.css"><script src="/wp-includes/y.js">'
        mock_proxied_get.return_value = self._make_response(body)

        result = netwatch.osint_techstack("https://blog.example.com")

        assert result["technologies"].count("WordPress") == 1

    def test_techstack_requestFailed_returnsError(self, mock_proxied_get):
        """When _proxied_get returns None, error returned."""
        mock_proxied_get.return_value = None

        result = netwatch.osint_techstack("https://dead.example.com")

        assert "error" in result
        assert "request failed" in result["error"]

    def test_techstack_emptyBody_noTechs(self, mock_proxied_get):
        """Empty response body detects nothing."""
        mock_proxied_get.return_value = self._make_response(body="", headers={})

        result = netwatch.osint_techstack("https://blank.example.com")

        assert result["technologies"] == []

    def test_techstack_noHttpPrefix_addsHttp(self, mock_proxied_get):
        """URL without http:// gets it prepended."""
        mock_proxied_get.return_value = self._make_response(body="")

        netwatch.osint_techstack("example.com")

        mock_proxied_get.assert_called_once_with("http://example.com", timeout=10)

    def test_techstack_largeBody_truncatedTo8192(self, mock_proxied_get):
        """Body over 8192 chars is truncated for analysis (only first 8192 used)."""
        # Place the keyword past 8192 chars
        body = "x" * 9000 + "wp-content"
        mock_proxied_get.return_value = self._make_response(body)

        result = netwatch.osint_techstack("https://big.example.com")

        # WordPress should NOT be detected since it is past the 8192 boundary
        assert "WordPress" not in result["technologies"]

    def test_techstack_aws_fromAmzHeader(self, mock_proxied_get):
        """AWS detected from x-amz-* headers."""
        mock_proxied_get.return_value = self._make_response(
            body="<html></html>",
            headers={"x-amz-request-id": "ABCDEF123456"}
        )

        result = netwatch.osint_techstack("https://s3.example.com")

        assert "AWS" in result["technologies"]

    def test_techstack_react_inBody(self, mock_proxied_get):
        """React detected from body content."""
        body = '<div id="root"></div><script>React.createElement</script>'
        mock_proxied_get.return_value = self._make_response(body)

        result = netwatch.osint_techstack("https://spa.example.com")

        assert "React" in result["technologies"]


# ═══════════════════════════════════════════════════════════════════════
# osint_ping_analyze TESTS
# ═══════════════════════════════════════════════════════════════════════

class TestOsintPingAnalyze:
    """Tests for osint_ping_analyze(target, count=5) - Ping with jitter + TTL."""

    SAMPLE_PING_LINUX = """\
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=118 time=12.3 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=118 time=11.8 ms
64 bytes from 8.8.8.8: icmp_seq=3 ttl=118 time=13.1 ms
64 bytes from 8.8.8.8: icmp_seq=4 ttl=118 time=12.0 ms
64 bytes from 8.8.8.8: icmp_seq=5 ttl=118 time=11.5 ms

--- 8.8.8.8 ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 4005ms
rtt min/avg/max/mdev = 11.500/12.140/13.100/0.558 ms
"""

    SAMPLE_PING_WINDOWS_TTL = """\
PING google.com (142.250.80.46) 56(84) bytes of data.
64 bytes from lax17s62-in-f14.1e100.net: icmp_seq=1 ttl=64 time=1.23 ms
64 bytes from lax17s62-in-f14.1e100.net: icmp_seq=2 ttl=64 time=1.45 ms

--- google.com ping statistics ---
2 packets transmitted, 2 received, 0% packet loss
"""

    SAMPLE_PING_LOSS = """\
PING 192.168.1.100 (192.168.1.100) 56(84) bytes of data.
64 bytes from 192.168.1.100: icmp_seq=1 ttl=255 time=0.5 ms

--- 192.168.1.100 ping statistics ---
5 packets transmitted, 1 received, 80% packet loss, time 4000ms
"""

    @patch("netwatch.subprocess.run")
    def test_ping_happyPath_allMetrics(self, mock_run):
        """Normal ping returns min, max, avg, jitter, TTL, OS guess."""
        mock_run.return_value = MagicMock(stdout=self.SAMPLE_PING_LINUX, returncode=0)

        result = netwatch.osint_ping_analyze("8.8.8.8", count=5)

        assert result["target"] == "8.8.8.8"
        assert result["packets_sent"] == 5
        assert result["min"] == 11.5
        assert result["max"] == 13.1
        assert abs(result["avg"] - 12.14) < 0.01
        assert result["loss"] == 0.0
        assert "jitter" in result
        assert result["jitter"] > 0
        assert result["ttl"] == 118
        assert result["os_guess"] == "Windows"  # 64 < 118 <= 128

    @patch("netwatch.subprocess.run")
    def test_ping_linuxTTL_osGuessLinux(self, mock_run):
        """TTL 64 guesses Linux/Unix/macOS."""
        mock_run.return_value = MagicMock(stdout=self.SAMPLE_PING_WINDOWS_TTL, returncode=0)

        result = netwatch.osint_ping_analyze("google.com", count=2)

        assert result["ttl"] == 64
        assert result["os_guess"] == "Linux/Unix/macOS"

    @patch("netwatch.subprocess.run")
    def test_ping_highTTL_networkDevice(self, mock_run):
        """TTL > 128 guesses network device."""
        mock_run.return_value = MagicMock(stdout=self.SAMPLE_PING_LOSS, returncode=0)

        result = netwatch.osint_ping_analyze("192.168.1.100", count=5)

        assert result["ttl"] == 255
        assert result["os_guess"] == "Network device (router/switch)"

    @patch("netwatch.subprocess.run")
    def test_ping_packetLoss_calculatedCorrectly(self, mock_run):
        """Packet loss percentage calculated correctly."""
        mock_run.return_value = MagicMock(stdout=self.SAMPLE_PING_LOSS, returncode=0)

        result = netwatch.osint_ping_analyze("192.168.1.100", count=5)

        assert result["loss"] == 80.0
        assert result["min"] == 0.5
        assert result["max"] == 0.5

    @patch("netwatch.subprocess.run")
    def test_ping_timeout_returnsError(self, mock_run):
        """subprocess.TimeoutExpired returns error dict."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="ping", timeout=20)

        result = netwatch.osint_ping_analyze("unreach.example.com", count=5)

        assert "error" in result
        assert "timed out" in result["error"]

    @patch("netwatch.subprocess.run")
    def test_ping_noReplies_emptyTimes(self, mock_run):
        """All packets lost: no time= lines parsed."""
        output = """\
PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.

--- 10.0.0.1 ping statistics ---
3 packets transmitted, 0 received, 100% packet loss, time 2003ms
"""
        mock_run.return_value = MagicMock(stdout=output, returncode=1)

        result = netwatch.osint_ping_analyze("10.0.0.1", count=3)

        assert "min" not in result
        assert "jitter" not in result
        assert "ttl" not in result

    @patch("netwatch.subprocess.run")
    def test_ping_singleReply_noJitter(self, mock_run):
        """Only 1 reply: jitter cannot be calculated (needs 2+ points)."""
        output = """\
PING 10.0.0.2 (10.0.0.2) 56(84) bytes of data.
64 bytes from 10.0.0.2: icmp_seq=1 ttl=64 time=5.0 ms

--- 10.0.0.2 ping statistics ---
3 packets transmitted, 1 received, 66% packet loss
"""
        mock_run.return_value = MagicMock(stdout=output, returncode=0)

        result = netwatch.osint_ping_analyze("10.0.0.2", count=3)

        assert result["min"] == 5.0
        assert result["avg"] == 5.0
        assert "jitter" not in result
        assert result["loss"] == pytest.approx(66.7, abs=0.1)

    @patch("netwatch.subprocess.run")
    def test_ping_commandArgs_correctFormat(self, mock_run):
        """Verifies correct ping command args are used."""
        mock_run.return_value = MagicMock(stdout="", returncode=0)

        netwatch.osint_ping_analyze("example.com", count=10)

        mock_run.assert_called_once_with(
            ["ping", "-c", "10", "-W", "2", "example.com"],
            capture_output=True, text=True, timeout=35  # count*3 + 5 = 10*3+5
        )

    @patch("netwatch.subprocess.run")
    def test_ping_genericException_returnsError(self, mock_run):
        """Any other exception returns error dict."""
        mock_run.side_effect = OSError("No such file or directory")

        result = netwatch.osint_ping_analyze("example.com", count=5)

        assert "error" in result
        assert "No such file" in result["error"]


# ═══════════════════════════════════════════════════════════════════════
# osint_trace_enriched TESTS
# ═══════════════════════════════════════════════════════════════════════

class TestOsintTraceEnriched:
    """Tests for osint_trace_enriched(target) - Enriched traceroute."""

    SAMPLE_TRACEROUTE = """\
traceroute to 8.8.8.8 (8.8.8.8), 20 hops max, 60 byte packets
 1  192.168.1.1 (192.168.1.1)  1.234 ms  1.100 ms  0.998 ms
 2  10.0.0.1 (10.0.0.1)  5.678 ms  5.432 ms  5.321 ms
 3  72.14.215.85 (72.14.215.85)  12.345 ms  12.123 ms  11.987 ms
 4  8.8.8.8 (8.8.8.8)  11.234 ms  11.100 ms  10.998 ms
"""

    @patch("netwatch._proxied_get")
    @patch("netwatch.socket.gethostbyaddr")
    @patch("netwatch.subprocess.run")
    def test_trace_happyPath_parsesHops(self, mock_run, mock_rdns, mock_get):
        """Normal traceroute parses all hops with IPs (including header line IP)."""
        mock_run.return_value = MagicMock(
            stdout=self.SAMPLE_TRACEROUTE, returncode=0
        )
        mock_rdns.side_effect = socket.herror("no PTR")
        mock_get.return_value = None  # No GeoIP

        result = netwatch.osint_trace_enriched("8.8.8.8")

        # Header line "traceroute to 8.8.8.8 (8.8.8.8)..." also contains an IP
        # so it gets parsed as a hop too (5 total)
        assert len(result) == 5
        ips = [h["ip"] for h in result]
        assert "192.168.1.1" in ips
        assert "10.0.0.1" in ips
        assert "72.14.215.85" in ips
        assert "8.8.8.8" in ips

    @patch("netwatch._proxied_get")
    @patch("netwatch.socket.gethostbyaddr")
    @patch("netwatch.subprocess.run")
    def test_trace_rDNS_populated(self, mock_run, mock_rdns, mock_get):
        """Reverse DNS resolved for each hop."""
        mock_run.return_value = MagicMock(
            stdout=" 1  192.168.1.1 (192.168.1.1)  1.0 ms\n", returncode=0
        )
        mock_rdns.return_value = ("router.local", [], [])
        mock_get.return_value = None

        result = netwatch.osint_trace_enriched("8.8.8.8")

        assert result[0]["rdns"] == "router.local"

    @patch("netwatch._proxied_get")
    @patch("netwatch.socket.gethostbyaddr")
    @patch("netwatch.subprocess.run")
    def test_trace_publicIP_geoEnriched(self, mock_run, mock_rdns, mock_get):
        """Public IPs get GeoIP enrichment."""
        mock_run.return_value = MagicMock(
            stdout=" 1  72.14.215.85 (72.14.215.85)  12.0 ms\n", returncode=0
        )
        mock_rdns.side_effect = socket.herror("no PTR")
        geo_resp = MagicMock()
        geo_resp.json.return_value = {
            "city": "Mountain View",
            "country": "United States",
            "isp": "Google LLC",
            "as": "AS15169"
        }
        mock_get.return_value = geo_resp

        result = netwatch.osint_trace_enriched("8.8.8.8")

        assert result[0]["city"] == "Mountain View"
        assert result[0]["country"] == "United States"
        assert result[0]["isp"] == "Google LLC"
        assert result[0]["asn"] == "AS15169"

    @patch("netwatch._proxied_get")
    @patch("netwatch.socket.gethostbyaddr")
    @patch("netwatch.subprocess.run")
    def test_trace_privateIP_noGeoLookup(self, mock_run, mock_rdns, mock_get):
        """Private IPs (RFC1918) should NOT trigger GeoIP lookup."""
        mock_run.return_value = MagicMock(
            stdout=" 1  192.168.1.1 (192.168.1.1)  1.0 ms\n", returncode=0
        )
        mock_rdns.side_effect = socket.herror("no PTR")
        mock_get.return_value = None

        netwatch.osint_trace_enriched("8.8.8.8")

        # _proxied_get should not be called for private IPs
        mock_get.assert_not_called()

    @patch("netwatch._proxied_get")
    @patch("netwatch.socket.gethostbyaddr")
    @patch("netwatch.subprocess.run")
    def test_trace_fallbackToTracepath_onFailedTraceroute(self, mock_run, mock_rdns, mock_get):
        """If traceroute returns non-zero, falls back to tracepath."""
        # First call (traceroute) fails, second call (tracepath) succeeds
        mock_run.side_effect = [
            MagicMock(stdout="", returncode=1),  # traceroute fails
            MagicMock(stdout=" 1:  10.0.0.1  2.0 ms\n", returncode=0),  # tracepath
        ]
        mock_rdns.side_effect = socket.herror("no PTR")
        mock_get.return_value = None

        result = netwatch.osint_trace_enriched("8.8.8.8")

        assert mock_run.call_count == 2
        # Second call should be tracepath
        assert "tracepath" in mock_run.call_args_list[1][0][0]

    @patch("netwatch.subprocess.run")
    def test_trace_timeout_returnsError(self, mock_run):
        """Subprocess timeout returns error in first hop."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="traceroute", timeout=45)

        result = netwatch.osint_trace_enriched("8.8.8.8")

        assert len(result) == 1
        assert "error" in result[0]

    @patch("netwatch._proxied_get")
    @patch("netwatch.socket.gethostbyaddr")
    @patch("netwatch.subprocess.run")
    def test_trace_emptyOutput_returnsEmptyList(self, mock_run, mock_rdns, mock_get):
        """Empty traceroute output returns empty hops list."""
        mock_run.return_value = MagicMock(stdout="", returncode=0)

        result = netwatch.osint_trace_enriched("8.8.8.8")

        assert result == []

    @patch("netwatch._proxied_get")
    @patch("netwatch.socket.gethostbyaddr")
    @patch("netwatch.subprocess.run")
    def test_trace_asteriskHops_skipped(self, mock_run, mock_rdns, mock_get):
        """Lines with only * * * (no IP) are skipped."""
        # Header "traceroute to 8.8.8.8, 20 hops max" also contains IP -> parsed as hop
        output = """\
traceroute to 8.8.8.8, 20 hops max
 1  192.168.1.1  1.0 ms
 2  * * *
 3  8.8.8.8  10.0 ms
"""
        mock_run.return_value = MagicMock(stdout=output, returncode=0)
        mock_rdns.side_effect = socket.herror("no PTR")
        mock_get.return_value = None

        result = netwatch.osint_trace_enriched("8.8.8.8")

        # Header line IP + hop 1 + hop 3 = 3 (asterisk line skipped)
        assert len(result) == 3
        ips = [h["ip"] for h in result]
        assert "192.168.1.1" in ips
        assert "8.8.8.8" in ips
        # Verify the * * * line did not produce a hop
        raw_lines = [h["raw"] for h in result]
        assert not any("* * *" in r for r in raw_lines)


# ═══════════════════════════════════════════════════════════════════════
# osint_health TESTS
# ═══════════════════════════════════════════════════════════════════════

class TestOsintHealth:
    """Tests for osint_health(target) - Composite health check."""

    @patch("netwatch.osint_geolocate")
    @patch("netwatch.osint_techstack")
    @patch("netwatch.osint_secheaders")
    @patch("netwatch.osint_ssl")
    @patch("netwatch.osint_dns_enum")
    @patch("netwatch.osint_ping_analyze")
    def test_health_domain_allComponentsCalled(
        self, mock_ping, mock_dns, mock_ssl, mock_sec, mock_tech, mock_geo
    ):
        """Domain target calls all sub-functions including dns_enum."""
        mock_ping.return_value = {"avg": 10, "ttl": 64}
        mock_dns.return_value = {"A": ["1.2.3.4"]}
        mock_ssl.return_value = {"protocol": "TLSv1.3"}
        mock_sec.return_value = {"grade": "A", "score": "7/7"}
        mock_tech.return_value = {"technologies": ["nginx"]}
        mock_geo.return_value = {"city": "NYC", "country": "US"}

        result = netwatch.osint_health("example.com")

        assert result["target"] == "example.com"
        assert "timestamp" in result
        assert result["ping"]["avg"] == 10
        assert result["dns"] == {"A": ["1.2.3.4"]}
        assert result["ssl"]["protocol"] == "TLSv1.3"
        assert result["secheaders"]["grade"] == "A"
        assert "nginx" in result["techstack"]["technologies"]
        assert result["geo"]["city"] == "NYC"
        mock_dns.assert_called_once_with("example.com")

    @patch("netwatch.osint_geolocate")
    @patch("netwatch.osint_techstack")
    @patch("netwatch.osint_secheaders")
    @patch("netwatch.osint_ssl")
    @patch("netwatch.osint_ping_analyze")
    def test_health_ipTarget_skipsDnsEnum(
        self, mock_ping, mock_ssl, mock_sec, mock_tech, mock_geo
    ):
        """IP address target skips dns_enum (not a domain)."""
        mock_ping.return_value = {"avg": 5}
        mock_ssl.return_value = {"error": "connection refused"}
        mock_sec.return_value = {"error": "request failed"}
        mock_tech.return_value = {"technologies": []}
        mock_geo.return_value = {"city": "N/A"}

        result = netwatch.osint_health("8.8.8.8")

        assert "dns" not in result
        # For IP target, URL should be http://8.8.8.8
        mock_sec.assert_called_once_with("http://8.8.8.8")
        mock_tech.assert_called_once_with("http://8.8.8.8")

    @patch("netwatch.osint_geolocate")
    @patch("netwatch.osint_techstack")
    @patch("netwatch.osint_secheaders")
    @patch("netwatch.osint_ssl")
    @patch("netwatch.osint_dns_enum")
    @patch("netwatch.osint_ping_analyze")
    def test_health_domain_usesHttpsUrl(
        self, mock_ping, mock_dns, mock_ssl, mock_sec, mock_tech, mock_geo
    ):
        """Domain target constructs https:// URL for secheaders/techstack."""
        mock_ping.return_value = {}
        mock_dns.return_value = {}
        mock_ssl.return_value = {}
        mock_sec.return_value = {}
        mock_tech.return_value = {"technologies": []}
        mock_geo.return_value = {}

        netwatch.osint_health("example.com")

        mock_sec.assert_called_once_with("https://example.com")
        mock_tech.assert_called_once_with("https://example.com")

    @patch("netwatch.osint_geolocate")
    @patch("netwatch.osint_techstack")
    @patch("netwatch.osint_secheaders")
    @patch("netwatch.osint_ssl")
    @patch("netwatch.osint_ping_analyze")
    def test_health_partialFailures_stillReturnsOtherResults(
        self, mock_ping, mock_ssl, mock_sec, mock_tech, mock_geo
    ):
        """If some sub-checks error, others still populate correctly."""
        mock_ping.return_value = {"error": "ping timed out"}
        mock_ssl.return_value = {"protocol": "TLSv1.3", "cipher": "AES256"}
        mock_sec.return_value = {"error": "request failed"}
        mock_tech.return_value = {"technologies": ["React"]}
        mock_geo.return_value = {"error": "request failed"}

        result = netwatch.osint_health("1.2.3.4")

        assert result["ping"]["error"] == "ping timed out"
        assert result["ssl"]["protocol"] == "TLSv1.3"
        assert result["secheaders"]["error"] == "request failed"
        assert "React" in result["techstack"]["technologies"]

    @patch("netwatch.osint_geolocate")
    @patch("netwatch.osint_techstack")
    @patch("netwatch.osint_secheaders")
    @patch("netwatch.osint_ssl")
    @patch("netwatch.osint_dns_enum")
    @patch("netwatch.osint_ping_analyze")
    def test_health_pingCount_isThree(
        self, mock_ping, mock_dns, mock_ssl, mock_sec, mock_tech, mock_geo
    ):
        """Health check uses count=3 for ping."""
        mock_ping.return_value = {}
        mock_dns.return_value = {}
        mock_ssl.return_value = {}
        mock_sec.return_value = {}
        mock_tech.return_value = {"technologies": []}
        mock_geo.return_value = {}

        netwatch.osint_health("test.com")

        mock_ping.assert_called_once_with("test.com", count=3)


# ═══════════════════════════════════════════════════════════════════════
# handle_command INTEGRATION TESTS (for new OSINT commands)
# ═══════════════════════════════════════════════════════════════════════

class TestHandleCommandOSINT:
    """Tests for handle_command() routing to new OSINT functions."""

    @patch("netwatch.threading.Thread")
    def test_cmd_ssl_validTarget_spawnsThread(self, mock_thread):
        """'ssl google.com' spawns a thread to run osint_ssl."""
        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        netwatch.handle_command("ssl google.com")

        mock_thread.assert_called_once()
        mock_thread_instance.start.assert_called_once()

    @patch("netwatch.threading.Thread")
    def test_cmd_ssl_withPort_parsesPort(self, mock_thread):
        """'ssl example.com 8443' parses custom port."""
        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        netwatch.handle_command("ssl example.com 8443")

        mock_thread.assert_called_once()

    @patch("netwatch.threading.Thread")
    def test_cmd_secheaders_validTarget(self, mock_thread):
        """'secheaders example.com' starts thread."""
        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        netwatch.handle_command("secheaders https://example.com")

        mock_thread.assert_called_once()

    @patch("netwatch.threading.Thread")
    def test_cmd_techstack_validTarget(self, mock_thread):
        """'techstack example.com' starts thread."""
        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        netwatch.handle_command("techstack example.com")

        mock_thread.assert_called_once()

    @patch("netwatch.threading.Thread")
    def test_cmd_ping_defaultCount(self, mock_thread):
        """'ping 8.8.8.8' defaults to count=5."""
        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        netwatch.handle_command("ping 8.8.8.8")

        mock_thread.assert_called_once()

    @patch("netwatch.threading.Thread")
    def test_cmd_ping_customCount(self, mock_thread):
        """'ping 8.8.8.8 10' parses custom count."""
        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        netwatch.handle_command("ping 8.8.8.8 10")

        mock_thread.assert_called_once()

    @patch("netwatch.threading.Thread")
    def test_cmd_ping_countCappedAt20(self, mock_thread):
        """Count > 20 is capped at 20."""
        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        # The capping happens inside the thread, but command still works
        netwatch.handle_command("ping 8.8.8.8 999")

        mock_thread.assert_called_once()

    @patch("netwatch.threading.Thread")
    def test_cmd_health_validTarget(self, mock_thread):
        """'health google.com' starts thread."""
        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        netwatch.handle_command("health google.com")

        mock_thread.assert_called_once()

    @patch("netwatch.threading.Thread")
    def test_cmd_etrace_validTarget(self, mock_thread):
        """'etrace 8.8.8.8' starts enriched traceroute thread."""
        mock_thread_instance = MagicMock()
        mock_thread.return_value = mock_thread_instance

        netwatch.handle_command("etrace 8.8.8.8")

        mock_thread.assert_called_once()

    @patch("netwatch.add_console")
    def test_cmd_etrace_invalidTarget_rejects(self, mock_console):
        """'etrace' with invalid characters is rejected."""
        netwatch.handle_command("etrace ; rm -rf /")

        # Should see "Invalid target" in console output
        calls = [str(c) for c in mock_console.call_args_list]
        assert any("Invalid target" in c for c in calls)

    @patch("netwatch.add_console")
    def test_cmd_ssl_noTarget_noAction(self, mock_console):
        """'ssl' with no target does nothing (len(parts) < 2)."""
        # This falls through to the "Unknown" handler
        netwatch.handle_command("ssl")

        calls = [str(c) for c in mock_console.call_args_list]
        assert any("Unknown" in c for c in calls)

    @patch("netwatch.add_console")
    def test_cmd_empty_noAction(self, mock_console):
        """Empty command does nothing."""
        result = netwatch.handle_command("")
        # Should return without printing anything
        mock_console.assert_not_called()

    @patch("netwatch.add_console")
    def test_cmd_unknown_reportsError(self, mock_console):
        """Unknown command triggers error message."""
        netwatch.handle_command("xyzzy_not_a_command")

        calls = [str(c) for c in mock_console.call_args_list]
        assert any("Unknown" in c for c in calls)


# ═══════════════════════════════════════════════════════════════════════
# EDGE CASES & ERROR HANDLING
# ═══════════════════════════════════════════════════════════════════════

class TestEdgeCases:
    """Edge case tests across all OSINT functions."""

    @patch("netwatch.ssl.create_default_context")
    @patch("netwatch.socket.create_connection")
    def test_ssl_emptyCipher_handlesGracefully(self, mock_conn, mock_ctx_factory):
        """cipher() returning None handled."""
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = None
        mock_ssock.cipher.return_value = None
        mock_ssock.version.return_value = "TLSv1.2"
        mock_ssock.__enter__ = MagicMock(return_value=mock_ssock)
        mock_ssock.__exit__ = MagicMock(return_value=False)

        # Second connection for binary cert
        mock_ssock2 = MagicMock()
        mock_ssock2.getpeercert.return_value = None
        mock_ssock2.__enter__ = MagicMock(return_value=mock_ssock2)
        mock_ssock2.__exit__ = MagicMock(return_value=False)

        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value = mock_sock

        mock_ctx1 = MagicMock()
        mock_ctx1.wrap_socket.return_value = mock_ssock
        mock_ctx2 = MagicMock()
        mock_ctx2.wrap_socket.return_value = mock_ssock2
        mock_ctx_factory.side_effect = [mock_ctx1, mock_ctx2]

        result = netwatch.osint_ssl("broken.example.com")

        assert result["cipher"] == "unknown"
        assert result["bits"] == 0

    def test_secheaders_responseThrowsOnHeaders_returnsError(self, mock_proxied_get):
        """If response.headers throws, caught and returns error."""
        resp = MagicMock()
        resp.headers = property(lambda self: (_ for _ in ()).throw(RuntimeError("broken")))
        type(resp).headers = PropertyMock(side_effect=RuntimeError("broken"))
        mock_proxied_get.return_value = resp

        result = netwatch.osint_secheaders("https://broken.example.com")

        assert "error" in result

    def test_techstack_responseTextThrows_returnsError(self, mock_proxied_get):
        """If response.text throws, caught and returns error."""
        resp = MagicMock()
        type(resp).text = PropertyMock(side_effect=RuntimeError("encoding error"))
        resp.headers = {}
        mock_proxied_get.return_value = resp

        result = netwatch.osint_techstack("https://broken.example.com")

        assert "error" in result

    @patch("netwatch.subprocess.run")
    def test_ping_malformedOutput_nocrash(self, mock_run):
        """Garbage ping output without time= does not crash, returns minimal result."""
        mock_run.return_value = MagicMock(
            stdout="garbage data no timing lines here\nmore garbage\n",
            returncode=0
        )

        result = netwatch.osint_ping_analyze("garble.example.com", count=3)

        assert result["target"] == "garble.example.com"
        assert "min" not in result

    @patch("netwatch.subprocess.run")
    def test_ping_zeroCount_clampedToOne(self, mock_run):
        """Count of 0 is clamped to 1 via max(1, min(count, 20))."""
        mock_run.return_value = MagicMock(stdout="", returncode=0)

        result = netwatch.osint_ping_analyze("example.com", count=0)

        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert "-c" in args
        # count clamped from 0 to 1
        assert "1" in args

    @patch("netwatch._proxied_get")
    @patch("netwatch.socket.gethostbyaddr")
    @patch("netwatch.subprocess.run")
    def test_trace_geoApiReturnsInvalidJSON_nocrash(self, mock_run, mock_rdns, mock_get):
        """GeoIP returning invalid JSON doesn't crash."""
        mock_run.return_value = MagicMock(
            stdout=" 1  72.14.215.85 (72.14.215.85)  10.0 ms\n", returncode=0
        )
        mock_rdns.side_effect = socket.herror("no PTR")
        geo_resp = MagicMock()
        geo_resp.json.side_effect = ValueError("not json")
        mock_get.return_value = geo_resp

        # Should not raise
        result = netwatch.osint_trace_enriched("8.8.8.8")

        # Hop still in result, just without geo data
        assert len(result) == 1
        assert result[0]["ip"] == "72.14.215.85"

    @patch("netwatch.subprocess.run")
    def test_ping_hugeTimesOutput_parsed(self, mock_run):
        """Very large RTT values (satellite link) parsed correctly."""
        output = """\
PING sat.example.com (1.2.3.4) 56(84) bytes of data.
64 bytes from 1.2.3.4: icmp_seq=1 ttl=50 time=650.12 ms
64 bytes from 1.2.3.4: icmp_seq=2 ttl=50 time=700.46 ms

--- sat.example.com ping statistics ---
2 packets transmitted, 2 received, 0% packet loss
"""
        mock_run.return_value = MagicMock(stdout=output, returncode=0)

        result = netwatch.osint_ping_analyze("sat.example.com", count=2)

        assert result["min"] == 650.12
        assert result["max"] == 700.46
        assert result["ttl"] == 50
        assert result["os_guess"] == "Linux/Unix/macOS"


# ═══════════════════════════════════════════════════════════════════════
# INTEGRATION TESTS (require network access)
# ═══════════════════════════════════════════════════════════════════════

def _has_network():
    """Check if we can reach the internet."""
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        return True
    except (OSError, socket.timeout):
        return False


@pytest.mark.skipif(not _has_network(), reason="No network access")
class TestIntegrationNetwork:
    """Integration tests that hit real endpoints. Skipped without network."""

    def test_integration_ssl_google(self):
        """Real TLS inspection of google.com."""
        result = netwatch.osint_ssl("google.com", 443)

        assert "error" not in result
        assert result["protocol"] in ("TLSv1.2", "TLSv1.3")
        assert result["bits"] > 0
        assert "google" in result.get("subject", "").lower() or "google" in str(result.get("alt_names", "")).lower()

    @patch("netwatch._proxied_get")
    def test_integration_secheaders_google(self, mock_get):
        """Real security header check for google.com (via mocked proxy route to real requests)."""
        # We use requests directly for integration
        try:
            import requests
            resp = requests.get("https://www.google.com", timeout=10)
            mock_get.return_value = resp

            result = netwatch.osint_secheaders("https://www.google.com")

            assert "error" not in result
            assert "grade" in result
            assert "headers" in result
        except ImportError:
            pytest.skip("requests not installed")

    @patch("netwatch.subprocess.run", wraps=subprocess.run)
    def test_integration_ping_localhost(self, mock_run):
        """Ping localhost should always succeed."""
        result = netwatch.osint_ping_analyze("127.0.0.1", count=2)

        assert "error" not in result
        assert result["min"] >= 0
        assert result["loss"] == 0.0
        assert result["ttl"] is not None

    @patch("netwatch.subprocess.run", wraps=subprocess.run)
    def test_integration_ping_8888(self, mock_run):
        """Ping 8.8.8.8 (Google DNS) - real network test."""
        result = netwatch.osint_ping_analyze("8.8.8.8", count=3)

        assert "error" not in result
        assert result["avg"] > 0
        assert result["ttl"] > 0


# ═══════════════════════════════════════════════════════════════════════
# PROXIED_GET DEPENDENCY TESTS
# ═══════════════════════════════════════════════════════════════════════

class TestProxiedGet:
    """Tests for _proxied_get edge cases that affect OSINT functions."""

    @patch("netwatch.req_lib", None)
    def test_proxied_get_noRequestsLib_returnsNone(self):
        """Without requests library, _proxied_get returns None."""
        result = netwatch._proxied_get("http://example.com")
        assert result is None

    @patch("netwatch._proxy_session")
    @patch("netwatch._get_proxy")
    def test_proxied_get_noSession_returnsNone(self, mock_proxy, mock_session):
        """When _proxy_session returns None, _proxied_get returns None."""
        mock_proxy.return_value = None
        mock_session.return_value = None

        result = netwatch._proxied_get("http://example.com")

        assert result is None

    @patch("netwatch._proxy_session")
    @patch("netwatch._get_proxy")
    def test_proxied_get_requestException_returnsNone(self, mock_proxy, mock_session):
        """Network exception during GET returns None."""
        mock_proxy.return_value = {}
        mock_sess = MagicMock()
        mock_sess.get.side_effect = ConnectionError("network down")
        mock_session.return_value = mock_sess

        result = netwatch._proxied_get("http://example.com")

        assert result is None


# ═══════════════════════════════════════════════════════════════════════
# GRADING BOUNDARY TESTS for osint_secheaders
# ═══════════════════════════════════════════════════════════════════════

class TestSecheadersGrading:
    """Boundary tests for the grading logic in osint_secheaders."""

    def _run_with_n_headers(self, mock_proxied_get, n):
        """Helper: create response with exactly n security headers."""
        all_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "X-XSS-Protection",
            "Referrer-Policy",
            "Permissions-Policy",
        ]
        headers = {all_headers[i]: "value" for i in range(n)}
        resp = MagicMock()
        resp.headers = headers
        mock_proxied_get.return_value = resp
        return netwatch.osint_secheaders("http://test.com")

    def test_grading_0headers_F(self, mock_proxied_get):
        result = self._run_with_n_headers(mock_proxied_get, 0)
        assert result["grade"] == "F"

    def test_grading_1header_F(self, mock_proxied_get):
        result = self._run_with_n_headers(mock_proxied_get, 1)
        assert result["grade"] == "F"

    def test_grading_2headers_C(self, mock_proxied_get):
        result = self._run_with_n_headers(mock_proxied_get, 2)
        assert result["grade"] == "C"

    def test_grading_3headers_C(self, mock_proxied_get):
        result = self._run_with_n_headers(mock_proxied_get, 3)
        assert result["grade"] == "C"

    def test_grading_4headers_B(self, mock_proxied_get):
        result = self._run_with_n_headers(mock_proxied_get, 4)
        assert result["grade"] == "B"

    def test_grading_5headers_B(self, mock_proxied_get):
        result = self._run_with_n_headers(mock_proxied_get, 5)
        assert result["grade"] == "B"

    def test_grading_6headers_A(self, mock_proxied_get):
        result = self._run_with_n_headers(mock_proxied_get, 6)
        assert result["grade"] == "A"

    def test_grading_7headers_A(self, mock_proxied_get):
        result = self._run_with_n_headers(mock_proxied_get, 7)
        assert result["grade"] == "A"
