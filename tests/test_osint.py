"""
Tests for all OSINT functions in netwatch.py:
  osint_geolocate, osint_whois, osint_dns_enum, osint_reverse_dns,
  osint_port_scan, osint_subnet_ping, osint_crt, osint_headers,
  osint_asn, osint_abuse, osint_ssl, osint_secheaders, osint_techstack,
  osint_ping_analyze, osint_trace_enriched, osint_health, decode_payload,
  analyze_attacker, banner_grab, traceroute
"""
import base64
import binascii
import socket
import urllib.parse
import pytest
from unittest.mock import patch, MagicMock, PropertyMock

import netwatch


# ═══════════════════════════════════════════════════════════
#  osint_geolocate
# ═══════════════════════════════════════════════════════════

class TestOsintGeolocate:
    def test_successful_geo(self, mock_requests, sample_geo_response):
        resp = MagicMock()
        resp.json.return_value = sample_geo_response
        mock_requests.return_value = resp
        result = netwatch.osint_geolocate("203.0.113.42")
        assert result["city"] == "San Francisco"
        assert result["country"] == "United States"

    def test_request_fails(self, mock_requests):
        mock_requests.return_value = None
        result = netwatch.osint_geolocate("1.2.3.4")
        assert "error" in result

    def test_json_parse_error(self, mock_requests):
        resp = MagicMock()
        resp.json.side_effect = ValueError("bad json")
        mock_requests.return_value = resp
        result = netwatch.osint_geolocate("1.2.3.4")
        assert "error" in result

    def test_empty_target(self, mock_requests):
        mock_requests.return_value = None
        result = netwatch.osint_geolocate("")
        assert "error" in result


# ═══════════════════════════════════════════════════════════
#  osint_whois
# ═══════════════════════════════════════════════════════════

class TestOsintWhois:
    def test_successful_whois(self, mock_whois_lib):
        result = netwatch.osint_whois("example.com")
        assert "domain_name" in result or "registrar" in result

    def test_whois_lib_not_installed(self):
        original = netwatch.whois_lib
        netwatch.whois_lib = None
        result = netwatch.osint_whois("example.com")
        assert "error" in result
        assert "not installed" in result["error"]
        netwatch.whois_lib = original

    def test_whois_exception(self, mock_whois_lib):
        mock_whois_lib.whois.side_effect = Exception("timeout")
        result = netwatch.osint_whois("bad.domain")
        assert "error" in result

    def test_whois_list_fields(self, mock_whois_lib):
        mock_whois_lib.whois.return_value = MagicMock(
            domain_name=["EXAMPLE.COM", "example.com"],
            registrar="Test",
            creation_date=None, expiration_date=None,
            name_servers=None, org=None, country=None,
            whois_server=None, state=None, city=None,
            emails=None, dnssec=None,
        )
        result = netwatch.osint_whois("example.com")
        assert "EXAMPLE.COM" in result.get("domain_name", "")


# ═══════════════════════════════════════════════════════════
#  osint_dns_enum
# ═══════════════════════════════════════════════════════════

class TestOsintDnsEnum:
    def test_dns_not_installed(self):
        original = netwatch.dns
        netwatch.dns = None
        result = netwatch.osint_dns_enum("example.com")
        assert "error" in result
        netwatch.dns = original

    def test_successful_enum(self, mock_dns_lib):
        mock_answer = MagicMock()
        mock_answer.__iter__ = lambda self: iter([MagicMock(__str__=lambda s: "1.2.3.4")])
        mock_dns_lib.resolver.resolve.return_value = mock_answer
        result = netwatch.osint_dns_enum("example.com")
        assert "A" in result

    def test_partial_failure(self, mock_dns_lib):
        def resolver_side_effect(target, rtype):
            if rtype == "A":
                mock = MagicMock()
                mock.__iter__ = lambda self: iter([MagicMock(__str__=lambda s: "1.2.3.4")])
                return mock
            raise Exception("no record")
        mock_dns_lib.resolver.resolve.side_effect = resolver_side_effect
        result = netwatch.osint_dns_enum("example.com")
        assert "A" in result
        assert "MX" not in result


# ═══════════════════════════════════════════════════════════
#  osint_reverse_dns
# ═══════════════════════════════════════════════════════════

class TestOsintReverseDns:
    def test_with_dns_lib(self, mock_dns_lib):
        mock_answer = MagicMock()
        mock_answer.__iter__ = lambda self: iter([MagicMock(__str__=lambda s: "host.example.com.")])
        mock_dns_lib.resolver.resolve.return_value = mock_answer
        result = netwatch.osint_reverse_dns("1.2.3.4")
        assert "PTR" in result

    def test_without_dns_lib_success(self):
        original = netwatch.dns
        netwatch.dns = None
        with patch("socket.gethostbyaddr", return_value=("example.com", [], [])):
            result = netwatch.osint_reverse_dns("1.2.3.4")
            assert result == {"PTR": "example.com"}
        netwatch.dns = original

    def test_without_dns_lib_failure(self):
        original = netwatch.dns
        netwatch.dns = None
        with patch("socket.gethostbyaddr", side_effect=Exception("no PTR")):
            result = netwatch.osint_reverse_dns("1.2.3.4")
            assert "error" in result
        netwatch.dns = original

    def test_dns_lib_exception(self, mock_dns_lib):
        mock_dns_lib.resolver.resolve.side_effect = Exception("NXDOMAIN")
        result = netwatch.osint_reverse_dns("1.2.3.4")
        assert "error" in result


# ═══════════════════════════════════════════════════════════
#  osint_port_scan
# ═══════════════════════════════════════════════════════════

class TestOsintPortScan:
    @patch("socket.gethostbyname", return_value="1.2.3.4")
    @patch("socket.socket")
    def test_open_port_detected(self, mock_sock_class, mock_resolve):
        instance = MagicMock()
        mock_sock_class.return_value = instance
        instance.connect_ex.return_value = 0
        instance.recv.return_value = b"SSH-2.0-OpenSSH"
        result = netwatch.osint_port_scan("1.2.3.4", max_ports=5)
        assert len(result) > 0
        assert result[0][0] >= 1

    @patch("socket.gethostbyname", side_effect=socket.gaierror("DNS fail"))
    def test_dns_failure(self, mock_resolve):
        result = netwatch.osint_port_scan("nonexistent.invalid")
        assert result == []

    @patch("socket.gethostbyname", return_value="1.2.3.4")
    @patch("socket.socket")
    def test_closed_ports(self, mock_sock_class, mock_resolve):
        instance = MagicMock()
        mock_sock_class.return_value = instance
        instance.connect_ex.return_value = 1  # connection refused
        result = netwatch.osint_port_scan("1.2.3.4", max_ports=5)
        assert result == []

    @patch("socket.gethostbyname", return_value="1.2.3.4")
    @patch("socket.socket")
    def test_max_ports_limit(self, mock_sock_class, mock_resolve):
        instance = MagicMock()
        mock_sock_class.return_value = instance
        instance.connect_ex.return_value = 1
        # Should not crash with max_ports=1
        result = netwatch.osint_port_scan("1.2.3.4", max_ports=1)
        assert isinstance(result, list)


# ═══════════════════════════════════════════════════════════
#  osint_subnet_ping
# ═══════════════════════════════════════════════════════════

class TestOsintSubnetPing:
    def test_invalid_cidr(self):
        result = netwatch.osint_subnet_ping("not-a-cidr")
        assert result == []

    def test_network_too_large(self):
        result = netwatch.osint_subnet_ping("10.0.0.0/20")
        assert result[0][0] == "error"

    @patch("netwatch.subprocess.run")
    @patch("socket.gethostbyaddr", side_effect=Exception("no PTR"))
    def test_successful_ping(self, mock_dns, mock_run):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "64 bytes from 10.0.1.1: time=1.23 ms"
        mock_run.return_value = mock_result
        result = netwatch.osint_subnet_ping("10.0.1.0/30")
        assert len(result) > 0

    @patch("netwatch.subprocess.run")
    def test_all_hosts_down(self, mock_run):
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stdout = ""
        mock_run.return_value = mock_result
        result = netwatch.osint_subnet_ping("10.0.1.0/30")
        assert result == []


# ═══════════════════════════════════════════════════════════
#  osint_crt
# ═══════════════════════════════════════════════════════════

class TestOsintCrt:
    def test_successful_crt(self, mock_requests):
        resp = MagicMock()
        resp.json.return_value = [
            {"common_name": "sub1.example.com", "issuer_name": "Let's Encrypt", "not_after": "2025-01-01"},
            {"common_name": "sub2.example.com", "issuer_name": "Let's Encrypt", "not_after": "2025-06-01"},
            {"common_name": "sub1.example.com", "issuer_name": "Let's Encrypt", "not_after": "2025-01-01"},  # dup
        ]
        mock_requests.return_value = resp
        result = netwatch.osint_crt("example.com")
        assert len(result) == 2  # deduped
        assert result[0]["cn"] == "sub1.example.com"

    def test_request_fails(self, mock_requests):
        mock_requests.return_value = None
        result = netwatch.osint_crt("example.com")
        assert "error" in result

    def test_json_error(self, mock_requests):
        resp = MagicMock()
        resp.json.side_effect = ValueError("bad json")
        mock_requests.return_value = resp
        result = netwatch.osint_crt("example.com")
        assert "error" in result


# ═══════════════════════════════════════════════════════════
#  osint_headers
# ═══════════════════════════════════════════════════════════

class TestOsintHeaders:
    def test_successful_headers(self, mock_requests):
        resp = MagicMock()
        resp.headers = {"Server": "nginx/1.22", "X-Powered-By": "PHP/8.1"}
        resp.status_code = 200
        mock_requests.return_value = resp
        with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 0))]):
            result = netwatch.osint_headers("http://example.com")
        assert result["status"] == 200
        assert any("nginx" in t for t in result["tech"])

    def test_adds_http_prefix(self, mock_requests):
        resp = MagicMock()
        resp.headers = {}
        resp.status_code = 200
        mock_requests.return_value = resp
        with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 0))]):
            result = netwatch.osint_headers("example.com")
        assert result["status"] == 200

    def test_request_fails(self, mock_requests):
        mock_requests.return_value = None
        with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 0))]):
            result = netwatch.osint_headers("http://example.com")
        assert "error" in result

    def test_private_ip_refused(self, mock_requests):
        with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("192.168.1.1", 0))]):
            result = netwatch.osint_headers("http://internal.local")
        assert "error" in result
        assert "private" in result["error"]

    def test_aspnet_detection(self, mock_requests):
        resp = MagicMock()
        resp.headers = {"X-AspNet-Version": "4.0", "Server": "IIS/10"}
        resp.status_code = 200
        mock_requests.return_value = resp
        with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 0))]):
            result = netwatch.osint_headers("http://example.com")
        assert any("ASP.NET" in t for t in result["tech"])


# ═══════════════════════════════════════════════════════════
#  osint_ssl
# ═══════════════════════════════════════════════════════════

class TestOsintSsl:
    @patch("ssl.create_default_context")
    @patch("socket.create_connection")
    def test_successful_ssl(self, mock_conn, mock_ctx):
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = {
            "subject": [[("commonName", "example.com")]],
            "issuer": [[("organizationName", "Let's Encrypt")]],
            "notBefore": "Jan  1 00:00:00 2024 GMT",
            "notAfter": "Dec 31 23:59:59 2025 GMT",
            "subjectAltName": [("DNS", "example.com"), ("DNS", "www.example.com")],
        }
        mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssock.version.return_value = "TLSv1.3"
        # Setup context manager chain
        mock_ctx_instance = MagicMock()
        mock_ctx.return_value = mock_ctx_instance
        mock_ctx_instance.wrap_socket.return_value.__enter__ = MagicMock(return_value=mock_ssock)
        mock_ctx_instance.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)
        mock_sock = MagicMock()
        mock_conn.return_value.__enter__ = MagicMock(return_value=mock_sock)
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        result = netwatch.osint_ssl("example.com", 443)
        assert result["protocol"] == "TLSv1.3"
        assert result["cipher"] == "TLS_AES_256_GCM_SHA384"

    def test_connection_error(self):
        with patch("socket.create_connection", side_effect=ConnectionRefusedError("refused")):
            result = netwatch.osint_ssl("1.2.3.4", 443)
            assert "error" in result

    def test_custom_port(self):
        with patch("socket.create_connection", side_effect=ConnectionRefusedError("refused")):
            result = netwatch.osint_ssl("1.2.3.4", 8443)
            assert "error" in result


# ═══════════════════════════════════════════════════════════
#  osint_secheaders
# ═══════════════════════════════════════════════════════════

class TestOsintSecheaders:
    def test_all_headers_present(self, mock_requests):
        resp = MagicMock()
        resp.headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "X-XSS-Protection": "1; mode=block",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        }
        mock_requests.return_value = resp
        result = netwatch.osint_secheaders("https://example.com")
        assert result["grade"] == "A"
        assert result["score"] == "7/7"

    def test_no_headers(self, mock_requests):
        resp = MagicMock()
        resp.headers = {}
        mock_requests.return_value = resp
        result = netwatch.osint_secheaders("http://bad.site")
        assert result["grade"] == "F"
        assert result["score"] == "0/7"

    def test_request_fails(self, mock_requests):
        mock_requests.return_value = None
        result = netwatch.osint_secheaders("http://down.site")
        assert "error" in result

    def test_partial_headers(self, mock_requests):
        resp = MagicMock()
        resp.headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        }
        mock_requests.return_value = resp
        result = netwatch.osint_secheaders("http://partial.site")
        assert result["grade"] == "B"

    def test_adds_http_prefix(self, mock_requests):
        resp = MagicMock()
        resp.headers = {}
        mock_requests.return_value = resp
        result = netwatch.osint_secheaders("example.com")
        # Should not crash - auto-prefixes http://
        assert "grade" in result


# ═══════════════════════════════════════════════════════════
#  osint_techstack
# ═══════════════════════════════════════════════════════════

class TestOsintTechstack:
    def test_wordpress_detection(self, mock_requests):
        resp = MagicMock()
        resp.text = '<link rel="stylesheet" href="/wp-content/themes/style.css">'
        resp.headers = {"Server": "nginx/1.22"}
        mock_requests.return_value = resp
        result = netwatch.osint_techstack("http://wp.site")
        assert "WordPress" in result["technologies"]

    def test_nextjs_detection(self, mock_requests):
        resp = MagicMock()
        resp.text = '<script src="/_next/static/chunks/main.js"></script>'
        resp.headers = {"Server": "next.js", "x-vercel-id": "abc"}
        mock_requests.return_value = resp
        result = netwatch.osint_techstack("http://next.site")
        assert "Next.js" in result["technologies"]
        assert "Vercel" in result["technologies"]

    def test_cloudflare_detection(self, mock_requests):
        resp = MagicMock()
        resp.text = "<html><body>Hello</body></html>"
        resp.headers = {"Server": "cloudflare", "cf-ray": "abc123"}
        mock_requests.return_value = resp
        result = netwatch.osint_techstack("http://cf.site")
        assert "Cloudflare" in result["technologies"]

    def test_request_fails(self, mock_requests):
        mock_requests.return_value = None
        result = netwatch.osint_techstack("http://down.site")
        assert "error" in result

    def test_no_tech_detected(self, mock_requests):
        resp = MagicMock()
        resp.text = "<html><body>Plain page</body></html>"
        resp.headers = {"Content-Type": "text/html"}
        mock_requests.return_value = resp
        result = netwatch.osint_techstack("http://plain.site")
        assert result["technologies"] == []

    def test_multiple_techs(self, mock_requests):
        resp = MagicMock()
        resp.text = '<html><script src="/wp-content/foo"></script><link href="bootstrap.min.css">'
        resp.headers = {"Server": "apache/2.4", "x-powered-by": "PHP/8.1"}
        mock_requests.return_value = resp
        result = netwatch.osint_techstack("http://multi.site")
        assert "WordPress" in result["technologies"]
        assert "Bootstrap" in result["technologies"]


# ═══════════════════════════════════════════════════════════
#  osint_ping_analyze
# ═══════════════════════════════════════════════════════════

class TestOsintPingAnalyze:
    def test_successful_ping(self, mock_subprocess_run):
        mock_subprocess_run.return_value.stdout = (
            "PING 1.2.3.4 (1.2.3.4) 56(84) bytes of data.\n"
            "64 bytes from 1.2.3.4: icmp_seq=1 ttl=55 time=10.1 ms\n"
            "64 bytes from 1.2.3.4: icmp_seq=2 ttl=55 time=12.3 ms\n"
            "64 bytes from 1.2.3.4: icmp_seq=3 ttl=55 time=11.5 ms\n"
        )
        result = netwatch.osint_ping_analyze("1.2.3.4", count=3)
        assert result["min"] == 10.1
        assert result["max"] == 12.3
        assert result["ttl"] == 55
        assert result["os_guess"] == "Linux/Unix/macOS"

    def test_windows_ttl(self, mock_subprocess_run):
        mock_subprocess_run.return_value.stdout = (
            "64 bytes from 1.2.3.4: icmp_seq=1 ttl=120 time=5.0 ms\n"
        )
        result = netwatch.osint_ping_analyze("1.2.3.4", count=1)
        assert result["os_guess"] == "Windows"

    def test_network_device_ttl(self, mock_subprocess_run):
        mock_subprocess_run.return_value.stdout = (
            "64 bytes from 1.2.3.4: icmp_seq=1 ttl=254 time=1.0 ms\n"
        )
        result = netwatch.osint_ping_analyze("1.2.3.4", count=1)
        assert result["os_guess"] == "Network device (router/switch)"

    def test_timeout(self, mock_subprocess_run):
        import subprocess
        mock_subprocess_run.side_effect = subprocess.TimeoutExpired("ping", 10)
        result = netwatch.osint_ping_analyze("1.2.3.4", count=3)
        assert "error" in result
        assert "timed out" in result["error"]

    def test_packet_loss(self, mock_subprocess_run):
        mock_subprocess_run.return_value.stdout = (
            "64 bytes from 1.2.3.4: icmp_seq=1 ttl=55 time=10.0 ms\n"
        )
        result = netwatch.osint_ping_analyze("1.2.3.4", count=5)
        assert result["loss"] == 80.0

    def test_jitter_calculation(self, mock_subprocess_run):
        mock_subprocess_run.return_value.stdout = (
            "64 bytes from 1.2.3.4: icmp_seq=1 ttl=55 time=10.0 ms\n"
            "64 bytes from 1.2.3.4: icmp_seq=2 ttl=55 time=20.0 ms\n"
            "64 bytes from 1.2.3.4: icmp_seq=3 ttl=55 time=15.0 ms\n"
        )
        result = netwatch.osint_ping_analyze("1.2.3.4", count=3)
        # jitter = avg(|20-10|, |15-20|) = avg(10, 5) = 7.5
        assert result["jitter"] == 7.5


# ═══════════════════════════════════════════════════════════
#  osint_trace_enriched
# ═══════════════════════════════════════════════════════════

class TestOsintTraceEnriched:
    def test_successful_trace(self, mock_subprocess_run, mock_requests):
        mock_subprocess_run.return_value.stdout = (
            " 1  10.0.1.1 (10.0.1.1) 1.234 ms\n"
            " 2  203.0.113.1 (203.0.113.1) 5.678 ms\n"
        )
        mock_subprocess_run.return_value.returncode = 0
        # Mock geo lookup for non-private IP
        geo_resp = MagicMock()
        geo_resp.json.return_value = {"city": "NYC", "country": "US", "isp": "ISP", "as": "AS123"}
        mock_requests.return_value = geo_resp
        with patch("socket.gethostbyaddr", return_value=("router.local", [], [])):
            result = netwatch.osint_trace_enriched("8.8.8.8")
        assert len(result) == 2
        assert result[0]["ip"] == "10.0.1.1"

    def test_trace_error(self, mock_subprocess_run):
        mock_subprocess_run.side_effect = Exception("traceroute failed")
        result = netwatch.osint_trace_enriched("1.2.3.4")
        assert result[0].get("error")


# ═══════════════════════════════════════════════════════════
#  osint_health
# ═══════════════════════════════════════════════════════════

class TestOsintHealth:
    @patch("netwatch.osint_ping_analyze")
    @patch("netwatch.osint_ssl")
    @patch("netwatch.osint_secheaders")
    @patch("netwatch.osint_techstack")
    @patch("netwatch.osint_geolocate")
    @patch("netwatch.osint_dns_enum")
    def test_domain_health(self, mock_dns, mock_geo, mock_tech, mock_sec, mock_ssl, mock_ping):
        mock_ping.return_value = {"avg": 10.0}
        mock_ssl.return_value = {"protocol": "TLSv1.3"}
        mock_sec.return_value = {"grade": "A"}
        mock_tech.return_value = {"technologies": ["nginx"]}
        mock_geo.return_value = {"city": "NYC"}
        mock_dns.return_value = {"A": ["1.2.3.4"]}
        result = netwatch.osint_health("example.com")
        assert result["target"] == "example.com"
        assert "ping" in result
        assert "ssl" in result
        assert "dns" in result

    @patch("netwatch.osint_ping_analyze")
    @patch("netwatch.osint_ssl")
    @patch("netwatch.osint_secheaders")
    @patch("netwatch.osint_techstack")
    @patch("netwatch.osint_geolocate")
    def test_ip_health_no_dns(self, mock_geo, mock_tech, mock_sec, mock_ssl, mock_ping):
        mock_ping.return_value = {"avg": 5.0}
        mock_ssl.return_value = {"error": "refused"}
        mock_sec.return_value = {"grade": "F"}
        mock_tech.return_value = {"technologies": []}
        mock_geo.return_value = {"city": "London"}
        result = netwatch.osint_health("1.2.3.4")
        assert "dns" not in result  # Not a domain


# ═══════════════════════════════════════════════════════════
#  osint_asn
# ═══════════════════════════════════════════════════════════

class TestOsintAsn:
    def test_valid_ip(self, mock_requests):
        resp = MagicMock()
        resp.json.return_value = {"as": "AS15169", "org": "Google", "isp": "Google LLC"}
        mock_requests.return_value = resp
        result = netwatch.osint_asn("8.8.8.8")
        assert result["as"] == "AS15169"

    def test_invalid_ip(self, mock_requests):
        result = netwatch.osint_asn("not-an-ip")
        assert "error" in result
        assert "invalid" in result["error"]

    def test_request_fails(self, mock_requests):
        mock_requests.return_value = None
        result = netwatch.osint_asn("1.2.3.4")
        assert "error" in result


# ═══════════════════════════════════════════════════════════
#  osint_abuse
# ═══════════════════════════════════════════════════════════

class TestOsintAbuse:
    def test_valid_ip_clean(self, mock_requests):
        resp1 = MagicMock()
        resp1.text = ""
        resp2 = MagicMock()
        resp2.json.return_value = {"proxy": False, "hosting": False, "mobile": False}
        mock_requests.side_effect = [resp1, resp2]
        result = netwatch.osint_abuse("1.2.3.4")
        assert result["blocklist_de"] == "clean"
        assert result["is_proxy"] == False

    def test_invalid_ip(self, mock_requests):
        result = netwatch.osint_abuse("invalid")
        assert "error" in result

    def test_flagged_ip(self, mock_requests):
        resp1 = MagicMock()
        resp1.text = "attacks:15"
        resp2 = MagicMock()
        resp2.json.return_value = {"proxy": True, "hosting": True, "mobile": False}
        mock_requests.side_effect = [resp1, resp2]
        result = netwatch.osint_abuse("203.0.113.1")
        assert "15" in result["blocklist_de"]
        assert result["is_proxy"] == True


# ═══════════════════════════════════════════════════════════
#  decode_payload
# ═══════════════════════════════════════════════════════════

class TestDecodePayload:
    def test_base64_decode(self):
        encoded = base64.b64encode(b"hello world").decode()
        result = netwatch.decode_payload(encoded)
        assert result["base64"] == "hello world"

    def test_hex_decode(self):
        encoded = binascii.hexlify(b"test").decode()
        result = netwatch.decode_payload(encoded)
        assert result["hex"] == "test"

    def test_url_decode(self):
        encoded = "hello%20world%21"
        result = netwatch.decode_payload(encoded)
        assert result["url"] == "hello world!"

    def test_raw_always_present(self):
        result = netwatch.decode_payload("plain text")
        assert result["raw"] == "plain text"

    def test_invalid_base64(self):
        result = netwatch.decode_payload("not valid base64!!!")
        assert "base64" not in result

    def test_invalid_hex(self):
        result = netwatch.decode_payload("xyz not hex")
        assert "hex" not in result

    def test_truncation(self):
        long_data = "A" * 1000
        result = netwatch.decode_payload(long_data)
        assert len(result["raw"]) == 500

    def test_empty_string(self):
        result = netwatch.decode_payload("")
        assert result["raw"] == ""


# ═══════════════════════════════════════════════════════════
#  analyze_attacker
# ═══════════════════════════════════════════════════════════

class TestAnalyzeAttacker:
    def test_no_events_returns_none(self):
        result = netwatch.analyze_attacker("1.2.3.4")
        assert result is None

    def test_with_events(self, populated_honeypot_events, mock_requests):
        mock_requests.return_value = None
        with patch("netwatch.resolve_host", return_value="evil.host"):
            result = netwatch.analyze_attacker("203.0.113.42")
        assert result is not None
        assert result["total_events"] == 3
        assert "telnet" in result["services_targeted"]

    def test_geo_included(self, populated_honeypot_events, mock_requests):
        resp = MagicMock()
        resp.json.return_value = {"city": "Moscow", "country": "Russia", "status": "success", "isp": "Evil ISP"}
        mock_requests.return_value = resp
        with patch("netwatch.resolve_host", return_value=""):
            # Need req_lib to be truthy for geo call
            original = netwatch.req_lib
            netwatch.req_lib = MagicMock()
            result = netwatch.analyze_attacker("203.0.113.42")
            netwatch.req_lib = original
        assert result is not None


# ═══════════════════════════════════════════════════════════
#  banner_grab
# ═══════════════════════════════════════════════════════════

class TestBannerGrab:
    @patch("socket.socket")
    def test_successful_grab(self, mock_sock_cls):
        instance = MagicMock()
        mock_sock_cls.return_value = instance
        instance.recv.return_value = b"SSH-2.0-OpenSSH_8.9\r\n"
        result = netwatch.banner_grab("1.2.3.4", 22)
        assert "SSH-2.0" in result

    @patch("socket.socket")
    def test_connection_error(self, mock_sock_cls):
        instance = MagicMock()
        mock_sock_cls.return_value = instance
        instance.connect.side_effect = ConnectionRefusedError("refused")
        result = netwatch.banner_grab("1.2.3.4", 22)
        assert "ERROR" in result

    @patch("socket.socket")
    def test_truncates_long_banner(self, mock_sock_cls):
        instance = MagicMock()
        mock_sock_cls.return_value = instance
        instance.recv.return_value = b"X" * 500
        result = netwatch.banner_grab("1.2.3.4", 80)
        assert len(result) <= 200


# ═══════════════════════════════════════════════════════════
#  traceroute
# ═══════════════════════════════════════════════════════════

class TestTraceroute:
    def test_successful_traceroute(self, mock_subprocess_run):
        mock_subprocess_run.return_value.stdout = " 1  10.0.1.1\n 2  203.0.113.1\n"
        result = netwatch.traceroute("8.8.8.8")
        assert "10.0.1.1" in result

    def test_traceroute_not_found(self, mock_subprocess_run):
        mock_subprocess_run.side_effect = [
            FileNotFoundError("traceroute not found"),
            MagicMock(stdout="nmap traceroute\n")
        ]
        result = netwatch.traceroute("8.8.8.8")
        assert "nmap traceroute" in result

    def test_both_fail(self, mock_subprocess_run):
        mock_subprocess_run.side_effect = [
            FileNotFoundError("traceroute not found"),
            Exception("nmap also failed")
        ]
        result = netwatch.traceroute("8.8.8.8")
        assert "not available" in result
