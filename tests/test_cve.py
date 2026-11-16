"""CVE lookup: CPE handling, nmap XML parsing, NVD client (cache, rate limit,
errors), ranking, the `cve` command and its web gating, and the geo cache."""
import json
from unittest.mock import MagicMock, patch

import pytest

import netwatch
import netwatch_cve as nc

NMAP_XML = """<?xml version="1.0"?>
<nmaprun><host><ports>
<port protocol="tcp" portid="22"><state state="open"/>
  <service name="ssh" product="OpenSSH" version="8.9p1"><cpe>cpe:/a:openbsd:openssh:8.9p1</cpe><cpe>cpe:/o:linux:linux_kernel</cpe></service></port>
<port protocol="tcp" portid="80"><state state="open"/>
  <service name="http" product="nginx" version="1.18.0"><cpe>cpe:/a:igor_sysoev:nginx:1.18.0</cpe></service></port>
<port protocol="tcp" portid="443"><state state="closed"/><service name="https"/></port>
<port protocol="tcp" portid="8080"><state state="open"/><service name="http-proxy"/></port>
</ports></host></nmaprun>"""


def _vuln(cve_id, score=None, sev=None, kev=None, published="2024-01-01T00:00:00.000", status="Analyzed"):
    cve = {"id": cve_id, "published": published, "vulnStatus": status,
           "descriptions": [{"lang": "es", "value": "no"}, {"lang": "en", "value": f"{cve_id}  summary\ntext"}],
           "metrics": {}}
    if score is not None:
        cve["metrics"]["cvssMetricV31"] = [{"type": "Primary", "cvssData": {"baseScore": score, "baseSeverity": sev}}]
    if kev:
        cve["cisaExploitAdd"] = kev
        cve["cisaActionDue"] = "2024-02-01"
    return {"cve": cve}


class FakeClock:
    def __init__(self):
        self.t = 1_000_000.0
        self.slept = []

    def now(self):
        return self.t

    def sleep(self, s):
        self.slept.append(round(s, 2))
        self.t += s


def _client(responses, tmp_path=None, api_key=None, clock=None):
    clock = clock or FakeClock()
    calls = []

    def http_get(url, params, headers, timeout):
        calls.append((url, dict(params), dict(headers)))
        r = responses[min(len(calls) - 1, len(responses) - 1)]
        return r

    c = nc.NvdClient(http_get, api_key=api_key,
                     cache_path=str(tmp_path / "cve_cache.json") if tmp_path else None,
                     clock=clock.now, sleep=clock.sleep)
    return c, calls, clock


class TestCpe:
    @pytest.mark.parametrize("raw,want", [
        ("cpe:/a:openbsd:openssh:8.9p1", "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*"),
        ("CPE:/A:OpenBSD:OpenSSH:8.9p1", "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*"),
        ("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"),
        ("cpe:/a:vendor:prod:1.0:sp1", "cpe:2.3:a:vendor:prod:1.0:sp1:*:*:*:*:*:*"),
    ])
    def test_normalize(self, raw, want):
        assert nc.normalize_cpe(raw) == want

    @pytest.mark.parametrize("raw", [
        "", None, "openssh 8.9", "cpe:/o:linux:linux_kernel", "cpe:/a:vendor:prod:*",
        "cpe:/a:vendor:prod:-", "cpe:/x:vendor:prod:1.0", "cpe:/a:ven dor:prod:1.0",
        "cpe:/a:vendor:prod:1.0&cveId=CVE-1", "cpe:/a:vendor:prod:1.0?x=1", "cpe:/a:vendor:../x:1.0"])
    def test_refused(self, raw):
        assert nc.normalize_cpe(raw) is None

    def test_ids(self):
        assert nc.is_cve_id("CVE-2021-44228") and nc.is_cve_id("cve-2024-1234567")
        assert not nc.is_cve_id("CVE-21-1") and not nc.is_cve_id("CVE-2021-44228; rm")
        assert nc.is_cpe("cpe:/a:x:y:1") and not nc.is_cpe("8.8.8.8")


class TestNmapXml:
    def test_open_ports_with_versioned_cpes(self):
        svcs = nc.parse_nmap_xml(NMAP_XML)
        assert [s["port"] for s in svcs] == [22, 80, 8080]
        assert svcs[0]["cpes"] == ["cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*"]   # versionless OS CPE dropped
        assert svcs[2]["cpes"] == []

    @pytest.mark.parametrize("bad", ["", "not xml", "<nmaprun>", '<!DOCTYPE x [<!ENTITY a "b">]><nmaprun/>',
                                     "<a>" + "x" * (nc.MAX_XML_BYTES + 1) + "</a>"])
    def test_bad_input_is_empty(self, bad):
        assert nc.parse_nmap_xml(bad) == []


class TestParseAndRank:
    def test_fields(self):
        f = nc.parse_nvd_response({"vulnerabilities": [_vuln("CVE-2024-0001", 9.8, "CRITICAL", kev="2024-01-10")]})[0]
        assert f == {"id": "CVE-2024-0001", "score": 9.8, "severity": "CRITICAL", "kev": True,
                     "kev_added": "2024-01-10", "kev_due": "2024-02-01", "published": "2024-01-01",
                     "summary": "CVE-2024-0001 summary text"}

    def test_tolerates_garbage(self):
        assert nc.parse_nvd_response(None) == []
        assert nc.parse_nvd_response({"vulnerabilities": [None, {}, {"cve": {"id": "nope"}},
                                                           _vuln("CVE-2024-0009", status="Rejected")]}) == []
        f = nc.parse_nvd_response({"vulnerabilities": [{"cve": {"id": "CVE-2024-0002"}}]})[0]
        assert f["score"] is None and f["kev"] is False and f["summary"] == ""

    def test_v2_severity_and_primary_preferred(self):
        body = {"vulnerabilities": [{"cve": {"id": "CVE-2010-0001", "metrics": {
            "cvssMetricV2": [{"type": "Primary", "baseSeverity": "HIGH", "cvssData": {"baseScore": 7.5}}]}}},
            {"cve": {"id": "CVE-2023-0001", "metrics": {"cvssMetricV31": [
                {"type": "Secondary", "cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM"}},
                {"type": "Primary", "cvssData": {"baseScore": 8.1, "baseSeverity": "HIGH"}}]}}}]}
        a, b = nc.parse_nvd_response(body)
        assert (a["score"], a["severity"]) == (7.5, "HIGH")
        assert (b["score"], b["severity"]) == (8.1, "HIGH")

    def test_exploited_first_then_score_then_newest(self):
        fs = nc.parse_nvd_response({"vulnerabilities": [
            _vuln("CVE-2024-0001", 9.8, "CRITICAL"),
            _vuln("CVE-2024-0002", 5.0, "MEDIUM", kev="2024-03-01"),
            _vuln("CVE-2024-0003"),
            _vuln("CVE-2023-0004", 7.5, "HIGH", published="2023-05-01T00:00:00"),
            _vuln("CVE-2024-0005", 7.5, "HIGH", published="2024-05-01T00:00:00")]})
        assert [f["id"] for f in nc.rank(fs)] == [
            "CVE-2024-0002", "CVE-2024-0001", "CVE-2024-0005", "CVE-2023-0004", "CVE-2024-0003"]
        assert nc.summarize(fs) == {"total": 5, "kev": 1, "CRITICAL": 1, "HIGH": 2, "MEDIUM": 1, "LOW": 0}


class TestNvdClient:
    OK = (200, {"vulnerabilities": [_vuln("CVE-2024-0001", 9.8, "CRITICAL")]})

    def test_request_shape(self):
        c, calls, _ = _client([self.OK], api_key="k123")
        c.lookup_cpe("cpe:/a:openbsd:openssh:8.9p1")
        url, params, headers = calls[0]
        assert url == "https://services.nvd.nist.gov/rest/json/cves/2.0"
        assert params == {"cpeName": "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*", "resultsPerPage": 2000}
        assert headers == {"apiKey": "k123"}

    def test_no_key_sends_no_header(self):
        c, calls, _ = _client([self.OK])
        c.lookup_cve("cve-2024-0001")
        assert calls[0][1] == {"cveId": "CVE-2024-0001"} and calls[0][2] == {}

    def test_cache_hit_makes_no_second_request(self, tmp_path):
        c, calls, _ = _client([self.OK], tmp_path)
        first, cached1 = c.lookup_cpe("cpe:/a:x:y:1.0")
        second, cached2 = c.lookup_cpe("cpe:/a:x:y:1.0")
        assert len(calls) == 1 and (cached1, cached2) == (False, True) and first == second

    def test_cache_survives_restart_and_expires(self, tmp_path):
        clock = FakeClock()
        c, calls, _ = _client([self.OK], tmp_path, clock=clock)
        c.lookup_cpe("cpe:/a:x:y:1.0")
        assert oct((tmp_path / "cve_cache.json").stat().st_mode & 0o777) == "0o600"
        c2, calls2, _ = _client([self.OK], tmp_path, clock=clock)
        c2.lookup_cpe("cpe:/a:x:y:1.0")
        assert calls2 == []
        clock.t += nc.CACHE_TTL + 1
        c2.lookup_cpe("cpe:/a:x:y:1.0")
        assert len(calls2) == 1

    def test_corrupt_cache_file_is_ignored(self, tmp_path):
        (tmp_path / "cve_cache.json").write_text("{not json")
        c, calls, _ = _client([self.OK], tmp_path)
        assert c.lookup_cpe("cpe:/a:x:y:1.0")[0][0]["id"] == "CVE-2024-0001"

    def test_rate_limit_spacing(self):
        c, _, clock = _client([self.OK])
        for v in ("1.0", "1.1", "1.2"):
            c.lookup_cpe(f"cpe:/a:x:y:{v}")
        assert clock.slept == [nc.MIN_INTERVAL_NO_KEY, nc.MIN_INTERVAL_NO_KEY]
        c2, _, clock2 = _client([self.OK], api_key="k")
        for v in ("1.0", "1.1"):
            c2.lookup_cpe(f"cpe:/a:x:y:{v}")
        assert clock2.slept == [nc.MIN_INTERVAL_WITH_KEY]

    @pytest.mark.parametrize("status", [403, 429])
    def test_rate_limited(self, status):
        c, _, _ = _client([(status, None)])
        with pytest.raises(nc.NvdError, match="rate limit"):
            c.lookup_cpe("cpe:/a:x:y:1.0")

    @pytest.mark.parametrize("resp", [(0, None), (500, None), (200, None)])
    def test_failure_is_an_error_and_is_not_cached(self, resp, tmp_path):
        c, calls, _ = _client([resp, self.OK], tmp_path)
        with pytest.raises(nc.NvdError, match="lookup failed"):
            c.lookup_cpe("cpe:/a:x:y:1.0")
        assert c.lookup_cpe("cpe:/a:x:y:1.0")[0][0]["id"] == "CVE-2024-0001"

    def test_unknown_cpe_is_empty_not_an_error(self):
        c, _, _ = _client([(404, None)])
        assert c.lookup_cpe("cpe:/a:x:y:1.0") == ([], False)

    def test_bad_input(self):
        c, calls, _ = _client([self.OK])
        with pytest.raises(nc.NvdError):
            c.lookup_cpe("cpe:/a:x:y")
        with pytest.raises(nc.NvdError):
            c.lookup_cve("CVE-1")
        assert calls == []

    def test_services_limit(self):
        c, calls, _ = _client([(200, {"vulnerabilities": []})], api_key="k")
        svcs = [{"port": i, "cpes": [f"cpe:2.3:a:x:y:{i}:*:*:*:*:*:*:*"]} for i in range(1, 31)]
        results, skipped = c.lookup_services(svcs)
        assert len(results) == nc.MAX_SERVICES_PER_SCAN == len(calls) and skipped == 5


@pytest.fixture
def cve_cmd(tmp_path, monkeypatch):
    """Run _cmd_cve with a fake NVD and a fake nmap; returns (run, calls)."""
    monkeypatch.setenv("NETWATCH_CONFIG_DIR", str(tmp_path))
    monkeypatch.delenv("NETWATCH_NVD_API_KEY", raising=False)
    calls = []
    body = {"vulnerabilities": [_vuln("CVE-2024-0001", 9.8, "CRITICAL", kev="2024-01-10"),
                                _vuln("CVE-2024-0002", 5.3, "MEDIUM")]}

    def http_get(url, params, headers, timeout):
        calls.append(params)
        return 200, body

    netwatch._cve_client = nc.NvdClient(http_get, sleep=lambda s: None)

    def run(target, xml=NMAP_XML):
        proc = MagicMock(stdout=xml)
        with patch("netwatch.subprocess.run", return_value=proc) as sp:
            netwatch._cmd_cve(target)
        return "\n".join(netwatch.console_output), sp

    yield run, calls
    netwatch._cve_client = None


class TestCveCommand:
    def test_cve_id(self, cve_cmd):
        run, calls = cve_cmd
        out, sp = run("CVE-2024-0001")
        assert "CVE-2024-0001" in out and "EXPLOITED" in out and "known-exploited catalog since 2024-01-10" in out
        assert not sp.called and calls == [{"cveId": "CVE-2024-0001"}]

    def test_host_scan(self, cve_cmd):
        run, calls = cve_cmd
        netwatch.hosts["203.0.113.5"]["packets"] = 1
        out, sp = run("203.0.113.5")
        argv = sp.call_args[0][0]
        assert argv[0] == "nmap" and argv[-1] == "203.0.113.5" and "-oX" in argv
        assert sp.call_args[1].get("shell") is None
        assert "3 open ports, 2 with a product version" in out
        assert "22/tcp OpenSSH 8.9p1" in out and "80/tcp nginx 1.18.0" in out
        assert "2 CVE, 1 known exploited, 1 critical" in out
        assert out.index("CVE-2024-0001") < out.index("CVE-2024-0002")
        assert "confirm before you act" in out
        assert len(calls) == 2
        assert "KEV" in netwatch.hosts["203.0.113.5"]["tags"]

    def test_host_scan_does_not_create_host_records(self, cve_cmd):
        run, _ = cve_cmd
        run("203.0.113.77")
        assert "203.0.113.77" not in netwatch.hosts

    def test_no_versions(self, cve_cmd):
        run, calls = cve_cmd
        out, _ = run("203.0.113.5", xml='<nmaprun><host><ports><port protocol="tcp" portid="80">'
                                        '<state state="open"/><service name="http"/></port></ports></host></nmaprun>')
        assert "nothing to match" in out and calls == []

    def test_no_open_ports(self, cve_cmd):
        run, _ = cve_cmd
        assert "No open port" in run("203.0.113.5", xml="<nmaprun/>")[0]

    @pytest.mark.parametrize("bad", ["-oN/tmp/x", "a b", "host;id", "$(id)", "x" * 300, "bad_host!"])
    def test_bad_target_never_reaches_nmap(self, cve_cmd, bad):
        run, _ = cve_cmd
        out, sp = run(bad)
        assert not sp.called

    def test_hostile_service_banner_is_sanitised(self, cve_cmd):
        run, _ = cve_cmd
        xml = NMAP_XML.replace('product="OpenSSH"', 'product="Open&#27;[2JSSH"')
        out, _ = run("203.0.113.5", xml=xml)
        assert "\x1b[2J" not in out

    def test_nvd_error_is_reported(self, cve_cmd):
        run, _ = cve_cmd
        netwatch._cve_client = nc.NvdClient(lambda *a: (429, None), sleep=lambda s: None)
        assert "rate limit" in run("CVE-2024-0001")[0]

    def test_nmap_missing(self, cve_cmd):
        _, _ = cve_cmd
        with patch("netwatch.subprocess.run", side_effect=FileNotFoundError):
            netwatch._cmd_cve("203.0.113.5")
        assert "nmap is not installed" in "\n".join(netwatch.console_output)


class TestCveWiring:
    def test_dispatch_rejects_option_like_target(self):
        with patch("netwatch.threading.Thread") as th:
            netwatch.handle_command("cve -sV")
        assert not th.called
        assert any("Invalid target" in c for c in netwatch.console_output)

    def test_dispatch_runs_in_thread(self):
        with patch("netwatch.threading.Thread") as th:
            netwatch.handle_command("cve CVE-2024-0001")
        assert th.call_args[1]["target"] is netwatch._cmd_cve

    def test_tables(self):
        assert "cve" in netwatch._WEB_SAFE_CMDS and "cve" in netwatch._EXPENSIVE_CMDS
        assert netwatch._CMD_MIN_ROLE["cve"] == "operator"
        assert any(e[0].startswith("cve ") for _n, _h, entries in netwatch._HELP_SECTIONS for e in entries)

    def test_internal_target_rule(self):
        assert netwatch._cve_target_is_host("169.254.169.254") is True
        assert netwatch._cve_target_is_host("CVE-2024-0001") is False
        assert netwatch._cve_target_is_host("cpe:2.3:a:x:y:1") is False


class TestGeoCache:
    def _resp(self):
        r = MagicMock()
        r.status_code = 200
        return r

    def test_second_lookup_is_cached(self, monkeypatch):
        monkeypatch.delenv("NETWATCH_IPAPI_KEY", raising=False)
        with patch("netwatch._proxied_get", return_value=self._resp()) as g:
            a = netwatch._ipapi_get("8.8.8.8?fields=country")
            b = netwatch._ipapi_get("8.8.8.8?fields=country")
        assert a is b and g.call_count == 1
        assert g.call_args[0][0] == "http://ip-api.com/json/8.8.8.8?fields=country"

    def test_failures_and_own_address_are_not_cached(self, monkeypatch):
        monkeypatch.delenv("NETWATCH_IPAPI_KEY", raising=False)
        bad = MagicMock()
        bad.status_code = 429
        with patch("netwatch._proxied_get", side_effect=[None, bad, self._resp(), self._resp()]) as g:
            netwatch._ipapi_get("1.1.1.1")
            netwatch._ipapi_get("1.1.1.1")
            netwatch._ipapi_get("?fields=query", cache=False)
            netwatch._ipapi_get("?fields=query", cache=False)
        assert g.call_count == 4

    def test_key_uses_https_endpoint(self, monkeypatch):
        monkeypatch.setenv("NETWATCH_IPAPI_KEY", "k&y")
        with patch("netwatch._proxied_get", return_value=self._resp()) as g:
            netwatch._ipapi_get("8.8.4.4?fields=country")
            netwatch._ipapi_get("9.9.9.9")
        assert g.call_args_list[0][0][0] == "https://pro.ip-api.com/json/8.8.4.4?fields=country&key=k%26y"
        assert g.call_args_list[1][0][0] == "https://pro.ip-api.com/json/9.9.9.9?key=k%26y"

    def test_cache_is_bounded(self, monkeypatch):
        monkeypatch.delenv("NETWATCH_IPAPI_KEY", raising=False)
        with patch.object(netwatch, "_IPAPI_MAX", 20), patch("netwatch._proxied_get", side_effect=lambda *a, **k: self._resp()):
            for i in range(100):
                netwatch._ipapi_get(f"10.0.0.{i}")
        assert len(netwatch._ipapi_cache) <= 20


class TestGeoProviders:
    def _resp(self, body):
        r = MagicMock()
        r.status_code = 200
        r.json.return_value = body
        return r

    LITE = {"ip": "8.8.8.8", "asn": "AS15169", "as_name": "Google LLC", "as_domain": "google.com",
            "country_code": "US", "country": "United States", "continent_code": "NA", "continent": "North America"}

    def test_ipinfo_lite_is_mapped_to_the_common_shape(self, monkeypatch):
        monkeypatch.delenv("NETWATCH_IPAPI_KEY", raising=False)
        monkeypatch.setenv("NETWATCH_IPINFO_TOKEN", "t0k&n")
        with patch("netwatch._proxied_get", return_value=self._resp(self.LITE)) as g:
            d = netwatch._ipapi_get("8.8.8.8?fields=as,org,isp,query,country,city").json()
        assert g.call_args[0][0] == "https://api.ipinfo.io/lite/8.8.8.8?token=t0k%26n"
        assert d == {"status": "success", "query": "8.8.8.8", "country": "United States",
                     "countryCode": "US", "as": "AS15169 Google LLC", "org": "Google LLC",
                     "isp": "Google LLC", "source": "IPinfo"}

    def test_ipinfo_lite_feeds_the_real_commands(self, monkeypatch):
        monkeypatch.delenv("NETWATCH_IPAPI_KEY", raising=False)
        monkeypatch.setenv("NETWATCH_IPINFO_TOKEN", "tok")
        with patch("netwatch._proxied_get", return_value=self._resp(self.LITE)):
            assert netwatch.osint_geolocate("8.8.8.8")["country"] == "United States"
            assert netwatch.osint_asn("8.8.8.8")["as"] == "AS15169 Google LLC"
            netwatch._cmd_geo("8.8.8.8")
        assert any("United States" in c for c in netwatch.console_output)

    def test_ipinfo_lite_own_address_and_names(self, monkeypatch):
        monkeypatch.delenv("NETWATCH_IPAPI_KEY", raising=False)
        monkeypatch.setenv("NETWATCH_IPINFO_TOKEN", "tok")
        with patch("netwatch._proxied_get", return_value=self._resp(self.LITE)) as g:
            netwatch._ipapi_get("?fields=query", cache=False)
            assert g.call_args[0][0].startswith("https://api.ipinfo.io/lite/me?token=")
            g.reset_mock()
            d = netwatch._ipapi_get("example.com").json()
        assert d["status"] == "fail" and not g.called

    @pytest.mark.parametrize("bad", [None, "status500", "notjson", "empty"])
    def test_ipinfo_lite_failures_return_none(self, monkeypatch, bad):
        monkeypatch.delenv("NETWATCH_IPAPI_KEY", raising=False)
        monkeypatch.setenv("NETWATCH_IPINFO_TOKEN", "tok")
        r = MagicMock()
        r.status_code = 500 if bad == "status500" else 200
        if bad == "notjson":
            r.json.side_effect = ValueError
        else:
            r.json.return_value = {}
        with patch("netwatch._proxied_get", return_value=None if bad is None else r):
            assert netwatch._ipapi_get("8.8.8.8") is None

    def test_paid_key_wins_and_cache_is_per_provider(self, monkeypatch):
        monkeypatch.setenv("NETWATCH_IPINFO_TOKEN", "tok")
        monkeypatch.delenv("NETWATCH_IPAPI_KEY", raising=False)
        assert netwatch._geo_provider() == "ipinfo-lite"
        with patch("netwatch._proxied_get", return_value=self._resp(self.LITE)) as g:
            netwatch._ipapi_get("8.8.8.8")
            monkeypatch.setenv("NETWATCH_IPAPI_KEY", "k")
            assert netwatch._geo_provider() == "ip-api-pro"
            netwatch._ipapi_get("8.8.8.8")
        assert g.call_count == 2 and "pro.ip-api.com" in g.call_args[0][0]

    def test_paid_tier_on_free_endpoint_warns_once(self, monkeypatch):
        monkeypatch.delenv("NETWATCH_IPAPI_KEY", raising=False)
        monkeypatch.delenv("NETWATCH_IPINFO_TOKEN", raising=False)
        with patch("netwatch.tier_at_least", return_value=True), \
                patch("netwatch._proxied_get", return_value=self._resp({"status": "success"})):
            netwatch._ipapi_get("1.1.1.1")
            netwatch._ipapi_get("1.0.0.1")
        assert sum("non-commercial" in a["msg"] for a in netwatch.alerts) == 1

    def test_free_tier_gets_no_warning(self, monkeypatch):
        monkeypatch.delenv("NETWATCH_IPAPI_KEY", raising=False)
        monkeypatch.delenv("NETWATCH_IPINFO_TOKEN", raising=False)
        with patch("netwatch.tier_at_least", return_value=False), \
                patch("netwatch._proxied_get", return_value=self._resp({"status": "success"})):
            netwatch._ipapi_get("1.1.1.1")
        assert not any("non-commercial" in a["msg"] for a in netwatch.alerts)


class TestRealNvdRecords:
    """Records copied from NVD (see tests/fixtures/nvd_sample.json)."""

    def _body(self):
        import os
        with open(os.path.join(os.path.dirname(__file__), "fixtures", "nvd_sample.json"), encoding="utf-8") as fh:
            return json.load(fh)

    def test_real_records_parse_and_rank(self):
        out = nc.rank(nc.parse_nvd_response(self._body()))
        assert [f["id"] for f in out] == ["CVE-2021-44228", "CVE-2023-38408", "CVE-2024-6387"]
        log4shell = out[0]
        assert log4shell["kev"] is True and log4shell["kev_added"] == "2021-12-10"
        assert (log4shell["score"], log4shell["severity"]) == (10.0, "CRITICAL")
        assert log4shell["published"] == "2021-12-10" and log4shell["summary"].startswith("Apache Log4j2")
        assert (out[2]["score"], out[2]["severity"], out[2]["kev"]) == (8.1, "HIGH", False)
        assert nc.summarize(out) == {"total": 3, "kev": 1, "CRITICAL": 2, "HIGH": 1, "MEDIUM": 0, "LOW": 0}

    def test_real_record_through_the_command(self, cve_cmd):
        run, _ = cve_cmd
        body = self._body()
        netwatch._cve_client = nc.NvdClient(lambda *a: (200, body), sleep=lambda s: None)
        out, _ = run("CVE-2021-44228")
        assert "10.0 CRITICAL" in out and "EXPLOITED" in out and "since 2021-12-10" in out


class TestPaging:
    def _page(self, ids, total):
        return (200, {"totalResults": total, "vulnerabilities": [_vuln(i, 5.0, "MEDIUM") for i in ids]})

    def test_follows_pages_until_complete(self):
        pages = [self._page([f"CVE-2024-{i:04d}" for i in range(1, 2001)], 2003),
                 (200, {"totalResults": 2003, "vulnerabilities": [
                     _vuln("CVE-2024-9001", 5.0, "MEDIUM"), _vuln("CVE-2024-9002", 9.8, "CRITICAL", kev="2024-06-01"),
                     _vuln("CVE-2024-9003", 5.0, "MEDIUM")]})]
        c, calls, _ = _client(pages, api_key="k")
        findings, _cached = c.lookup_cpe("cpe:/a:x:y:1.0")
        assert len(findings) == 2003 and findings[0]["id"] == "CVE-2024-9002"     # the exploited one was on page 2
        assert [p[1].get("startIndex") for p in calls] == [None, 2000]
        assert c.missing_for("cpe:/a:x:y:1.0") == 0

    def test_reports_what_was_not_fetched(self, tmp_path):
        pages = [self._page([f"CVE-202{p}-{i:04d}" for i in range(1, 2001)], 9000) for p in range(nc.MAX_PAGES)]
        c, calls, _ = _client(pages, tmp_path, api_key="k")
        findings, _cached = c.lookup_cpe("cpe:/a:x:y:1.0")
        assert len(calls) == nc.MAX_PAGES and len(findings) == 2000 * nc.MAX_PAGES
        assert [p[1].get("startIndex") for p in calls] == [None, 2000, 4000]
        assert c.missing_for("cpe:/a:x:y:1.0") == 9000 - 2000 * nc.MAX_PAGES
        c2, calls2, _ = _client(pages, tmp_path, api_key="k")        # survives a restart
        assert c2.missing_for("cpe:/a:x:y:1.0") == 3000 and calls2 == []

    def test_a_repeated_record_is_listed_once(self):
        same = self._page(["CVE-2024-0001", "CVE-2024-0002"], 6)
        c, _calls, _ = _client([same], api_key="k")
        assert [f["id"] for f in c.lookup_cpe("cpe:/a:x:y:1.0")[0]] == ["CVE-2024-0001", "CVE-2024-0002"]

    def test_single_page_makes_one_request(self):
        c, calls, _ = _client([self._page(["CVE-2024-0001"], 1)])
        c.lookup_cpe("cpe:/a:x:y:1.0")
        assert len(calls) == 1 and c.missing_for("cpe:/a:x:y:1.0") == 0
        assert c.missing_for("cpe:/a:never:seen:1.0") == 0 and c.missing_for("garbage") == 0

    def test_a_failed_page_is_an_error_and_caches_nothing(self):
        c, calls, _ = _client([self._page(["CVE-2024-0001"] * 1, 5000), (500, None)], api_key="k")
        with pytest.raises(nc.NvdError):
            c.lookup_cpe("cpe:/a:x:y:1.0")
        assert c._cache == {}

    def test_command_says_when_the_list_is_incomplete(self, cve_cmd):
        run, _ = cve_cmd
        page = (200, {"totalResults": 9000, "vulnerabilities": [_vuln("CVE-2024-0001", 9.8, "CRITICAL")]})
        netwatch._cve_client = nc.NvdClient(lambda *a: page, sleep=lambda s: None)
        out, _ = run("203.0.113.5")
        assert "more CVE for this version that were not fetched" in out
