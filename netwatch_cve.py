"""
CVE lookup for NetWatch.

Service versions (CPE names from an nmap version scan) are matched against the
NVD CVE API 2.0. Results are ranked with known-exploited vulnerabilities first:
NVD carries the CISA KEV catalog date on each CVE record (`cisaExploitAdd`).

This module has no NetWatch imports and no network code of its own. The caller
passes `http_get`, so all traffic follows NetWatch's proxy and SSRF rules and
the module can be tested without a network.

    http_get(url, params, headers, timeout) -> (status_code, parsed_json_or_None)

Only outbound HTTPS to services.nvd.nist.gov is needed.
"""
import json
import os
import re
import threading
import time
import xml.etree.ElementTree as ET

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NVD public rate limits: 5 requests per rolling 30 s without an API key, 50
# with one. The intervals below stay under both.
MIN_INTERVAL_NO_KEY = 6.5
MIN_INTERVAL_WITH_KEY = 0.7

CACHE_TTL = 24 * 3600        # a CVE list for a product version changes slowly
CACHE_MAX_ENTRIES = 2000
MAX_SERVICES_PER_SCAN = 25   # bound the NVD calls one scan can cause
MAX_XML_BYTES = 4 * 1024 * 1024

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
# One CPE component: what nmap and NVD emit, and nothing that could alter a URL.
_CPE_PART_RE = re.compile(r"^[a-z0-9._\-~%+!]+$")
_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def is_cve_id(text):
    return bool(text) and bool(CVE_ID_RE.match(text))


def is_cpe(text):
    return bool(text) and text.lower().startswith(("cpe:/", "cpe:2.3:"))


def normalize_cpe(cpe):
    """Return a CPE 2.3 name with a version, or None.

    Accepts the 2.2 URI form nmap prints (cpe:/a:openbsd:openssh:8.9p1) and the
    2.3 form. A CPE with no version is refused: it would match every CVE the
    product ever had, which is noise, not a finding.
    """
    if not cpe or not isinstance(cpe, str):
        return None
    cpe = cpe.strip().lower()
    if cpe.startswith("cpe:2.3:"):
        parts = cpe[len("cpe:2.3:"):].split(":")
    elif cpe.startswith("cpe:/"):
        parts = cpe[len("cpe:/"):].split(":")
    else:
        return None
    if len(parts) < 4 or len(parts) > 11:
        return None
    part, vendor, product, version = parts[0], parts[1], parts[2], parts[3]
    if part not in ("a", "o", "h"):
        return None
    if version in ("", "*", "-"):
        return None
    for comp in (vendor, product, version):
        if not _CPE_PART_RE.match(comp):
            return None
    update = parts[4] if len(parts) > 4 and _CPE_PART_RE.match(parts[4] or "") else "*"
    return f"cpe:2.3:{part}:{vendor}:{product}:{version}:{update}:*:*:*:*:*:*"


def parse_nmap_xml(xml_text):
    """Open ports with service detail from `nmap -sV -oX -` output.

    Returns [{"port", "proto", "service", "product", "version", "cpes"}].
    Product and version strings come from the scanned host: treat them as
    untrusted text (the caller strips control characters before display).
    """
    if not xml_text or len(xml_text) > MAX_XML_BYTES:
        return []
    if "<!ENTITY" in xml_text:      # nmap never emits entity declarations
        return []
    try:
        root = ET.fromstring(xml_text)   # nosec B314 - nmap wrote it locally; entity declarations refused above
    except ET.ParseError:
        return []
    services = []
    for port in root.iter("port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        svc = port.find("service")
        if svc is None:
            continue
        cpes = []
        for node in svc.findall("cpe"):
            norm = normalize_cpe(node.text or "")
            if norm and norm not in cpes:
                cpes.append(norm)
        try:
            portid = int(port.get("portid", "0"))
        except ValueError:
            continue
        services.append({
            "port": portid,
            "proto": (port.get("protocol") or "tcp")[:8],
            "service": (svc.get("name") or "")[:40],
            "product": (svc.get("product") or "")[:80],
            "version": (svc.get("version") or "")[:40],
            "cpes": cpes,
        })
    services.sort(key=lambda s: s["port"])
    return services


def _metric(cve):
    """(score, severity) from the newest CVSS version the record carries."""
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        # NVD's own assessment ("Primary") first, then any other source
        entries = sorted(entries, key=lambda e: e.get("type") != "Primary")
        data = entries[0].get("cvssData") or {}
        score = data.get("baseScore")
        severity = data.get("baseSeverity") or entries[0].get("baseSeverity") or ""
        if isinstance(score, (int, float)):
            return float(score), str(severity).upper()
    return None, ""


def parse_nvd_response(body):
    """NVD API 2.0 response -> list of finding dicts. Tolerates missing fields."""
    findings = []
    if not isinstance(body, dict):
        return findings
    for item in body.get("vulnerabilities") or []:
        cve = (item or {}).get("cve") or {}
        cve_id = cve.get("id")
        if not is_cve_id(cve_id or ""):
            continue
        if str(cve.get("vulnStatus", "")).lower() == "rejected":
            continue
        summary = ""
        for desc in cve.get("descriptions") or []:
            if desc.get("lang") == "en":
                summary = " ".join(str(desc.get("value", "")).split())
                break
        score, severity = _metric(cve)
        findings.append({
            "id": cve_id.upper(),
            "score": score,
            "severity": severity,
            "kev": bool(cve.get("cisaExploitAdd")),
            "kev_added": cve.get("cisaExploitAdd") or "",
            "kev_due": cve.get("cisaActionDue") or "",
            "published": str(cve.get("published", ""))[:10],
            "summary": summary[:400],
        })
    return findings


def rank(findings):
    """Known-exploited first, then by score, then newest."""
    out = sorted(findings, key=lambda f: f.get("id", ""))
    out.sort(key=lambda f: f.get("published", ""), reverse=True)
    out.sort(key=lambda f: (f.get("score") if f.get("score") is not None else -1.0,
                            _SEVERITY_ORDER.get(f.get("severity", ""), 0)), reverse=True)
    out.sort(key=lambda f: not f.get("kev"))
    return out


def summarize(findings):
    """Counts for a one-line summary."""
    out = {"total": len(findings), "kev": 0, "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        if f.get("kev"):
            out["kev"] += 1
        if f.get("severity") in out:
            out[f["severity"]] += 1
    return out


class NvdError(Exception):
    """A lookup failed. str(error) is safe to show to the user."""


class NvdClient:
    """Rate-limited, cached NVD lookups."""

    def __init__(self, http_get, api_key=None, cache_path=None,
                 clock=time.time, sleep=time.sleep):
        self._http_get = http_get
        self._api_key = api_key or None
        self._cache_path = cache_path
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.Lock()
        self._last_call = 0.0
        self._cache = None

    # -- cache ---------------------------------------------------------
    def _load_cache(self):
        if self._cache is not None:
            return
        self._cache = {}
        if not self._cache_path:
            return
        try:
            with open(self._cache_path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                self._cache = {k: v for k, v in data.items()
                               if isinstance(v, dict) and isinstance(v.get("data"), list)}
        except (OSError, ValueError):
            self._cache = {}

    def _save_cache(self):
        if not self._cache_path:
            return
        if len(self._cache) > CACHE_MAX_ENTRIES:
            keep = sorted(self._cache, key=lambda k: self._cache[k].get("ts", 0))
            for key in keep[:len(self._cache) - CACHE_MAX_ENTRIES]:
                del self._cache[key]
        tmp = f"{self._cache_path}.tmp"
        try:
            os.makedirs(os.path.dirname(self._cache_path) or ".", exist_ok=True)
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self._cache, fh)
            os.replace(tmp, self._cache_path)
        except OSError:
            pass   # the cache is an optimisation; a read-only disk must not break lookups

    # -- transport -----------------------------------------------------
    def _query(self, cache_key, params):
        with self._lock:
            self._load_cache()
            hit = self._cache.get(cache_key)
            if hit and self._clock() - hit.get("ts", 0) < CACHE_TTL:
                return hit["data"], True
            interval = MIN_INTERVAL_WITH_KEY if self._api_key else MIN_INTERVAL_NO_KEY
            wait = self._last_call + interval - self._clock()
            if wait > 0:
                self._sleep(wait)
            headers = {"apiKey": self._api_key} if self._api_key else {}
            self._last_call = self._clock()
            status, body = self._http_get(NVD_URL, params, headers, 30)
            if status in (403, 429):
                raise NvdError("NVD rate limit reached. Wait 30 seconds, or set "
                               "NETWATCH_NVD_API_KEY (free key from nvd.nist.gov).")
            if status == 404:
                data = []          # NVD answers 404 for a CPE name it does not know
            elif status != 200 or body is None:
                raise NvdError(f"NVD lookup failed (HTTP {status or 'no response'}). "
                               "Check outbound HTTPS to services.nvd.nist.gov.")
            else:
                data = parse_nvd_response(body)
            self._cache[cache_key] = {"ts": self._clock(), "data": data}
            self._save_cache()
            return data, False

    # -- public --------------------------------------------------------
    def lookup_cve(self, cve_id):
        """One CVE by id -> finding dict or None."""
        if not is_cve_id(cve_id):
            raise NvdError(f"Not a CVE id: {str(cve_id)[:40]}")
        cve_id = cve_id.upper()
        data, _cached = self._query(f"id:{cve_id}", {"cveId": cve_id})
        return data[0] if data else None

    def lookup_cpe(self, cpe):
        """CVEs that apply to one product version -> (ranked findings, from_cache)."""
        norm = normalize_cpe(cpe)
        if not norm:
            raise NvdError("CPE needs vendor, product and a version "
                           "(example: cpe:2.3:a:openbsd:openssh:8.9p1).")
        data, cached = self._query(f"cpe:{norm}", {"cpeName": norm, "resultsPerPage": 500})
        return rank(data), cached

    def lookup_services(self, services, progress=None):
        """Look up every versioned CPE of a scan.

        Returns (results, skipped): results is [(service, cpe, findings)] and
        skipped is the count of services left out by MAX_SERVICES_PER_SCAN.
        """
        todo = [(svc, cpe) for svc in services for cpe in svc.get("cpes", [])]
        skipped = max(0, len(todo) - MAX_SERVICES_PER_SCAN)
        results = []
        for svc, cpe in todo[:MAX_SERVICES_PER_SCAN]:
            if progress:
                progress(svc, cpe)
            findings, _cached = self.lookup_cpe(cpe)
            results.append((svc, cpe, findings))
        return results, skipped
