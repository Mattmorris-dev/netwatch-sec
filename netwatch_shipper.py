"""Apiary shipper — ship this node's honeypot events up to a fleet hub.

This is a FREE feature: any NetWatch node can `join` a hub and contribute its
attack data to the collective (the hub itself is a Pro capability). The shipper
tails `logs/all_events.json`, batches new lines, and POSTs them to the hub's
`/ingest` endpoint authenticated with a per-node key.

Robustness (the parts a naive `tail -f` gets wrong):
* Resumes from a persisted (device, inode, offset) so a restart never re-ships
  history and never skips events written while it was down.
* Survives NetWatch's rename-based rotation at 50 MB: the open handle keeps
  reading the renamed `.1` to EOF, then reopens the fresh file — no gap.
* At-least-once delivery: a batch that fails to POST is spooled to disk and
  replayed on the next successful connection, so a hub outage drops nothing.

Data policy (Doc 2 §5): by default only attack-vector fields are shipped; the
full `data` payload is opt-in (`payload_optin`), so a node can contribute intel
without exporting request bodies that might carry sensitive content.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import ssl
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

log = logging.getLogger("netwatch.shipper")

CONFIG_DIR = Path(os.path.expanduser("~/.config/netwatch"))
CONFIG_PATH = CONFIG_DIR / "apiary_node.json"
STATE_PATH = CONFIG_DIR / "apiary_shipper_state.json"
SPOOL_DIR = CONFIG_DIR / "apiary_spool"
# Where a pulled edge model is installed. This is the CORTEX config tree, not the
# Apiary one — the local cortex edge agent reads its model from here.
DEFAULT_MODEL_TARGET = Path(os.path.expanduser("~/.config/cortex/edge_model.json"))

BATCH = 100
FLUSH_INTERVAL = 2.0          # seconds — flush a partial batch so low-traffic nodes still ship
POLL_SLEEP = 0.5
MAX_SPOOL_FILES = 10_000      # cap disk use if the hub is down for a very long time
MODEL_INTERVAL = 1800.0       # seconds between edge-model pull checks (opt-in, default off)
_MAX_MODEL_BYTES = 64 * 1024  # match the hub cap — never read an unbounded body

# Fields kept when payload is NOT opted in — the attack vector, no request body.
_VECTOR_FIELDS = ("timestamp", "service", "source_ip", "source_port")

# ─── Community hive ("burned once, blocked everywhere") ─────────────────────
# The public community hub. Empty until the project pins one — then joining is
# just `netwatch join --community`. Both are overridable so self-hosted hives
# work today: NETWATCH_COMMUNITY_HUB / NETWATCH_COMMUNITY_TOKEN.
DEFAULT_COMMUNITY_HUB = os.environ.get("NETWATCH_COMMUNITY_HUB", "")
# Pinned CA for the community hub (PEM). Empty → system CAs (real cert on the
# hub). Non-empty → pinned, self-signed hubs work without touching system trust.
COMMUNITY_CA_PEM = ""

_NODE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}\Z")   # mirror the hub's slug rule


def enroll_community(hub_url: str | None = None, token: str = "",
                     name: str = "", config_path: Path = CONFIG_PATH) -> dict:
    """Self-enroll this node on a community hive hub (POST /enroll) and persist
    the returned credentials. Opt-IN only — nothing calls this automatically.

    Hardened like the rest of the shipper: https-only, no redirects, pinned CA
    when COMMUNITY_CA_PEM is set, bounded response, validated fields. Only
    attack-vector fields ever ship for a community node (hub re-strips too)."""
    hub = (hub_url or DEFAULT_COMMUNITY_HUB).strip()
    if not hub:
        raise ValueError("no community hub configured — pass a hub URL or set "
                         "NETWATCH_COMMUNITY_HUB")
    parsed = urlparse(hub)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("community hub must be https://")
    token = (token or os.environ.get("NETWATCH_COMMUNITY_TOKEN", "")).strip()
    if not token:
        raise ValueError("community hub needs an enroll token — set "
                         "NETWATCH_COMMUNITY_TOKEN (published with the hive)")
    ctx = ssl.create_default_context()
    if COMMUNITY_CA_PEM:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        ctx.load_verify_locations(cadata=COMMUNITY_CA_PEM)
    body = json.dumps({"token": token,
                       "name": re.sub(r"[^a-z0-9_-]", "-",
                                      (name or os.uname().nodename).lower())[:32]}).encode()
    req = urllib.request.Request(
        hub.rstrip("/") + "/enroll", data=body, method="POST",
        headers={"Content-Type": "application/json"})
    try:
        with _https_get(ctx, req, timeout=10) as resp:
            raw = resp.read(8192)
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = json.loads(e.read(512)).get("error", "")
        except Exception:
            pass
        raise ValueError(f"hive enrollment refused ({e.code}"
                         f"{': ' + detail if detail else ''})")
    except (urllib.error.URLError, OSError, ssl.SSLError) as e:
        raise ValueError(f"hive unreachable: {getattr(e, 'reason', e)}")
    try:
        info = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        raise ValueError("hive sent a malformed response")
    node_id = str(info.get("node_id", ""))
    key = str(info.get("key", ""))
    if not _NODE_ID_RE.match(node_id) or not key or len(key) > 512:
        raise ValueError("hive sent invalid credentials")
    cfg = load_config(config_path)
    cfg.update({"hub_url": hub, "node_id": node_id, "node_key": key,
                "community": True})
    cfg.pop("payload_optin", None)             # community nodes never ship payloads
    if COMMUNITY_CA_PEM:
        ca_path = CONFIG_DIR / "apiary_hub_ca.pem"
        ca_path.parent.mkdir(parents=True, exist_ok=True)
        ca_path.write_text(COMMUNITY_CA_PEM)
        os.chmod(ca_path, 0o600)
        cfg["ca_cert"] = str(ca_path)
    save_config(cfg, config_path)
    return cfg


def load_config(path: Path = CONFIG_PATH) -> dict:
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def save_config(cfg: dict, path: Path = CONFIG_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(cfg, indent=2))
    os.chmod(tmp, 0o600)                     # holds the node key — keep it 0600
    os.replace(tmp, path)


def parse_enroll_token(token: str) -> dict:
    """Decode a `nwj_` enrollment token (from `collector keygen … <hub-url>`).
    Validates defensively — the token is operator-pasted, so bound its size and
    require an https hub + non-empty creds before trusting any field."""
    if not isinstance(token, str) or not token.startswith("nwj_"):
        raise ValueError("not an enrollment token")
    body = token[4:]
    if len(body) > 20000:
        raise ValueError("token too large")
    try:
        raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
        blob = json.loads(raw)
    except (ValueError, json.JSONDecodeError):
        raise ValueError("malformed token")
    if not isinstance(blob, dict):
        raise ValueError("malformed token")
    hub, nid, key = str(blob.get("h", "")), str(blob.get("i", "")), str(blob.get("k", ""))
    if not hub.lower().startswith("https://"):
        raise ValueError("hub_url must be https")
    if not nid or not key:
        raise ValueError("missing node id/key")
    return {"hub_url": hub, "node_id": nid, "node_key": key, "ca_pem": str(blob.get("ca", "")),
            "model_fetch": bool(blob.get("m", False))}


def configure_from_token(token: str, config_path: Path = CONFIG_PATH,
                         ca_path: Path | None = None) -> dict:
    """Decode a token and persist config + a pinned CA (to a FIXED path, never one
    from the token). Returns the saved config."""
    info = parse_enroll_token(token)
    cfg = load_config(config_path)
    cfg.update({"hub_url": info["hub_url"], "node_id": info["node_id"],
                "node_key": info["node_key"]})
    if info.get("model_fetch"):
        cfg["model_fetch"] = True                # hub opted this node into edge-model pull
    if info["ca_pem"]:
        # Validate the PEM here so a garbage `ca` field fails cleanly at join
        # instead of raising ssl.SSLError later at connect time.
        try:
            ssl.create_default_context().load_verify_locations(cadata=info["ca_pem"])
        except ssl.SSLError:
            raise ValueError("token CA is not valid PEM")
        ca_path = Path(ca_path) if ca_path else (CONFIG_DIR / "apiary_hub_ca.pem")
        ca_path.parent.mkdir(parents=True, exist_ok=True)
        ca_path.write_text(info["ca_pem"])
        os.chmod(ca_path, 0o600)
        cfg["ca_cert"] = str(ca_path)
    save_config(cfg, config_path)
    return cfg


def _ssl_context(cfg: dict) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ca = cfg.get("ca_cert")
    if ca and os.path.exists(ca):
        ctx.load_verify_locations(ca)        # pin the hub's (self-signed) CA — recommended
    elif cfg.get("allow_insecure_tls"):
        # Explicit, unambiguous opt-out ONLY. This DISABLES cert + hostname
        # verification, exposing the node key to an active MITM. Prefer ca_cert.
        log.warning("allow_insecure_tls set — TLS cert/hostname verification DISABLED; "
                    "pin the hub CA with ca_cert instead")
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    # else: default system-CA verification. Against a self-signed hub this FAILS,
    # so the batch is spooled (not sent) — the node key is never shipped insecurely.
    return ctx


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never auto-follow a redirect — used for the model fetch so a hostile hub
    can't bounce the node (and its key header) to http:// or a third party."""
    def redirect_request(self, *a, **k):
        return None


def _https_get(ctx, req, timeout: int = 10):
    """HTTPS GET that does NOT follow redirects (a redirect surfaces as an
    HTTPError). Single seam so the fetch path is easy to test."""
    opener = urllib.request.build_opener(
        _NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    return opener.open(req, timeout=timeout)


def _trim(event: dict, payload_optin: bool) -> dict:
    if payload_optin:
        return event
    return {k: event[k] for k in _VECTOR_FIELDS if k in event}


class Shipper:
    def __init__(self, config: dict | None = None, source_path: str | None = None,
                 state_path: Path = STATE_PATH, spool_dir: Path = SPOOL_DIR):
        self.cfg = config if config is not None else load_config()
        self.source = Path(source_path or self.cfg.get("source_path")
                           or (Path(__file__).parent / "logs" / "all_events.json"))
        self.state_path = Path(state_path)
        self.spool_dir = Path(spool_dir)
        self.batch = int(self.cfg.get("batch", BATCH))
        self.flush_interval = float(self.cfg.get("flush_interval", FLUSH_INTERVAL))
        self.payload_optin = bool(self.cfg.get("payload_optin", False))
        if self.cfg.get("community"):
            # Community nodes contribute the attack vector only — payload opt-in
            # can never apply, even if someone hand-edits the config.
            self.payload_optin = False
        # Edge-model pull: OFF by default (opt-in). When on, periodically GET the
        # hub's distilled model and install it where the local cortex agent reads.
        self.model_fetch = bool(self.cfg.get("model_fetch", False))
        self.model_target = Path(os.path.expanduser(
            self.cfg.get("model_target") or str(DEFAULT_MODEL_TARGET)))
        # Floor at 60s: the model GET shares the hub's per-node rate budget with
        # /ingest, so a mis-set tiny interval could 429 the node's own event ship.
        self.model_interval = max(60.0, float(self.cfg.get("model_interval", MODEL_INTERVAL)))
        self._last_model_check = 0.0
        self._stop = threading.Event()
        self._ctx = _ssl_context(self.cfg)

    # ── state persistence ────────────────────────────────────────────────
    def _load_state(self) -> dict:
        try:
            return json.loads(self.state_path.read_text())
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return {}

    def _save_state(self, dev: int, ino: int, offset: int) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"dev": dev, "ino": ino, "offset": offset}))
        os.replace(tmp, self.state_path)

    # ── HTTP ─────────────────────────────────────────────────────────────
    def _post(self, events: list) -> bool:
        url = self.cfg.get("hub_url", "").rstrip("/") + "/ingest"
        if not url.lower().startswith("https://"):
            log.error("hub_url must be https:// — refusing to ship node key over http")
            return False
        body = json.dumps(events).encode()
        req = urllib.request.Request(url, data=body, method="POST", headers={
            "Content-Type": "application/json",
            "X-Node-Id": self.cfg.get("node_id", ""),
            "X-Node-Key": self.cfg.get("node_key", ""),
            "User-Agent": "netwatch-apiary-shipper/1.0",
        })
        try:
            with urllib.request.urlopen(req, timeout=10, context=self._ctx) as r:
                return 200 <= r.status < 300
        except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError) as e:
            log.debug("ship failed: %s", type(e).__name__)
            return False

    def _local_model_sha(self) -> str:
        try:
            return hashlib.sha256(self.model_target.read_bytes()).hexdigest()
        except OSError:
            return ""

    def _fetch_model(self) -> bool:
        """Pull the hub's distilled edge model and install it atomically.

        Mirrors _post: same pinned TLS context, same per-node auth headers,
        https-only. Deliberately does NOT use the Pro package's safe_urlopen —
        that guard refuses private LAN hub IPs and isn't present on a Free node.
        Sends the current local sha so an unchanged model returns 304 (no body).
        Any failure keeps the existing model untouched."""
        url = self.cfg.get("hub_url", "").rstrip("/") + "/model"
        if not url.lower().startswith("https://"):
            log.error("hub_url must be https:// — refusing to fetch model over http")
            return False
        req = urllib.request.Request(url, method="GET", headers={
            "X-Node-Id": self.cfg.get("node_id", ""),
            "X-Node-Key": self.cfg.get("node_key", ""),
            "X-Model-Sha": self._local_model_sha(),
            "User-Agent": "netwatch-apiary-shipper/1.0",
        })
        # _https_get does NOT follow redirects: a compromised hub must not be able
        # to 302 us to http:// (or a third party) and thereby leak the node key.
        try:
            with _https_get(self._ctx, req, timeout=10) as r:
                if not (200 <= r.status < 300):
                    return False
                data = r.read(_MAX_MODEL_BYTES + 1)    # one over the cap detects overflow
        except urllib.error.HTTPError as e:
            # urllib raises HTTPError for any >=300, so a 304 Not Modified (our
            # "you already have this model" reply) lands here, not above.
            if e.code == 304:
                return True                           # already current
            log.debug("model fetch failed: HTTP %s", e.code)
            return False
        except (urllib.error.URLError, OSError, ValueError) as e:
            log.debug("model fetch failed: %s", type(e).__name__)
            return False
        if len(data) > _MAX_MODEL_BYTES:
            log.warning("model fetch rejected: body exceeds %d bytes", _MAX_MODEL_BYTES)
            return False
        # Validate before install — never overwrite a good model with a bad blob.
        try:
            obj = json.loads(data)
        except (json.JSONDecodeError, ValueError):
            log.warning("model fetch rejected: not valid JSON")
            return False
        if not isinstance(obj, dict) or obj.get("kind") != "cortex-edge":
            log.warning("model fetch rejected: not a cortex-edge model")
            return False
        if not isinstance(obj.get("tables"), dict):
            log.warning("model fetch rejected: model has no tables object")
            return False
        try:
            self.model_target.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.model_target.with_suffix(self.model_target.suffix + ".tmp")
            tmp.write_bytes(data)
            os.chmod(tmp, 0o600)
            os.replace(tmp, self.model_target)         # atomic install
        except OSError as e:
            log.warning("model install failed: %s", type(e).__name__)
            return False
        log.info("edge model updated (%d bytes) → %s", len(data), self.model_target)
        return True

    def _maybe_fetch_model(self) -> None:
        if not self.model_fetch:
            return
        now = time.time()
        if now - self._last_model_check < self.model_interval:
            return
        self._last_model_check = now
        self._fetch_model()

    # ── spool (at-least-once) ────────────────────────────────────────────
    def _spool(self, events: list) -> None:
        self.spool_dir.mkdir(parents=True, exist_ok=True)
        existing = sorted(self.spool_dir.glob("*.json"))
        if len(existing) >= MAX_SPOOL_FILES:
            log.warning("spool full (%d) — dropping oldest", len(existing))
            try:
                existing[0].unlink()
            except OSError:
                pass
        name = f"{time.time():.6f}-{os.getpid()}.json"
        (self.spool_dir / name).write_text(json.dumps(events))

    def _drain_spool(self) -> None:
        if not self.spool_dir.exists():
            return
        for f in sorted(self.spool_dir.glob("*.json")):
            try:
                events = json.loads(f.read_text())
            except (json.JSONDecodeError, OSError):
                f.unlink(missing_ok=True)          # corrupt spool file — discard
                continue
            if self._post(events):
                f.unlink(missing_ok=True)
            else:
                return                              # still down; stop, retry later

    def _flush(self, buf: list) -> None:
        if not buf:
            return
        self._drain_spool()                         # keep ordering: old spool first
        if not self._post(buf):
            self._spool(buf)

    # ── main loop ────────────────────────────────────────────────────────
    def run(self) -> None:
        while not self.source.exists() and not self._stop.is_set():
            self._stop.wait(POLL_SLEEP)             # wait for first honeypot hit
        if self._stop.is_set():
            return

        st = self.source.stat()
        state = self._load_state()
        # Resume only if the file is the same inode we last saw; else start at EOF.
        if state.get("dev") == st.st_dev and state.get("ino") == st.st_ino \
                and state.get("offset", 0) <= st.st_size:
            offset = state["offset"]
        else:
            offset = st.st_size                     # first run: only new events

        fh = open(self.source, "r")
        fh.seek(offset)
        buf: list = []
        last_flush = time.time()

        try:
            while not self._stop.is_set():
                line = fh.readline()
                if line:
                    try:
                        ev = json.loads(line)
                        buf.append(_trim(ev, self.payload_optin))
                    except json.JSONDecodeError:
                        pass                        # partial/garbled line — skip
                    if len(buf) >= self.batch:
                        self._flush(buf); buf = []
                        last_flush = time.time()
                    fpos = fh.tell()
                    fstat = os.fstat(fh.fileno())
                    self._save_state(fstat.st_dev, fstat.st_ino, fpos)
                    continue

                # EOF on the current handle — check for rotation before sleeping.
                try:
                    path_ino = self.source.stat().st_ino
                except FileNotFoundError:
                    path_ino = None
                cur_ino = os.fstat(fh.fileno()).st_ino
                if path_ino is not None and path_ino != cur_ino:
                    # Rotated: we've drained the renamed old file to EOF; reopen.
                    fh.close()
                    fh = open(self.source, "r")
                    st = os.fstat(fh.fileno())
                    self._save_state(st.st_dev, st.st_ino, 0)
                    continue

                now = time.time()
                if buf and (now - last_flush) >= self.flush_interval:
                    self._flush(buf); buf = []
                    last_flush = now
                else:
                    self._drain_spool()             # nothing new — retry any backlog
                self._maybe_fetch_model()           # opt-in edge-model pull (rate-gated)
                self._stop.wait(POLL_SLEEP)
        finally:
            if buf:
                self._flush(buf)
            fh.close()

    def stop(self) -> None:
        self._stop.set()

    def start_background(self) -> threading.Thread:
        t = threading.Thread(target=self.run, daemon=True, name="apiary-shipper")
        t.start()
        return t


def is_configured(path: Path = CONFIG_PATH) -> bool:
    cfg = load_config(path)
    return bool(cfg.get("hub_url") and cfg.get("node_id") and cfg.get("node_key"))
