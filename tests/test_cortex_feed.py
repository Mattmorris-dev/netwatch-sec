"""Local Cortex feed: honeypot events mirror into the Apiary store Cortex reads,
attack-vectors only, zero egress, opt-out honored."""
import glob
import json
import os

import netwatch


def _read_store(d):
    return [json.loads(l) for f in glob.glob(os.path.join(d, "*.json")) for l in open(f)]


def test_feed_writes_vector_only(tmp_path, monkeypatch):
    store = tmp_path / "apiary_data" / "local"
    monkeypatch.setattr(netwatch, "_CORTEX_STORE_DIR", str(store))
    monkeypatch.setattr(netwatch, "_cortex_feed_state", {"checked": True, "on": True})
    netwatch._cortex_feed_event({
        "timestamp": "2026-07-15T10:00:00+00:00", "service": "ssh",
        "source_ip": "203.0.113.7", "source_port": 54321,
        "data": {"password": "SECRET", "user": "root"}})
    rows = _read_store(str(store))
    assert len(rows) == 1
    assert rows[0] == {"timestamp": "2026-07-15T10:00:00+00:00", "service": "ssh",
                       "source_ip": "203.0.113.7", "source_port": 54321}
    assert "SECRET" not in json.dumps(rows)          # payload never mirrored
    assert "data" not in rows[0]


def test_feed_dir_is_0700(tmp_path, monkeypatch):
    store = tmp_path / "apiary_data" / "local"
    monkeypatch.setattr(netwatch, "_CORTEX_STORE_DIR", str(store))
    monkeypatch.setattr(netwatch, "_cortex_feed_state", {"checked": True, "on": True})
    netwatch._cortex_feed_event({"timestamp": "t", "service": "x",
                                 "source_ip": "1.1.1.1", "source_port": 1})
    assert (os.stat(store).st_mode & 0o777) == 0o700


def test_feed_disabled_writes_nothing(tmp_path, monkeypatch):
    store = tmp_path / "apiary_data" / "local"
    monkeypatch.setattr(netwatch, "_CORTEX_STORE_DIR", str(store))
    monkeypatch.setattr(netwatch, "_cortex_feed_state", {"checked": True, "on": False})
    netwatch._cortex_feed_event({"timestamp": "t", "service": "x",
                                 "source_ip": "1.1.1.1", "source_port": 1})
    assert not store.exists()


def test_env_opt_out_wins(monkeypatch):
    monkeypatch.setenv("NETWATCH_CORTEX_FEED", "0")
    monkeypatch.setattr(netwatch, "_cortex_feed_state", {"checked": True, "on": True})
    assert netwatch._cortex_feed_enabled() is False


def test_env_force_on(monkeypatch):
    monkeypatch.setenv("NETWATCH_CORTEX_FEED", "1")
    monkeypatch.setattr(netwatch, "_cortex_feed_state", {"checked": False, "on": False})
    assert netwatch._cortex_feed_enabled() is True


def test_feed_never_raises(tmp_path, monkeypatch):
    # Unwritable path must not propagate into the honeypot logging path.
    monkeypatch.setattr(netwatch, "_CORTEX_STORE_DIR", "/proc/nonexistent/nope")
    monkeypatch.setattr(netwatch, "_cortex_feed_state", {"checked": True, "on": True})
    netwatch._cortex_feed_event({"timestamp": "t", "service": "x",
                                 "source_ip": "1.1.1.1", "source_port": 1})  # no raise
