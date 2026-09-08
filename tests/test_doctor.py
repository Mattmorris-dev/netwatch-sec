"""Free-tier `doctor` command — dependency + environment self-check."""
import os
import re

import netwatch


def _run_doctor(monkeypatch):
    out = []
    monkeypatch.setattr(netwatch, "add_console", lambda *a, **k: out.append(a[0] if a else ""))
    netwatch._disp_doctor([])
    return "\n".join(re.sub(r"\x1b\[[0-9;]*m", "", line) for line in out)


def test_doctor_reports_env_and_deps(monkeypatch):
    text = _run_doctor(monkeypatch)
    assert "Env:" in text
    assert "flask" in text          # a required pip dep is listed
    assert "nmap" in text           # a system tool is listed
    assert "cloudflared" in text    # tunnel tool surfaced


def test_doctor_flags_passive_when_no_root(monkeypatch):
    monkeypatch.setattr(netwatch, "HAS_RAW_NET", False)
    text = _run_doctor(monkeypatch)
    assert "PASSIVE" in text


def test_doctor_handler_is_registered():
    assert callable(netwatch._disp_doctor)


# ═══════════════════════════════════════════════════════════
# CONFIG DIRECTORY (sudo vs non-sudo must share one store)
# ═══════════════════════════════════════════════════════════

class TestConfigDir:
    """`sudo netwatch` runs as root (~ = /root) while `netwatch cam list` runs
    as the user, so a home-relative store is really two. NETWATCH_CONFIG_DIR
    names the one both use."""

    def test_default_is_the_historical_location(self, monkeypatch):
        monkeypatch.delenv("NETWATCH_CONFIG_DIR", raising=False)
        assert netwatch._config_dir() == os.path.expanduser("~/.config/netwatch")

    def test_env_var_moves_the_directory(self, monkeypatch, tmp_path):
        monkeypatch.setenv("NETWATCH_CONFIG_DIR", str(tmp_path))
        assert netwatch._config_dir() == str(tmp_path)
        assert netwatch._config_path("cameras.json") == str(tmp_path / "cameras.json")

    def test_blank_env_var_falls_back(self, monkeypatch):
        monkeypatch.setenv("NETWATCH_CONFIG_DIR", "  ")
        assert netwatch._config_dir() == os.path.expanduser("~/.config/netwatch")

    def test_read_at_call_time(self, monkeypatch, tmp_path):
        before = netwatch._config_dir()
        monkeypatch.setenv("NETWATCH_CONFIG_DIR", str(tmp_path))
        assert netwatch._config_dir() != before

    def test_compliance_snapshot_follows_the_config_dir(self, monkeypatch, tmp_path):
        monkeypatch.setenv("NETWATCH_CONFIG_DIR", str(tmp_path))
        monkeypatch.setattr(netwatch, "tier_at_least", lambda t: False)
        assert netwatch._compliance_snapshot()["siem_configured"] is False
        (tmp_path / "siem.json").write_text("{}")
        (tmp_path / "watchlist.json").write_text("{}")
        snap = netwatch._compliance_snapshot()
        assert snap["siem_configured"] is True and snap["threat_intel"] is True

    def test_alerts_configured_follows_the_config_dir(self, monkeypatch, tmp_path):
        monkeypatch.setenv("NETWATCH_CONFIG_DIR", str(tmp_path))
        assert netwatch._alerts_configured() is False
        (tmp_path / "alerts.json").write_text("{}")
        assert netwatch._alerts_configured() is True

    def test_shipper_shares_the_same_directory(self, tmp_path):
        """Checked in a clean interpreter: importlib.reload() swaps out classes
        other test modules already imported (it broke an unrelated suite once)."""
        import subprocess
        import sys
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env = dict(os.environ, NETWATCH_CONFIG_DIR=str(tmp_path), PYTHONPATH=root)
        out = subprocess.run(
            [sys.executable, "-c",
             "import netwatch_shipper as s; print(s.CONFIG_DIR); print(s.CONFIG_PATH)"],
            env=env, capture_output=True, text=True, timeout=120)
        assert out.returncode == 0, out.stderr
        assert out.stdout.split() == [str(tmp_path),
                                      str(tmp_path / "apiary_node.json")]

    def test_no_hardcoded_config_paths_left_in_code(self):
        """Regression guard: a new call site must not create a second store."""
        offenders = []
        for name in ("netwatch.py", "netwatch_shipper.py"):
            path = os.path.join(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), name)
            for i, line in enumerate(open(path).read().splitlines(), 1):
                code = line.split("#", 1)[0]
                if "expanduser" in code and ".config/netwatch" in code:
                    offenders.append(f"{name}:{i}")
        assert not offenders, (
            f"These bypass _config_dir() and split in two under sudo: {offenders}")
