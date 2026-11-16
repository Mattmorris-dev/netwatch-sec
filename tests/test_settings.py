"""Saved settings: allow-list, validation, file permission checks, load order,
the `config` command (in-app and from the shell)."""
import os
import stat
import subprocess
import sys

import pytest

import netwatch
import netwatch_settings as ns

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    monkeypatch.setenv("NETWATCH_CONFIG_DIR", str(tmp_path))
    for env_key, _kind, _desc in ns.SETTINGS.values():
        monkeypatch.delenv(env_key, raising=False)
    return tmp_path / "settings.env"


class TestNames:
    def test_resolve(self):
        assert ns.resolve("nvd-key") == "NETWATCH_NVD_API_KEY"
        assert ns.resolve("NVD-Key ") == "NETWATCH_NVD_API_KEY"
        assert ns.resolve("netwatch_whitelist") == "NETWATCH_WHITELIST"

    @pytest.mark.parametrize("name", ["NETWATCH_TOKEN", "NETWATCH_TIER", "NETWATCH_PRO", "NETWATCH_WEB_ALLOW",
                                      "NETWATCH_TRUST_PROXY", "NETWATCH_CLOUDFLARED_BIN",
                                      "NETWATCH_PROXYCHAIN_SCRIPT", "NETWATCH_CONFIG_DIR", "NETWATCH_MODE",
                                      "PATH", "LD_PRELOAD", "", None, "nope"])
    def test_access_and_program_settings_cannot_be_saved(self, name):
        assert ns.resolve(name) is None

    def test_every_setting_is_read_by_the_program(self):
        with open(os.path.join(REPO, "netwatch.py"), encoding="utf-8") as fh:
            src = fh.read()
        for env_key, _kind, _desc in ns.SETTINGS.values():
            assert f'"{env_key}"' in src, f"{env_key} is saved but never read"


class TestValidate:
    @pytest.mark.parametrize("key,value,want", [
        ("NETWATCH_NVD_API_KEY", " 1234abcd-ef01-2345 ", "1234abcd-ef01-2345"),
        ("NETWATCH_HTTP_PORT", "0080", "80"),
        ("NETWATCH_MESH_TIMEOUT", "20", "20"),
        ("NETWATCH_MESH_PORT", "/dev/ttyACM0", "/dev/ttyACM0"),
        ("NETWATCH_WHITELIST", "198.51.100.7, 203.0.113.", "198.51.100.7, 203.0.113."),
    ])
    def test_good(self, key, value, want):
        assert ns.validate(key, value) == (True, want)

    @pytest.mark.parametrize("key,value", [
        ("NETWATCH_NVD_API_KEY", "short"), ("NETWATCH_NVD_API_KEY", "has space in it"),
        ("NETWATCH_NVD_API_KEY", "abc\ndef12345"), ("NETWATCH_NVD_API_KEY", "x" * 201),
        ("NETWATCH_HTTP_PORT", "0"), ("NETWATCH_HTTP_PORT", "65536"), ("NETWATCH_HTTP_PORT", "80; id"),
        ("NETWATCH_HTTP_PORT", "-1"), ("NETWATCH_MESH_TIMEOUT", "4"), ("NETWATCH_MESH_TIMEOUT", "301"),
        ("NETWATCH_MESH_PORT", "/etc/passwd"), ("NETWATCH_MESH_PORT", "/dev/sda"),
        ("NETWATCH_WHITELIST", "$(id)"), ("NETWATCH_WHITELIST", ""), ("NETWATCH_TOKEN", "abcdefgh12345"),
        ("NETWATCH_NVD_API_KEY", None),
    ])
    def test_bad(self, key, value):
        assert ns.validate(key, value)[0] is False


class TestFile:
    def test_round_trip_and_mode(self, cfg):
        assert ns.save(str(cfg), "NETWATCH_NVD_API_KEY", "abcd1234efgh") == (True, "abcd1234efgh")
        assert ns.save(str(cfg), "NETWATCH_HTTP_PORT", "8081")[0]
        assert stat.S_IMODE(cfg.stat().st_mode) == 0o600
        assert ns.read_file(str(cfg)) == ({"NETWATCH_NVD_API_KEY": "abcd1234efgh", "NETWATCH_HTTP_PORT": "8081"}, [])
        assert ns.save(str(cfg), "NETWATCH_HTTP_PORT", None) == (True, "")
        assert ns.read_file(str(cfg))[0] == {"NETWATCH_NVD_API_KEY": "abcd1234efgh"}
        assert ns.save(str(cfg), "NETWATCH_HTTP_PORT", None) == (False, "not set in the settings file")

    def test_bad_value_is_not_written(self, cfg):
        assert ns.save(str(cfg), "NETWATCH_HTTP_PORT", "99999")[0] is False
        assert ns.save(str(cfg), "NETWATCH_TOKEN", "abcdefgh1234")[0] is False
        assert not cfg.exists()

    def test_hand_written_file(self, cfg):
        cfg.write_text('# comment\n\nexport NETWATCH_NVD_API_KEY="abcd1234efgh"\nipinfo-token = tok12345\n'
                       "NETWATCH_TOKEN=stolen12345\nNETWATCH_HTTP_PORT=notaport\nLD_PRELOAD=/tmp/x.so\ngarbage\n")
        cfg.chmod(0o600)
        valid, rejected = ns.read_file(str(cfg))
        assert valid == {"NETWATCH_NVD_API_KEY": "abcd1234efgh", "NETWATCH_IPINFO_TOKEN": "tok12345"}
        assert len(rejected) == 4 and any("http-port" in r for r in rejected)

    @pytest.mark.parametrize("mode", [0o620, 0o602, 0o666])
    def test_file_others_can_write_is_ignored(self, cfg, mode):
        cfg.write_text("NETWATCH_HTTP_PORT=8081\n")
        cfg.chmod(mode)
        valid, rejected = ns.read_file(str(cfg))
        assert valid == {} and "writable by group or others" in rejected[0]

    def test_symlink_is_ignored(self, cfg, tmp_path):
        real = tmp_path / "elsewhere"
        real.write_text("NETWATCH_HTTP_PORT=8081\n")
        real.chmod(0o600)
        cfg.symlink_to(real)
        valid, rejected = ns.read_file(str(cfg))
        assert valid == {} and "not a regular file" in rejected[0]

    def test_file_of_another_user_is_ignored(self, cfg, monkeypatch):
        cfg.write_text("NETWATCH_HTTP_PORT=8081\n")
        cfg.chmod(0o600)
        real = os.lstat(str(cfg))
        owner = {"uid": 4242}

        class _Stat:
            st_mode, st_size = real.st_mode, real.st_size

            @property
            def st_uid(self):
                return owner["uid"]

        monkeypatch.setattr(ns.os, "lstat", lambda _p: _Stat())
        monkeypatch.setattr(ns.os, "geteuid", lambda: 1000)
        assert ns.read_file(str(cfg)) == ({}, [f"{cfg}: owned by another user, ignored"])
        owner["uid"] = 0                                  # a root-owned file is accepted
        assert ns.read_file(str(cfg))[0] == {"NETWATCH_HTTP_PORT": "8081"}
        owner["uid"] = 1000                               # and so is our own
        assert ns.read_file(str(cfg))[0] == {"NETWATCH_HTTP_PORT": "8081"}

    def test_missing_file(self, cfg):
        assert ns.read_file(str(cfg)) == ({}, [])

    def test_save_does_not_write_through_a_planted_tmp_symlink(self, cfg, tmp_path):
        victim = tmp_path / "victim"
        victim.write_text("keep me")
        (tmp_path / "settings.env.tmp").symlink_to(victim)
        assert ns.save(str(cfg), "NETWATCH_HTTP_PORT", "8081")[0]
        assert victim.read_text() == "keep me"


class TestLoad:
    def test_environment_wins_over_file(self, cfg):
        ns.save(str(cfg), "NETWATCH_HTTP_PORT", "8081")
        ns.save(str(cfg), "NETWATCH_FTP_PORT", "2122")
        env = {"NETWATCH_HTTP_PORT": "9999"}
        applied, rejected = ns.load(str(cfg), env)
        assert env == {"NETWATCH_HTTP_PORT": "9999", "NETWATCH_FTP_PORT": "2122"}
        assert applied == {"NETWATCH_FTP_PORT": "2122"} and rejected == []

    def test_program_reads_saved_ports_at_start(self, tmp_path):
        """End to end: a saved port is in effect in a fresh process, and a bad
        hand edit cannot crash start-up."""
        (tmp_path / "settings.env").write_text("NETWATCH_HTTP_PORT=18080\nNETWATCH_FTP_PORT=notaport\n")
        (tmp_path / "settings.env").chmod(0o600)
        env = {k: v for k, v in os.environ.items() if not k.startswith("NETWATCH_")}
        env["NETWATCH_CONFIG_DIR"] = str(tmp_path)
        out = subprocess.run(
            [sys.executable, "-c",
             "import sys; sys.argv=['netwatch.py']; import netwatch as n; "
             "print(n.HTTP_PORT, n.FTP_PORT, len(n._SETTINGS_REJECTED))"],
            cwd=REPO, env=env, capture_output=True, text=True, timeout=60)
        assert out.stdout.split() == ["18080", "2121", "1"], out.stderr[-400:]


class TestConfigCommand:
    def _run(self, text):
        netwatch.handle_command(text)
        return netwatch._ansi_strip("\n".join(netwatch.console_output))

    def test_set_show_unset(self, cfg):
        out = self._run("config set nvd-key abcd1234efgh5678")
        assert "nvd-key = ********5678" in out and "abcd1234" not in out
        assert os.environ["NETWATCH_NVD_API_KEY"] == "abcd1234efgh5678"
        out = self._run("config")
        assert "nvd-key" in out and "********5678 (file)" in out and "ipinfo-token" in out and "not set" in out
        out = self._run("config unset nvd-key")
        assert "nvd-key = removed" in out and "NETWATCH_NVD_API_KEY" not in os.environ
        assert ns.read_file(str(cfg))[0] == {}

    def test_new_key_takes_effect_without_restart(self, cfg):
        netwatch._cve_client = object()
        netwatch._ipapi_cache[("ip-api-free", "x")] = (0, None)
        self._run("config set nvd-key abcd1234efgh5678")
        assert netwatch._cve_client is None and netwatch._ipapi_cache == {}
        assert netwatch._get_cve_client()._api_key == "abcd1234efgh5678"
        netwatch._cve_client = None

    def test_whitelist_applies_now(self, cfg):
        scan, pref = set(netwatch.WHITELIST_SCAN), netwatch.WHITELIST_PREFIXES
        try:
            assert not netwatch.is_whitelisted("198.51.100.7")
            self._run("config set whitelist 198.51.100.7, 203.0.113.")
            assert netwatch.is_whitelisted("198.51.100.7") and netwatch.is_whitelisted("203.0.113.9")
        finally:
            netwatch.WHITELIST_SCAN.clear()
            netwatch.WHITELIST_SCAN.update(scan)
            netwatch.WHITELIST_PREFIXES = pref

    def test_port_needs_restart_and_is_not_changed_live(self, cfg):
        before = netwatch.HTTP_PORT
        out = self._run("config set http-port 8081")
        assert "Restart NetWatch" in out and netwatch.HTTP_PORT == before

    @pytest.mark.parametrize("cmd,expect", [
        ("config set http-port 99999", "expected a number from 1 to 65535"),
        ("config set token abcdefgh1234", "Unknown setting 'token'"),
        ("config set NETWATCH_WEB_ALLOW 0.0.0.0/0", "Unknown setting"),
        ("config set nvd-key", "usage: config set"),
        ("config unset nvd-key", "not set in the settings file"),
        ("config bogus", "usage: config"),
    ])
    def test_errors(self, cfg, cmd, expect):
        assert expect in self._run(cmd)
        assert not cfg.exists()

    def test_environment_value_is_labelled(self, cfg, monkeypatch):
        monkeypatch.setenv("NETWATCH_MESH_PORT", "/dev/ttyUSB0")
        assert "/dev/ttyUSB0 (environment)" in self._run("config")

    def test_not_reachable_from_the_web(self):
        assert "config" not in netwatch._WEB_SAFE_CMDS

    def test_shell_subcommand(self, cfg, capsys):
        assert netwatch._cli_subcommand(["config", "set", "mesh-timeout", "30"]) == 0
        assert "mesh-timeout = 30" in netwatch._ansi_strip(capsys.readouterr().out)
        assert netwatch._cli_subcommand(["config", "set", "mesh-timeout", "9999"]) == 1
        assert netwatch._cli_subcommand(["config"]) == 0
        assert "30 (file)" in netwatch._ansi_strip(capsys.readouterr().out)
