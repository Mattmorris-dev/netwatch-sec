"""Tests for the new bounded-deque buffers and persistent Fernet key.

Covers item 2 (CLI/CONSOLE BUFFERS, deque maxlen 5000) and item 3 (WEB UI
ENCRYPTION, ~/.config/netwatch/web.key) from the refactor spec.
"""
from __future__ import annotations

import os
import stat
import tempfile
from collections import deque
from pathlib import Path

import pytest

import netwatch


# --- Console buffer (deque) ---

class TestConsoleDeque:

    def test_is_deque_with_maxlen(self):
        assert isinstance(netwatch.console_output, deque)
        assert netwatch.console_output.maxlen == 5000

    def test_self_trims_at_capacity(self):
        netwatch.console_output.clear()
        for i in range(6000):
            netwatch.console_output.append(f"line{i}")
        assert len(netwatch.console_output) == 5000
        assert netwatch.console_output[0] == "line1000"
        assert netwatch.console_output[-1] == "line5999"

    def test_clear_command_empties_buffer(self):
        netwatch.add_console("a")
        netwatch.add_console("b")
        assert len(netwatch.console_output) >= 2
        netwatch.handle_command("clear")
        assert len(netwatch.console_output) == 0

    def test_add_console_appends_under_lock(self):
        netwatch.console_output.clear()
        netwatch.add_console("under-lock")
        assert "under-lock" in list(netwatch.console_output)

    def test_indexing_works_on_deque(self):
        netwatch.console_output.clear()
        for s in ("first", "second", "third"):
            netwatch.add_console(s)
        assert netwatch.console_output[0] == "first"
        assert netwatch.console_output[-1] == "third"

    def test_snapshot_pattern_for_slicing(self):
        """list(deque)[start:end] is the safe slicing pattern."""
        netwatch.console_output.clear()
        for i in range(10):
            netwatch.add_console(f"x{i}")
        snap = list(netwatch.console_output)
        assert snap[3:6] == ["x3", "x4", "x5"]


class TestCmdHistoryDeque:

    def test_is_deque_with_maxlen(self):
        assert isinstance(netwatch._cmd_history, deque)
        assert netwatch._cmd_history.maxlen == 5000

    def test_history_self_trims(self):
        netwatch._cmd_history.clear()
        for i in range(6000):
            netwatch._cmd_history.append(f"cmd{i}")
        assert len(netwatch._cmd_history) == 5000
        assert netwatch._cmd_history[-1] == "cmd5999"


# --- Fernet key persistence ---

class TestKeyPersistence:

    def test_key_file_exists_and_locked_down(self):
        path = netwatch._KEY_PATH
        assert os.path.exists(path)
        st = os.stat(path)
        mode = st.st_mode & 0o777
        assert mode == 0o600, f"key file should be 0600, got {oct(mode)}"

    def test_key_dir_is_0700(self):
        d = os.path.dirname(netwatch._KEY_PATH)
        assert os.path.isdir(d)
        mode = os.stat(d).st_mode & 0o777
        assert mode == 0o700, f"key dir should be 0700, got {oct(mode)}"

    def test_load_or_create_returns_valid_key(self, tmp_path):
        p = tmp_path / "k.key"
        key = netwatch.load_or_create_key(str(p))
        from cryptography.fernet import Fernet
        Fernet(key)  # raises if invalid

    def test_load_or_create_idempotent(self, tmp_path):
        p = tmp_path / "k.key"
        k1 = netwatch.load_or_create_key(str(p))
        k2 = netwatch.load_or_create_key(str(p))
        assert k1 == k2, "second call must return same persisted key"

    def test_load_or_create_chmods_0600(self, tmp_path):
        p = tmp_path / "k.key"
        netwatch.load_or_create_key(str(p))
        mode = os.stat(p).st_mode & 0o777
        assert mode == 0o600

    def test_rotate_key_replaces_material(self, tmp_path):
        p = tmp_path / "k.key"
        k1 = netwatch.load_or_create_key(str(p))
        k2 = netwatch.rotate_key(str(p))
        assert k1 != k2
        assert open(p, "rb").read().strip() == k2

    def test_rotate_key_atomic_no_tmp_leftover(self, tmp_path):
        p = tmp_path / "k.key"
        netwatch.rotate_key(str(p))
        assert not (tmp_path / "k.key.tmp").exists()

    def test_get_cipher_round_trip(self):
        c = netwatch.get_cipher()
        token = c.encrypt(b"hello")
        assert c.decrypt(token) == b"hello"

    def test_corrupt_key_file_regenerates(self, tmp_path):
        p = tmp_path / "k.key"
        p.write_bytes(b"not-a-valid-fernet-key")
        key = netwatch.load_or_create_key(str(p))
        from cryptography.fernet import Fernet
        Fernet(key)  # must be valid now
