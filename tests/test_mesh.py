"""Meshtastic connect: env-port override, surfaced failures, no-device path."""
import glob
from unittest.mock import MagicMock

import netwatch


def test_mesh_not_installed(monkeypatch):
    monkeypatch.setattr(netwatch, "_HAS_MESH", False)
    monkeypatch.setattr(netwatch, "mesh_interface", None)
    assert netwatch._mesh_connect() is False
    assert "meshtastic" in netwatch._mesh_last_error.lower()


def test_mesh_env_port_override(monkeypatch):
    monkeypatch.setattr(netwatch, "_HAS_MESH", True)
    monkeypatch.setattr(netwatch, "add_console", lambda *a, **k: None)
    monkeypatch.setattr(netwatch, "mesh_interface", None)
    serial_mod = MagicMock()
    serial_mod.SerialInterface.return_value = MagicMock()
    monkeypatch.setattr(netwatch, "_mesh_serial", serial_mod, raising=False)
    monkeypatch.setenv("NETWATCH_MESH_PORT", "/dev/ttyACM9")

    assert netwatch._mesh_connect() is True
    serial_mod.SerialInterface.assert_called_once_with("/dev/ttyACM9", timeout=20)


def test_mesh_no_device_surfaces_error(monkeypatch):
    monkeypatch.setattr(netwatch, "_HAS_MESH", True)
    monkeypatch.setattr(netwatch, "add_console", lambda *a, **k: None)
    monkeypatch.setattr(netwatch, "mesh_interface", None)
    monkeypatch.delenv("NETWATCH_MESH_PORT", raising=False)
    monkeypatch.setattr(glob, "glob", lambda pattern: [])

    assert netwatch._mesh_connect() is False
    assert "no serial device" in netwatch._mesh_last_error.lower()


def test_mesh_open_failure_surfaces_error(monkeypatch):
    monkeypatch.setattr(netwatch, "_HAS_MESH", True)
    monkeypatch.setattr(netwatch, "add_console", lambda *a, **k: None)
    monkeypatch.setattr(netwatch, "mesh_interface", None)
    monkeypatch.delenv("NETWATCH_MESH_PORT", raising=False)
    monkeypatch.setattr(glob, "glob",
                        lambda pattern: ["/dev/ttyACM0"] if "ACM" in pattern else [])
    serial_mod = MagicMock()
    serial_mod.SerialInterface.side_effect = OSError("port busy")
    monkeypatch.setattr(netwatch, "_mesh_serial", serial_mod, raising=False)

    assert netwatch._mesh_connect() is False
    assert "could not open" in netwatch._mesh_last_error.lower()


# ── 1.6.2: fast timeout, clear reasons, connect/disconnect, names, byte limit ──
import pytest


@pytest.fixture
def mesh(monkeypatch):
    """A fake library + captured console; returns (serial_mod, console lines)."""
    out = []
    serial_mod = MagicMock()
    monkeypatch.setattr(netwatch, "_HAS_MESH", True)
    monkeypatch.setattr(netwatch, "add_console", out.append)
    monkeypatch.setattr(netwatch, "mesh_interface", None)
    monkeypatch.setattr(netwatch, "_mesh_last_error", "")
    monkeypatch.setattr(netwatch, "_mesh_port", "")
    monkeypatch.setattr(netwatch, "_mesh_serial", serial_mod, raising=False)
    monkeypatch.setattr(netwatch, "_mesh_candidate_ports", lambda explicit="": [explicit] if explicit else ["/dev/ttyACM0"])
    monkeypatch.delenv("NETWATCH_MESH_PORT", raising=False)
    monkeypatch.delenv("NETWATCH_MESH_TIMEOUT", raising=False)
    return serial_mod, out


def test_connect_uses_a_short_timeout(mesh, monkeypatch):
    serial_mod, _ = mesh
    assert netwatch._mesh_connect() is True
    serial_mod.SerialInterface.assert_called_once_with("/dev/ttyACM0", timeout=20)
    assert netwatch._mesh_port == "/dev/ttyACM0"
    monkeypatch.setenv("NETWATCH_MESH_TIMEOUT", "9999")
    netwatch._mesh_connect()
    assert serial_mod.SerialInterface.call_args[1]["timeout"] == 300      # clamped


def test_old_library_without_timeout_argument(mesh):
    serial_mod, _ = mesh
    iface = MagicMock()
    serial_mod.SerialInterface.side_effect = [TypeError("unexpected keyword 'timeout'"), iface]
    assert netwatch._mesh_connect() is True and netwatch.mesh_interface is iface


@pytest.mark.parametrize("exc,expect", [
    (PermissionError(13, "Permission denied"), "dialout"),
    (OSError("Could not exclusively lock port /dev/ttyACM0"), "another program"),
    (Exception("Timed out waiting for connection completion"), "no answer from a Meshtastic device"),
    (FileNotFoundError(2, "No such file or directory"), "device not found"),
    (SystemExit(1), "/dev/ttyACM0: SystemExit"),
])
def test_failure_reason_is_actionable(mesh, exc, expect):
    serial_mod, out = mesh
    serial_mod.SerialInterface.side_effect = exc
    assert netwatch._mesh_connect() is False
    assert expect in netwatch._mesh_last_error and "could not open" in netwatch._mesh_last_error
    assert netwatch.mesh_interface is None and any(expect in line for line in out)


def test_second_port_is_tried(mesh, monkeypatch):
    serial_mod, _ = mesh
    monkeypatch.setattr(netwatch, "_mesh_candidate_ports", lambda explicit="": ["/dev/ttyUSB0", "/dev/ttyACM0"])
    serial_mod.SerialInterface.side_effect = [OSError("busy"), MagicMock()]
    assert netwatch._mesh_connect() is True and netwatch._mesh_port == "/dev/ttyACM0"


def test_candidate_ports_prefer_the_library_list(monkeypatch):
    lib = MagicMock()
    lib.util.findPorts.return_value = ["/dev/ttyACM3"]
    monkeypatch.setattr(netwatch, "_meshtastic_lib", lib, raising=False)
    monkeypatch.setattr(glob, "glob", lambda p: ["/dev/ttyUSB0"] if "USB" in p else [])
    assert netwatch._mesh_candidate_ports() == ["/dev/ttyACM3"]
    assert netwatch._mesh_candidate_ports("/dev/ttyS1") == ["/dev/ttyS1"]
    lib.util.findPorts.side_effect = RuntimeError
    assert netwatch._mesh_candidate_ports() == ["/dev/ttyUSB0"]


def test_connect_while_connecting_does_not_stack(mesh):
    assert netwatch._mesh_connect_lock.acquire(blocking=False)
    try:
        assert netwatch._mesh_connect() is False
        assert "already running" in netwatch._mesh_last_error
    finally:
        netwatch._mesh_connect_lock.release()


def test_connect_and_disconnect_commands(mesh, monkeypatch):
    serial_mod, out = mesh
    started = []

    class _Inline:
        def __init__(self, target=None, args=(), **_kw):
            self._t, self._a = target, args

        def start(self):
            started.append(self._a)
            self._t(*self._a)

    monkeypatch.setattr(netwatch.threading, "Thread", _Inline)
    netwatch._disp_mesh(["mesh", "connect", "/dev/ttyUSB1"])
    assert started == [("/dev/ttyUSB1",)] and netwatch._mesh_port == "/dev/ttyUSB1"
    iface = netwatch.mesh_interface
    netwatch._disp_mesh(["mesh", "status"])
    assert any("connected on /dev/ttyUSB1" in line for line in out)
    netwatch._disp_mesh(["mesh", "disconnect"])
    assert netwatch.mesh_interface is None and iface.close.called


@pytest.mark.parametrize("bad", ["/dev/sda", "/etc/passwd", "/dev/../etc/shadow", "ttyACM0", "/dev/tty ACM0", "-x"])
def test_connect_refuses_non_serial_paths(mesh, monkeypatch, bad):
    serial_mod, out = mesh
    monkeypatch.setattr(netwatch.threading, "Thread", MagicMock())
    netwatch._disp_mesh(["mesh", "connect", bad])
    assert not netwatch.threading.Thread.called and any("Usage: mesh connect" in line for line in out)


def test_status_shows_the_last_error(mesh):
    _, out = mesh
    netwatch._mesh_last_error = "could not open mesh device (/dev/ttyACM0: busy)"
    netwatch._disp_mesh(["mesh", "status"])
    text = "\n".join(out)
    assert "Last attempt: could not open" in text and "mesh connect" in text


def test_radio_unplugged_marks_disconnected(mesh):
    _, out = mesh
    iface = MagicMock()
    netwatch.mesh_interface = iface
    netwatch._on_mesh_lost(interface=MagicMock())          # some other interface: ignored
    assert netwatch.mesh_interface is iface
    netwatch._on_mesh_lost(interface=iface)
    assert netwatch.mesh_interface is None and "disconnected" in netwatch._mesh_last_error


def test_send_cuts_on_bytes_not_characters(mesh):
    iface = MagicMock()
    netwatch.mesh_interface = iface
    assert netwatch.mesh_send("é" * 150) is True                 # 300 bytes
    sent = iface.sendText.call_args[0][0]
    assert len(sent.encode("utf-8")) <= netwatch.MESH_TEXT_MAX_BYTES and sent == "é" * 100
    netwatch.mesh_messages.clear()


def test_send_failure_keeps_the_reason(mesh):
    _, out = mesh
    iface = MagicMock()
    iface.sendText.side_effect = RuntimeError("Data payload too big")
    netwatch.mesh_interface = iface
    assert netwatch.mesh_send("hi") is False
    assert "send failed: RuntimeError: Data payload too big" in netwatch._mesh_last_error
    netwatch._disp_mesh(["mesh", "send", "hi"])
    assert any("send failed" in line for line in out)
    netwatch.mesh_interface = None
    netwatch._mesh_last_error = ""
    netwatch._disp_mesh(["mesh", "send", "hi"])
    assert any("mesh connect" in line for line in out)


def test_received_message_shows_the_node_name(mesh):
    iface = MagicMock()
    iface.nodes = {"!a1b2c3d4": {"user": {"longName": "Base Station", "shortName": "BS"}}}
    netwatch.mesh_interface = iface
    netwatch.mesh_messages.clear()
    netwatch._on_mesh_recv({"decoded": {"text": "hello"}, "fromId": "!a1b2c3d4", "from": 2712847316, "snr": 6.5})
    netwatch._on_mesh_recv({"decoded": {"text": "who"}, "fromId": "!ffffffff", "from": 4294967295})
    assert [m["from"] for m in netwatch.mesh_messages] == ["Base Station", "4294967295"]
    assert netwatch.mesh_nodes["!a1b2c3d4"]["name"] == "Base Station"
    netwatch.mesh_messages.clear()
    netwatch.mesh_nodes.clear()


def test_startup_does_not_block_on_the_radio():
    import inspect
    src = inspect.getsource(netwatch.main)
    assert "threading.Thread(target=_mesh_connect, daemon=True).start()" in src
    assert "mesh_ok = _mesh_connect()" not in src
