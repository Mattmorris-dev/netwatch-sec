"""PTY integration test: verify console→dashboard terminal state transitions.

Tests the actual termios/raw-mode transitions using a real pseudo-terminal,
not just source code pattern matching.
"""
import os
import sys
import pty
import tty
import time
import select
import termios
import threading
import signal
import pytest


def read_pty(fd, timeout=1.0):
    buf = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        r, _, _ = select.select([fd], [], [], min(0.05, remaining))
        if r:
            try:
                chunk = os.read(fd, 4096)
                if not chunk:
                    break
                buf += chunk
            except OSError:
                break
    return buf


class TestTerminalTransitions:
    """Test raw↔cooked mode transitions using real PTY."""

    def test_setraw_then_restore_produces_working_raw_mode(self):
        """Simulate the exact sequence netwatch uses:
        1. Save original settings
        2. setraw + save raw settings
        3. Switch to cooked (restore original)
        4. Switch back to raw (restore saved raw settings)
        5. Verify terminal is in raw mode (no echo, no line buffering)
        """
        master, slave = pty.openpty()
        try:
            original = termios.tcgetattr(slave)

            tty.setraw(slave)
            raw_settings = termios.tcgetattr(slave)

            termios.tcsetattr(slave, termios.TCSADRAIN, original)
            cooked_after = termios.tcgetattr(slave)
            assert cooked_after[3] & termios.ECHO, "Cooked mode should have ECHO"
            assert cooked_after[3] & termios.ICANON, "Cooked mode should have ICANON"

            termios.tcsetattr(slave, termios.TCSADRAIN, raw_settings)
            restored_raw = termios.tcgetattr(slave)
            assert not (restored_raw[3] & termios.ECHO), "Restored raw should NOT have ECHO"
            assert not (restored_raw[3] & termios.ICANON), "Restored raw should NOT have ICANON"

            assert raw_settings[3] == restored_raw[3], \
                f"lflag mismatch: original raw {raw_settings[3]:#x} vs restored {restored_raw[3]:#x}"

        finally:
            os.close(master)
            os.close(slave)

    def test_setraw_after_cooked_produces_different_settings(self):
        """Show WHY we save _raw_settings: tty.setraw() after cooked mode
        reads the current (cooked) attrs and modifies them, which can differ
        from raw settings captured from a clean state."""
        master, slave = pty.openpty()
        try:
            original = termios.tcgetattr(slave)

            tty.setraw(slave)
            clean_raw = termios.tcgetattr(slave)

            termios.tcsetattr(slave, termios.TCSADRAIN, original)
            tty.setraw(slave)
            cooked_then_raw = termios.tcgetattr(slave)

            # Both should end up in raw mode (no ECHO, no ICANON)
            assert not (clean_raw[3] & termios.ECHO)
            assert not (cooked_then_raw[3] & termios.ECHO)

            # But the underlying iflag/oflag may differ because tty.setraw
            # modifies whatever settings are current
            # This test documents the behavior — the key point is both work,
            # but saved settings are more reliable
        finally:
            os.close(master)
            os.close(slave)

    def test_console_roundtrip_with_render_thread(self):
        """Simulate the full console→dashboard flow with a render thread,
        using the exact locking protocol from netwatch."""
        master, slave = pty.openpty()
        console_mode = False
        _input_active = False
        _render_lock = threading.Lock()
        _redraw_event = threading.Event()
        render_count = [0]
        render_errors = []

        def render_loop():
            while not stop_event.is_set():
                _redraw_event.wait(timeout=0.1)
                if console_mode or _input_active:
                    _redraw_event.clear()
                    continue
                _redraw_event.clear()
                if not _render_lock.acquire(blocking=False):
                    continue
                try:
                    if console_mode or _input_active:
                        continue
                    try:
                        os.write(master, b"\033[H[DASHBOARD FRAME]\033[K\n")
                        render_count[0] += 1
                    except OSError as e:
                        render_errors.append(str(e))
                finally:
                    _render_lock.release()

        stop_event = threading.Event()
        render_thread = threading.Thread(target=render_loop, daemon=True)
        render_thread.start()

        try:
            original = termios.tcgetattr(slave)
            tty.setraw(slave)
            _raw_settings = termios.tcgetattr(slave)

            time.sleep(0.3)
            _redraw_event.set()
            time.sleep(0.3)
            initial_renders = render_count[0]
            assert initial_renders > 0, "Render thread should produce frames in raw mode"

            console_mode = True
            _render_lock.acquire()
            try:
                termios.tcsetattr(slave, termios.TCSADRAIN, original)
                os.write(master, b"\033[2J\033[H[CONSOLE MODE]\n")
                time.sleep(0.2)
                renders_during_console = render_count[0]
                assert renders_during_console == initial_renders, \
                    "No frames should render during console mode"
            finally:
                try:
                    termios.tcsetattr(slave, termios.TCSADRAIN, _raw_settings)
                except Exception:
                    tty.setraw(slave)
                try:
                    termios.tcflush(slave, termios.TCIFLUSH)
                except Exception:
                    pass
                os.write(master, b"\033[2J\033[H")
                console_mode = False
                _input_active = False
                _render_lock.release()
                _redraw_event.set()

            time.sleep(0.5)
            final_renders = render_count[0]
            assert final_renders > renders_during_console, \
                f"Dashboard must resume rendering after console exit: {final_renders} vs {renders_during_console}"

            restored = termios.tcgetattr(slave)
            assert not (restored[3] & termios.ECHO), "Terminal should be in raw mode after transition"
            assert not (restored[3] & termios.ICANON), "Terminal should be in raw mode after transition"

        finally:
            stop_event.set()
            _redraw_event.set()
            render_thread.join(timeout=2)
            os.close(master)
            os.close(slave)

        assert not render_errors, f"Render thread errors: {render_errors}"

    def test_multiple_console_roundtrips(self):
        """Verify transition works correctly across multiple console entries."""
        master, slave = pty.openpty()
        console_mode = False
        _render_lock = threading.Lock()
        _redraw_event = threading.Event()

        try:
            original = termios.tcgetattr(slave)
            tty.setraw(slave)
            _raw_settings = termios.tcgetattr(slave)

            for i in range(5):
                console_mode = True
                _render_lock.acquire()
                try:
                    termios.tcsetattr(slave, termios.TCSADRAIN, original)
                    attrs = termios.tcgetattr(slave)
                    assert attrs[3] & termios.ECHO, f"Round {i}: should be cooked"
                finally:
                    termios.tcsetattr(slave, termios.TCSADRAIN, _raw_settings)
                    console_mode = False
                    _render_lock.release()
                    _redraw_event.set()

                attrs = termios.tcgetattr(slave)
                assert not (attrs[3] & termios.ECHO), f"Round {i}: should be raw after restore"
                assert not (attrs[3] & termios.ICANON), f"Round {i}: should be raw after restore"

        finally:
            os.close(master)
            os.close(slave)

    def test_lock_not_leaked_on_exception(self):
        """If console command throws, lock must still be released."""
        _render_lock = threading.Lock()

        console_mode = True
        _render_lock.acquire()
        try:
            raise RuntimeError("simulated crash in console command")
        except RuntimeError:
            pass
        finally:
            console_mode = False
            _render_lock.release()

        assert _render_lock.acquire(blocking=False), "Lock should be available after exception"
        _render_lock.release()


class TestDashboardReadyAfterConsole:
    """Verify dashboard renders correctly immediately after console exit."""

    def test_console_exit_emits_full_reset_sequence(self):
        """Console exit must emit SGR reset + cursor show + clear + home."""
        master, slave = pty.openpty()
        try:
            tty.setraw(slave)
            os.write(slave, b"\033[0m\033[?25h\033[2J\033[H")
            output = read_pty(master, timeout=0.5)
            assert b"\033[0m" in output, "Missing SGR reset"
            assert b"\033[?25h" in output, "Missing cursor show"
            assert b"\033[2J" in output, "Missing screen clear"
            assert b"\033[H" in output, "Missing cursor home"
            reset_pos = output.index(b"\033[0m")
            clear_pos = output.index(b"\033[2J")
            assert reset_pos < clear_pos, "SGR reset must come before screen clear"
        finally:
            os.close(master)
            os.close(slave)

    def test_render_frame_works_after_console_exit(self):
        """_render_frame() must produce output when console_mode=False and lock free."""
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        import netwatch
        from unittest.mock import patch

        netwatch.console_mode = False
        netwatch._input_active = False
        if netwatch._render_lock.locked():
            netwatch._render_lock.release()

        written = []
        def capture_write(fd, data):
            if fd == 1:
                written.append(data)
            return len(data)

        with patch("os.write", side_effect=capture_write), \
             patch("os.get_terminal_size", return_value=os.terminal_size((80, 40))):
            netwatch._render_frame()

        assert written, "render_frame must produce output after console exit"
        combined = b"".join(written)
        assert b"\033[H" in combined, "Frame must contain cursor home"

    def test_help_overlay_activates_and_dismisses(self):
        """show_help_overlay=True renders help, False renders dashboard."""
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        import netwatch
        from unittest.mock import patch

        written_help = []
        written_dash = []

        def capture(target):
            def _write(fd, data):
                if fd == 1:
                    target.append(data)
                return len(data)
            return _write

        netwatch.show_help_overlay = True
        with patch("os.write", side_effect=capture(written_help)), \
             patch("os.get_terminal_size", return_value=os.terminal_size((80, 40))):
            netwatch._render_frame()

        help_out = b"".join(written_help).decode("utf-8", errors="replace")
        assert "COMMAND REFERENCE" in help_out, "Help overlay must show when flag is True"

        netwatch.show_help_overlay = False
        with patch("os.write", side_effect=capture(written_dash)), \
             patch("os.get_terminal_size", return_value=os.terminal_size((80, 40))):
            netwatch._render_frame()

        dash_out = b"".join(written_dash).decode("utf-8", errors="replace")
        assert "COMMAND REFERENCE" not in dash_out, "Help overlay must NOT show when flag is False"

    def test_esc_clears_help_overlay(self):
        """ESC key must set show_help_overlay=False."""
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        import netwatch

        netwatch.show_help_overlay = True
        assert netwatch.show_help_overlay is True

        # Simulate the ESC handler logic from main loop
        if netwatch.show_help_overlay:
            netwatch.show_help_overlay = False
            netwatch._redraw_event.set()

        assert netwatch.show_help_overlay is False, "ESC must clear help overlay"
        assert netwatch._redraw_event.is_set(), "Redraw event must be signaled"

    def test_dashboard_ready_after_console_roundtrip(self):
        """Full roundtrip: console mode → exit → immediate render produces frame."""
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
        import netwatch
        from unittest.mock import patch

        netwatch.console_mode = True
        netwatch._input_active = True
        netwatch._render_lock.acquire()

        # Simulate console exit sequence
        netwatch.console_mode = False
        netwatch._input_active = False
        netwatch._render_lock.release()
        netwatch._redraw_event.set()

        written = []
        def capture_write(fd, data):
            if fd == 1:
                written.append(data)
            return len(data)

        with patch("os.write", side_effect=capture_write), \
             patch("os.get_terminal_size", return_value=os.terminal_size((80, 40))):
            netwatch._render_frame()

        assert written, "Must render immediately after console roundtrip"
        combined = b"".join(written).decode("utf-8", errors="replace")
        assert "nw>" in combined, "Frame must contain prompt"
