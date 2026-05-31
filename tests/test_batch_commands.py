"""End-to-end coverage for batch commands (reconall, scanall, geoall, whoisall, blockall).

Mocks the per-IP worker so we verify dispatch + IP-list filtering without doing
real network work. Each test verifies:
  - The right number of workers gets dispatched (one per eligible IP)
  - Each worker is called with the expected IP
  - The dispatch banner is emitted
  - Filtering rules (private IPs, attackers list, etc.) are honored
"""
import netwatch
from unittest.mock import patch, MagicMock


def _seed_attackers(*ips):
    netwatch.honeypot_events.clear()
    for ip in ips:
        netwatch.honeypot_events.append({
            "time": "10:00", "service": "telnet", "ip": ip, "summary": "test",
        })


def _seed_hosts(*ips):
    for ip in ips:
        netwatch.hosts[ip]["ports"] = set()
        netwatch.hosts[ip]["bytes_in"] = 1
        netwatch.hosts[ip]["bytes_out"] = 1


# ─── reconall ──────────────────────────────────────────────────────────────

class TestReconallEnd2End:

    def test_reconall_calls_worker_per_attacker(self):
        _seed_attackers("203.0.113.10", "198.51.100.5", "203.0.113.20")
        with patch.object(netwatch, "_batch_recon_worker") as mock_worker:
            with patch("threading.Thread") as mock_thread:
                def fake_thread(target=None, args=(), **_):
                    if target is not None:
                        target(*args)
                    return MagicMock()
                mock_thread.side_effect = fake_thread
                netwatch.handle_command("reconall")
        assert mock_worker.call_count == 3
        called_ips = {c.args[2] for c in mock_worker.call_args_list}
        assert called_ips == {"203.0.113.10", "198.51.100.5", "203.0.113.20"}

    def test_reconall_empty_attacker_list(self):
        netwatch.honeypot_events.clear()
        with patch.object(netwatch, "_batch_recon_worker") as mock_worker:
            netwatch.handle_command("reconall")
        assert mock_worker.call_count == 0
        assert any("No IPs" in c for c in netwatch.console_output)

    def test_reconall_emits_banner(self):
        _seed_attackers("203.0.113.30")
        with patch("threading.Thread"):
            netwatch.handle_command("reconall")
        assert any("BATCH RECON" in c for c in netwatch.console_output)

    def test_reconall_with_hosts_list(self):
        _seed_hosts("8.8.8.8", "1.1.1.1")
        with patch.object(netwatch, "_batch_recon_worker") as mock_worker:
            with patch("threading.Thread") as mock_thread:
                def fake(target=None, args=(), **_):
                    if target is not None:
                        target(*args)
                    return MagicMock()
                mock_thread.side_effect = fake
                netwatch.handle_command("reconall hosts")
        called_ips = {c.args[2] for c in mock_worker.call_args_list}
        assert "8.8.8.8" in called_ips
        assert "1.1.1.1" in called_ips


# ─── batch worker contract ─────────────────────────────────────────────────

class TestBatchReconWorker:

    def test_batch_recon_worker_calls_recon_target(self):
        fake_report = {"hostname": "example.com", "os_guess": "Linux", "ports": [80, 443]}
        with patch.object(netwatch, "recon_target", return_value=fake_report) as mock_recon:
            netwatch._batch_recon_worker(0, 1, "93.184.216.34")
        mock_recon.assert_called_once_with("93.184.216.34")
        out = "\n".join(netwatch.console_output)
        assert "example.com" in out
        assert "Linux" in out

    def test_batch_recon_worker_handles_exception(self):
        with patch.object(netwatch, "recon_target", side_effect=RuntimeError("boom")):
            netwatch._batch_recon_worker(0, 1, "203.0.113.40")
        out = "\n".join(netwatch.console_output)
        assert "boom" in out or "error" in out.lower()


# ─── scanall / geoall / whoisall worker dispatch ───────────────────────────

class TestOtherBatchOps:

    def test_scanall_dispatches_one_per_attacker(self):
        _seed_attackers("203.0.113.50", "203.0.113.51")
        with patch.object(netwatch, "_batch_scan_worker") as mock_worker:
            with patch("threading.Thread") as mock_thread:
                def fake(target=None, args=(), **_):
                    if target is not None:
                        target(*args)
                    return MagicMock()
                mock_thread.side_effect = fake
                netwatch.handle_command("scanall")
        assert mock_worker.call_count == 2

    def test_geoall_filters_private(self):
        _seed_attackers("10.0.1.5", "192.168.1.5")
        with patch.object(netwatch, "_batch_geo_worker") as mock_worker:
            with patch("threading.Thread") as mock_thread:
                mock_thread.side_effect = lambda *_, **__: MagicMock()
                netwatch.handle_command("geoall")
        assert mock_worker.call_count == 0
        assert any("No external" in c for c in netwatch.console_output)

    def test_whoisall_dispatches_external_only(self):
        _seed_attackers("10.0.1.10", "93.184.216.34")
        with patch.object(netwatch, "_batch_whois_worker") as mock_worker:
            with patch("threading.Thread") as mock_thread:
                def fake(target=None, args=(), **_):
                    if target is not None:
                        target(*args)
                    return MagicMock()
                mock_thread.side_effect = fake
                netwatch.handle_command("whoisall")
        called_ips = {c.args[2] for c in mock_worker.call_args_list}
        assert "93.184.216.34" in called_ips
        assert "10.0.1.10" not in called_ips


# ─── blockall safety ───────────────────────────────────────────────────────

class TestBlockallSafety:

    @patch("netwatch.HAS_RAW_NET", True)
    @patch("netwatch.subprocess.run")
    def test_blockall_attackers_invokes_iptables(self, mock_run):
        _seed_attackers("203.0.113.60", "203.0.113.61")
        mock_run.return_value = MagicMock(returncode=0)
        netwatch.handle_command("blockall attackers")
        # Each block adds 2 iptables rules (INPUT + OUTPUT)
        assert mock_run.call_count == 4

    def test_blockall_hosts_rejected_for_safety(self):
        _seed_hosts("8.8.8.8")
        netwatch.handle_command("blockall hosts")
        out = "\n".join(netwatch.console_output)
        # Should refuse to mass-block from generic hosts list
        assert "Safety" in out or "safety" in out.lower() or "only" in out.lower()


# ─── rotate commands ───────────────────────────────────────────────────────

class TestRotateCommands:

    def test_rotate_key_swaps_fernet(self):
        old_key = netwatch.WEB_ENCRYPTION_KEY
        netwatch.handle_command("rotate-key")
        assert netwatch.WEB_ENCRYPTION_KEY != old_key
        assert any("rotated" in c for c in netwatch.console_output)

    def test_rotate_token_swaps_and_persists(self, tmp_path):
        token_path = tmp_path / "token"
        with patch.object(netwatch, "_TOKEN_PATH", str(token_path)):
            old_token = netwatch.WEB_TOKEN
            netwatch.handle_command("rotate-token")
            assert netwatch.WEB_TOKEN != old_token
            assert token_path.exists()
            saved = token_path.read_text().strip()
            assert saved == netwatch.WEB_TOKEN
            # 0600 perms
            import stat
            mode = token_path.stat().st_mode & 0o777
            assert mode == 0o600
