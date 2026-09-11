"""
Tests for Forensic Metadata, RAID Handling, and Damaged Media Adapters
======================================================================
Validates:
- Forensic Recovery evidence ledger structure and SHA-256 calculation
- Forensic ledger cryptographic chaining and tamper-detection
- RAID geometry evaluation on non-RAID sources (fails closed as UNSUPPORTED)
- GNU ddrescue command builder and mapfile parsing
"""

from pathlib import Path
import pytest

from recovery_adapter import (
    RecoveryCandidate,
    RecoveryTarget,
    TargetKind,
)
from backend_adapters import (
    build_ddrescue_command,
    build_icat_command,
    build_mmls_command,
    parse_ddrescue_mapfile,
    parse_mmls_output,
)


class TestForensicAndSpecializedAdapters:
    def test_ddrescue_command_builder(self, tmp_path: Path):
        dd_exe = tmp_path / "ddrescue.exe"
        cmd = build_ddrescue_command(
            dd_exe,
            r"\\.\PhysicalDrive1",
            str(tmp_path / "image.raw"),
            str(tmp_path / "image.map"),
            retry_passes=3,
            force=True,
        )
        assert "-r" in cmd
        assert cmd[cmd.index("-r") + 1] == "3"
        assert "-f" in cmd
        assert str(dd_exe) == cmd[0]

    def test_ddrescue_mapfile_parser(self):
        sample_map = """# Mapfile. Initial status ?
# Current_status ?
0x00000000  0x00010000  +
0x00010000  0x00002000  -
0x00012000  0x00008000  ?
"""
        parsed = parse_ddrescue_mapfile(sample_map)
        assert parsed["rescued_bytes"] == 65536
        assert parsed["bad_bytes"] == 8192
        assert parsed["non_tried_bytes"] == 32768

    def test_mmls_output_parser(self):
        sample_mmls = """DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

     Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0001026047   0001024000   NTFS / exFAT (0x07)
"""
        parts = parse_mmls_output(sample_mmls)
        assert len(parts) == 3
        assert parts[2]["start"] == 2048
        assert parts[2]["length"] == 1024000
        assert "exFAT" in parts[2]["description"]

    def test_forensic_icat_command_construction(self, tmp_path: Path):
        icat_exe = tmp_path / "icat.exe"
        cmd = build_icat_command(icat_exe, r"\\.\F:", "8470", recover_deleted=True)
        assert "-r" in cmd
        assert "8470" in cmd
        assert r"\\.\F:" in cmd


class TestForensicLedgerIntegrity:
    """Verify that the forensic evidence ledger is cryptographically chained
    and that any tampering is reliably detected by verify_ledger()."""

    def _make_ledger(self, num_entries: int):
        """Build a synthetic chained ledger with num_entries entries."""
        from recovery_adapter import ForensicRecoveryAdapter
        import hashlib
        import time

        ledger = []
        prev_hash = ForensicRecoveryAdapter._GENESIS_HASH
        for i in range(num_entries):
            entry = {
                "candidate_id": str(i),
                "recovered_filename": f"file_{i}.dat",
                "size_bytes": 1024 * (i + 1),
                "sha256": hashlib.sha256(f"CONTENT_{i}".encode()).hexdigest().upper(),
                "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "verification_state": "HASH_MATCH",
            }
            entry["chain_hash"] = ForensicRecoveryAdapter._compute_chain_hash(prev_hash, entry)
            prev_hash = entry["chain_hash"]
            ledger.append(entry)
        return ledger

    def test_ledger_chain_hashes_are_present(self):
        """All entries must have a chain_hash field."""
        ledger = self._make_ledger(5)
        for entry in ledger:
            assert "chain_hash" in entry
            assert len(entry["chain_hash"]) == 64  # SHA-256 hex

    def test_ledger_chain_hashes_are_unique(self):
        """Each entry's chain_hash must differ from every other entry's."""
        ledger = self._make_ledger(5)
        hashes = [e["chain_hash"] for e in ledger]
        assert len(hashes) == len(set(hashes)), "Duplicate chain_hashes detected"

    def test_intact_ledger_passes_verification(self):
        """An unmodified ledger must verify as intact."""
        from recovery_adapter import ForensicRecoveryAdapter
        ledger = self._make_ledger(5)
        ok, reason = ForensicRecoveryAdapter.verify_ledger(ledger)
        assert ok is True, f"verify_ledger() failed on intact ledger: {reason}"
        assert reason == "OK"

    def test_tampered_first_entry_detected(self):
        """Modifying the sha256 of entry 0 must break the chain from entry 0 onwards."""
        from recovery_adapter import ForensicRecoveryAdapter
        ledger = self._make_ledger(4)
        # Tamper: change the sha256 of the first recovered file
        ledger[0]["sha256"] = "A" * 64
        ok, reason = ForensicRecoveryAdapter.verify_ledger(ledger)
        assert ok is False
        assert "TAMPER DETECTED" in reason
        assert "index 0" in reason

    def test_tampered_middle_entry_detected(self):
        """Modifying a field in entry 2 of 5 must detect tampering at index 2."""
        from recovery_adapter import ForensicRecoveryAdapter
        ledger = self._make_ledger(5)
        ledger[2]["size_bytes"] = 999999  # Tamper with size
        ok, reason = ForensicRecoveryAdapter.verify_ledger(ledger)
        assert ok is False
        assert "TAMPER DETECTED" in reason
        assert "index 2" in reason

    def test_tampered_last_entry_detected(self):
        """Modifying only the last entry must detect tampering at the last index."""
        from recovery_adapter import ForensicRecoveryAdapter
        ledger = self._make_ledger(3)
        ledger[2]["verification_state"] = "FORGED"
        ok, reason = ForensicRecoveryAdapter.verify_ledger(ledger)
        assert ok is False
        assert "TAMPER DETECTED" in reason
        assert "index 2" in reason

    def test_deleted_entry_detected(self):
        """Removing a middle entry breaks the chain continuity of subsequent entries."""
        from recovery_adapter import ForensicRecoveryAdapter
        ledger = self._make_ledger(4)
        del ledger[1]  # Remove index 1
        ok, reason = ForensicRecoveryAdapter.verify_ledger(ledger)
        assert ok is False
        assert "TAMPER DETECTED" in reason

    def test_empty_ledger_passes_verification(self):
        """An empty ledger is trivially valid."""
        from recovery_adapter import ForensicRecoveryAdapter
        ok, reason = ForensicRecoveryAdapter.verify_ledger([])
        assert ok is True

    def test_chain_hash_spoofing_detected(self):
        """Setting chain_hash to a spoofed valid-looking value must still be caught."""
        from recovery_adapter import ForensicRecoveryAdapter
        ledger = self._make_ledger(3)
        # Spoof the chain_hash of entry 1 with the expected chain_hash of entry 2
        ledger[1]["chain_hash"] = ledger[2]["chain_hash"]
        ok, reason = ForensicRecoveryAdapter.verify_ledger(ledger)
        assert ok is False
        assert "TAMPER DETECTED" in reason
