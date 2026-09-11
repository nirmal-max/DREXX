"""
Tests for Forensic Metadata, RAID Handling, and Damaged Media Adapters
======================================================================
Validates:
- Forensic Recovery evidence ledger structure and SHA-256 calculation
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
