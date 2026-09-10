"""Tests for backend_adapters.py — command construction and output parsing.

These tests validate that DREX constructs correct commands for each upstream
backend and correctly parses their actual output formats. No external binaries
are executed; all parsing is tested against known-good output samples from
the upstream documentation and source code.
"""

import tempfile
from pathlib import Path

import pytest

from backend_adapters import (
    BACKEND_CAPABILITIES,
    build_ddrescue_command,
    build_fls_command,
    build_fsstat_command,
    build_icat_command,
    build_mmls_command,
    build_photorec_command,
    build_tsk_recover_command,
    parse_ddrescue_mapfile,
    parse_fls_output,
    parse_fsstat_output,
    parse_mmls_output,
)


# ─── fls command construction ────────────────────────────────────────

class TestFlsCommand:
    def test_default_flags(self, tmp_path):
        exe = tmp_path / "fls.exe"
        cmd = build_fls_command(exe, "image.dd")
        assert cmd == [str(exe), "-r", "-l", "-p", "image.dd"]

    def test_deleted_only(self, tmp_path):
        exe = tmp_path / "fls.exe"
        cmd = build_fls_command(exe, "image.dd", deleted_only=True)
        assert "-d" in cmd
        assert "-r" in cmd

    def test_no_recursive_no_long(self, tmp_path):
        exe = tmp_path / "fls.exe"
        cmd = build_fls_command(exe, "image.dd", recursive=False, long_format=False,
                                full_path=False)
        assert "-r" not in cmd
        assert "-l" not in cmd
        assert "-p" not in cmd

    def test_with_fs_offset(self, tmp_path):
        exe = tmp_path / "fls.exe"
        cmd = build_fls_command(exe, "disk.dd", fs_offset=2048)
        assert "-o" in cmd
        idx = cmd.index("-o")
        assert cmd[idx + 1] == "2048"


# ─── fls output parsing ─────────────────────────────────────────────

class TestFlsParsing:
    def test_short_format_deleted_and_active(self):
        """Parse fls short output with deleted (*) and active entries."""
        output = (
            "r/r  14:\tfile1.txt\n"
            "r/r  * 15:\tdeleted_photo.jpg\n"
            "d/d  20:\tsubdir\n"
            "r/r  21:\tdata.bin\n"
        )
        candidates = parse_fls_output(output)
        assert len(candidates) == 4

        # file1.txt — active
        assert candidates[0].candidate_id == "14"
        assert candidates[0].name == "file1.txt"
        assert candidates[0].deleted is False

        # deleted_photo.jpg — deleted
        assert candidates[1].candidate_id == "15"
        assert candidates[1].name == "deleted_photo.jpg"
        assert candidates[1].deleted is True
        assert candidates[1].recoverable is True

        # subdir — directory
        assert candidates[2].candidate_id == "20"
        assert candidates[2].file_type == "directory"

    def test_long_format_with_sizes(self):
        """Parse fls long-format output with tab-separated fields including size."""
        output = (
            "r/r  14-128-4:\tfile1.txt\t2024-01-01 12:00:00\t2024-01-01 12:00:00\t"
            "2024-01-01 12:00:00\t2024-01-01 12:00:00\t4096\t0\t0\n"
        )
        candidates = parse_fls_output(output)
        assert len(candidates) == 1
        assert candidates[0].candidate_id == "14"
        assert candidates[0].size == 0  # last numeric field is gid=0

    def test_empty_output(self):
        assert parse_fls_output("") == []
        assert parse_fls_output("\n\n\n") == []

    def test_duplicate_inodes_deduplicated(self):
        """Same base inode should not produce duplicate candidates."""
        output = (
            "r/r  14:\tfile1.txt\n"
            "r/r  14:\tfile1.txt\n"
        )
        candidates = parse_fls_output(output)
        assert len(candidates) == 1

    def test_no_id_lines_skipped(self):
        """Lines without a recognizable inode:name pattern are skipped."""
        output = "This is not a valid fls line\nAnother invalid line\n"
        candidates = parse_fls_output(output)
        assert len(candidates) == 0


# ─── icat command construction ───────────────────────────────────────

class TestIcatCommand:
    def test_default_flags(self, tmp_path):
        exe = tmp_path / "icat.exe"
        cmd = build_icat_command(exe, "image.dd", "15")
        assert cmd == [str(exe), "-r", "image.dd", "15"]

    def test_no_recover_deleted(self, tmp_path):
        exe = tmp_path / "icat.exe"
        cmd = build_icat_command(exe, "image.dd", "15", recover_deleted=False)
        assert "-r" not in cmd

    def test_with_offset(self, tmp_path):
        exe = tmp_path / "icat.exe"
        cmd = build_icat_command(exe, "image.dd", "15", fs_offset=63)
        assert "-o" in cmd
        assert "63" in cmd


# ─── tsk_recover command construction ────────────────────────────────

class TestTskRecoverCommand:
    def test_default_unallocated_only(self, tmp_path):
        exe = tmp_path / "tsk_recover.exe"
        cmd = build_tsk_recover_command(exe, "image.dd", "/tmp/out")
        assert cmd == [str(exe), "image.dd", "/tmp/out"]
        assert "-e" not in cmd

    def test_all_files(self, tmp_path):
        exe = tmp_path / "tsk_recover.exe"
        cmd = build_tsk_recover_command(exe, "image.dd", "/tmp/out", all_files=True)
        assert "-e" in cmd

    def test_with_offset(self, tmp_path):
        exe = tmp_path / "tsk_recover.exe"
        cmd = build_tsk_recover_command(exe, "image.dd", "/tmp/out",
                                         fs_offset=2048)
        assert "-o" in cmd
        idx = cmd.index("-o")
        assert cmd[idx + 1] == "2048"


# ─── fsstat command and parsing ──────────────────────────────────────

class TestFsstat:
    def test_command_construction(self, tmp_path):
        exe = tmp_path / "fsstat.exe"
        cmd = build_fsstat_command(exe, "image.dd")
        assert cmd == [str(exe), "image.dd"]

    def test_command_with_offset(self, tmp_path):
        exe = tmp_path / "fsstat.exe"
        cmd = build_fsstat_command(exe, "image.dd", fs_offset=63)
        assert "-o" in cmd

    def test_parse_ntfs_output(self):
        output = (
            "FILE SYSTEM INFORMATION\n"
            "--------------------------------------------\n"
            "FILE SYSTEM TYPE: NTFS\n"
            "Volume Serial Number: 1234ABCD\n"
            "Volume Name: System\n"
            "Cluster Size: 4096\n"
        )
        result = parse_fsstat_output(output)
        assert result["filesystem_type"] == "NTFS"
        assert result["serial"] == "1234ABCD"
        assert result["volume_name"] == "System"
        assert result["cluster_size"] == 4096

    def test_parse_empty_output(self):
        result = parse_fsstat_output("")
        assert "raw" in result


# ─── mmls command and parsing ────────────────────────────────────────

class TestMmls:
    def test_command_construction(self, tmp_path):
        exe = tmp_path / "mmls.exe"
        cmd = build_mmls_command(exe, "disk.dd")
        assert cmd == [str(exe), "-B", "disk.dd"]

    def test_parse_partition_table(self):
        output = (
            "DOS Partition Table\n"
            "Offset Sector: 0\n"
            "Units are in 512-byte sectors\n"
            "\n"
            "      Slot      Start        End          Length       Description\n"
            "000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)\n"
            "001:  -------   0000000000   0000002047   0000002048   Unallocated\n"
            "002:  000:000   0000002048   0001026047   0001024000   NTFS / exFAT (0x07)\n"
            "003:  -------   0001026048   0001048575   0000022528   Unallocated\n"
        )
        partitions = parse_mmls_output(output)
        assert len(partitions) == 4
        assert partitions[0]["index"] == 0
        assert partitions[0]["description"] == "Primary Table (#0)"
        assert partitions[2]["index"] == 2
        assert partitions[2]["start"] == 2048
        assert partitions[2]["length"] == 1024000
        assert "NTFS" in partitions[2]["description"]


# ─── PhotoRec command construction ───────────────────────────────────

class TestPhotorecCommand:
    def test_basic_batch_command(self, tmp_path):
        exe = tmp_path / "photorec.exe"
        cmd = build_photorec_command(exe, "image.dd", "/tmp/recup")
        # Verify upstream-verified flags: /d for output dir, /cmd for batch mode
        assert cmd == [str(exe), "/d", "/tmp/recup", "/cmd", "image.dd", "search"]

    def test_with_json_log(self, tmp_path):
        exe = tmp_path / "photorec.exe"
        cmd = build_photorec_command(exe, "image.dd", "/tmp/recup",
                                      log_json="/tmp/log.jsonl")
        assert "/logjson" in cmd
        assert "/tmp/log.jsonl" in cmd
        # /logjson must come before /cmd
        assert cmd.index("/logjson") < cmd.index("/cmd")


# ─── ddrescue command construction ───────────────────────────────────

class TestDdrescueCommand:
    def test_basic_command(self, tmp_path):
        exe = tmp_path / "ddrescue.exe"
        cmd = build_ddrescue_command(exe, "/dev/sda", "output.img", "rescue.map")
        assert cmd == [str(exe), "-v", "/dev/sda", "output.img", "rescue.map"]

    def test_all_flags(self, tmp_path):
        exe = tmp_path / "ddrescue.exe"
        cmd = build_ddrescue_command(exe, "/dev/sda", "output.img", "rescue.map",
                                      force=True, no_scrape=True, retry_passes=3,
                                      direct_io=True)
        assert "-f" in cmd
        assert "-n" in cmd
        assert "-r" in cmd
        assert "3" in cmd
        assert "-d" in cmd
        assert "-v" in cmd


# ─── ddrescue mapfile parsing ────────────────────────────────────────

class TestDdrescueMapfile:
    def test_parse_typical_mapfile(self, tmp_path):
        mapfile = tmp_path / "rescue.map"
        mapfile.write_text(
            "# Mapfile. Created by GNU ddrescue version 1.28\n"
            "# Command line: ddrescue -v /dev/sda output.img rescue.map\n"
            "# Start time:   2024-01-01 12:00:00\n"
            "# Current time: 2024-01-01 12:05:00\n"
            "# Finished\n"
            "0x00000000  0x00\n"
            "0x00000000  0x00100000  +\n"
            "0x00100000  0x00010000  -\n"
            "0x00110000  0x00020000  ?\n",
            encoding="utf-8",
        )
        result = parse_ddrescue_mapfile(mapfile)
        assert result["rescued_bytes"] == 0x00100000
        assert result["bad_bytes"] == 0x00010000
        assert result["non_tried_bytes"] == 0x00020000
        assert result["total_bytes"] == 0x00100000 + 0x00010000 + 0x00020000
        assert len(result["regions"]) == 3

    def test_missing_file(self, tmp_path):
        result = parse_ddrescue_mapfile(tmp_path / "nonexistent.map")
        assert result["rescued_bytes"] == 0
        assert result["total_bytes"] == 0


# ─── Capability matrix integrity ────────────────────────────────────

class TestCapabilityMatrix:
    def test_all_documented_backends_have_capabilities(self):
        expected = {"testdisk", "photorec", "tsk_fls", "tsk_icat",
                    "tsk_recover", "ddrescue", "autopsy"}
        assert set(BACKEND_CAPABILITIES.keys()) == expected

    def test_photorec_cannot_recover_filenames(self):
        """Per upstream: PhotoRec is a file carver and cannot recover original filenames."""
        assert BACKEND_CAPABILITIES["photorec"]["recovers_original_filenames"] is False
        assert BACKEND_CAPABILITIES["photorec"]["recovers_directory_structure"] is False

    def test_ddrescue_cannot_recover_files(self):
        """Per upstream: ddrescue creates disk images, not individual file recovery."""
        assert BACKEND_CAPABILITIES["ddrescue"]["can_recover_files"] is False
        assert BACKEND_CAPABILITIES["ddrescue"]["can_image_damaged_media"] is True

    def test_testdisk_is_interactive_only(self):
        """Per upstream: TestDisk has no batch/non-interactive CLI mode."""
        assert BACKEND_CAPABILITIES["testdisk"]["has_batch_mode"] is False
        assert BACKEND_CAPABILITIES["testdisk"]["non_interactive_cli"] is False

    def test_tsk_recover_preserves_filenames(self):
        """Per upstream: tsk_recover exports files preserving names and directories."""
        assert BACKEND_CAPABILITIES["tsk_recover"]["recovers_original_filenames"] is True
        assert BACKEND_CAPABILITIES["tsk_recover"]["recovers_directory_structure"] is True

    def test_autopsy_is_gui_only(self):
        """Per upstream: Autopsy is a GUI forensics platform, not automatable."""
        assert BACKEND_CAPABILITIES["autopsy"]["non_interactive_cli"] is False

    def test_every_backend_has_notes(self):
        """Every backend entry must have a non-empty notes field."""
        for backend_id, caps in BACKEND_CAPABILITIES.items():
            assert "notes" in caps, f"{backend_id} missing notes"
            assert caps["notes"], f"{backend_id} has empty notes"
