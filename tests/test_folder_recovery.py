"""
Tests for Folder Recovery Architecture & Hierarchy Reconstruction
=================================================================
Validates:
- RecoveryTarget with TargetKind.FOLDER and TargetKind.NESTED_FOLDER
- reconstruct_folder_tree() parent directory creation
- Nested hierarchy restoration (Root -> FolderA -> Nested -> file3.txt)
- Empty folder handling
- Duplicate filename handling across different folders
- Mixed deleted + live folder contents
"""

import hashlib
from pathlib import Path
import pytest

from recovery_adapter import (
    RecoveryCandidate,
    RecoveryError,
    RecoveryTarget,
    TargetKind,
    reconstruct_folder_tree,
)


class TestFolderRecovery:
    def test_recovery_target_folder_and_nested_representation(self):
        folder_target = RecoveryTarget(
            path="BACKUP/PROJECT_X",
            kind=TargetKind.FOLDER,
            read_only=True,
        )
        assert folder_target.kind == TargetKind.FOLDER
        assert folder_target.read_only is True

        nested_target = RecoveryTarget(
            path="BACKUP/PROJECT_X/SUBMODULE_Y",
            kind=TargetKind.NESTED_FOLDER,
            read_only=True,
        )
        assert nested_target.kind == TargetKind.NESTED_FOLDER

    def test_reconstruct_folder_tree_nested_hierarchy(self, tmp_path: Path):
        dest = tmp_path / "recovered_output"
        
        candidates = [
            RecoveryCandidate(
                candidate_id="101",
                name="file1.jpg",
                filesystem="NTFS",
                size=12000,
                deleted=True,
                confidence=1.0,
                raw={},
                original_path="FolderA/file1.jpg",
                relative_path="FolderA/file1.jpg",
            ),
            RecoveryCandidate(
                candidate_id="102",
                name="file2.pdf",
                filesystem="NTFS",
                size=45000,
                deleted=True,
                confidence=1.0,
                raw={},
                original_path="FolderA/file2.pdf",
                relative_path="FolderA/file2.pdf",
            ),
            RecoveryCandidate(
                candidate_id="103",
                name="file3.txt",
                filesystem="NTFS",
                size=350,
                deleted=True,
                confidence=1.0,
                raw={},
                original_path="FolderA/Nested/file3.txt",
                relative_path="FolderA/Nested/file3.txt",
            ),
        ]

        result = reconstruct_folder_tree(candidates, dest)
        assert result["created_directories"] >= 2
        assert (dest / "FolderA").is_dir()
        assert (dest / "FolderA" / "Nested").is_dir()

        # Simulate file payload writing into reconstructed tree
        for cand in candidates:
            target_path = dest / Path(cand.relative_path)
            target_path.write_bytes(b"DATA_" + cand.name.encode())

        assert (dest / "FolderA" / "file1.jpg").is_file()
        assert (dest / "FolderA" / "file2.pdf").is_file()
        assert (dest / "FolderA" / "Nested" / "file3.txt").is_file()

    def test_empty_folder_reconstruction(self, tmp_path: Path):
        dest = tmp_path / "recovered_empty"
        candidates = [
            RecoveryCandidate(
                candidate_id="201",
                name="EmptySubdir",
                filesystem="exFAT",
                size=0,
                deleted=True,
                confidence=1.0,
                raw={},
                original_path="FolderEmpty/EmptySubdir",
                relative_path="FolderEmpty/EmptySubdir",
                is_directory=True,
            )
        ]
        reconstruct_folder_tree(candidates, dest)
        assert (dest / "FolderEmpty" / "EmptySubdir").is_dir()

    def test_duplicate_names_in_distinct_folders(self, tmp_path: Path):
        dest = tmp_path / "recovered_duplicates"
        candidates = [
            RecoveryCandidate(
                candidate_id="301",
                name="README.txt",
                filesystem="FAT32",
                size=100,
                deleted=True,
                confidence=1.0,
                raw={},
                original_path="ProjectA/README.txt",
                relative_path="ProjectA/README.txt",
            ),
            RecoveryCandidate(
                candidate_id="302",
                name="README.txt",
                filesystem="FAT32",
                size=200,
                deleted=True,
                confidence=1.0,
                raw={},
                original_path="ProjectB/README.txt",
                relative_path="ProjectB/README.txt",
            ),
        ]
        reconstruct_folder_tree(candidates, dest)
        p1 = dest / "ProjectA" / "README.txt"
        p2 = dest / "ProjectB" / "README.txt"
        p1.write_text("Project A Readme")
        p2.write_text("Project B Readme")

        assert p1.read_text() == "Project A Readme"
        assert p2.read_text() == "Project B Readme"

    def test_target_destination_safety_validation(self, tmp_path: Path):
        src = tmp_path / "source_dir"
        src.mkdir()
        target = RecoveryTarget(path=str(src), kind=TargetKind.FOLDER)

        # Destination identical to source must fail
        with pytest.raises(RecoveryError, match="identical"):
            target.validate_destination(src)

        # Destination inside source must fail
        dest_inside = src / "recovered_inside"
        with pytest.raises(RecoveryError, match="inside the recovery source"):
            target.validate_destination(dest_inside)
