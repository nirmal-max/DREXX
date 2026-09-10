"""Adapters for DREX native recovery engines.

Only Quick Recovery is wired in this release.  The adapter deliberately fails
closed when the native executable is absent or when the source is not a raw
image/physical-device path.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


class RecoveryError(RuntimeError):
    pass


@dataclass(frozen=True)
class RecoveryCandidate:
    candidate_id: str
    name: str
    filesystem: str
    size: int | None
    deleted: bool | None
    confidence: float | None
    raw: dict[str, Any]


@dataclass(frozen=True)
class RecoveryScan:
    status: str
    message: str
    source: dict[str, Any]
    candidates: tuple[RecoveryCandidate, ...]
    warnings: tuple[str, ...]
    raw: dict[str, Any]


def find_quickscan(root: Path, meipass: Path | None = None) -> Path | None:
    roots = [
        root / "native_bin" / "quickscan.exe",
        root / "methods" / "Recovery" / "Module1_Quick_Recovery_Production_Baseline_v0.1.0" / "module1_quick_recovery" / "build" / "Release" / "quickscan.exe",
        root / "methods" / "Recovery" / "Module1_Quick_Recovery_Production_Baseline_v0.1.0" / "module1_quick_recovery" / "build" / "quickscan.exe",
    ]
    if meipass:
        roots.insert(0, meipass / "native_bin" / "quickscan.exe")
    for candidate in roots:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


def parse_scan_result(payload: dict[str, Any]) -> RecoveryScan:
    if not isinstance(payload, dict):
        raise RecoveryError("Quick Recovery returned a non-object JSON result.")
    raw_candidates = payload.get("candidates", [])
    if not isinstance(raw_candidates, list):
        raise RecoveryError("Quick Recovery returned an invalid candidates field.")
    candidates: list[RecoveryCandidate] = []
    for item in raw_candidates:
        if not isinstance(item, dict) or "id" not in item:
            continue
        candidates.append(RecoveryCandidate(
            candidate_id=str(item["id"]),
            name=str(item.get("name") or "Unknown"),
            filesystem=str(item.get("filesystem") or "Unknown"),
            size=int(item["size"]) if isinstance(item.get("size"), (int, float)) else None,
            deleted=item.get("deleted") if isinstance(item.get("deleted"), bool) else None,
            confidence=float(item["confidence"]) if isinstance(item.get("confidence"), (int, float)) else None,
            raw=item,
        ))
    return RecoveryScan(
        status=str(payload.get("status") or "UNKNOWN"),
        message=str(payload.get("message") or ""),
        source=payload.get("source") if isinstance(payload.get("source"), dict) else {},
        candidates=tuple(candidates),
        warnings=tuple(str(x) for x in payload.get("warnings", []) if x is not None),
        raw=payload,
    )


class QuickRecoveryAdapter:
    def __init__(self, root: Path, meipass: Path | None = None):
        self.executable = find_quickscan(root, meipass)

    @property
    def available(self) -> bool:
        return self.executable is not None

    def require_executable(self) -> Path:
        if self.executable is None:
            raise RecoveryError("Quick Recovery engine is not built/installed.")
        return self.executable

    @staticmethod
    def validate_source(source: str) -> None:
        if not source:
            raise RecoveryError("No physical recovery source was mapped.")
        if not (source.startswith("\\\\.\\PhysicalDrive") or Path(source).is_file()):
            raise RecoveryError("Quick Recovery requires a raw image or PhysicalDrive source.")

    def scan(self, source: str, cancel: Callable[[], bool] | None = None, timeout: int = 86400) -> RecoveryScan:
        exe = self.require_executable()
        self.validate_source(source)
        with tempfile.TemporaryDirectory(prefix="drex-quickscan-") as temp:
            result_path = Path(temp) / "result.json"
            proc = subprocess.Popen([str(exe), "--source", source, "--output", str(result_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                raise RecoveryError("Quick Recovery scan timed out.")
            if cancel and cancel():
                if proc.poll() is None:
                    proc.terminate()
                raise RecoveryError("Recovery scan cancelled by the user.")
            if proc.returncode != 0:
                detail = (stderr or stdout).strip() or f"native exit code {proc.returncode}"
                raise RecoveryError(f"Quick Recovery engine failed: {detail}")
            if not result_path.is_file():
                raise RecoveryError("Quick Recovery completed without producing a JSON result.")
            try:
                payload = json.loads(result_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise RecoveryError(f"Quick Recovery returned invalid JSON: {exc}") from exc
            return parse_scan_result(payload)

    def recover(self, source: str, candidate_id: str, destination: Path, timeout: int = 86400) -> Path:
        exe = self.require_executable()
        self.validate_source(source)
        if not candidate_id or not candidate_id.isdigit():
            raise RecoveryError("Candidate ID is invalid.")
        destination.mkdir(parents=True, exist_ok=True)
        proc = subprocess.run([str(exe), "--source", source, "--recover-candidate", candidate_id, "--destination", str(destination)], capture_output=True, text=True, timeout=timeout, check=False)
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout).strip() or f"native exit code {proc.returncode}"
            raise RecoveryError(f"Candidate recovery failed: {detail}")
        outputs = [p for p in destination.rglob("*") if p.is_file()]
        if not outputs:
            raise RecoveryError("Recovery engine reported success but produced no readable output.")
        return outputs[0]
