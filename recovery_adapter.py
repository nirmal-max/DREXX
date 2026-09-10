"""Adapters and dispatch for the local DREX recovery engines.

The C++ modules under ``methods/Recovery`` are the source of truth.  This
layer only discovers packaged/build outputs, validates raw read-only sources,
and normalizes engine results.  Missing native binaries fail closed with an
actionable reason; a card is never considered available merely because its
module directory exists.
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


@dataclass(frozen=True)
class RecoveryMethodSpec:
    method_id: str
    display_name: str
    module_dir: str
    executable_names: tuple[str, ...]
    native_contract: str


def _search_native(root: Path, meipass: Path | None, module_dir: str, names: tuple[str, ...]) -> Path | None:
    roots = [
        root / "native_bin",
        root / "methods" / "Recovery" / module_dir / "build" / "Release",
        root / "methods" / "Recovery" / module_dir / "build",
    ]
    if meipass:
        roots.insert(0, meipass / "native_bin")
    for directory in roots:
        for name in names:
            candidate = directory / name
            if candidate.is_file():
                return candidate
    return None


def find_quickscan(root: Path, meipass: Path | None = None) -> Path | None:
    return _search_native(root, meipass, "Module1_Quick_Recovery_Production_Baseline_v0.1.0", ("quickscan.exe",))


RECOVERY_METHOD_SPECS: tuple[RecoveryMethodSpec, ...] = (
    RecoveryMethodSpec("quick", "Quick Recovery", "Module1_Quick_Recovery_Production_Baseline_v0.1.0", ("quickscan.exe",), "--source <image|\\\\.\\PhysicalDriveN> [--output result.json] [--recover-candidate N --destination DIR]"),
    RecoveryMethodSpec("smart", "Smart Recovery", "Module2_Smart_Recovery_Production_Baseline_v0.1.0", ("smartscan.exe",), "--source <image|PhysicalDrive> [--output result.json]"),
    RecoveryMethodSpec("targeted", "Targeted Recovery", "Module3_Targeted_Recovery_Production_Baseline_v0.1.0", ("targetedscan.exe",), "--source <image|PhysicalDrive> [--types ...] [--output result.json]"),
    RecoveryMethodSpec("filesystem", "Filesystem Recovery", "Module4_Filesystem_Recovery_Production_Baseline_v0.1.0", ("fsrecover.exe",), "--source <image|PhysicalDrive> [--output result.json]"),
    RecoveryMethodSpec("deep", "Deep Recovery", "Module5_Deep_Recovery_Production_Baseline_v0.1.0", ("deepscan.exe",), "--source <image> [--output result.json]"),
    RecoveryMethodSpec("fragment", "Fragment Recovery", "Module6_Fragment_Recovery_Production_Baseline_v0.1.0", ("fragmentscan.exe",), "--source <image> --type pdf|jpeg|png|zip [--output result.json]"),
    RecoveryMethodSpec("raid", "Storage / RAID Recovery", "Module7_Storage_RAID_Recovery_Production_Baseline_v0.1.0", ("raidscan.exe",), "--level ... --members ... [--output result.json]"),
    RecoveryMethodSpec("damaged", "Damaged Media Recovery", "Module8_Damaged_Media_Recovery_Production_Baseline_v0.1.0", ("mediaimager.exe",), "--source input --output image --map map [--report json]"),
    RecoveryMethodSpec("forensic", "Forensic Recovery", "Module9_Forensic_Recovery_Production_Baseline_v0.1.0", ("forensicctl.exe",), "forensic case/evidence command contract; no scan adapter is claimed without the native binary"),
)


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


class NativeRecoveryAdapter:
    """Availability record for a module whose native contract is not Quick's.

    We intentionally do not invent a command line or result schema.  Such a
    module becomes runnable only when its native binary and a matching adapter
    are present; otherwise the UI reports the exact local binary requirement.
    """

    def __init__(self, spec: RecoveryMethodSpec, root: Path, meipass: Path | None = None):
        self.spec = spec
        self.executable = _search_native(root, meipass, spec.module_dir, spec.executable_names)

    @property
    def available(self) -> bool:
        return self.executable is not None

    @property
    def unavailable_reason(self) -> str:
        if self.executable is not None:
            return "Native executable is present, but this module requires its dedicated result adapter before it can be exposed as runnable."
        return f"{self.spec.display_name} engine is not built/installed. Expected one of: {', '.join(self.spec.executable_names)}."


class RecoveryDispatcher:
    """Central method-id → local module adapter registry."""

    def __init__(self, root: Path, meipass: Path | None = None):
        self.adapters: dict[str, Any] = {}
        for spec in RECOVERY_METHOD_SPECS:
            if spec.method_id == "quick":
                self.adapters[spec.method_id] = QuickRecoveryAdapter(root, meipass)
            else:
                self.adapters[spec.method_id] = NativeRecoveryAdapter(spec, root, meipass)

    def get(self, method_id: str) -> Any:
        try:
            return self.adapters[method_id]
        except KeyError as exc:
            raise RecoveryError(f"Unknown recovery method: {method_id}") from exc

    def status(self, method_id: str) -> tuple[str, str]:
        adapter = self.get(method_id)
        if isinstance(adapter, QuickRecoveryAdapter):
            return ("Available", "") if adapter.available else ("Unavailable", "Quick Recovery engine is not built/installed. Expected quickscan.exe.")
        return ("Unavailable", adapter.unavailable_reason)
