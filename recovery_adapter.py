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
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from recovery_backends import METHOD_BACKENDS, backend_status


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
    original_path: str | None = None
    file_type: str | None = None
    source_offset: int | None = None
    source_device: str | None = None
    source_partition: str | None = None
    recoverable: bool | None = None
    backend: str | None = None
    verification_state: str = "UNKNOWN"


@dataclass(frozen=True)
class RecoveryScan:
    status: str
    message: str
    source: dict[str, Any]
    candidates: tuple[RecoveryCandidate, ...]
    warnings: tuple[str, ...]
    raw: dict[str, Any]
    backend: str | None = None


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


def parse_scan_result(payload: dict[str, Any], module: str = "Quick Recovery") -> RecoveryScan:
    if not isinstance(payload, dict):
        raise RecoveryError(f"{module} returned a non-object JSON result.")
    raw_candidates = payload.get("candidates", payload.get("objects", payload.get("chains", [])))
    if not isinstance(raw_candidates, list):
        raise RecoveryError(f"{module} returned an invalid candidate/result field.")
    candidates: list[RecoveryCandidate] = []
    for index, item in enumerate(raw_candidates, start=1):
        if not isinstance(item, dict):
            continue
        candidate_id = item.get("id")
        if candidate_id is None and module == "Deep Recovery":
            candidate_id = index
        if candidate_id is None:
            continue
        candidates.append(RecoveryCandidate(
            candidate_id=str(candidate_id),
            name=str(item.get("name") or item.get("type") or "Unknown"),
            filesystem=str(item.get("filesystem") or item.get("type") or "Unknown"),
            size=int(item["size"]) if isinstance(item.get("size"), (int, float)) else None,
            deleted=item.get("deleted") if isinstance(item.get("deleted"), bool) else None,
            confidence=float(item["confidence"]) if isinstance(item.get("confidence"), (int, float)) else None,
            raw=item,
            original_path=item.get("path") or item.get("original_path"),
            file_type=item.get("file_type") or item.get("type"),
            source_offset=int(item["offset"]) if isinstance(item.get("offset"), (int, float)) else None,
            recoverable=item.get("recoverable") if isinstance(item.get("recoverable"), bool) else True,
            backend=module,
        ))
    return RecoveryScan(
        status=str(payload.get("status") or "UNKNOWN"),
        message=str(payload.get("message") or ""),
        source=payload.get("source") if isinstance(payload.get("source"), dict) else {},
        candidates=tuple(candidates),
        warnings=tuple(str(x) for x in payload.get("warnings", []) if x is not None),
        raw=payload,
        backend=module,
    )


def _run_native(command: list[str], cancel: Callable[[], bool] | None, timeout: int, module: str) -> tuple[str, str]:
    """Run one native command while polling cancellation and enforcing timeout."""
    try:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except OSError as exc:
        raise RecoveryError(f"{module} could not start: {exc}") from exc
    started = time.monotonic()
    while proc.poll() is None:
        if cancel and cancel():
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            raise RecoveryError(f"{module} scan cancelled by the user.")
        if time.monotonic() - started >= timeout:
            proc.kill()
            proc.wait()
            raise RecoveryError(f"{module} timed out after {timeout} seconds.")
        time.sleep(0.05)
    stdout, stderr = proc.communicate()
    if proc.returncode != 0:
        detail = (stderr or stdout).strip() or f"native exit code {proc.returncode}"
        raise RecoveryError(f"{module} failed: {detail}")
    return stdout, stderr


def _recover_native_candidate(adapter: Any, source: str, candidate_id: str, destination: Path, recover_switch: list[str], timeout: int) -> Path:
    if adapter.executable is None:
        raise RecoveryError(adapter.unavailable_reason)
    if not candidate_id.isdigit():
        raise RecoveryError("Candidate ID is invalid.")
    if not (source.startswith("\\\\.\\PhysicalDrive") or Path(source).is_file()):
        raise RecoveryError(f"{adapter.spec.display_name} requires a raw image or PhysicalDrive source.")
    destination.mkdir(parents=True, exist_ok=True)
    _run_native([str(adapter.executable), "--source", source, *recover_switch, candidate_id, "--destination", str(destination)], None, timeout, f"{adapter.spec.display_name} candidate recovery")
    outputs = [path for path in destination.rglob("*") if path.is_file()]
    if not outputs:
        raise RecoveryError(f"{adapter.spec.display_name} reported success but produced no output file.")
    return outputs[0]


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
            stdout, stderr = _run_native([str(exe), "--source", source, "--output", str(result_path)], cancel, timeout, "Quick Recovery")
            if proc.returncode != 0:
                detail = (stderr or stdout).strip() or f"native exit code {proc.returncode}"
                raise RecoveryError(f"Quick Recovery engine failed: {detail}")
            if not result_path.is_file():
                raise RecoveryError("Quick Recovery completed without producing a JSON result.")
            try:
                payload = json.loads(result_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise RecoveryError(f"Quick Recovery returned invalid JSON: {exc}") from exc
            return parse_scan_result(payload, "Quick Recovery")

    def recover(self, source: str, candidate_id: str, destination: Path, timeout: int = 86400) -> Path:
        exe = self.require_executable()
        self.validate_source(source)
        if not candidate_id or not candidate_id.isdigit():
            raise RecoveryError("Candidate ID is invalid.")
        destination.mkdir(parents=True, exist_ok=True)
        _run_native([str(exe), "--source", source, "--recover-candidate", candidate_id, "--destination", str(destination)], None, timeout, "Quick Recovery candidate recovery")
        outputs = [p for p in destination.rglob("*") if p.is_file()]
        if not outputs:
            raise RecoveryError("Recovery engine reported success but produced no readable output.")
        return outputs[0]


class NativeRecoveryAdapter:
    """Base for method-specific native adapters."""

    def __init__(self, spec: RecoveryMethodSpec, root: Path, meipass: Path | None = None):
        self.spec = spec
        self.executable = _search_native(root, meipass, spec.module_dir, spec.executable_names)

    @property
    def available(self) -> bool:
        return self.executable is not None

    @property
    def unavailable_reason(self) -> str:
        if self.executable is not None:
            return "Native executable is present, but this method requires configuration not available in the folder workflow."
        return f"{self.spec.display_name} engine is not built/installed. Expected one of: {', '.join(self.spec.executable_names)}."

    def status(self) -> tuple[str, str]:
        return ("Unavailable", self.unavailable_reason)


class JsonScanAdapter(NativeRecoveryAdapter):
    """Adapter for engines that accept a source and emit a JSON report."""

    def scan(self, source: str, cancel: Callable[[], bool] | None = None, timeout: int = 86400) -> RecoveryScan:
        if self.executable is None:
            raise RecoveryError(self.unavailable_reason)
        if not (source.startswith("\\\\.\\PhysicalDrive") or Path(source).is_file()):
            raise RecoveryError(f"{self.spec.display_name} requires a raw image or PhysicalDrive source.")
        with tempfile.TemporaryDirectory(prefix=f"drex-{self.spec.method_id}-") as temp:
            result_path = Path(temp) / "result.json"
            command = self.scan_command(source, result_path)
            _run_native(command, cancel, timeout, self.spec.display_name)
            if not result_path.is_file():
                raise RecoveryError(f"{self.spec.display_name} completed without producing a JSON result.")
            try:
                payload = json.loads(result_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise RecoveryError(f"{self.spec.display_name} returned invalid JSON: {exc}") from exc
            return parse_scan_result(payload, self.spec.display_name)

    def scan_command(self, source: str, result_path: Path) -> list[str]:
        return [str(self.executable), "--source", source, "--output", str(result_path)]

    def status(self) -> tuple[str, str]:
        return ("Available", "") if self.executable is not None else ("Unavailable", self.unavailable_reason)


class SmartRecoveryAdapter(JsonScanAdapter):
    def recover(self, source: str, candidate_id: str, destination: Path, timeout: int = 86400) -> Path:
        return _recover_native_candidate(self, source, candidate_id, destination, ["--recover-candidate"] , timeout)


class TargetedRecoveryAdapter(JsonScanAdapter):
    def scan_command(self, source: str, result_path: Path) -> list[str]:
        return [str(self.executable), "--source", source, "--output", str(result_path)]

    def recover(self, source: str, candidate_id: str, destination: Path, timeout: int = 86400) -> Path:
        return _recover_native_candidate(self, source, candidate_id, destination, ["--recover"], timeout)


class FilesystemRecoveryAdapter(JsonScanAdapter):
    pass


class DeepRecoveryAdapter(JsonScanAdapter):
    pass


class FragmentRecoveryAdapter(JsonScanAdapter):
    def scan_command(self, source: str, result_path: Path) -> list[str]:
        raise RecoveryError("Fragment Recovery requires an explicit file type (pdf, jpeg, png, or zip) before scanning.")

    def recover(self, source: str, candidate_id: str, destination: Path, timeout: int = 86400) -> Path:
        return _recover_native_candidate(self, source, candidate_id, destination, ["--recover"], timeout)


class RaidRecoveryAdapter(NativeRecoveryAdapter):
    pass


class DamagedMediaRecoveryAdapter(NativeRecoveryAdapter):
    pass


class ForensicRecoveryAdapter(NativeRecoveryAdapter):
    pass


class RecoveryDispatcher:
    """Central method-id → local module adapter registry."""

    def __init__(self, root: Path, meipass: Path | None = None):
        self.root = root
        self.meipass = meipass
        self.adapters: dict[str, Any] = {}
        for spec in RECOVERY_METHOD_SPECS:
            if spec.method_id == "quick":
                self.adapters[spec.method_id] = QuickRecoveryAdapter(root, meipass)
            elif spec.method_id == "smart":
                self.adapters[spec.method_id] = SmartRecoveryAdapter(spec, root, meipass)
            elif spec.method_id == "targeted":
                self.adapters[spec.method_id] = TargetedRecoveryAdapter(spec, root, meipass)
            elif spec.method_id == "filesystem":
                self.adapters[spec.method_id] = FilesystemRecoveryAdapter(spec, root, meipass)
            elif spec.method_id == "deep":
                self.adapters[spec.method_id] = DeepRecoveryAdapter(spec, root, meipass)
            elif spec.method_id == "fragment":
                self.adapters[spec.method_id] = FragmentRecoveryAdapter(spec, root, meipass)
            elif spec.method_id == "raid":
                self.adapters[spec.method_id] = RaidRecoveryAdapter(spec, root, meipass)
            elif spec.method_id == "damaged":
                self.adapters[spec.method_id] = DamagedMediaRecoveryAdapter(spec, root, meipass)
            elif spec.method_id == "forensic":
                self.adapters[spec.method_id] = ForensicRecoveryAdapter(spec, root, meipass)
            else:
                self.adapters[spec.method_id] = NativeRecoveryAdapter(spec, root, meipass)

    def get(self, method_id: str) -> Any:
        try:
            return self.adapters[method_id]
        except KeyError as exc:
            raise RecoveryError(f"Unknown recovery method: {method_id}") from exc

    def status(self, method_id: str) -> tuple[str, str]:
        adapter = self.get(method_id)
        backend_state, backend_reason = backend_status(method_id, self.root, self.meipass)
        if backend_state == "BACKEND MISSING":
            return "Unavailable", f"{getattr(adapter, 'spec', None).display_name if hasattr(adapter, 'spec') else 'Quick Recovery'}: {backend_reason}"
        if isinstance(adapter, QuickRecoveryAdapter):
            if not adapter.available:
                return "Unavailable", "Quick Recovery requires an official TestDisk/PhotoRec backend and no executable was found."
            return "Unavailable", "The legacy local Quick engine is present, but the official TestDisk/PhotoRec adapter is not packaged yet."
        native_status, native_reason = adapter.status()
        if native_status != "Available":
            return native_status, native_reason
        return "Unavailable", f"Official backend detected ({backend_reason}), but its method-specific adapter is not packaged in this build."
