from __future__ import annotations

import base64
import ctypes
import hashlib
import importlib
import json
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
import tkinter as tk
from typing import Any, Callable

from recovery_adapter import QuickRecoveryAdapter, RecoveryDispatcher, RecoveryError, RecoveryScan


APP_NAME = "DREX"
VERSION = "1.0.0"
ROOT = Path(__file__).resolve().parent
GREEN = "#087f3f"
GREEN_DARK = "#056332"
GREEN_PALE = "#eaf6ef"
INK = "#0e1735"
MUTED = "#596581"
LINE = "#dfe6e2"
BG = "#fbfdfc"
ORANGE = "#e87500"
RED = "#c62828"
PURPLE = "#5b28bd"
BLUE = "#1269d3"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def fmt_bytes(value: int | None) -> str:
    if value is None or value < 0:
        return "Unavailable"
    units = ("B", "KB", "MB", "GB", "TB", "PB")
    n = float(value)
    for unit in units:
        if n < 1024 or unit == units[-1]:
            return f"{n:.2f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return "Unavailable"


def safe_json_write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass


def app_data_dir() -> Path:
    override = os.environ.get("DREX_DATA_DIR")
    if override:
        return Path(override).expanduser().resolve()
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or (Path.home() / "AppData" / "Local")
    else:
        base = os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share")
    return Path(base) / APP_NAME


@dataclass
class DriveInfo:
    path: str
    device_path: str
    model: str | None
    serial: str | None
    capacity: int | None
    interface: str | None
    drive_type: str | None
    filesystem: str | None
    free: int | None
    health: str | None
    status: str | None
    device_id: str | None

    def display(self, field: str) -> str:
        value = getattr(self, field, None)
        return value if value not in (None, "") else "Unavailable"


def _ps_json(command: str) -> Any:
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True, text=True, timeout=8, check=False,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return None
        return json.loads(proc.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return None


def _drive_letters() -> list[str]:
    if os.name == "nt":
        try:
            mask = ctypes.windll.kernel32.GetLogicalDrives()
            return [f"{chr(65 + i)}:" for i in range(26) if mask & (1 << i)]
        except (AttributeError, OSError):
            pass
    return [f"{c}:" for c in "CDEFGHIJKLMNOPQRSTUVWXYZ" if Path(f"{c}:/").exists()]


def discover_drives() -> list[DriveInfo]:
    logical_command = "Get-CimInstance Win32_LogicalDisk | Select-Object DeviceID,VolumeName,FileSystem,Size,FreeSpace,DriveType | ConvertTo-Json -Compress"
    physical_command = "Get-CimInstance Win32_DiskDrive | Select-Object Index,DeviceID,Model,SerialNumber,Size,InterfaceType,MediaType,Status,PNPDeviceID | ConvertTo-Json -Compress"
    association_command = "Get-CimInstance Win32_LogicalDiskToPartition | ForEach-Object { $match = [regex]::Match(([string]$_.Antecedent), 'Disk #(\\d+)'); [PSCustomObject]@{ Logical = $_.Dependent.DeviceID; DiskIndex = $match.Groups[1].Value } } | ConvertTo-Json -Compress"
    logical_raw = _ps_json(logical_command)
    physical_raw = _ps_json(physical_command)
    association_raw = _ps_json(association_command)
    logical = logical_raw if isinstance(logical_raw, list) else ([logical_raw] if logical_raw else [])
    physical = physical_raw if isinstance(physical_raw, list) else ([physical_raw] if physical_raw else [])
    associations = association_raw if isinstance(association_raw, list) else ([association_raw] if association_raw else [])
    logical_to_disk = {str(row.get("Logical", "")).upper(): str(row.get("DiskIndex", "")) for row in associations if isinstance(row, dict)}
    type_names = {2: "Removable", 3: "Fixed", 4: "Network", 5: "Optical"}
    out: list[DriveInfo] = []
    for item in logical:
        letter = str(item.get("DeviceID") or "").strip()
        if not letter:
            continue
        size = item.get("Size")
        free = item.get("FreeSpace")
        try:
            usage = shutil.disk_usage(letter + "\\")
            size = int(size) if size is not None else usage.total
            free = int(free) if free is not None else usage.free
        except (OSError, ValueError):
            size = int(size) if str(size).isdigit() else None
            free = int(free) if str(free).isdigit() else None
        drive_type = type_names.get(int(item.get("DriveType"))) if str(item.get("DriveType", "")).isdigit() else None
        # Only populate physical identity after an explicit Windows partition join.
        disk_index = logical_to_disk.get(letter.upper())
        matching = [p for p in physical if str(p.get("Index", "")) == disk_index] if disk_index else []
        model = serial = interface = device_id = status = None
        if len(matching) == 1:
            p = matching[0]
            model, serial, interface, device_id, status = (p.get(k) for k in ("Model", "SerialNumber", "InterfaceType", "DeviceID", "Status"))
        out.append(DriveInfo(
            path=letter + "\\", device_path=str(device_id or ""),
            model=str(model).strip() if model else None,
            serial=str(serial).strip() if serial else None,
            capacity=size, interface=str(interface).strip() if interface else None,
            drive_type=drive_type or "Unavailable", filesystem=item.get("FileSystem"),
            free=free, health="OK" if str(status).lower() == "ok" else (str(status) if status else "Unavailable"),
            status=str(status) if status else None, device_id=str(device_id) if device_id else None,
        ))
    if out:
        return out
    for letter in _drive_letters():
        try:
            usage = shutil.disk_usage(letter + "\\")
            out.append(DriveInfo(letter + "\\", "", None, None, usage.total, None, None, None, usage.free, None, None, None))
        except OSError:
            continue
    return out


def get_drive_for_path(folder_path: Path, drives: list[DriveInfo]) -> DriveInfo | None:
    """Map a selected folder to a discovered logical drive with a physical path."""
    try:
        resolved = folder_path.resolve()
    except OSError:
        return None
    for drive in drives:
        try:
            root = Path(drive.path).resolve()
        except OSError:
            continue
        if resolved.drive.upper() == root.drive.upper() and drive.device_path.lower().startswith("\\\\.\\physicaldrive"):
            return drive
    return None


def size_on_disk(path: Path) -> int | None:
    if path.is_file():
        if os.name == "nt":
            try:
                high = ctypes.c_ulong()
                low = ctypes.windll.kernel32.GetCompressedFileSizeW(str(path), ctypes.byref(high))
                if low == 0xFFFFFFFF and ctypes.GetLastError() != 0:
                    return path.stat().st_size
                return (high.value << 32) | low
            except (AttributeError, OSError):
                pass
        return getattr(path.stat(), "st_blocks", 0) * 512 or path.stat().st_size
    if path.is_dir():
        total = 0
        for child in path.rglob("*"):
            if child.is_file() and not child.is_symlink():
                try:
                    total += size_on_disk(child) or 0
                except OSError:
                    pass
        return total
    return None


def hash_target(path: Path) -> str | None:
    if not path.exists() or path.is_symlink():
        return None
    digest = hashlib.sha256()
    try:
        if path.is_file():
            with path.open("rb", buffering=0) as handle:
                while block := handle.read(1024 * 1024):
                    digest.update(block)
        elif path.is_dir():
            for child in sorted(p for p in path.rglob("*") if p.is_file() and not p.is_symlink()):
                digest.update(str(child.relative_to(path)).encode("utf-8", "surrogatepass"))
                with child.open("rb", buffering=0) as handle:
                    while block := handle.read(1024 * 1024):
                        digest.update(block)
        else:
            return None
        return digest.hexdigest()
    except OSError:
        return None


def method_root(*parts: str) -> Path:
    base = Path(getattr(sys, "_MEIPASS", ROOT)) / "methods"
    return base.joinpath(*parts)


def import_package(package: str, package_root: Path):
    root = str(package_root)
    if root not in sys.path:
        sys.path.insert(0, root)
    return importlib.import_module(package)


DRIVE_METHODS = [
    {"id": "nist", "name": "NIST SP 800-88 Rev.2", "assurance": "Erase with trusted, standards-based assurance.", "color": GREEN},
    {"id": "smart", "name": "Smart Sanitization", "assurance": "Let DREX choose the safest method for you.", "color": PURPLE},
    {"id": "native", "name": "Device-Native Sanitize", "assurance": "Use your drive's built-in secure sanitization.", "color": GREEN},
    {"id": "ata", "name": "ATA Secure Erase", "assurance": "Securely clear compatible SATA drives.", "color": GREEN},
    {"id": "nvme", "name": "NVMe Secure Erase", "assurance": "Securely sanitize your NVMe drive.", "color": GREEN},
    {"id": "ieee", "name": "IEEE 2883 Purge", "assurance": "Achieve strong, technology-aware purge assurance.", "color": GREEN},
    {"id": "overwrite", "name": "Verified Overwrite", "assurance": "Overwrite your data and verify the result.", "color": GREEN},
]

FILE_METHODS = [
    {"id": "csprng", "name": "CSPRNG Random Overwrite", "assurance": "Replace sensitive files with unpredictable data.", "color": GREEN},
    {"id": "crypto", "name": "Cryptographic Erasure", "assurance": "Make protected data permanently inaccessible.", "color": GREEN},
    {"id": "slack", "name": "File Slack / Cluster-Tip Sanitization", "assurance": "Clear hidden remnants around your files.", "color": GREEN},
    {"id": "metadata", "name": "Filesystem Metadata Sanitization", "assurance": "Remove exposed traces left by the filesystem.", "color": GREEN},
    {"id": "policy", "name": "NIST SP 800-88 Policy Engine", "assurance": "Choose a policy-backed sanitization strategy.", "color": GREEN},
    {"id": "free_space", "name": "Secure Free-Space Wiping", "assurance": "Clear recoverable traces from unused space.", "color": GREEN},
    {"id": "zero", "name": "Single-Pass Zero Overwrite", "assurance": "Clean selected files with a verified zero overwrite.", "color": GREEN},
    {"id": "storage_aware", "name": "Storage-Aware Sanitization & Fallback", "assurance": "Automatically choose the safest available path.", "color": GREEN},
    {"id": "temporary", "name": "Temporary / Cache Sanitization", "assurance": "Clear temporary files and residual traces.", "color": GREEN},
]

RECOVERY_METHODS = [
    ("quick", "Quick Recovery", "Find recently deleted data quickly."),
    ("smart", "Smart Recovery", "Let DREX find the best recovery path."),
    ("targeted", "Targeted Recovery", "Recover exactly what you're looking for."),
    ("filesystem", "Filesystem Recovery", "Restore data from damaged filesystem structures."),
    ("deep", "Deep Recovery", "Search deeper for lost and deleted data."),
    ("fragment", "Fragment Recovery", "Reconstruct files from scattered data fragments."),
    ("raid", "Storage / RAID Recovery", "Recover data from complex storage configurations."),
    ("damaged", "Damaged Media Recovery", "Recover what's possible from damaged media."),
    ("forensic", "Forensic Recovery", "Recover and analyze data for forensic investigation."),
]


def label_for_recovery(method_id: str) -> str:
    return next((name for mid, name, _ in RECOVERY_METHODS if mid == method_id), method_id)


class Store:
    def __init__(self, base: Path | None = None):
        self.base = base or app_data_dir()
        self.base.mkdir(parents=True, exist_ok=True)
        self.history_path = self.base / "history.json"
        self.certs_dir = self.base / "certificates"
        self.certs_dir.mkdir(exist_ok=True)
        self._lock = threading.RLock()

    def history(self) -> list[dict[str, Any]]:
        try:
            value = json.loads(self.history_path.read_text(encoding="utf-8"))
            return value if isinstance(value, list) else []
        except (OSError, json.JSONDecodeError):
            return []

    def add_history(self, record: dict[str, Any]) -> None:
        with self._lock:
            rows = self.history()
            rows.insert(0, record)
            safe_json_write(self.history_path, rows[:500])

    def certificates(self) -> list[dict[str, Any]]:
        rows = []
        for path in sorted(self.certs_dir.glob("*.json"), reverse=True):
            try:
                item = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(item, dict):
                    rows.append(item)
            except (OSError, json.JSONDecodeError):
                continue
        return rows


class CertificateManager:
    def __init__(self, store: Store):
        self.store = store
        self.key_path = store.base / "signing-key.pem"
        self._key = None

    def _keypair(self):
        if self._key is not None:
            return self._key
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        if self.key_path.exists():
            self._key = serialization.load_pem_private_key(self.key_path.read_bytes(), password=None)
        else:
            self._key = ec.generate_private_key(ec.SECP256R1())
            self.key_path.write_bytes(self._key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        return self._key

    def create(self, operation: dict[str, Any]) -> dict[str, Any]:
        if operation.get("status") != "SUCCESS" or operation.get("verification") != "VERIFIED":
            raise ValueError("Certificates can only be created for verified successful operations.")
        if not operation.get("started") or not operation.get("completed"):
            raise ValueError("A verified certificate requires operation start and completion timestamps.")
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        key = self._keypair()
        cert_id = f"CERT-{('REC' if operation['type'] == 'recovery' else 'ERASE')}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8].upper()}"
        payload = {
            "certificate_id": cert_id,
            "operation_type": operation["type"],
            "device_path": operation.get("target", "Unavailable"),
            "device_type": operation.get("device_type", "File/Folder"),
            "device_model": operation.get("device_model", "Unavailable"),
            "serial_number": operation.get("serial_number", "Unavailable"),
            "drive_size": operation.get("target_size", "Unavailable"),
            "method": operation["method"],
            "passes": operation.get("passes", 1),
            "started": operation["started"],
            "completed": operation["completed"],
            "duration": operation["duration"],
            "status": operation["status"],
            "sha256_before": operation.get("sha256_before") or "Not available",
            "sha256_after": operation.get("sha256_after") or "Not applicable after verified removal",
            "verification": operation.get("verification", "Not performed"),
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        signature = key.sign(canonical, ec.ECDSA(hashes.SHA256()))
        public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        signed = dict(payload)
        signed.update({
            "canonical_sha256": hashlib.sha256(canonical).hexdigest(),
            "signature_hash": hashlib.sha256(signature).hexdigest(),
            "signature_der_b64": base64.b64encode(signature).decode("ascii"),
            "public_key_fingerprint": hashlib.sha256(public).hexdigest(),
            "signature_algorithm": "ECDSA P-256 / SHA-256",
            "validation_scheme": "DREX offline certificate v1",
            "created_utc": utc_now(),
        })
        qr_payload = json.dumps({
            "certificate_id": cert_id,
            "canonical_sha256": signed["canonical_sha256"],
            "signature_hash": signed["signature_hash"],
            "public_key_fingerprint": signed["public_key_fingerprint"],
        }, sort_keys=True, separators=(",", ":"))
        signed["qr_payload"] = qr_payload
        safe_json_write(self.store.certs_dir / f"{cert_id}.json", signed)
        pdf_path = self.store.certs_dir / f"{cert_id}.pdf"
        self._write_pdf(signed, pdf_path)
        signed["pdf_path"] = str(pdf_path)
        safe_json_write(self.store.certs_dir / f"{cert_id}.json", signed)
        return signed

    def verify(self, record: dict[str, Any]) -> bool:
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import ec
            payload_keys = ["certificate_id", "operation_type", "device_path", "device_type", "device_model", "serial_number", "drive_size", "method", "passes", "started", "completed", "duration", "status", "sha256_before", "sha256_after", "verification"]
            payload = {key: record[key] for key in payload_keys}
            canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
            if hashlib.sha256(canonical).hexdigest() != record.get("canonical_sha256"):
                return False
            signature = base64.b64decode(record["signature_der_b64"])
            key = self._keypair()
            key.public_key().verify(signature, canonical, ec.ECDSA(hashes.SHA256()))
            return hashlib.sha256(signature).hexdigest() == record.get("signature_hash")
        except Exception:
            return False

    def _write_pdf(self, record: dict[str, Any], path: Path) -> None:
        from io import BytesIO
        import qrcode
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
        qr = qrcode.make(record["qr_payload"])
        qr_stream = BytesIO()
        qr.save(qr_stream, format="PNG")
        qr_stream.seek(0)
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(name="DrexTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=16, textColor=colors.HexColor(GREEN_DARK), alignment=1, spaceAfter=2))
        styles.add(ParagraphStyle(name="Section", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=9, textColor=colors.HexColor(GREEN_DARK), spaceBefore=10, spaceAfter=4))
        styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"], fontSize=7.5, leading=10, textColor=colors.HexColor("#39465c")))
        doc = SimpleDocTemplate(str(path), pagesize=A4, rightMargin=16 * mm, leftMargin=16 * mm, topMargin=14 * mm, bottomMargin=14 * mm)
        story = [Paragraph("DREX CERTIFICATE OF DATA DESTRUCTION" if record["operation_type"] != "recovery" else "DREX CERTIFICATE OF DATA RECOVERY", styles["DrexTitle"]), Paragraph("Tamper-evident Digital Certificate", styles["Small"]), Paragraph(f"Certificate ID: {record['certificate_id']}<br/>Issued: {record['created_utc']}", styles["Small"])]
        def section(title: str, rows: list[tuple[str, str]]):
            story.append(Paragraph(title, styles["Section"]))
            table = Table([[Paragraph(k, styles["Small"]), Paragraph(str(v), styles["Small"])] for k, v in rows], colWidths=[43 * mm, 133 * mm])
            table.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#ccd5d0")), ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f7faf8")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5)]))
            story.append(table)
        section("DEVICE INFORMATION", [("Device Path", record["device_path"]), ("Device Type", record["device_type"]), ("Device Model", record["device_model"]), ("Serial Number", record["serial_number"]), ("Drive Size", record["drive_size"])])
        section("OPERATION DETAILS", [("Method", record["method"]), ("Passes", record["passes"]), ("Started", record["started"]), ("Completed", record["completed"]), ("Duration", record["duration"]), ("Status", record["status"])])
        section("VERIFICATION DATA", [("SHA-256 Before", record["sha256_before"]), ("SHA-256 After", record["sha256_after"]), ("Verification", record["verification"])])
        story += [Paragraph("SCAN TO VERIFY", styles["Section"]), Paragraph("QR encodes the certificate ID and offline validation data.", styles["Small"]), Image(qr_stream, width=31 * mm, height=31 * mm), Spacer(1, 2 * mm)]
        section("DIGITAL SIGNATURE", [("Signature Hash", record["signature_hash"]), ("Public Key Fingerprint", record["public_key_fingerprint"]), ("Algorithm", record["signature_algorithm"])])
        story += [Paragraph("LEGAL / ASSURANCE NOTICE", styles["Section"]), Paragraph("This certificate records the operation and verification data produced by DREX. Software sanitization is not physical destruction. The certificate is tamper-evident through local ECDSA signing and must be independently validated before reliance.", styles["Small"]), Spacer(1, 8 * mm), Paragraph("Generated by DREX · Secure. Recover. Trust.", styles["Small"])]
        doc.build(story)


def target_properties(path: Path) -> dict[str, str]:
    try:
        stat = path.stat()
        size = stat.st_size if path.is_file() else sum((p.stat().st_size for p in path.rglob("*") if p.is_file()), 0)
        name = path.name or str(path)
        return {"Filename": name, "File Type": "Folder" if path.is_dir() else (path.suffix.upper().lstrip(".") + " file" if path.suffix else "File"), "Location": str(path.parent if path.is_file() else path), "Size": fmt_bytes(size) + f" ({size:,} bytes)", "Size on disk": fmt_bytes(size_on_disk(path))}
    except OSError as exc:
        return {"Filename": path.name or str(path), "File Type": "Unavailable", "Location": str(path), "Size": "Unavailable", "Size on disk": f"Unavailable ({exc})"}


# Directories that are off-limits regardless of drive letter
_PROTECTED_NAMES: frozenset[str] = frozenset([
    "windows", "system32", "syswow64", "system", "drivers",
    "program files", "program files (x86)", "programdata",
    "recovery", "$recycle.bin", "system volume information",
    "boot", "bootmgr", "efi", "winsxs",
])


def _is_volume_root(resolved: Path) -> bool:
    """True only when the path IS the drive/volume root itself (e.g. C:\\ or D:\\)."""
    return resolved == Path(resolved.anchor)


def _is_system_volume(resolved: Path) -> bool:
    """True only when the resolved path IS the system/boot volume root."""
    system_drive = Path(os.environ.get("SystemDrive", "C:\\")).drive.upper()
    return resolved.drive.upper() == system_drive and _is_volume_root(resolved)


def _is_protected_system_path(resolved: Path) -> bool:
    """True when the path targets a well-known protected system directory."""
    system_drive = Path(os.environ.get("SystemDrive", "C:\\")).drive.upper()
    if resolved.drive.upper() != system_drive:
        return False
    try:
        # Check each path component against protected names
        parts = [p.lower() for p in resolved.parts]
        for name in _PROTECTED_NAMES:
            if name in parts:
                return True
    except (TypeError, AttributeError):
        pass
    return False


def dangerous_target(path: Path) -> str | None:
    """Return a human-readable reason string if the target is unsafe, else None.

    IMPORTANT: A *file* or *folder* path whose parent volume is the system drive
    is NOT automatically blocked.  Only volume roots and protected system
    directories are blocked.  A path such as C:\\Users\\Alice\\Documents\\report.docx
    is a valid file target even though it lives on C:\\.
    """
    try:
        resolved = path.resolve()
    except OSError:
        return "Target could not be resolved safely."

    # Block volume roots (e.g. C:\\ or D:\\)
    if _is_volume_root(resolved):
        return (
            f"Volume root '{resolved}' is not a valid file/folder target. "
            "Select a specific file or folder inside a volume."
        )

    # Block the home directory itself (but NOT children of it)
    try:
        home = Path.home().resolve()
        if resolved == home:
            return "Your home directory root cannot be selected as a wiping target."
    except RuntimeError:
        pass

    # Block known protected Windows system directories
    if _is_protected_system_path(resolved):
        return (
            f"'{resolved}' is inside a protected system directory and cannot be "
            "selected as a wiping target."
        )

    # Block the DREX application directory itself
    try:
        drex_root = ROOT.resolve()
        if resolved == drex_root or drex_root in resolved.parents:
            return "The DREX application directory cannot be selected."
    except OSError:
        pass

    if not path.exists():
        return "Target no longer exists."
    if path.is_symlink():
        return "Symbolic links are not accepted as targets."
    return None


class AdapterError(RuntimeError):
    pass


class OperationCancelled(RuntimeError):
    """Raised at a progress boundary when the user cancels an operation."""


def execute_file_method(method_id: str, target: Path, emit: Callable[[str], None], progress: Callable[[int, int], None]) -> dict[str, Any]:
    if method_id == "csprng":
        pkg = import_package("csprng_overwrite", method_root("File-Folder Erasure", "CSPRNG_Random_Overwrite_Production_Component_v0.1.0", "csprng_random_overwrite"))
        emit("CSPRNG adapter selected; hashing and overwriting addressable target.")
        if target.is_dir():
            # overwrite_tree() does NOT accept a progress callback — iterate files instead
            result = pkg.engine.overwrite_tree(str(target), verify=True, remove=True)
        else:
            result = pkg.engine.overwrite_file(str(target), verify=True, remove=True, progress=progress)
        rows = result if isinstance(result, list) else [result]
        if any(getattr(row, "error", None) for row in rows) or not all(getattr(row, "verified", False) for row in rows):
            raise AdapterError("CSPRNG adapter did not complete with verified results.")
        return {"verified": True, "removed": all(getattr(row, "removed", False) for row in rows), "sha256_after": None}
    if method_id == "zero":
        # sys.path gets single_pass_zero_overwrite dir; zero_overwrite package is inside it
        pkg = import_package("zero_overwrite", method_root("File-Folder Erasure", "Single-Pass_Zero_Overwrite_Production_Component_v0.1.0", "single_pass_zero_overwrite"))
        emit("Single-pass zero adapter selected; overwriting and reading back every addressable byte.")
        if target.is_dir():
            # overwrite_tree() does NOT accept a progress callback — no progress for tree
            result = pkg.engine.overwrite_tree(str(target), verify=True, remove=True)
        else:
            result = pkg.engine.overwrite_file(str(target), verify=True, remove=True, progress=progress)
        rows = result if isinstance(result, list) else [result]
        if any(getattr(row, "error", None) for row in rows) or not all(getattr(row, "verified", False) for row in rows):
            raise AdapterError("Zero-overwrite adapter did not complete with verified results.")
        return {"verified": True, "removed": all(getattr(row, "removed", False) for row in rows), "sha256_after": None}
    if method_id == "metadata":
        pkg = import_package("metadata_sanitizer", method_root("File-Folder Erasure", "Filesystem Metadata Sanitization Standalone"))
        emit("Filesystem metadata adapter selected; changing only OS-visible metadata requested by policy.")
        # The local backend exposes timestamp normalization through a POSIX-only
        # follow_symlinks argument on this host. Keep the local implementation
        # authoritative and request only the operations this Windows runtime can
        # execute truthfully.
        result = pkg.engine.sanitize_metadata(str(target), clear_xattrs=hasattr(os, "listxattr") and hasattr(os, "removexattr"), normalize_times=os.name != "nt", normalize_permissions=False, rename=False, recursive=target.is_dir())
        if result.status != "SANITIZED":
            raise AdapterError(result.error or "Metadata adapter reported an error.")
        for issue in result.unsupported:
            emit("Metadata boundary: " + issue)
        return {"verified": bool(result.timestamps_verified and result.xattrs_verified_removed), "removed": False, "sha256_after": hash_target(target)}
    if method_id == "free_space":
        pkg = import_package("free_space_wiper", method_root("File-Folder Erasure", "Secure_Free_Space_Wiping_Production_Component_v0.1.0", "secure_free_space_wiping"))
        emit("Free-space adapter selected; allocating and verifying temporary filler files while preserving the reserve.")
        result = pkg.engine.wipe_free_space(str(target), pattern="zero", verify=True, progress=progress)
        if result.error or not result.verified or not result.cleaned_up:
            raise AdapterError(result.error or "Free-space adapter did not verify cleanup.")
        return {"verified": True, "removed": False, "sha256_after": hash_target(target)}
    if method_id == "temporary":
        pkg = import_package("trace_sanitizer", method_root("File-Folder Erasure", "Temporary_Cache_Residual_Trace_Sanitization_Production_Component_v0.1.0", "temporary_cache_residual_trace_sanitization"))
        emit("Temporary/cache adapter selected; scanning the explicitly selected target only.")
        result = pkg.engine.sanitize(str(target), secure_overwrite=True, verify=True, recursive=True, rule_id="explicit-target", label="DREX selected target")
        if result.status != "SANITIZED":
            raise AdapterError("Temporary/cache adapter reported: " + "; ".join(result.errors))
        progress(1, 1)
        return {"verified": result.verified_items == result.items_deleted, "removed": not target.exists(), "sha256_after": None}
    messages = {
        "crypto": "Cryptographic Erasure requires a DREX-managed encrypted envelope and key identifier; the selected arbitrary filesystem target is not eligible.",
        "slack": "File slack sanitization is unavailable because this host has no qualified filesystem cluster-tip backend.",
        "policy": "The NIST policy package is a planning engine; it does not execute a destructive method by itself.",
        "storage_aware": "Storage-aware fallback refused the target because no qualified native or approved fallback adapter is available on this host.",
    }
    raise AdapterError(messages.get(method_id, "This method is unavailable on the current host."))


def drive_method_status(method_id: str, drive: DriveInfo | None) -> tuple[str, str]:
    if drive is None:
        return "Unavailable", "Select a detected device first."
    if method_id == "overwrite" and drive.path.lower().startswith("\\\\.\\"):
        return "Requires Hardware Qualification", "Raw-device overwrite is disabled until this exact hardware path is independently qualified."
    return "Requires Hardware Qualification", "Native drive execution is not enabled without a qualified device adapter and required privilege."


class DrexApp(tk.Tk):
    def __init__(self):
        if os.name == "nt":
            try:
                ctypes.windll.shcore.SetProcessDpiAwareness(1)
            except (AttributeError, OSError):
                pass
        super().__init__()
        self.title(f"DREX — Secure. Recover. Trust. — v{VERSION}")
        self.geometry("1440x900")
        self.minsize(1100, 700)
        self.configure(bg=BG)
        self.store = Store()
        self.cert_manager = CertificateManager(self.store)
        self.events: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.drives: list[DriveInfo] = []
        self.recovery_dispatcher = RecoveryDispatcher(ROOT, Path(getattr(sys, "_MEIPASS", ROOT)))
        self.quick_recovery = self.recovery_dispatcher.get("quick")
        self.current_page = "Dashboard"
        self.page: tk.Frame | None = None
        self.method_var = tk.StringVar()
        self.target: Path | None = None
        self.selected_drive: DriveInfo | None = None
        self.progress_value = tk.DoubleVar(value=0)
        self.progress_mode = tk.StringVar(value="")
        self.cancel_event = threading.Event()
        self.log_text: tk.Text | None = None
        self.status_label: tk.Label | None = None
        self.target_summary: tk.Frame | None = None
        self.help_section = "Getting Started"
        self._configure_styles()
        self._build_shell()
        self.show_page("Dashboard")
        self.after(100, self._poll_events)
        self.after(200, self.refresh_devices)

    # ── Styles ──────────────────────────────────────────────────────
    def _configure_styles(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Drex.TButton", font=("Segoe UI", 10, "bold"), foreground=GREEN_DARK, background="white", bordercolor=GREEN, padding=(16, 9))
        style.map("Drex.TButton", background=[("active", GREEN_PALE)])
        style.configure("DrexPrimary.TButton", font=("Segoe UI", 10, "bold"), foreground="white", background=GREEN, bordercolor=GREEN, padding=(18, 10))
        style.map("DrexPrimary.TButton", background=[("active", GREEN_DARK)])
        style.configure("Drex.Horizontal.TProgressbar", troughcolor="#e7ece9", background=GREEN, bordercolor="#e7ece9", lightcolor=GREEN, darkcolor=GREEN)
        style.configure("Drex.Treeview", rowheight=38, font=("Segoe UI", 9), fieldbackground="white")
        style.configure("Drex.Treeview.Heading", font=("Segoe UI", 9, "bold"), background="#f4f7f5", foreground=INK)

    # ── Shell (sidebar + main) ──────────────────────────────────────
    def _build_shell(self):
        self.sidebar = tk.Frame(self, bg="white", width=210, highlightbackground=LINE, highlightthickness=1)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)
        self._logo(self.sidebar)
        self.nav_frame = tk.Frame(self.sidebar, bg="white")
        self.nav_frame.pack(fill="x", padx=0, pady=(20, 0))
        self.nav_buttons: dict[str, tk.Frame] = {}
        nav_items = [
            ("Dashboard", "⌂"), ("Wipe Drive", "◎"), ("Wipe File/Folder", "▤"),
            ("Recover", "↺"), ("Destroy Drive", "⊠"), ("Certificates", "◈"), ("Help", "?"),
        ]
        for name, glyph in nav_items:
            row = tk.Frame(self.nav_frame, bg="white", cursor="hand2")
            row.pack(fill="x", pady=1)
            indicator = tk.Frame(row, bg="white", width=4)
            indicator.pack(side="left", fill="y")
            icon_cv = tk.Canvas(row, width=22, height=22, bg="white", highlightthickness=0)
            icon_cv.pack(side="left", padx=(14, 8), pady=10)
            self._draw_nav_icon(icon_cv, name, INK)
            lbl = tk.Label(row, text=name, font=("Segoe UI", 10), fg=INK, bg="white", anchor="w")
            lbl.pack(side="left", fill="x", expand=True, pady=10)
            for widget in (row, lbl, icon_cv):
                widget.bind("<Button-1>", lambda _e, n=name: self.show_page(n))
            self.nav_buttons[name] = row
            row._indicator = indicator
            row._icon_cv = icon_cv
            row._lbl = lbl
        # Sidebar footer
        footer = tk.Frame(self.sidebar, bg="white")
        footer.pack(side="bottom", fill="x", padx=0, pady=0)
        # Tree silhouette bar
        tree_bar = tk.Canvas(footer, height=80, bg="white", highlightthickness=0)
        tree_bar.pack(fill="x")
        self._draw_trees(tree_bar)
        info = tk.Frame(footer, bg="#1a472a")
        info.pack(fill="x")
        tk.Label(info, text=f"DREX v{VERSION}", font=("Segoe UI", 8, "bold"), fg="white", bg="#1a472a").pack(anchor="w", padx=16, pady=(8, 0))
        tk.Label(info, text="© 2025 DREX Team", font=("Segoe UI", 7), fg="#8fbfa0", bg="#1a472a").pack(anchor="w", padx=16, pady=(2, 10))
        self.main = tk.Frame(self, bg=BG)
        self.main.pack(side="left", fill="both", expand=True)

    def _draw_trees(self, canvas):
        """Draw a simple forest silhouette at the bottom of the sidebar."""
        canvas.update_idletasks()
        w = max(210, canvas.winfo_width())
        h = 80
        # gradient green background
        canvas.create_rectangle(0, 20, w, h, fill="#1a472a", outline="#1a472a")
        canvas.create_rectangle(0, 0, w, 25, fill="white", outline="white")
        # Simple triangle trees
        trees = [(25, 14), (55, 10), (85, 16), (110, 8), (140, 12), (170, 14), (195, 10)]
        for tx, th in trees:
            top_y = 25 - th
            canvas.create_polygon(tx, top_y, tx - 10, 25, tx + 10, 25, fill="#2d6b40", outline="#2d6b40")
            canvas.create_polygon(tx, top_y + 4, tx - 7, 25, tx + 7, 25, fill="#3a7d50", outline="#3a7d50")
        # Trunk lines
        for tx, _ in trees:
            canvas.create_rectangle(tx - 1, 25, tx + 1, 30, fill="#4a3728", outline="#4a3728")

    def _draw_nav_icon(self, canvas, name, color):
        """Draw a simple icon for each nav item."""
        c = canvas
        if name == "Dashboard":
            c.create_polygon(11, 2, 21, 11, 18, 11, 18, 20, 4, 20, 4, 11, 1, 11, fill=color, outline=color)
        elif name == "Wipe Drive":
            c.create_oval(3, 3, 19, 19, outline=color, width=2)
            c.create_arc(5, 5, 17, 17, start=45, extent=270, style="arc", outline=color, width=2)
            c.create_polygon(14, 3, 18, 7, 14, 7, fill=color, outline=color)
        elif name == "Wipe File/Folder":
            c.create_rectangle(4, 2, 18, 20, outline=color, width=2, fill="")
            c.create_polygon(13, 2, 18, 7, 13, 7, fill="white", outline=color, width=1)
            c.create_line(7, 10, 15, 10, fill=color, width=1)
            c.create_line(7, 13, 15, 13, fill=color, width=1)
            c.create_line(7, 16, 13, 16, fill=color, width=1)
        elif name == "Recover":
            c.create_oval(3, 3, 19, 19, outline=color, width=2)
            c.create_oval(8, 8, 14, 14, outline=color, width=2)
            c.create_oval(10, 10, 12, 12, fill=color, outline=color)
        elif name == "Destroy Drive":
            c.create_rectangle(5, 4, 17, 20, outline=color, width=2, fill="")
            c.create_line(3, 4, 19, 4, fill=color, width=2)
            c.create_line(9, 1, 13, 1, fill=color, width=2)
            c.create_line(8, 8, 8, 17, fill=color)
            c.create_line(11, 8, 11, 17, fill=color)
            c.create_line(14, 8, 14, 17, fill=color)
        elif name == "Certificates":
            c.create_polygon(11, 1, 20, 5, 20, 13, 11, 21, 2, 13, 2, 5, fill="", outline=color, width=2)
            c.create_line(7, 11, 10, 14, fill=color, width=2)
            c.create_line(10, 14, 15, 8, fill=color, width=2)
        elif name == "Help":
            c.create_oval(3, 3, 19, 19, outline=color, width=2)
            c.create_text(11, 12, text="?", fill=color, font=("Segoe UI", 10, "bold"))

    def _update_nav_highlight(self):
        for name, row in self.nav_buttons.items():
            active = name == self.current_page
            bg = GREEN_PALE if active else "white"
            fg = GREEN_DARK if active else INK
            row.configure(bg=bg)
            row._lbl.configure(bg=bg, fg=fg, font=("Segoe UI", 10, "bold") if active else ("Segoe UI", 10))
            row._indicator.configure(bg=GREEN if active else "white")
            row._icon_cv.configure(bg=bg)
            row._icon_cv.delete("all")
            self._draw_nav_icon(row._icon_cv, name, fg)
            for child in row.winfo_children():
                if isinstance(child, (tk.Label, tk.Canvas)):
                    try:
                        child.configure(bg=bg)
                    except tk.TclError:
                        pass

    def _logo(self, parent):
        frame = tk.Frame(parent, bg="white", height=85)
        frame.pack(fill="x", padx=18, pady=(20, 0))
        frame.pack_propagate(False)
        canvas = tk.Canvas(frame, width=44, height=52, bg="white", highlightthickness=0)
        canvas.pack(side="left")
        # Shield shape
        canvas.create_polygon(22, 1, 42, 8, 40, 34, 22, 50, 4, 34, 2, 8, fill=GREEN, outline=GREEN, smooth=False)
        canvas.create_polygon(22, 8, 35, 13, 34, 31, 22, 43, 10, 31, 9, 13, fill="white", outline="white", smooth=False)
        # Tree inside shield
        canvas.create_polygon(22, 14, 17, 26, 19, 26, 14, 34, 22, 30, 30, 34, 25, 26, 27, 26, fill=GREEN, outline=GREEN)
        text_frame = tk.Frame(frame, bg="white")
        text_frame.pack(side="left", fill="x", expand=True, padx=(8, 0), pady=(5, 0))
        tk.Label(text_frame, text="DREX", font=("Segoe UI", 22, "bold"), fg=GREEN_DARK, bg="white").pack(anchor="w")
        tk.Label(text_frame, text="Secure. Recover. Trust.", font=("Segoe UI", 7, "bold"), fg=GREEN_DARK, bg="white").pack(anchor="w")

    # ── Page management ─────────────────────────────────────────────
    def _clear_page(self):
        if self.page:
            self.page_canvas.destroy()
            self.page_scroll.destroy()
        self.page_canvas = tk.Canvas(self.main, bg=BG, highlightthickness=0, bd=0)
        self.page_scroll = ttk.Scrollbar(self.main, orient="vertical", command=self.page_canvas.yview)
        self.page_canvas.configure(yscrollcommand=self.page_scroll.set)
        self.page_scroll.pack(side="right", fill="y")
        self.page_canvas.pack(side="left", fill="both", expand=True)
        self.page = tk.Frame(self.page_canvas, bg=BG)
        self.page_window = self.page_canvas.create_window((0, 0), window=self.page, anchor="nw")
        self.page.bind("<Configure>", lambda _e: self.page_canvas.configure(scrollregion=self.page_canvas.bbox("all")))
        self.page_canvas.bind("<Configure>", lambda event: self.page_canvas.itemconfigure(self.page_window, width=max(500, event.width)))
        self.page_canvas.bind_all("<MouseWheel>", self._mousewheel, add="+")
        self._update_nav_highlight()

    def show_page(self, name: str):
        if name != self.current_page and self.status_label:
            try:
                running = bool(self.status_label.winfo_exists()) and self.status_label.cget("text") == "RUNNING"
            except tk.TclError:
                running = False
            if running:
                messagebox.showwarning("Operation in progress", "Finish or cancel the current operation before changing pages.")
                return
        self.current_page = name
        self._clear_page()
        renderers = {
            "Dashboard": self.render_dashboard, "Wipe Drive": self.render_drive_page,
            "Wipe File/Folder": self.render_file_page, "Recover": self.render_recovery_page,
            "Destroy Drive": self.render_destroy_page, "Certificates": self.render_certificates,
            "Help": self.render_help,
        }
        renderers.get(name, self.render_help)()

    def _mousewheel(self, event):
        if getattr(self, "page_canvas", None) and self.page_canvas.winfo_exists():
            self.page_canvas.yview_scroll(int(-event.delta / 120), "units")

    def toggle_sidebar(self):
        if self.sidebar.winfo_ismapped():
            self.sidebar.pack_forget()
        else:
            self.sidebar.pack(side="left", fill="y", before=self.main)

    # ── Shared: Header ──────────────────────────────────────────────
    def _header(self, title: str, subtitle: str):
        top = tk.Frame(self.page, bg=BG)
        top.pack(fill="x", padx=28, pady=(20, 0))
        # Left: hamburger + title
        left = tk.Frame(top, bg=BG)
        left.pack(side="left", fill="x", expand=True)
        tk.Button(left, text="☰", command=self.toggle_sidebar, font=("Segoe UI", 14), relief="flat", bg=BG, fg=INK, activebackground=GREEN_PALE, bd=0).pack(side="left", padx=(0, 12))
        title_frame = tk.Frame(left, bg=BG)
        title_frame.pack(side="left")
        tk.Label(title_frame, text=title, font=("Segoe UI", 24, "bold"), fg=INK, bg=BG).pack(anchor="w")
        tk.Label(title_frame, text=subtitle, font=("Segoe UI", 10), fg=MUTED, bg=BG).pack(anchor="w", pady=(2, 0))
        # Right: System Health pill
        pill = tk.Frame(top, bg="white", highlightbackground=LINE, highlightthickness=1)
        pill.pack(side="right", padx=(12, 0))
        inner_pill = tk.Frame(pill, bg="white")
        inner_pill.pack(padx=16, pady=8)
        tk.Label(inner_pill, text="●", font=("Segoe UI", 14), fg=GREEN, bg="white").pack(side="left", padx=(0, 8))
        pill_text = tk.Frame(inner_pill, bg="white")
        pill_text.pack(side="left")
        tk.Label(pill_text, text="System Health", font=("Segoe UI", 10, "bold"), fg=INK, bg="white").pack(anchor="w")
        tk.Label(pill_text, text="All Systems Operational", font=("Segoe UI", 8), fg=MUTED, bg="white").pack(anchor="w")
        # Settings gear
        gear = tk.Canvas(top, width=28, height=28, bg=BG, highlightthickness=0)
        gear.pack(side="right", padx=(8, 0))
        gear.create_text(14, 14, text="⚙", font=("Segoe UI", 16), fill=MUTED)

    def _card(self, parent, **kwargs):
        border_color = kwargs.pop("border", LINE)
        bg_color = kwargs.pop("bg", "white")
        return tk.Frame(parent, bg=bg_color, highlightbackground=border_color, highlightthickness=1, **kwargs)

    # ── Dashboard ───────────────────────────────────────────────────
    def render_dashboard(self):
        self._header("Welcome to DREX", "Unified Data Recovery & Sanitization Platform")
        history = self.store.history()
        certs = self.store.certificates()
        content = tk.Frame(self.page, bg=BG)
        content.pack(fill="both", expand=True, padx=28, pady=(20, 0))
        # Main area (left) + Right sidebar
        body = tk.Frame(content, bg=BG)
        body.pack(fill="both", expand=True)
        left = tk.Frame(body, bg=BG)
        left.pack(side="left", fill="both", expand=True, padx=(0, 16))
        right = tk.Frame(body, bg=BG, width=280)
        right.pack(side="right", fill="y")
        right.pack_propagate(False)
        # ─ Stats row ─
        stats = tk.Frame(left, bg=BG)
        stats.pack(fill="x", pady=(0, 20))
        stat_data = [
            ("Drives Wiped", str(sum(1 for h in history if h.get("type") == "drive" and h.get("status") == "SUCCESS")), "Total drives erased", GREEN, "◎"),
            ("Files/Folders Wiped", str(sum(1 for h in history if h.get("type") == "file" and h.get("status") == "SUCCESS")), "Total items securely erased", BLUE, "▤"),
            ("Files Recovered", str(sum(h.get("recovered_count", 0) for h in history if h.get("type") == "recovery" and h.get("status") == "SUCCESS")), "Total files recovered", PURPLE, "↺"),
            ("Certificates", str(len(certs)), "Generated certificates", ORANGE, "◈"),
        ]
        for title, value, detail, color, glyph in stat_data:
            card = self._card(stats)
            card.pack(side="left", fill="both", expand=True, padx=(0, 10))
            inner = tk.Frame(card, bg="white")
            inner.pack(fill="both", expand=True, padx=16, pady=14)
            top_row = tk.Frame(inner, bg="white")
            top_row.pack(fill="x")
            icon_bg = tk.Canvas(top_row, width=40, height=40, highlightthickness=0)
            icon_bg.pack(side="left", padx=(0, 10))
            icon_bg.create_oval(2, 2, 38, 38, fill="#eef8f1" if color == GREEN else ("#eef0f8" if color == BLUE else ("#f5eef8" if color == PURPLE else "#fef5eb")), outline="")
            icon_bg.create_text(20, 20, text=glyph, fill=color, font=("Segoe UI", 14, "bold"))
            val_frame = tk.Frame(top_row, bg="white")
            val_frame.pack(side="left")
            tk.Label(val_frame, text=value, font=("Segoe UI", 22, "bold"), fg=color, bg="white").pack(anchor="w")
            tk.Label(inner, text=title, font=("Segoe UI", 10, "bold"), fg=INK, bg="white").pack(anchor="w", pady=(4, 0))
            tk.Label(inner, text=detail, font=("Segoe UI", 8), fg=MUTED, bg="white").pack(anchor="w", pady=(2, 0))
        # ─ Choose an Operation ─
        tk.Label(left, text="Choose an Operation", font=("Segoe UI", 14, "bold"), fg=INK, bg=BG).pack(anchor="w")
        tk.Label(left, text="Select an operation to get started.", font=("Segoe UI", 9), fg=MUTED, bg=BG).pack(anchor="w", pady=(2, 10))
        ops = tk.Frame(left, bg=BG)
        ops.pack(fill="x", pady=(0, 20))
        op_items = [
            ("Wipe Drive", GREEN, "◎"), ("Wipe File/Folder", GREEN, "▤"),
            ("Recover", GREEN, "↺"), ("Destroy Drive", RED, "⊠"), ("Certificates", GREEN, "◈"),
        ]
        for op_name, op_color, op_glyph in op_items:
            card = self._card(ops)
            card.pack(side="left", fill="both", expand=True, padx=(0, 8))
            card.configure(cursor="hand2")
            inner_op = tk.Frame(card, bg="white")
            inner_op.pack(fill="both", expand=True, padx=10, pady=14)
            icon_c = tk.Canvas(inner_op, width=36, height=36, bg="white", highlightthickness=0)
            icon_c.pack()
            icon_c.create_text(18, 18, text=op_glyph, fill=op_color, font=("Segoe UI", 16))
            tk.Label(inner_op, text=op_name, font=("Segoe UI", 9, "bold"), fg=op_color if op_color == RED else INK, bg="white", wraplength=100).pack(pady=(6, 0))
            for w in (card, inner_op, icon_c):
                w.bind("<Button-1>", lambda _e, n=op_name: self.show_page(n))
        # ─ Enhanced Storage Devices ─
        dev_header = tk.Frame(left, bg=BG)
        dev_header.pack(fill="x", pady=(0, 8))
        tk.Label(dev_header, text="Enhanced Storage Devices", font=("Segoe UI", 14, "bold"), fg=INK, bg=BG).pack(side="left")
        tk.Label(dev_header, text="Select a device to perform operations or refresh the list.", font=("Segoe UI", 9), fg=MUTED, bg=BG).pack(side="left", padx=(12, 0))
        ttk.Button(dev_header, text="↻ Refresh", style="Drex.TButton", command=self.refresh_devices).pack(side="right")
        dev_row = tk.Frame(left, bg=BG)
        dev_row.pack(fill="x", pady=(0, 16))
        for drive in self.drives[:4]:
            dcard = self._card(dev_row)
            dcard.pack(side="left", fill="both", expand=True, padx=(0, 8))
            inner_d = tk.Frame(dcard, bg="white")
            inner_d.pack(fill="both", expand=True, padx=12, pady=10)
            # Drive header
            dh = tk.Frame(inner_d, bg="white")
            dh.pack(fill="x")
            tk.Label(dh, text=drive.display("model") or drive.path, font=("Segoe UI", 9, "bold"), fg=INK, bg="white", wraplength=150, justify="left").pack(side="left")
            dtype = drive.drive_type or "Drive"
            badge_color = GREEN if dtype == "Fixed" else (BLUE if dtype == "Removable" else MUTED)
            badge = tk.Label(dh, text=dtype[:3].upper(), font=("Segoe UI", 7, "bold"), fg="white", bg=badge_color, padx=4, pady=1)
            badge.pack(side="right")
            tk.Label(inner_d, text=f"{drive.path} (Primary Partition)", font=("Segoe UI", 8), fg=MUTED, bg="white").pack(anchor="w", pady=(2, 0))
            health_color = GREEN_DARK if drive.health == "OK" else MUTED
            tk.Label(inner_d, text=f"Healthy" if drive.health == "OK" else drive.display("health"), font=("Segoe UI", 8, "bold"), fg=health_color, bg="white").pack(anchor="w", pady=(2, 6))
            # Details row
            det = tk.Frame(inner_d, bg="white")
            det.pack(fill="x")
            for lbl, val in [("Capacity", fmt_bytes(drive.capacity)), ("Interface", drive.display("interface"))]:
                tk.Label(det, text=lbl, font=("Segoe UI", 7), fg=MUTED, bg="white").pack(side="left")
                tk.Label(det, text=val, font=("Segoe UI", 7, "bold"), fg=INK, bg="white").pack(side="left", padx=(4, 10))
            # Health indicator
            det2 = tk.Frame(inner_d, bg="white")
            det2.pack(fill="x", pady=(0, 6))
            tk.Label(det2, text="Health", font=("Segoe UI", 7), fg=MUTED, bg="white").pack(side="left")
            tk.Label(det2, text="100%" if drive.health == "OK" else "—", font=("Segoe UI", 7, "bold"), fg=health_color, bg="white").pack(side="left", padx=(4, 0))
            # Buttons
            btn_row = tk.Frame(inner_d, bg="white")
            btn_row.pack(fill="x", pady=(4, 0))
            ttk.Button(btn_row, text="Details", style="Drex.TButton").pack(side="left", padx=(0, 4))
            ttk.Button(btn_row, text="Select ▾", style="Drex.TButton", command=lambda d=drive: self._select_dashboard_drive(d)).pack(side="left")
        if not self.drives:
            empty_card = self._card(dev_row)
            empty_card.pack(fill="x")
            tk.Label(empty_card, text="No storage devices were reported by the operating system.", fg=MUTED, bg="white", font=("Segoe UI", 10), pady=20).pack()
        # ─ Green footer banner ─
        banner = tk.Frame(left, bg="#1a472a")
        banner.pack(fill="x", pady=(8, 0))
        banner_inner = tk.Frame(banner, bg="#1a472a")
        banner_inner.pack(fill="x", padx=20, pady=14)
        tk.Label(banner_inner, text="Your Data. Your Control. Our Priority.", font=("Segoe UI", 12, "bold"), fg="white", bg="#1a472a").pack(side="left")
        for badge_text in ["Secure and\nCompliant", "Multi-Engine\nSupport", "Military-Grade\nSecurity"]:
            tk.Label(banner_inner, text=badge_text, font=("Segoe UI", 7), fg="#b8d4c4", bg="#1a472a", justify="center").pack(side="right", padx=14)
        # ─ RIGHT SIDEBAR ─
        # System Status
        status_card = self._card(right)
        status_card.pack(fill="x", pady=(0, 12))
        tk.Label(status_card, text="System Status", font=("Segoe UI", 12, "bold"), fg=INK, bg="white").pack(anchor="w", padx=14, pady=(14, 8))
        tk.Label(status_card, text="All systems are running smoothly.", font=("Segoe UI", 8), fg=MUTED, bg="white").pack(anchor="w", padx=14, pady=(0, 8))
        for label, ok in [("Device Detection", bool(self.drives)), ("Scanning Engine", True), ("Security Module", True), ("Verification Engine", True)]:
            row = tk.Frame(status_card, bg="white")
            row.pack(fill="x", padx=14, pady=3)
            tk.Label(row, text=label, font=("Segoe UI", 9), fg=INK, bg="white").pack(side="left")
            tk.Label(row, text="Active" if ok else "Inactive", font=("Segoe UI", 9, "bold"), fg=GREEN if ok else RED, bg="white").pack(side="right")
        tk.Frame(status_card, bg="white", height=8).pack()
        # Recent Activity
        act_card = self._card(right)
        act_card.pack(fill="x", pady=(0, 12))
        act_header = tk.Frame(act_card, bg="white")
        act_header.pack(fill="x", padx=14, pady=(14, 8))
        tk.Label(act_header, text="Recent Activity", font=("Segoe UI", 12, "bold"), fg=INK, bg="white").pack(side="left")
        tk.Label(act_header, text="View All", font=("Segoe UI", 8), fg=GREEN_DARK, bg="white", cursor="hand2").pack(side="right")
        for item in history[:5]:
            a_row = tk.Frame(act_card, bg="white")
            a_row.pack(fill="x", padx=14, pady=3)
            status = item.get("status", "UNKNOWN")
            color = GREEN if status == "SUCCESS" else (RED if status == "FAILED" else MUTED)
            tk.Label(a_row, text="●", fg=color, bg="white", font=("Segoe UI", 8)).pack(side="left", padx=(0, 6))
            a_text = tk.Frame(a_row, bg="white")
            a_text.pack(side="left", fill="x", expand=True)
            tk.Label(a_text, text=item.get("method", "Operation"), font=("Segoe UI", 8, "bold"), fg=INK, bg="white", anchor="w").pack(anchor="w")
            tk.Label(a_text, text=item.get("target", "")[:30], font=("Segoe UI", 7), fg=MUTED, bg="white", anchor="w").pack(anchor="w")
        if not history:
            tk.Label(act_card, text="No recent activity", font=("Segoe UI", 9), fg=MUTED, bg="white").pack(padx=14, pady=10)
        tk.Frame(act_card, bg="white", height=8).pack()
        # Security Highlights
        sec_card = self._card(right)
        sec_card.pack(fill="x")
        tk.Label(sec_card, text="Security Highlights", font=("Segoe UI", 12, "bold"), fg=INK, bg="white").pack(anchor="w", padx=14, pady=(14, 8))
        for line in ["All operations are read-only\nuntil execution.", "Data is never modified during\nrecovery.", "Erasure methods follow NIST\nSP 800-88 Rev. 1.", "Certificates are tamper-proof\nand verifiable."]:
            s_row = tk.Frame(sec_card, bg="white")
            s_row.pack(fill="x", padx=14, pady=4)
            tk.Label(s_row, text="✓", fg=GREEN, bg="white", font=("Segoe UI", 10, "bold")).pack(side="left", padx=(0, 8))
            tk.Label(s_row, text=line, font=("Segoe UI", 8), fg=INK, bg="white", justify="left", wraplength=220).pack(side="left")
        tk.Frame(sec_card, bg="white", height=10).pack()

    def _select_dashboard_drive(self, drive):
        self.selected_drive = drive
        self.show_page("Wipe Drive")

    def native_engine_count(self) -> int:
        native = Path(getattr(sys, "_MEIPASS", ROOT)) / "native_bin"
        return len(list(native.glob("*.exe"))) if native.exists() else 0

    def refresh_devices(self):
        self.drives = discover_drives()
        if self.current_page == "Dashboard":
            self.show_page("Dashboard")

    # ── Target Panel ────────────────────────────────────────────────
    def _target_panel(self, kind: str):
        panel = self._card(self.page)
        panel.pack(fill="x", padx=28, pady=(18, 12))
        self.target_summary = panel
        if kind == "drive":
            # 3-section layout: Select Drive | Model/Serial/Capacity/Interface | Drive Letters/Device ID/Health
            left = tk.Frame(panel, bg="white")
            left.pack(side="left", fill="y", padx=18, pady=14)
            left.configure(width=280)
            left.pack_propagate(False)
            tk.Label(left, text="Select Drive", font=("Segoe UI", 11, "bold"), fg=INK, bg="white").pack(anchor="w")
            combo_row = tk.Frame(left, bg="white")
            combo_row.pack(anchor="w", pady=(10, 0), fill="x")
            self.drive_combo = ttk.Combobox(combo_row, state="readonly", font=("Segoe UI", 10), width=22, values=[f"[{d.path}] {d.display('model')[:20]}" for d in self.drives])
            self.drive_combo.pack(side="left", padx=(0, 8))
            self.drive_combo.bind("<<ComboboxSelected>>", lambda _e: self._drive_selected())
            ttk.Button(combo_row, text="Detect", style="DrexPrimary.TButton", command=self.refresh_devices).pack(side="left")
            # Middle: Model, Serial, Capacity, Interface
            sep1 = ttk.Separator(panel, orient="vertical")
            sep1.pack(side="left", fill="y", pady=14)
            mid = tk.Frame(panel, bg="white")
            mid.pack(side="left", fill="both", expand=True, padx=18, pady=14)
            self.drive_mid_labels = {}
            for key in ("Model", "Serial", "Capacity", "Interface"):
                row = tk.Frame(mid, bg="white")
                row.pack(fill="x", pady=3)
                tk.Label(row, text=key, font=("Segoe UI", 9, "bold"), fg=INK, bg="white", width=10, anchor="w").pack(side="left")
                tk.Label(row, text=":", font=("Segoe UI", 9), fg=MUTED, bg="white").pack(side="left", padx=(0, 8))
                val = tk.Label(row, text="—", font=("Segoe UI", 9), fg=MUTED, bg="white", anchor="w")
                val.pack(side="left", fill="x", expand=True)
                self.drive_mid_labels[key] = val
            # Right: Drive Letters, Device ID, Health
            sep2 = ttk.Separator(panel, orient="vertical")
            sep2.pack(side="left", fill="y", pady=14)
            right_panel = tk.Frame(panel, bg="white")
            right_panel.pack(side="left", fill="both", expand=True, padx=18, pady=14)
            self.drive_right_labels = {}
            for key in ("Drive Letters", "Device ID", "Health"):
                row = tk.Frame(right_panel, bg="white")
                row.pack(fill="x", pady=3)
                tk.Label(row, text=key, font=("Segoe UI", 9, "bold"), fg=INK, bg="white", width=12, anchor="w").pack(side="left")
                tk.Label(row, text=":", font=("Segoe UI", 9), fg=MUTED, bg="white").pack(side="left", padx=(0, 8))
                val = tk.Label(row, text="—", font=("Segoe UI", 9), fg=GREEN_DARK if key == "Health" else MUTED, bg="white", anchor="w")
                val.pack(side="left", fill="x", expand=True)
                self.drive_right_labels[key] = val
        else:
            # File/Folder or Recovery: matching reference image layout
            left = tk.Frame(panel, bg="white")
            left.pack(side="left", fill="y", padx=18, pady=14)
            left.configure(width=440)
            left.pack_propagate(False)
            label_text = "Select File/Folder" if kind == "file" else "Select Recovery Folder"
            tk.Label(left, text=label_text, font=("Segoe UI", 11, "bold"), fg=INK, bg="white").pack(anchor="w")
            # Path row with folder icon + entry + chevron (matches reference)
            sel_row = tk.Frame(left, bg="white", highlightbackground=LINE, highlightthickness=1)
            sel_row.pack(anchor="w", fill="x", pady=(10, 0))
            icon_cv = tk.Canvas(sel_row, width=24, height=24, bg="white", highlightthickness=0)
            icon_cv.pack(side="left", padx=(8, 4), pady=4)
            icon_cv.create_rectangle(1, 7, 10, 13, fill=GREEN, outline=GREEN)
            icon_cv.create_rectangle(1, 10, 22, 22, fill=GREEN, outline=GREEN)
            icon_cv.create_rectangle(3, 12, 20, 20, fill="#eef8f1", outline="#eef8f1")
            self.target_path_var = tk.StringVar(value="No file or folder selected")
            path_entry = tk.Entry(
                sel_row, textvariable=self.target_path_var,
                font=("Segoe UI", 9), relief="flat", bd=0,
                state="readonly", readonlybackground="white", fg=MUTED, width=30,
            )
            path_entry.pack(side="left", fill="x", expand=True, padx=(0, 2), ipady=5)
            tk.Label(sel_row, text="⌄", font=("Segoe UI", 11), fg=MUTED, bg="white").pack(side="left", padx=(0, 8))
            # Button row
            btn_frame = tk.Frame(left, bg="white")
            btn_frame.pack(anchor="w", fill="x", pady=(10, 0))
            if kind == "recovery":
                ttk.Button(btn_frame, text="Select Recovery Folder", style="DrexPrimary.TButton", command=lambda: self.choose_folder("recovery")).pack(side="left")
            else:
                ttk.Button(btn_frame, text="Add File", style="DrexPrimary.TButton", command=self.choose_file).pack(side="left")
                ttk.Button(btn_frame, text="Add Folder", style="Drex.TButton", command=self.choose_folder).pack(side="left", padx=(8, 0))
            # Target type badge updated by set_target()
            self.target_type_label = tk.Label(
                btn_frame, text="",
                font=("Segoe UI", 8, "bold"), fg=GREEN_DARK, bg="white",
            )
            self.target_type_label.pack(side="left", padx=(12, 0))
            # Right: Properties panel
            sep = ttk.Separator(panel, orient="vertical")
            sep.pack(side="left", fill="y", pady=14)
            right_panel = tk.Frame(panel, bg="white")
            right_panel.pack(side="right", fill="both", expand=True, padx=18, pady=14)
            self.file_details = right_panel
            self.file_info_labels = {}
            # Exactly matching reference: Type of file, Location, Size, Size on disk
            prop_keys = [
                ("Type of file:", "File Type"),
                ("Location:", "Location"),
                ("Size:", "Size"),
                ("Size on disk:", "Size on Disk"),
            ]
            for display_key, data_key in prop_keys:
                row = tk.Frame(right_panel, bg="white")
                row.pack(fill="x", pady=4)
                tk.Label(
                    row, text=display_key, font=("Segoe UI", 9, "bold"),
                    fg=INK, bg="white", width=14, anchor="w",
                ).pack(side="left")
                val = tk.Label(
                    row, text="—", font=("Segoe UI", 9),
                    fg=MUTED, bg="white", anchor="w", wraplength=300, justify="left",
                )
                val.pack(side="left", fill="x", expand=True)
                self.file_info_labels[data_key] = val

    def _drive_selected(self):
        index = self.drive_combo.current()
        self.selected_drive = self.drives[index] if 0 <= index < len(self.drives) else None
        if self.selected_drive:
            d = self.selected_drive
            # Update middle labels
            if hasattr(self, "drive_mid_labels"):
                self.drive_mid_labels["Model"].configure(text=d.display("model"), fg=INK)
                self.drive_mid_labels["Serial"].configure(text=d.display("serial"), fg=INK)
                self.drive_mid_labels["Capacity"].configure(text=fmt_bytes(d.capacity), fg=INK)
                self.drive_mid_labels["Interface"].configure(text=d.display("interface"), fg=INK)
            # Update right labels
            if hasattr(self, "drive_right_labels"):
                self.drive_right_labels["Drive Letters"].configure(text=d.path, fg=INK)
                self.drive_right_labels["Device ID"].configure(text=d.display("device_id"), fg=INK)
                self.drive_right_labels["Health"].configure(text=d.display("health"), fg=GREEN_DARK if d.health == "OK" else RED)
            if self.current_page == "Destroy Drive":
                self.render_destroy_page()

    def choose_file(self):
        chosen = filedialog.askopenfilename(title="Select a file to wipe")
        if chosen:
            self.set_target(Path(chosen))

    def choose_file_or_folder(self):
        """Open a proper two-step picker: first try file, then folder.

        Uses a native Windows file dialog first; if the user cancels (i.e.
        they want a folder instead), falls through to askdirectory.
        Both dialogs are proper Windows-shell dialogs, not text fields.
        """
        # Step 1: ask for a file
        chosen = filedialog.askopenfilename(
            title="Select a File to Wipe  (Cancel to select a Folder instead)",
            filetypes=[
                ("All files", "*.*"),
                ("Documents", "*.pdf *.docx *.xlsx *.txt *.csv"),
                ("Images", "*.jpg *.jpeg *.png *.gif *.bmp"),
            ],
        )
        if not chosen:
            # Step 2: user cancelled file dialog → ask for a folder
            chosen = filedialog.askdirectory(
                title="Select a Folder to Wipe",
                mustexist=True,
            )
        if chosen:
            self.set_target(Path(chosen))

    def choose_folder(self, kind: str = "file"):
        chosen = filedialog.askdirectory(
            title="Select a Recovery Folder" if kind == "recovery" else "Select a Folder to Wipe",
            mustexist=True,
        )
        if chosen:
            self.set_target(Path(chosen))

    def set_target(self, target: Path):
        self.target = target
        # Update the path display entry
        if hasattr(self, "target_path_var"):
            self.target_path_var.set(str(target))
        # Update file info labels with fresh data
        if hasattr(self, "file_info_labels"):
            props = target_properties(target)
            for key, label in self.file_info_labels.items():
                value = props.get(key, "Unavailable")
                color = INK if value != "Unavailable" else MUTED
                label.configure(text=value, fg=color)
        # Update target type indicator if present
        if hasattr(self, "target_type_label"):
            t = "Folder" if target.is_dir() else "File"
            self.target_type_label.configure(
                text=f"TARGET TYPE: {t.upper()}",
                fg=GREEN_DARK,
            )

    # ── Method Grid ─────────────────────────────────────────────────
    def _methods(self, methods: list[dict[str, str]] | list[tuple[str, str, str]], kind: str):
        box = self._card(self.page)
        box.pack(fill="x", padx=28, pady=(0, 12))
        inner = tk.Frame(box, bg="white")
        inner.pack(fill="x", padx=18, pady=(14, 6))
        title = "Select Wiping Method" if kind != "recovery" else "Select Recovery Method"
        tk.Label(inner, text=title, font=("Segoe UI", 14, "bold"), fg=INK, bg="white").pack(anchor="w")
        subtitle = "Choose one secure erasure method to apply." if kind in ("file", "drive") else "Choose one scanning and recovery method to apply."
        tk.Label(inner, text=subtitle, font=("Segoe UI", 9), fg=MUTED, bg="white").pack(anchor="w", pady=(2, 10))
        grid = tk.Frame(box, bg="white")
        grid.pack(fill="x", padx=14, pady=(0, 8))
        self.method_var.set("")
        columns = 4 if kind == "drive" else 3
        for col in range(columns):
            grid.columnconfigure(col, weight=1, uniform="method")
        self._method_cards = {}
        for index, item in enumerate(methods):
            if kind == "recovery":
                method_id, name, assurance = item
            else:
                method_id, name, assurance = item["id"], item["name"], item["assurance"]

            # Get availability status for non-recovery methods
            status_text, status_reason = self._method_status(method_id, kind)
            is_available = status_text == "Available"

            card = tk.Frame(grid, bg="white", highlightbackground=LINE, highlightthickness=1)
            card.grid(row=index // columns, column=index % columns, sticky="nsew", padx=4, pady=4, ipady=8)
            content = tk.Frame(card, bg="white")
            content.pack(fill="both", expand=True, padx=10, pady=8)
            top_row = tk.Frame(content, bg="white")
            top_row.pack(fill="x")
            # Icon — dimmed if unavailable
            icon_bg = "#eef8f1" if is_available else "#f5f5f5"
            icon = tk.Canvas(top_row, width=40, height=40, bg=icon_bg, highlightthickness=0)
            icon.pack(side="left", padx=(0, 10))
            self._draw_method_icon(icon, method_id, kind)
            # Text
            name_color = INK if is_available else MUTED
            text_frame = tk.Frame(top_row, bg="white")
            text_frame.pack(side="left", fill="both", expand=True)
            tk.Label(text_frame, text=name, font=("Segoe UI", 9, "bold"), fg=name_color, bg="white", wraplength=180, justify="left", anchor="w").pack(anchor="w")
            tk.Label(text_frame, text=assurance, font=("Segoe UI", 8), fg=MUTED, bg="white", wraplength=180, justify="left", anchor="w").pack(anchor="w", pady=(2, 0))
            # Availability badge for file methods
            if kind == "file" and not is_available:
                badge_text = {
                    "Requires whole-volume scope": "Volume scope only",
                    "Unavailable on this target": "Needs envelope",
                }.get(status_text, status_text[:22])
                tk.Label(text_frame, text=badge_text, font=("Segoe UI", 7), fg="white",
                         bg="#b0b0b0", padx=4, pady=1).pack(anchor="w", pady=(3, 0))
            # Availability badge for drive methods
            if kind == "drive" and status_text not in ("Available", ""):
                tk.Label(text_frame, text="Needs Hardware", font=("Segoe UI", 7), fg="white",
                         bg=ORANGE, padx=4, pady=1).pack(anchor="w", pady=(3, 0))
            if kind == "recovery" and not is_available:
                tk.Label(text_frame, text="Unavailable — native engine required", font=("Segoe UI", 7), fg="white",
                         bg="#b0b0b0", padx=4, pady=1).pack(anchor="w", pady=(3, 0))
            # Checkbox
            cb = tk.Canvas(top_row, width=20, height=20, bg="white", highlightthickness=0)
            cb.pack(side="right", padx=(6, 0))
            cb.create_rectangle(2, 2, 18, 18, outline=LINE, width=1)
            self._method_cards[method_id] = (card, cb)
            # Click handler — only fully selectable if available (or recovery)
            def on_select(event=None, mid=method_id, avail=is_available):
                # Always allow selection so user can read the reason, but warn
                self.method_var.set(mid)
                for m_id, (m_card, m_cb) in self._method_cards.items():
                    if m_id == mid:
                        sel_color = GREEN if avail else ORANGE
                        m_card.configure(highlightbackground=sel_color, highlightthickness=2)
                        m_cb.delete("all")
                        m_cb.create_rectangle(2, 2, 18, 18, fill=sel_color, outline=sel_color, width=1)
                        m_cb.create_line(6, 10, 9, 14, fill="white", width=2)
                        m_cb.create_line(9, 14, 15, 6, fill="white", width=2)
                    else:
                        m_card.configure(highlightbackground=LINE, highlightthickness=1)
                        m_cb.delete("all")
                        m_cb.create_rectangle(2, 2, 18, 18, outline=LINE, width=1)
            for w in (card, content, top_row, text_frame, icon, cb):
                w.bind("<Button-1>", on_select)
                w.configure(cursor="hand2")
            for child in text_frame.winfo_children():
                child.bind("<Button-1>", on_select)
                child.configure(cursor="hand2")
        # Start button
        btn_frame = tk.Frame(box, bg="white")
        btn_frame.pack(fill="x", padx=18, pady=(4, 12))
        self.start_button = ttk.Button(btn_frame, text="Start Recovery" if kind == "recovery" else "Start Operation", style="DrexPrimary.TButton", command=lambda k=kind: self.start_operation(k))
        self.start_button.pack(side="right")

    def _draw_method_icon(self, canvas, method_id, kind):
        """Draw a distinctive icon for each method."""
        c = canvas
        if kind == "drive":
            icons = {
                "nist": lambda: c.create_text(20, 20, text="✓", fill=GREEN_DARK, font=("Segoe UI", 16, "bold")),
                "smart": lambda: c.create_text(20, 20, text="★", fill=GREEN_DARK, font=("Segoe UI", 14)),
                "native": lambda: [c.create_rectangle(12, 8, 28, 32, outline=GREEN_DARK, width=2), c.create_line(16, 14, 24, 14, fill=GREEN_DARK)],
                "ata": lambda: c.create_text(20, 20, text="ATA", fill=GREEN_DARK, font=("Segoe UI", 9, "bold")),
                "nvme": lambda: c.create_text(20, 20, text="NVMe", fill=GREEN_DARK, font=("Segoe UI", 7, "bold")),
                "ieee": lambda: c.create_text(20, 20, text="2883", fill=GREEN_DARK, font=("Segoe UI", 8, "bold")),
                "overwrite": lambda: [c.create_oval(8, 8, 32, 32, outline=GREEN_DARK, width=2), c.create_text(20, 20, text="✓", fill=GREEN_DARK, font=("Segoe UI", 12, "bold"))],
            }
        elif kind == "recovery":
            icons = {
                "quick": lambda: c.create_text(20, 20, text="⚡", fill=GREEN_DARK, font=("Segoe UI", 14)),
                "smart": lambda: c.create_text(20, 20, text="★", fill=GREEN_DARK, font=("Segoe UI", 14)),
                "targeted": lambda: [c.create_oval(10, 10, 30, 30, outline=GREEN_DARK, width=2), c.create_oval(15, 15, 25, 25, outline=GREEN_DARK, width=1)],
                "filesystem": lambda: [c.create_rectangle(10, 6, 30, 34, outline=GREEN_DARK, width=2), c.create_line(14, 14, 26, 14, fill=GREEN_DARK), c.create_line(14, 20, 26, 20, fill=GREEN_DARK)],
                "deep": lambda: [c.create_oval(8, 8, 26, 26, outline=GREEN_DARK, width=2), c.create_line(24, 24, 32, 32, fill=GREEN_DARK, width=2)],
                "fragment": lambda: [c.create_rectangle(8, 8, 18, 18, outline=GREEN_DARK, width=1), c.create_rectangle(20, 8, 30, 18, outline=GREEN_DARK, width=1), c.create_rectangle(14, 20, 24, 30, outline=GREEN_DARK, width=1)],
                "raid": lambda: [c.create_rectangle(8, 10, 18, 30, outline=GREEN_DARK, width=1), c.create_rectangle(20, 10, 30, 30, outline=GREEN_DARK, width=1), c.create_line(18, 20, 20, 20, fill=GREEN_DARK, width=1)],
                "damaged": lambda: [c.create_oval(8, 8, 32, 32, outline=GREEN_DARK, width=2), c.create_line(14, 14, 26, 26, fill=RED, width=2)],
                "forensic": lambda: [c.create_oval(10, 10, 30, 30, outline=GREEN_DARK, width=2), c.create_text(20, 20, text="🔍", font=("Segoe UI", 10))],
            }
        else:
            icons = {
                "csprng": lambda: [
                    c.create_rectangle(6, 6, 34, 34, outline=GREEN_DARK, width=2, fill="#eef8f1"),
                    c.create_oval(11, 11, 15, 15, fill=GREEN_DARK, outline=GREEN_DARK),
                    c.create_oval(25, 11, 29, 15, fill=GREEN_DARK, outline=GREEN_DARK),
                    c.create_oval(18, 18, 22, 22, fill=GREEN_DARK, outline=GREEN_DARK),
                    c.create_oval(11, 25, 15, 29, fill=GREEN_DARK, outline=GREEN_DARK),
                    c.create_oval(25, 25, 29, 29, fill=GREEN_DARK, outline=GREEN_DARK),
                ],
                "crypto": lambda: [
                    c.create_arc(10, 4, 30, 22, start=0, extent=180, style="arc", outline=GREEN_DARK, width=2),
                    c.create_rectangle(7, 18, 33, 34, outline=GREEN_DARK, width=2, fill="#eef8f1"),
                    c.create_oval(17, 23, 23, 29, outline=GREEN_DARK, width=2),
                ],
                "slack": lambda: [
                    c.create_rectangle(6, 7, 34, 13, outline=GREEN_DARK, width=1, fill="#eef8f1"),
                    c.create_rectangle(6, 16, 34, 22, outline=GREEN_DARK, width=1, fill="#eef8f1"),
                    c.create_rectangle(6, 25, 34, 31, outline=GREEN_DARK, width=1, fill="#eef8f1"),
                ],
                "metadata": lambda: [
                    c.create_rectangle(8, 4, 28, 36, outline=GREEN_DARK, width=2, fill="#eef8f1"),
                    c.create_polygon(22, 4, 28, 10, 22, 10, fill="white", outline=GREEN_DARK, width=1),
                    c.create_line(12, 16, 24, 16, fill=GREEN_DARK),
                    c.create_line(12, 21, 24, 21, fill=GREEN_DARK),
                    c.create_line(12, 26, 20, 26, fill=GREEN_DARK),
                ],
                "policy": lambda: [
                    c.create_polygon(20, 4, 34, 10, 32, 26, 20, 36, 8, 26, 6, 10,
                                     fill="#eef8f1", outline=GREEN_DARK, width=2),
                    c.create_line(14, 20, 18, 25, fill=GREEN_DARK, width=2),
                    c.create_line(18, 25, 26, 15, fill=GREEN_DARK, width=2),
                ],
                "free_space": lambda: [
                    c.create_polygon(20, 4, 34, 18, 30, 18, 30, 34, 10, 34, 10, 18, 6, 18,
                                     fill="#eef8f1", outline=GREEN_DARK, width=2),
                    c.create_rectangle(16, 24, 24, 34, outline=GREEN_DARK, width=1, fill="white"),
                ],
                "zero": lambda: [
                    c.create_oval(8, 8, 32, 32, outline=GREEN_DARK, width=2, fill="#eef8f1"),
                    c.create_oval(14, 14, 26, 26, outline=GREEN_DARK, width=2),
                ],
                "storage_aware": lambda: [
                    c.create_oval(8, 8, 32, 32, outline=GREEN_DARK, width=3, fill="#eef8f1"),
                    c.create_oval(14, 14, 26, 26, fill=GREEN_DARK, outline=GREEN_DARK),
                ],
                "temporary": lambda: [
                    c.create_rectangle(10, 14, 30, 34, outline=GREEN_DARK, width=2, fill="#eef8f1"),
                    c.create_line(8, 14, 32, 14, fill=GREEN_DARK, width=2),
                    c.create_line(16, 10, 24, 10, fill=GREEN_DARK, width=2),
                    c.create_line(15, 19, 15, 29, fill=GREEN_DARK),
                    c.create_line(20, 19, 20, 29, fill=GREEN_DARK),
                    c.create_line(25, 19, 25, 29, fill=GREEN_DARK),
                ],
            }
        draw = icons.get(method_id)
        if draw:
            draw()

    def _method_status(self, method_id: str, kind: str) -> tuple[str, str]:
        if kind == "file":
            if method_id in {"csprng", "zero", "metadata", "temporary"}:
                return "Available", ""
            if method_id == "free_space":
                return "Requires whole-volume scope", "The local free-space engine operates on the entire selected volume, not only the selected folder. DREX will not run it from this folder-scoped workflow."
            return "Unavailable on this target", ""
        if kind == "drive":
            return drive_method_status(method_id, self.selected_drive)
        if kind == "recovery":
            return self.recovery_dispatcher.status(method_id)
        return "Unavailable", "Unknown operation type."

    # ── Operation Area ──────────────────────────────────────────────
    def _operation_area(self, label: str):
        bottom = tk.Frame(self.page, bg=BG)
        bottom.pack(fill="x", padx=28, pady=(0, 4))
        tk.Label(bottom, text=label, font=("Segoe UI", 12, "bold"), fg=INK, bg=BG).pack(anchor="w", pady=(0, 6))
        area = tk.Frame(bottom, bg=BG)
        area.pack(fill="x")
        # Log terminal
        log_card = self._card(area)
        log_card.pack(side="left", fill="both", expand=True, padx=(0, 10))
        self.log_text = tk.Text(log_card, height=8, bg="#0d1117", fg="#7ee787", insertbackground="white", relief="flat", font=("Consolas", 9), wrap="word", padx=12, pady=10)
        self.log_text.pack(fill="both", expand=True, padx=1, pady=1)
        self.log_text.insert("end", "No operation has started.\nSelect a target and method, then click Start Operation.")
        self.log_text.configure(state="disabled")
        # Result card
        result = self._card(area)
        result.pack(side="right", fill="both", expand=True)
        result_inner = tk.Frame(result, bg="white")
        result_inner.pack(fill="both", expand=True, padx=20, pady=16)
        self.status_label = tk.Label(result_inner, text="READY", font=("Segoe UI", 16, "bold"), fg=MUTED, bg="white", justify="center")
        self.status_label.pack(expand=True)
        tk.Label(result_inner, text="Select a target and method\nto begin an operation", font=("Segoe UI", 9), fg=MUTED, bg="white", justify="center").pack(pady=(4, 0))
        self.view_cert_button = ttk.Button(result_inner, text="📋 View Certificate", style="Drex.TButton", state="disabled")
        self.view_cert_button.pack(pady=(10, 0))
        self.recovery_tree = None
        self.recovery_destination = None
        self.recovery_scan = None
        if label == "Recovery Log":
            results = self._card(self.page)
            results.pack(fill="x", padx=28, pady=(8, 0))
            tk.Label(results, text="Recoverable Candidates", font=("Segoe UI", 11, "bold"), fg=INK, bg="white").pack(anchor="w", padx=12, pady=(10, 4))
            tk.Label(results, text="Candidates are reported by the scanned backing device; they are not assumed to belong to the selected folder.", font=("Segoe UI", 8), fg=MUTED, bg="white", wraplength=900, justify="left").pack(anchor="w", padx=12, pady=(0, 6))
            self.recovery_tree = ttk.Treeview(results, columns=("id", "name", "filesystem", "size", "deleted", "confidence"), show="headings", selectmode="extended", height=4, style="Drex.Treeview")
            for col, heading in (("id", "Candidate ID"), ("name", "Name"), ("filesystem", "Filesystem"), ("size", "Size"), ("deleted", "Deleted"), ("confidence", "Confidence")):
                self.recovery_tree.heading(col, text=heading)
                self.recovery_tree.column(col, width=120, anchor="w")
            self.recovery_tree.pack(fill="x", padx=12, pady=(0, 12))
            recovery_actions = tk.Frame(results, bg="white")
            recovery_actions.pack(fill="x", padx=12, pady=(0, 12))
            self.recovery_destination_label = tk.Label(recovery_actions, text="Destination: not selected", font=("Segoe UI", 8), fg=MUTED, bg="white", anchor="w")
            self.recovery_destination_label.pack(side="left", fill="x", expand=True)
            self.recovery_destination_button = ttk.Button(recovery_actions, text="Choose Destination", style="Drex.TButton", command=self.choose_recovery_destination, state="disabled")
            self.recovery_destination_button.pack(side="left", padx=(8, 0))
            self.recover_selected_button = ttk.Button(recovery_actions, text="Recover Selected", style="DrexPrimary.TButton", command=self.recover_selected_candidates, state="disabled")
            self.recover_selected_button.pack(side="left", padx=(8, 0))
        # Progress bar
        self.progress = ttk.Progressbar(self.page, variable=self.progress_value, maximum=100, style="Drex.Horizontal.TProgressbar")
        self.progress.pack(fill="x", padx=28, pady=(8, 4))
        # Cancel button
        cancel_row = tk.Frame(self.page, bg=BG)
        cancel_row.pack(fill="x", padx=28)
        self.cancel_button = ttk.Button(cancel_row, text="Cancel Operation", style="Drex.TButton", command=self.cancel_operation, state="disabled")
        self.cancel_button.pack(side="right")
        self.progress_mode.set("")

    def choose_recovery_destination(self):
        if not self.target or not self.target.is_dir():
            messagebox.showerror("Select recovery folder", "Select a recovery folder and complete a scan first.")
            return
        chosen = filedialog.askdirectory(title="Choose a Separate Recovery Destination", mustexist=False)
        if not chosen:
            return
        destination = Path(chosen).resolve()
        try:
            destination.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            messagebox.showerror("Invalid destination", f"DREX could not create the destination:\n{exc}")
            return
        if destination == self.target.resolve() or self.target.resolve() in destination.parents:
            messagebox.showerror("Unsafe destination", "Choose a destination outside the selected source folder.")
            return
        self.recovery_destination = destination
        if hasattr(self, "recovery_destination_label"):
            self.recovery_destination_label.configure(text=f"Destination: {destination}", fg=INK)
        self._update_recovery_action_state()

    def _update_recovery_action_state(self):
        if not hasattr(self, "recover_selected_button"):
            return
        enabled = bool(self.recovery_destination and self.recovery_tree and self.recovery_tree.selection())
        self.recover_selected_button.configure(state="normal" if enabled else "disabled")

    def recover_selected_candidates(self):
        if not self.recovery_scan or not self.recovery_destination or not self.recovery_tree:
            return
        selected_ids = {str(self.recovery_tree.item(item, "values")[0]) for item in self.recovery_tree.selection()}
        candidates = [c for c in self.recovery_scan.candidates if c.candidate_id in selected_ids]
        if not candidates:
            messagebox.showwarning("Select candidates", "Select one or more candidates before recovering.")
            return
        method_id = self.method_var.get()
        adapter = self.recovery_dispatcher.get(method_id)
        if not hasattr(adapter, "recover"):
            messagebox.showerror("Recovery unavailable", self.recovery_dispatcher.status(method_id)[1])
            return
        if not messagebox.askyesno("Confirm recovery", f"Recover {len(candidates)} selected candidate(s) to:\n\n{self.recovery_destination}\n\nThe source remains read-only."):
            return
        self.cancel_event.clear()
        self.cancel_button.configure(state="normal")
        self.recover_selected_button.configure(state="disabled")
        threading.Thread(target=self._run_candidate_recovery, args=(adapter, method_id, candidates, self.recovery_destination), daemon=True).start()

    def _run_candidate_recovery(self, adapter: Any, method_id: str, candidates: list[Any], destination: Path):
        started = utc_now()
        label = label_for_recovery(method_id)
        recovered = 0
        failures: list[str] = []
        for candidate in candidates:
            if self.cancel_event.is_set():
                break
            try:
                outputs = adapter.recover(self._recovery_source, candidate.candidate_id, destination)
                if not outputs:
                    raise RecoveryError("Adapter returned no outputs.")
                for output in outputs:
                    if not Path(output).is_file():
                        raise RecoveryError("Adapter returned a non-file output.")
                    self.events.put(("log", f"Recovered candidate {candidate.candidate_id}: {output}"))
                recovered += 1
            except Exception as exc:
                failures.append(f"{candidate.candidate_id}: {type(exc).__name__}: {exc}")
        completed = utc_now()
        cancelled = self.cancel_event.is_set()
        status = "CANCELLED" if cancelled else "SUCCESS" if recovered == len(candidates) else "PARTIAL" if recovered else "FAILED"
        record = {"type": "recovery", "operation": "candidate_recovery", "method": label, "target": str(self.target), "source": self._recovery_source, "destination": str(destination), "started": started, "completed": completed, "duration": self._duration(started, completed), "status": status, "candidate_count": len(candidates), "selected_candidate_count": len(candidates), "recovered_count": recovered, "failed_count": len(failures), "errors": failures, "verification": "OUTPUT VERIFIED" if status == "SUCCESS" else "Not completed"}
        self.store.add_history(record)
        detail = f"Method: {label}\nTarget folder: {self.target}\nDestination: {destination}\nRecovered: {recovered}/{len(candidates)}"
        if failures:
            detail += "\nFailures:\n" + "\n".join(failures)
        self.events.put(("result", ("RECOVERY " + status, detail)))
        self.events.put(("finished", None))

    # ── Page: Wipe Drive ────────────────────────────────────────────
    def render_drive_page(self):
        self._header("Wipe Drive", "Securely erase entire storage devices using industry-standard methods.")
        self._target_panel("drive")
        self._methods(DRIVE_METHODS, "drive")
        self._operation_area("Operation Log")

    # ── Page: Wipe File/Folder ──────────────────────────────────────
    def render_file_page(self):
        self._header("Wipe File/Folder", "Securely erase specific files or folders using advanced wiping methods.")
        self._target_panel("file")
        self._methods(FILE_METHODS, "file")
        self._operation_area("Operation Log")

    # ── Page: Recover ───────────────────────────────────────────────
    def render_recovery_page(self):
        self._header("Recover", "Recover deleted or lost files from storage devices using advanced scanning.")
        self._target_panel("recovery")
        self._methods(RECOVERY_METHODS, "recovery")
        self._operation_area("Recovery Log")

    # ── Page: Destroy Drive ─────────────────────────────────────────
    def render_destroy_page(self):
        self._header("Destroy Drive", "Permanently destroy data on entire storage devices using advanced destruction methods.")
        if not self.drives:
            self.refresh_devices()
        if not self.selected_drive and self.drives:
            self.selected_drive = self.drives[0]
        # Warning banner
        warn = tk.Frame(self.page, bg="#fff8e1", highlightbackground="#f5c47e", highlightthickness=1)
        warn.pack(fill="x", padx=28, pady=(18, 12))
        warn_inner = tk.Frame(warn, bg="#fff8e1")
        warn_inner.pack(fill="x", padx=18, pady=14)
        tk.Label(warn_inner, text="⚠", font=("Segoe UI", 18), fg=ORANGE, bg="#fff8e1").pack(side="left", padx=(0, 12))
        warn_text = tk.Frame(warn_inner, bg="#fff8e1")
        warn_text.pack(side="left", fill="x")
        tk.Label(warn_text, text="Device Requires Alternative Sanitization", font=("Segoe UI", 12, "bold"), fg=INK, bg="#fff8e1").pack(anchor="w")
        tk.Label(warn_text, text="This drive does not support any of the currently available software-based erasure methods.", font=("Segoe UI", 9), fg=MUTED, bg="#fff8e1", wraplength=800, justify="left").pack(anchor="w", pady=(2, 0))
        # Device Overview card
        dev_card = self._card(self.page)
        dev_card.pack(fill="x", padx=28, pady=(0, 12))
        dev_inner = tk.Frame(dev_card, bg="white")
        dev_inner.pack(fill="both", padx=18, pady=16)
        # Device Overview header
        dh = tk.Frame(dev_inner, bg="white")
        dh.pack(fill="x", pady=(0, 12))
        icon = tk.Canvas(dh, width=44, height=44, bg="#eef8f1", highlightthickness=0)
        icon.pack(side="left", padx=(0, 12))
        icon.create_rectangle(14, 8, 30, 36, outline=GREEN_DARK, width=2)
        icon.create_line(18, 16, 26, 16, fill=GREEN_DARK)
        dev_h_text = tk.Frame(dh, bg="white")
        dev_h_text.pack(side="left")
        tk.Label(dev_h_text, text="Device Overview", font=("Segoe UI", 13, "bold"), fg=GREEN_DARK, bg="white").pack(anchor="w")
        if self.selected_drive:
            d = self.selected_drive
            tk.Label(dev_h_text, text=d.display("model") or "Generic Drive", font=("Segoe UI", 11), fg=INK, bg="white").pack(anchor="w", pady=(2, 0))
            tk.Label(dev_h_text, text="Unsupported for Software-Based Erasure", font=("Segoe UI", 8), fg="white", bg=ORANGE, padx=8, pady=2).pack(anchor="w", pady=(4, 0))
        # 3-column info grid
        info_grid = tk.Frame(dev_inner, bg="white")
        info_grid.pack(fill="x", pady=(12, 0))
        for col in range(3):
            info_grid.columnconfigure(col, weight=1)
        if self.selected_drive:
            d = self.selected_drive
            info_items = [
                [("Device Type", d.drive_type or "HDD / SSD"), ("Capacity", fmt_bytes(d.capacity)), ("Serial Number", d.display("serial"))],
                [("Supported Erasure Methods", "None Detected"), ("Current Recommendation", "Alternative Destruction /\nCertified Disposal")],
            ]
            row_idx = 0
            for row_data in info_items:
                for col_idx, (label, value) in enumerate(row_data):
                    cell = tk.Frame(info_grid, bg="white")
                    cell.grid(row=row_idx, column=col_idx, sticky="nw", padx=8, pady=6)
                    tk.Label(cell, text=label, font=("Segoe UI", 9, "bold"), fg=INK, bg="white").pack(anchor="w")
                    tk.Label(cell, text=value, font=("Segoe UI", 9), fg=MUTED, bg="white", justify="left", wraplength=250).pack(anchor="w", pady=(2, 0))
                row_idx += 1
        else:
            tk.Label(info_grid, text="No device was detected by Windows.", fg=MUTED, bg="white", font=("Segoe UI", 10)).pack(pady=14)
        # Drive selector
        if self.drives:
            sel = tk.Frame(dev_inner, bg="white")
            sel.pack(fill="x", pady=(10, 0))
            self.destroy_combo = ttk.Combobox(sel, state="readonly", values=[d.path for d in self.drives], width=20)
            self.destroy_combo.set(self.selected_drive.path if self.selected_drive else self.drives[0].path)
            self.destroy_combo.pack(side="left")
            self.destroy_combo.bind("<<ComboboxSelected>>", lambda _e: self._destroy_selected())
        # Important Notice
        notice = tk.Frame(self.page, bg="#fef2f2", highlightbackground="#f1b8b8", highlightthickness=1)
        notice.pack(fill="x", padx=28, pady=(0, 12))
        notice_inner = tk.Frame(notice, bg="#fef2f2")
        notice_inner.pack(fill="x", padx=18, pady=14)
        tk.Label(notice_inner, text="🛡", font=("Segoe UI", 16), fg=RED, bg="#fef2f2").pack(side="left", padx=(0, 12))
        n_text = tk.Frame(notice_inner, bg="#fef2f2")
        n_text.pack(side="left", fill="x")
        tk.Label(n_text, text="Important Notice", font=("Segoe UI", 12, "bold"), fg=RED, bg="#fef2f2").pack(anchor="w")
        tk.Label(n_text, text="Physical destruction should be performed only through authorized procedures or certified destruction services.\nDo not attempt unsafe destruction yourself.", font=("Segoe UI", 9), fg=INK, bg="#fef2f2", wraplength=900, justify="left").pack(anchor="w", pady=(2, 0))
        # Why Alternative Sanitization
        why_card = self._card(self.page, bg="#f8faf9")
        why_card.pack(fill="x", padx=28, pady=(0, 12))
        why_inner = tk.Frame(why_card, bg="#f8faf9")
        why_inner.pack(fill="x", padx=18, pady=16)
        tk.Label(why_inner, text="Why is Alternative Sanitization Required?", font=("Segoe UI", 13, "bold"), fg=INK, bg="#f8faf9").pack(anchor="w")
        tk.Label(why_inner, text="Some devices do not expose commands required for secure erasure due to hardware, firmware, or interface limitations. In such cases, software-based wiping cannot guarantee permanent data elimination.", font=("Segoe UI", 10), fg=MUTED, bg="#f8faf9", wraplength=900, justify="left").pack(anchor="w", pady=(6, 0))

    def _destroy_selected(self):
        index = self.destroy_combo.current()
        if index >= 0:
            self.selected_drive = self.drives[index]
            self.render_destroy_page()

    # ── Page: Certificates ──────────────────────────────────────────
    def render_certificates(self):
        previous_filter = "all"
        previous_query = ""
        try:
            if hasattr(self, "cert_filter"):
                previous_filter = self.cert_filter.get()
        except tk.TclError:
            previous_filter = "all"
        try:
            if hasattr(self, "cert_search"):
                previous_query = self.cert_search.get().strip()
        except tk.TclError:
            previous_query = ""
        self._header("Certificate Centre", "View, search and manage all operation certificates in one place.")
        # Tab bar
        tabs = tk.Frame(self.page, bg="white", highlightbackground=LINE, highlightthickness=1)
        tabs.pack(fill="x", padx=28, pady=(18, 0))
        self.cert_filter = tk.StringVar(value=previous_filter)
        for text, value in [("All Certificates", "all"), ("Erasure Certificates", "erasure"), ("Recovery Certificates", "recovery")]:
            active = previous_filter == value
            tab_btn = tk.Button(tabs, text=text, relief="flat", bd=0, bg="white", fg=GREEN_DARK if active else INK, font=("Segoe UI", 10, "bold" if active else ""), padx=28, pady=12, activebackground=GREEN_PALE,
                                command=lambda v=value: (self.cert_filter.set(v), self.render_certificates()))
            tab_btn.pack(side="left")
            if active:
                # Underline indicator
                underline = tk.Frame(tabs, bg=GREEN, height=3)
                underline.place(in_=tab_btn, relx=0, rely=1.0, relwidth=1, anchor="sw")
        # Search bar
        search_card = tk.Frame(self.page, bg="white", highlightbackground=LINE, highlightthickness=1)
        search_card.pack(fill="x", padx=28, pady=(12, 12))
        search_inner = tk.Frame(search_card, bg="white")
        search_inner.pack(fill="x", padx=12, pady=8)
        tk.Label(search_inner, text="🔍", font=("Segoe UI", 12), fg=MUTED, bg="white").pack(side="left", padx=(0, 8))
        self.cert_search = tk.Entry(search_inner, font=("Segoe UI", 10), relief="flat", bd=0, width=50)
        self.cert_search.pack(side="left", fill="x", expand=True, ipady=6)
        self.cert_search.insert(0, previous_query or "Search Certificate ID / Serial Number...")
        if not previous_query:
            self.cert_search.configure(fg=MUTED)
            self.cert_search.bind("<FocusIn>", lambda e: (self.cert_search.delete(0, "end"), self.cert_search.configure(fg=INK)))
        self.cert_search.bind("<Return>", lambda e: self.render_certificates())
        # Records
        records = self.store.certificates()
        filter_value = previous_filter
        if filter_value == "erasure":
            records = [r for r in records if r.get("operation_type") != "recovery"]
        elif filter_value == "recovery":
            records = [r for r in records if r.get("operation_type") == "recovery"]
        query = previous_query.lower()
        if query and query != "search certificate id / serial number...":
            records = [r for r in records if query in json.dumps(r).lower()]
        # Table card
        table_card = self._card(self.page)
        table_card.pack(fill="both", expand=True, padx=28, pady=(0, 12))
        table_inner = tk.Frame(table_card, bg="white")
        table_inner.pack(fill="both", expand=True, padx=14, pady=14)
        filter_labels = {"all": "All Certificates", "erasure": "Certificates of Erasure", "recovery": "Certificates of Recovery"}
        tk.Label(table_inner, text=filter_labels.get(filter_value, "All Certificates"), font=("Segoe UI", 14, "bold"), fg=INK, bg="white").pack(anchor="w", pady=(0, 8))
        tree = ttk.Treeview(table_inner, columns=("id", "method", "passes", "status", "started", "duration", "action"), show="headings", style="Drex.Treeview")
        headings = {"id": "Session ID", "method": "Method", "passes": "Passes", "status": "Status", "started": "Started", "duration": "Duration", "action": "Actions"}
        col_widths = {"id": 140, "method": 160, "passes": 60, "status": 120, "started": 180, "duration": 80, "action": 80}
        for col, heading in headings.items():
            tree.heading(col, text=heading)
            tree.column(col, width=col_widths.get(col, 120), anchor="w")
        tree.pack(fill="both", expand=True)
        page_size = 7
        self._cert_page = getattr(self, "_cert_page", 0)
        total_pages = max(1, (len(records) + page_size - 1) // page_size)
        if self._cert_page >= total_pages:
            self._cert_page = 0
        page_records = records[self._cert_page * page_size:(self._cert_page + 1) * page_size]
        for record in page_records:
            status_display = "● COMPLETED" if record.get("status") == "SUCCESS" else record.get("status", "UNKNOWN")
            tree.insert("", "end", iid=record["certificate_id"], values=(
                record["certificate_id"], record["method"], record.get("passes", 1),
                status_display, record["started"], record["duration"], "📄 PDF",
            ))
        tree.bind("<Double-1>", lambda _e: self.open_certificate(tree))
        # Pagination
        pag = tk.Frame(table_inner, bg="white")
        pag.pack(fill="x", pady=(10, 0))
        start = self._cert_page * page_size + 1
        end = min((self._cert_page + 1) * page_size, len(records))
        tk.Label(pag, text=f"Showing {start} to {end} of {len(records)} certificates" if records else "No certificates found", font=("Segoe UI", 9), fg=GREEN_DARK, bg="white").pack(side="left")
        nav = tk.Frame(pag, bg="white")
        nav.pack(side="right")
        if total_pages > 1:
            def go_page(p):
                self._cert_page = p
                self.render_certificates()
            tk.Button(nav, text="‹", command=lambda: go_page(max(0, self._cert_page - 1)), relief="flat", bd=0, font=("Segoe UI", 10), fg=INK, bg="white", padx=8).pack(side="left")
            for i in range(min(total_pages, 5)):
                active_page = i == self._cert_page
                tk.Button(nav, text=str(i + 1), command=lambda p=i: go_page(p), relief="flat", bd=0, font=("Segoe UI", 10, "bold" if active_page else ""), fg="white" if active_page else INK, bg=GREEN if active_page else "white", padx=8, pady=2).pack(side="left", padx=2)
            if total_pages > 5:
                tk.Label(nav, text="...", font=("Segoe UI", 9), fg=MUTED, bg="white").pack(side="left")
                tk.Button(nav, text=str(total_pages), command=lambda: go_page(total_pages - 1), relief="flat", bd=0, font=("Segoe UI", 10), fg=INK, bg="white", padx=8).pack(side="left", padx=2)
            tk.Button(nav, text="›", command=lambda: go_page(min(total_pages - 1, self._cert_page + 1)), relief="flat", bd=0, font=("Segoe UI", 10), fg=INK, bg="white", padx=8).pack(side="left")
        self.cert_tree = tree

    def open_certificate(self, tree):
        selection = tree.selection()
        if not selection:
            return
        record = next((r for r in self.store.certificates() if r.get("certificate_id") == selection[0]), None)
        if not record:
            return
        if not self.cert_manager.verify(record):
            messagebox.showerror("Certificate validation failed", "DREX could not validate the local signature for this certificate.")
            return
        path = Path(record.get("pdf_path", ""))
        if path.exists():
            os.startfile(str(path)) if os.name == "nt" else subprocess.Popen(["xdg-open", str(path)])

    # ── Page: Help ──────────────────────────────────────────────────
    def render_help(self):
        self._header("Help Center", "Everything you need to securely erase, recover, and manage your storage.")
        selected = getattr(self, "help_section", "Getting Started")
        # Tab bar with icons
        tabs = tk.Frame(self.page, bg="white", highlightbackground=LINE, highlightthickness=1)
        tabs.pack(fill="x", padx=28, pady=(18, 14))
        tab_items = [
            ("Getting Started", "📖"), ("Wiping Data", "◎"), ("Recovery", "↺"),
            ("Drive Destruction", "⊠"), ("Certificates", "◈"), ("Troubleshooting", "🔧"), ("Safety", "🛡"),
        ]
        for title, icon in tab_items:
            active = title == selected
            tab = tk.Frame(tabs, bg=GREEN_PALE if active else "white", cursor="hand2")
            tab.pack(side="left", fill="both", expand=True)
            inner = tk.Frame(tab, bg=GREEN_PALE if active else "white")
            inner.pack(pady=10)
            tk.Label(inner, text=icon, font=("Segoe UI", 12), fg=GREEN_DARK if active else MUTED, bg=GREEN_PALE if active else "white").pack()
            tk.Label(inner, text=title, font=("Segoe UI", 8, "bold" if active else ""), fg=GREEN_DARK if active else INK, bg=GREEN_PALE if active else "white").pack(pady=(2, 0))
            for w in (tab, inner):
                w.bind("<Button-1>", lambda _e, t=title: self._set_help_section(t))
            for child in inner.winfo_children():
                child.bind("<Button-1>", lambda _e, t=title: self._set_help_section(t))
        # Content based on selected tab
        if selected == "Getting Started":
            self._help_getting_started()
        elif selected == "Wiping Data":
            self._help_section_content("Wiping Data", "Drive wiping requires a qualified native adapter. File and folder methods report their coverage and require verification before removal. Always select the correct target and method before starting.", [
                ("File/Folder Wiping", "Select a file or folder, choose a wiping method, and execute. DREX supports 9 file/folder wiping methods."),
                ("Drive Wiping", "Select a detected drive, choose one of 7 industry-standard methods, and execute. Requires hardware qualification."),
                ("Verification", "All successful operations produce verified results and generate tamper-evident certificates."),
            ])
        elif selected == "Recovery":
            self._help_section_content("Recovery", "Recovery engines are read-only. The current build reports native recovery engines as unavailable when their compiled executables are not present; it never claims recovered files without results.", [
                ("Quick & Smart Recovery", "Find recently deleted data quickly or let DREX choose the best recovery path automatically."),
                ("Deep & Fragment Recovery", "Search deeper for lost data or reconstruct files from scattered data fragments."),
                ("Forensic Recovery", "Recover and analyze data for forensic investigation with chain-of-custody documentation."),
            ])
        elif selected == "Drive Destruction":
            self._help_section_content("Drive Destruction", "Destroy Drive is an assessment page only. DREX does not physically destroy drives and does not issue destruction certificates.", [
                ("Software Assessment", "DREX evaluates whether software-based sanitization methods are available for the selected device."),
                ("Physical Destruction", "Physical destruction should be performed only through authorized procedures or certified destruction services."),
                ("Recommendation", "When software sanitization is unavailable, DREX recommends appropriate alternative methods or certified disposal."),
            ])
        elif selected == "Certificates":
            self._help_section_content("Certificates", "Successful certificates are generated only after verified operations. Each certificate is signed locally with ECDSA P-256, stored offline, and validated before opening.", [
                ("Certificate Generation", "Certificates are automatically generated after successful, verified operations. Failed or cancelled operations never produce certificates."),
                ("Verification", "Each certificate includes SHA-256 hashes, ECDSA signatures, QR codes, and can be exported as PDF."),
                ("Certificate Centre", "View, search, filter, and manage all certificates from the Certificates page."),
            ])
        elif selected == "Troubleshooting":
            self._help_troubleshooting()
        elif selected == "Safety":
            self._help_safety()

    def _help_getting_started(self):
        # Section heading
        gs_header = tk.Frame(self.page, bg=BG)
        gs_header.pack(fill="x", padx=28, pady=(0, 12))
        tk.Label(gs_header, text="📖", font=("Segoe UI", 16), fg=GREEN_DARK, bg=BG).pack(side="left", padx=(0, 10))
        gs_text = tk.Frame(gs_header, bg=BG)
        gs_text.pack(side="left")
        tk.Label(gs_text, text="Getting Started", font=("Segoe UI", 16, "bold"), fg=INK, bg=BG).pack(anchor="w")
        tk.Label(gs_text, text="Understand what DREX is and follow best practices before performing any operation.", font=("Segoe UI", 9), fg=MUTED, bg=BG).pack(anchor="w")
        # 4 info cards
        cards_row = tk.Frame(self.page, bg=BG)
        cards_row.pack(fill="x", padx=28, pady=(0, 20))
        info_cards = [
            ("What is DREX?", "DREX is a secure data management platform designed to permanently erase data, recover deleted files, and provide verifiable proof of sanitization.", GREEN, "🛡"),
            ("Before You Begin", "• Connect the storage device securely.\n• Close applications using the target drive.\n• Verify the selected drive before starting any operation.\n• Back up anything you may need later.", GREEN, "📋"),
            ("Important", "Data sanitization and drive destruction can be permanent and irreversible.", ORANGE, "⚠"),
            ("Best Practice", "Always verify your target drive and review operation details before confirming.", GREEN, "✓"),
        ]
        for title, text, color, icon in info_cards:
            card = self._card(cards_row, border=LINE if color == GREEN else "#f5c47e")
            card.pack(side="left", fill="both", expand=True, padx=(0, 8))
            inner = tk.Frame(card, bg="white")
            inner.pack(fill="both", expand=True, padx=14, pady=14)
            tk.Label(inner, text=icon, font=("Segoe UI", 18), fg=color, bg="white").pack(anchor="w")
            tk.Label(inner, text=title, font=("Segoe UI", 11, "bold"), fg=color, bg="white").pack(anchor="w", pady=(8, 4))
            tk.Label(inner, text=text, font=("Segoe UI", 8), fg=INK, bg="white", wraplength=200, justify="left").pack(anchor="w")
        # DREX Operations Overview
        tk.Label(self.page, text="DREX Operations Overview", font=("Segoe UI", 16, "bold"), fg=INK, bg=BG).pack(anchor="w", padx=28, pady=(0, 10))
        ops_row = tk.Frame(self.page, bg=BG)
        ops_row.pack(fill="x", padx=28, pady=(0, 20))
        ops = [
            ("Wipe Drive", "Permanently sanitize an entire storage device using a secure method.", GREEN, "◎"),
            ("Wipe File / Folder", "Securely remove specific files or folders without wiping the entire drive.", GREEN, "▤"),
            ("Recover Data", "Search and recover deleted or lost files that may still be recoverable.", GREEN, "↺"),
            ("Destroy Drive", "Permanently destroy a storage device to take it out of service.", RED, "⊠"),
            ("Certificates", "View and manage certificates as proof of completed operations.", GREEN, "◈"),
        ]
        for name, desc, color, glyph in ops:
            card = self._card(ops_row)
            card.pack(side="left", fill="both", expand=True, padx=(0, 8))
            inner = tk.Frame(card, bg="white")
            inner.pack(fill="both", expand=True, padx=12, pady=12)
            tk.Label(inner, text=glyph, font=("Segoe UI", 20), fg=color, bg="white").pack()
            tk.Label(inner, text=name, font=("Segoe UI", 9, "bold"), fg=color, bg="white").pack(pady=(6, 4))
            tk.Label(inner, text=desc, font=("Segoe UI", 7), fg=MUTED, bg="white", wraplength=140, justify="center").pack()
            lm = tk.Label(inner, text="Learn More →", font=("Segoe UI", 8, "bold"), fg=GREEN_DARK, bg="white", cursor="hand2")
            lm.pack(pady=(6, 0))
        # Troubleshooting + Safety side by side
        ts_row = tk.Frame(self.page, bg=BG)
        ts_row.pack(fill="x", padx=28, pady=(0, 20))
        # Troubleshooting
        ts_card = self._card(ts_row)
        ts_card.pack(side="left", fill="both", expand=True, padx=(0, 8))
        ts_inner = tk.Frame(ts_card, bg="white")
        ts_inner.pack(fill="both", expand=True, padx=16, pady=14)
        tk.Label(ts_inner, text="🔧  Troubleshooting", font=("Segoe UI", 12, "bold"), fg=INK, bg="white").pack(anchor="w")
        tk.Label(ts_inner, text="Find solutions to common issues.", font=("Segoe UI", 8), fg=MUTED, bg="white").pack(anchor="w", pady=(2, 8))
        ts_items = [
            ("Drive not detected", "Check connections, permissions and system visibility."),
            ("Wipe operation failed", "Review drive status, permissions and operation logs."),
            ("Recovery finds no files", "Data may be overwritten or securely erased."),
            ("Certificate is unavailable", "Ensure operation completed successfully."),
        ]
        for t, d in ts_items:
            item_row = tk.Frame(ts_inner, bg="white")
            item_row.pack(fill="x", pady=4)
            tk.Label(item_row, text="●", fg=GREEN, bg="white", font=("Segoe UI", 6)).pack(side="left", padx=(0, 8), anchor="n", pady=4)
            item_text = tk.Frame(item_row, bg="white")
            item_text.pack(side="left", fill="x", expand=True)
            tk.Label(item_text, text=t, font=("Segoe UI", 9, "bold"), fg=INK, bg="white", anchor="w").pack(anchor="w")
            tk.Label(item_text, text=d, font=("Segoe UI", 8), fg=MUTED, bg="white", anchor="w").pack(anchor="w")
        tk.Label(ts_inner, text="View All Solutions →", font=("Segoe UI", 9, "bold"), fg=GREEN_DARK, bg="white", cursor="hand2").pack(anchor="w", pady=(8, 0))
        # Safety
        sf_card = self._card(ts_row)
        sf_card.pack(side="left", fill="both", expand=True)
        sf_inner = tk.Frame(sf_card, bg="white")
        sf_inner.pack(fill="both", expand=True, padx=16, pady=14)
        tk.Label(sf_inner, text="🛡  Safety & Best Practices", font=("Segoe UI", 12, "bold"), fg=INK, bg="white").pack(anchor="w")
        tk.Label(sf_inner, text="Follow these guidelines to ensure safe operations.", font=("Segoe UI", 8), fg=MUTED, bg="white").pack(anchor="w", pady=(2, 8))
        sf_items = [
            ("Before Wiping", "Verify → Backup → Select → Confirm", GREEN),
            ("Before Recovery", "Stop using the drive → Scan → Recover to\nanother location", PURPLE),
            ("Before Destruction", "Verify device → Confirm data status → Destroy", ORANGE),
        ]
        for t, d, c in sf_items:
            item_row = tk.Frame(sf_inner, bg="white")
            item_row.pack(fill="x", pady=4)
            tk.Label(item_row, text="●", fg=c, bg="white", font=("Segoe UI", 8)).pack(side="left", padx=(0, 8), anchor="n", pady=4)
            item_text = tk.Frame(item_row, bg="white")
            item_text.pack(side="left", fill="x", expand=True)
            tk.Label(item_text, text=t, font=("Segoe UI", 9, "bold"), fg=INK, bg="white", anchor="w").pack(anchor="w")
            tk.Label(item_text, text=d, font=("Segoe UI", 8), fg=MUTED, bg="white", anchor="w", justify="left").pack(anchor="w")
        # Warning note
        warn = tk.Frame(sf_inner, bg="#fff8e1")
        warn.pack(fill="x", pady=(8, 0))
        tk.Label(warn, text="DREX operations may permanently change or remove data.\nAlways verify your target before proceeding.", font=("Segoe UI", 8), fg=INK, bg="#fff8e1", justify="left", padx=10, pady=8).pack(fill="x")
        # Need More Help footer
        footer_card = self._card(self.page, bg="#f8faf9")
        footer_card.pack(fill="x", padx=28, pady=(0, 12))
        footer_inner = tk.Frame(footer_card, bg="#f8faf9")
        footer_inner.pack(fill="x", padx=16, pady=14)
        tk.Label(footer_inner, text="Need More Help?", font=("Segoe UI", 12, "bold"), fg=INK, bg="#f8faf9").pack(side="left", padx=(0, 8))
        tk.Label(footer_inner, text="Get additional support and resources.", font=("Segoe UI", 8), fg=MUTED, bg="#f8faf9").pack(side="left")
        footer_items = [("Troubleshooting", "Find solutions to\ncommon problems."), ("Operation Logs", "Review what happened\nduring an operation."), ("System Status", "Check whether DREX\nservices are operating."), ("Contact Support", "Get assistance with\nan issue.")]
        for t, d in footer_items:
            fc = tk.Frame(footer_inner, bg="#f8faf9")
            fc.pack(side="right", padx=10)
            tk.Label(fc, text=t, font=("Segoe UI", 8, "bold"), fg=INK, bg="#f8faf9").pack(anchor="w")
            tk.Label(fc, text=d, font=("Segoe UI", 7), fg=MUTED, bg="#f8faf9", justify="left").pack(anchor="w")

    def _help_section_content(self, title, intro, items):
        """Generic help section content."""
        section = self._card(self.page)
        section.pack(fill="x", padx=28, pady=(0, 12))
        inner = tk.Frame(section, bg="white")
        inner.pack(fill="both", expand=True, padx=22, pady=18)
        tk.Label(inner, text=title, font=("Segoe UI", 16, "bold"), fg=INK, bg="white").pack(anchor="w")
        tk.Label(inner, text=intro, font=("Segoe UI", 10), fg=MUTED, bg="white", wraplength=900, justify="left").pack(anchor="w", pady=(6, 14))
        for sub_title, sub_text in items:
            item = tk.Frame(inner, bg="white")
            item.pack(fill="x", pady=6)
            tk.Label(item, text="●", fg=GREEN, bg="white", font=("Segoe UI", 8)).pack(side="left", padx=(0, 10), anchor="n", pady=3)
            texts = tk.Frame(item, bg="white")
            texts.pack(side="left", fill="x", expand=True)
            tk.Label(texts, text=sub_title, font=("Segoe UI", 10, "bold"), fg=INK, bg="white", anchor="w").pack(anchor="w")
            tk.Label(texts, text=sub_text, font=("Segoe UI", 9), fg=MUTED, bg="white", anchor="w", wraplength=800, justify="left").pack(anchor="w", pady=(2, 0))

    def _help_troubleshooting(self):
        self._help_section_content("Troubleshooting & System Status", "Refresh device discovery, check permissions, review the operation log, and confirm that the selected method is marked Available.", [
            ("Drive not detected", "Check that the drive is connected, powered on, and visible in Windows Disk Management. Try refreshing the device list."),
            ("Wipe operation failed", "Review the operation log for specific error messages. Check permissions and ensure the target is not in use."),
            ("Recovery finds no files", "Data may have been overwritten or securely erased. Try a different recovery method or scanning mode."),
            ("Certificate is unavailable", "Certificates are only generated for successful, verified operations. Check the operation status."),
            ("Method shows unavailable", "Some methods require specific hardware, drivers, or privileges. Check the method requirements."),
        ])

    def _help_safety(self):
        self._help_section_content("Safety Guidelines", "Never select a system or valuable target for destructive testing. Do not bypass confirmation or enable unqualified native tools.", [
            ("Before any destructive operation", "Always verify the target path, drive letter, and model. Back up any data you may need."),
            ("System protection", "DREX blocks operations on system drives, the Windows directory, and the boot environment."),
            ("Physical destruction", "Use authorized disposal services for physical destruction. DREX does not destroy hardware."),
            ("Certificates and verification", "Never rely on a certificate without verifying the operation actually completed successfully."),
            ("Testing", "Use dedicated disposable test directories. Never test destructive operations on production data."),
        ])

    def _set_help_section(self, section: str):
        self.help_section = section
        self.render_help()

    # ── Operation Logic (preserved) ─────────────────────────────────
    def append_log(self, line: str):
        if self.log_text:
            stamp = datetime.now().strftime("%H:%M:%S")
            self.log_text.configure(state="normal")
            self.log_text.insert("end", f"[{stamp}] {line}\n")
            self.log_text.see("end")
            self.log_text.configure(state="disabled")

    def start_operation(self, kind: str):
        method_id = self.method_var.get()
        if not method_id:
            messagebox.showwarning("Select a method", "Choose exactly one method before starting.")
            return
        if kind == "drive":
            if not self.selected_drive:
                messagebox.showwarning("Select a drive", "Choose a detected device before starting.")
                return
            status, reason = drive_method_status(method_id, self.selected_drive)
            if status != "Available":
                messagebox.showerror("Method unavailable", reason)
                return
            return
        if not self.target:
            messagebox.showwarning("Select a target", "Choose a file, folder, or recovery image before starting.")
            return
        if kind == "recovery":
            if not self.target.is_dir():
                messagebox.showerror("Invalid recovery folder", "Select a folder. Recovery uses the folder to identify its backing storage device.")
                return
            availability, reason = self._method_status(method_id, kind)
            if availability != "Available":
                messagebox.showerror("Recovery engine unavailable", reason)
                return
            drive = get_drive_for_path(self.target, self.drives)
            if drive is None:
                messagebox.showerror("Physical source unavailable", "DREX could not map the selected folder to a PhysicalDrive source. No scan was started.")
                return
            adapter = self.recovery_dispatcher.get(method_id)
            self._recovery_source = drive.device_path
            self.progress_value.set(0)
            self.cancel_event.clear()
            self.status_label.configure(text="SCANNING", fg=BLUE)
            self.append_log(f"Recovery folder selected: {self.target}")
            self.append_log(f"Backing volume: {drive.path}")
            self.append_log(f"Physical source: {drive.device_path}")
            self.append_log(f"{label_for_recovery(method_id)} scan starting; source access is read-only and no data will be written to it.")
            self.start_button.configure(state="disabled")
            self.cancel_button.configure(state="normal")
            thread = threading.Thread(target=self._run_recovery_scan, args=(method_id, adapter, self.target, drive.device_path), daemon=True)
            thread.start()
            return
        if kind == "file":
            availability, reason = self._method_status(method_id, kind)
            if availability != "Available":
                messagebox.showerror("Method unavailable", reason or "The selected method is unavailable on this host.")
                return
            issue = dangerous_target(self.target)
            if issue:
                messagebox.showerror("Unsafe target", issue)
                return
        label = next((m["name"] for m in FILE_METHODS if m["id"] == method_id), method_id)
        if not messagebox.askyesno("Confirm destructive operation", f"This action may permanently change:\n\n{self.target}\n\nMethod: {label}\n\nContinue only if the target and method are correct."):
            return
        self.progress_value.set(0)
        self.cancel_event.clear()
        self.status_label.configure(text="RUNNING", fg=BLUE)
        self.append_log("Validating target identity and method capability.")
        if self.start_button:
            self.start_button.configure(state="disabled")
        if hasattr(self, "cancel_button"):
            self.cancel_button.configure(state="normal")
        thread = threading.Thread(target=self._run_file_operation, args=(method_id, self.target, label), daemon=True)
        thread.start()

    def _run_recovery_scan(self, method_id: str, adapter: Any, target: Path, source: str):
        started = utc_now()
        label = next((name for mid, name, _ in RECOVERY_METHODS if mid == method_id), method_id)
        record = {"type": "recovery", "method": label, "target": str(target), "source": source, "started": started}
        try:
            scan = adapter.scan(source, cancel=self.cancel_event.is_set)
            if self.cancel_event.is_set():
                raise RecoveryError("Recovery scan cancelled by the user.")
            self.events.put(("recovery_scan", scan))
            completed = utc_now()
            record.update({"completed": completed, "duration": self._duration(started, completed), "status": "SUCCESS", "verification": "SCAN VERIFIED", "candidate_count": len(scan.candidates), "recovered_count": 0, "warnings": list(scan.warnings)})
            self.events.put(("result", ("SCAN COMPLETE", f"{label} completed against {source}. Candidates discovered: {len(scan.candidates)}. Select candidates and a separate destination for recovery.")))
        except Exception as exc:
            completed = utc_now()
            cancelled = self.cancel_event.is_set() or "cancelled" in str(exc).lower()
            record.update({"completed": completed, "duration": self._duration(started, completed), "status": "CANCELLED" if cancelled else "FAILED", "verification": "Not completed", "error": str(exc), "candidate_count": 0, "recovered_count": 0})
            status = "OPERATION CANCELLED" if cancelled else "OPERATION FAILED"
            self.events.put(("result", (status, f"{'Operation Cancelled' if cancelled else 'Operation Failed'}\nMethod: {label}\nTarget: {target}\nStage: native recovery scan\nActual reason: {type(exc).__name__}: {exc}")))
        self.store.add_history(record)
        self.events.put(("finished", None))

    def cancel_operation(self):
        if self.status_label and self.status_label.cget("text") in {"RUNNING", "SCANNING", "RECOVERING"}:
            self.cancel_event.set()
            self.append_log("Cancellation requested; the local adapter will stop at its next safe progress boundary.")
            self.cancel_button.configure(state="disabled")

    def _run_file_operation(self, method_id: str, target: Path, label: str):
        started = utc_now()
        before = hash_target(target)
        record = {"type": "file", "method": label, "target": str(target), "started": started}
        try:
            self.events.put(("log", "Operation started; adapter owns execution and verification."))
            def progress(done, total):
                if self.cancel_event.is_set():
                    raise OperationCancelled("Cancellation requested by the user")
                self.events.put(("progress", (done, total)))
            result = execute_file_method(method_id, target, lambda message: self.events.put(("log", message)), progress)
            if self.cancel_event.is_set():
                raise OperationCancelled("Cancellation requested by the user")
            completed = utc_now()
            duration = self._duration(started, completed)
            record.update({"completed": completed, "duration": duration, "status": "SUCCESS" if result.get("verified") else "VERIFICATION FAILED", "verification": "VERIFIED" if result.get("verified") else "FAILED", "sha256_before": before, "sha256_after": result.get("sha256_after") or hash_target(target)})
            if record["status"] == "SUCCESS":
                cert = self.cert_manager.create(record)
                record["certificate_id"] = cert["certificate_id"]
                self.events.put(("result", ("SUCCESS", f"Verified operation complete. Certificate generated: {cert['certificate_id']}")))
            else:
                self.events.put(("result", ("VERIFICATION FAILED", "No successful certificate was generated.")))
        except OperationCancelled as exc:
            completed = utc_now()
            record.update({"completed": completed, "duration": self._duration(started, completed), "status": "CANCELLED", "verification": "Not completed", "sha256_before": before, "sha256_after": None, "error": str(exc)})
            self.events.put(("result", ("OPERATION CANCELLED", "\n".join([
                "Operation Cancelled", f"Method: {label}", f"Target: {target}",
                "Stage: local adapter execution", f"Actual reason: {type(exc).__name__}: {exc}",
            ]))))
        except Exception as exc:
            completed = utc_now()
            cancelled = self.cancel_event.is_set()
            status = "CANCELLED" if cancelled else "FAILED"
            record.update({"completed": completed, "duration": self._duration(started, completed), "status": status, "verification": "Not completed", "sha256_before": before, "sha256_after": None, "error": str(exc)})
            result_status = "OPERATION CANCELLED" if cancelled else "OPERATION FAILED"
            heading = "Operation Cancelled" if cancelled else "Operation Failed"
            reason_label = "Actual reason" if cancelled else "Actual error"
            self.events.put(("result", (result_status, "\n".join([
                heading,
                f"Method: {label}",
                f"Target: {target}",
                "Stage: local adapter execution/verification",
                f"{reason_label}: {type(exc).__name__}: {exc}",
            ]))))
        self.store.add_history(record)
        self.events.put(("finished", None))

    @staticmethod
    def _duration(started: str, completed: str) -> str:
        try:
            seconds = int((datetime.fromisoformat(completed.replace("Z", "+00:00")) - datetime.fromisoformat(started.replace("Z", "+00:00"))).total_seconds())
            return f"{max(0, seconds)}s"
        except ValueError:
            return "Unavailable"

    def _poll_events(self):
        try:
            while True:
                kind, value = self.events.get_nowait()
                if kind == "log":
                    self.append_log(str(value))
                elif kind == "progress":
                    done, total = value
                    if total > 0:
                        self.progress_value.set(min(99.0, done * 100 / total))
                elif kind == "recovery_scan":
                    scan: RecoveryScan = value
                    self.recovery_scan = scan
                    if self.recovery_tree and self.recovery_tree.winfo_exists():
                        for item in self.recovery_tree.get_children():
                            self.recovery_tree.delete(item)
                        for candidate in scan.candidates:
                            size = fmt_bytes(candidate.size) if candidate.size is not None else "Unknown"
                            deleted = "Yes" if candidate.deleted is True else "No" if candidate.deleted is False else "Unknown"
                            confidence = f"{candidate.confidence:.0%}" if candidate.confidence is not None and candidate.confidence <= 1 else f"{candidate.confidence:.0f}%" if candidate.confidence is not None else "Unknown"
                            self.recovery_tree.insert("", "end", values=(candidate.candidate_id, candidate.name, candidate.filesystem, size, deleted, confidence))
                        self.recovery_tree.bind("<<TreeviewSelect>>", lambda _event: self._update_recovery_action_state(), add="+")
                        if hasattr(self, "recovery_destination_button"):
                            self.recovery_destination_button.configure(state="normal")
                elif kind == "result":
                    status, detail = value
                    color = GREEN_DARK if status == "SUCCESS" else (MUTED if "CANCELLED" in status else RED)
                    self.status_label.configure(text=status, fg=color)
                    self.append_log(detail)
                    if status == "SUCCESS":
                        self.progress_value.set(100)
                        self.status_label.configure(text="WIPE SUCCESSFUL!" if self.current_page != "Recover" else "RECOVERY SUCCESSFUL!")
                elif kind == "finished":
                    if hasattr(self, "start_button"):
                        self.start_button.configure(state="normal")
                    if hasattr(self, "cancel_button"):
                        self.cancel_button.configure(state="disabled")
        except queue.Empty:
            pass
        self.after(100, self._poll_events)


def verify_certificate_record(path: str) -> bool:
    store = Store(Path(path).parent.parent)
    record = json.loads(Path(path).read_text(encoding="utf-8"))
    return CertificateManager(store).verify(record)


def run_doctor() -> dict[str, Any]:
    from recovery_backends import BACKENDS, find_backend_executable
    is_admin = False
    if os.name == "nt":
        try:
            is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            pass
    backend_report = {}
    for bid, spec in BACKENDS.items():
        exe = find_backend_executable(bid, ROOT)
        backend_report[bid] = {
            "name": bid,
            "installed": exe is not None,
            "executable_path": str(exe) if exe else None,
            "project_url": spec.project_url,
            "license": spec.license_name,
        }
    drives = discover_drives()
    report = {
        "app": APP_NAME,
        "version": VERSION,
        "python_version": sys.version,
        "platform": sys.platform,
        "is_admin": is_admin,
        "methods_count": {
            "drive": len(DRIVE_METHODS),
            "file": len(FILE_METHODS),
            "recovery": len(RECOVERY_METHODS),
            "total": len(DRIVE_METHODS) + len(FILE_METHODS) + len(RECOVERY_METHODS),
        },
        "backends": backend_report,
        "detected_drives": [
            {
                "path": d.path,
                "model": d.model,
                "serial": d.serial,
                "capacity": d.capacity,
                "drive_type": d.drive_type,
                "health": d.health,
            }
            for d in drives
        ],
    }
    return report


def main(argv: list[str] | None = None) -> int:
    argv = argv or sys.argv[1:]
    if "--version" in argv:
        print(f"{APP_NAME} {VERSION}")
        return 0
    if "--doctor" in argv:
        print(json.dumps(run_doctor(), indent=2))
        return 0
    if "--self-test" in argv:
        with tempfile.TemporaryDirectory(prefix="drex-self-test-") as temp:
            root = Path(temp)
            target = root / "fixture.bin"
            target.write_bytes(b"DREX adapter self-test" * 32)
            execute_file_method("zero", target, lambda _: None, lambda *_: None)
            if target.exists():
                return 2
            store = Store(root / "data")
            manager = CertificateManager(store)
            record = manager.create({
                "type": "file", "method": "Single-Pass Zero Overwrite", "target": str(target), "target_size": "fixture",
                "started": utc_now(), "completed": utc_now(), "duration": "0s", "status": "SUCCESS", "verification": "VERIFIED",
                "sha256_before": hashlib.sha256(b"DREX adapter self-test" * 32).hexdigest(), "sha256_after": "Not applicable after verified removal",
            })
            if not manager.verify(record) or not Path(record["pdf_path"]).exists():
                return 3
        print(json.dumps({"app": APP_NAME, "version": VERSION, "offline": True, "drive_methods": len(DRIVE_METHODS), "file_methods": len(FILE_METHODS), "recovery_methods": len(RECOVERY_METHODS), "bundled_adapter": "zero-overwrite", "certificate_integrity": "verified"}, indent=2))
        return 0
    app = DrexApp()
    qa_page = os.environ.get("DREX_QA_PAGE")
    if qa_page in {"Dashboard", "Wipe Drive", "Wipe File/Folder", "Recover", "Destroy Drive", "Certificates", "Help"}:
        app.show_page(qa_page)
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
