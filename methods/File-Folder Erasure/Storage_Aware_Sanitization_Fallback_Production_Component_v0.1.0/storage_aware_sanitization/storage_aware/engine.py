from __future__ import annotations
from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib, json, os, shutil, subprocess, time


class PolicyError(RuntimeError):
    pass


def _utc_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@dataclass(frozen=True)
class DeviceProfile:
    path: str
    transport: str
    media: str
    encrypted: bool
    crypto_erase: bool
    block_erase: bool
    overwrite_sanitize: bool
    ata_secure_erase: bool
    scsi_sanitize: bool
    vendor_sanitize: bool
    removable: bool = False
    device_size_bytes: int | None = None
    identity: str | None = None

    @classmethod
    def from_dict(cls, d):
        return cls(**d)

    def to_dict(self):
        return asdict(self)


@dataclass(frozen=True)
class SanitizationPlan:
    method: str
    assurance: str
    target: str
    command: tuple[str, ...] | None
    rationale: str
    fallback_chain: tuple[str, ...]
    requires_privilege: bool
    destructive: bool
    status: str = "READY"

    def to_dict(self):
        return asdict(self)


def _has(cmd):
    return shutil.which(cmd) is not None


def choose_plan(profile: DeviceProfile, *, approved_logical_fallback=False):
    t = profile.transport.lower()
    m = profile.media.lower()

    if profile.crypto_erase and t == "nvme":
        return SanitizationPlan(
            "NVMe Sanitize — Crypto Erase", "PURGE", profile.path,
            ("nvme", "sanitize", profile.path, "--sanact=start-crypto-erase", "--wait"),
            "Controller-native NVMe crypto erase is available.",
            ("NVMe Sanitize — Block Erase", "NVMe Sanitize — Overwrite", "REFUSE"),
            True, True,
        )

    if profile.block_erase and t == "nvme":
        return SanitizationPlan(
            "NVMe Sanitize — Block Erase", "PURGE", profile.path,
            ("nvme", "sanitize", profile.path, "--sanact=start-block-erase", "--wait"),
            "Controller-native NVMe block erase is available.",
            ("NVMe Sanitize — Overwrite", "REFUSE"),
            True, True,
        )

    if profile.overwrite_sanitize and t == "nvme":
        return SanitizationPlan(
            "NVMe Sanitize — Overwrite", "PURGE", profile.path,
            ("nvme", "sanitize", profile.path, "--sanact=start-overwrite", "--wait"),
            "Controller-native NVMe overwrite sanitize is available.",
            ("REFUSE",),
            True, True,
        )

    if profile.ata_secure_erase and t in {"ata", "sata", "ide"}:
        return SanitizationPlan(
            "ATA Secure Erase", "PURGE", profile.path,
            ("hdparm", "--security-erase", "<password>", profile.path),
            "ATA device-native secure erase is advertised.",
            ("REFUSE",),
            True, True,
        )

    if profile.scsi_sanitize and t in {"scsi", "sas", "usb-scsi"}:
        return SanitizationPlan(
            "SCSI Sanitize", "PURGE", profile.path,
            ("sg_sanitize", "--block", profile.path),
            "SCSI sanitize capability is advertised.",
            ("REFUSE",),
            True, True,
        )

    if profile.vendor_sanitize:
        return SanitizationPlan(
            "Vendor-Native Sanitization", "PURGE", profile.path,
            None,
            "Device/vendor-specific sanitization is required; use the validated vendor adapter.",
            ("REFUSE",),
            True, True,
        )

    if profile.encrypted and profile.crypto_erase:
        return SanitizationPlan(
            "Cryptographic Erasure", "PURGE", profile.path,
            None,
            "Applicable encryption key destruction is available through the higher-level KMS/key hierarchy.",
            ("REFUSE",),
            True, True,
        )

    if approved_logical_fallback and m == "hdd":
        return SanitizationPlan(
            "Approved Logical Overwrite", "CLEAR", profile.path,
            ("logical-overwrite", profile.path),
            "No stronger device-native mechanism was advertised; policy explicitly permits logical HDD fallback.",
            ("REFUSE",),
            True, True,
        )

    return SanitizationPlan(
        "REFUSE", "NONE", profile.path, None,
        "No trustworthy technology-appropriate purge method is available.",
        ("REFUSE",), False, False, "REFUSED"
    )


def _validate_executable_plan(plan: SanitizationPlan):
    if plan.status == "REFUSED":
        raise PolicyError("policy refused sanitization")
    if not plan.destructive:
        raise PolicyError("non-destructive plan cannot be executed")
    if plan.command is None:
        raise PolicyError("plan requires a platform/vendor adapter; no command is executable")

    allowed = {"nvme", "hdparm", "sg_sanitize", "logical-overwrite"}
    if not plan.command or plan.command[0] not in allowed:
        raise PolicyError("command not allowed by execution policy")

    if plan.command[0] == "logical-overwrite":
        raise PolicyError("logical-overwrite adapter is not bundled; integrate approved HDD writer")

    # A plan containing unresolved placeholders is descriptive, not executable.
    # Never pass a literal placeholder such as <password> to a destructive tool.
    if any(token.startswith("<") and token.endswith(">") for token in plan.command):
        raise PolicyError("plan contains an unresolved placeholder; use a validated adapter with concrete parameters")

    # Never execute malformed device paths as commands.
    if not plan.target or any(not token for token in plan.command):
        raise PolicyError("plan contains an invalid target or command token")


def execute_plan(plan: SanitizationPlan, *, confirm_target: str, dry_run=True, timeout=3600):
    if plan.status == "REFUSED":
        raise PolicyError("policy refused sanitization")
    if confirm_target != plan.target:
        raise PolicyError("exact target confirmation mismatch")
    if dry_run:
        return {"status": "DRY_RUN", "plan": plan.to_dict()}

    _validate_executable_plan(plan)

    if timeout <= 0:
        raise PolicyError("timeout must be positive")

    proc = subprocess.run(
        list(plan.command),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return {
        "status": "EXECUTED" if proc.returncode == 0 else "FAILED",
        "returncode": proc.returncode,
        "stdout": proc.stdout[-4000:],
        "stderr": proc.stderr[-4000:],
        "plan": plan.to_dict(),
    }


def write_audit(path, *, profile, plan, result):
    record = {
        "schema": "secure-erasure.audit.v1",
        "method": "storage-aware-sanitization-and-fallback",
        "created_utc": _utc_now(),
        "device_identity": profile.identity,
        "target": profile.path,
        "profile": profile.to_dict(),
        "plan": plan.to_dict(),
        "result": result,
        "assurance_note": (
            "Device-native purge is claimed only from advertised capabilities and native "
            "command completion. Physical assurance depends on trusted device firmware, "
            "vendor implementation and independent validation."
        ),
    }
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, out)
    return out
