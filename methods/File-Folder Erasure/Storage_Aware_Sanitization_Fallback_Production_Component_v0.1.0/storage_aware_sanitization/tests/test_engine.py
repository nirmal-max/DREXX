import json
from pathlib import Path
import pytest
from storage_aware.engine import DeviceProfile, choose_plan, execute_plan, PolicyError, write_audit


def profile(**overrides):
    d=dict(path="/dev/test0",transport="nvme",media="ssd",encrypted=True,
           crypto_erase=True,block_erase=True,overwrite_sanitize=True,
           ata_secure_erase=False,scsi_sanitize=False,vendor_sanitize=False,
           removable=False,device_size_bytes=1000000,identity="TEST-DEVICE")
    d.update(overrides)
    return DeviceProfile.from_dict(d)


def test_nvme_crypto_preferred():
    p=choose_plan(profile())
    assert p.method=="NVMe Sanitize — Crypto Erase"
    assert p.assurance=="PURGE"
    assert p.command[:3]==("nvme","sanitize","/dev/test0")


def test_nvme_block_fallback():
    p=choose_plan(profile(crypto_erase=False))
    assert p.method=="NVMe Sanitize — Block Erase"


def test_nvme_overwrite_fallback():
    p=choose_plan(profile(crypto_erase=False,block_erase=False))
    assert p.method=="NVMe Sanitize — Overwrite"


def test_ata_native():
    p=choose_plan(profile(transport="sata",crypto_erase=False,block_erase=False,
                           overwrite_sanitize=False,ata_secure_erase=True))
    assert p.method=="ATA Secure Erase"


def test_scsi_native():
    p=choose_plan(profile(transport="sas",crypto_erase=False,block_erase=False,
                           overwrite_sanitize=False,scsi_sanitize=True))
    assert p.method=="SCSI Sanitize"


def test_vendor_required():
    p=choose_plan(profile(transport="usb",crypto_erase=False,block_erase=False,
                           overwrite_sanitize=False,vendor_sanitize=True))
    assert p.method=="Vendor-Native Sanitization"
    assert p.command is None


def test_hdd_logical_fallback_requires_policy():
    p=profile(transport="ata",media="hdd",crypto_erase=False,block_erase=False,
               overwrite_sanitize=False,ata_secure_erase=False)
    assert choose_plan(p).status=="REFUSED"
    assert choose_plan(p,approved_logical_fallback=True).method=="Approved Logical Overwrite"


def test_unknown_refused():
    p=profile(transport="unknown",media="unknown",crypto_erase=False,block_erase=False,
               overwrite_sanitize=False)
    assert choose_plan(p).status=="REFUSED"


def test_dry_run_never_executes():
    p=profile()
    plan=choose_plan(p)
    r=execute_plan(plan,confirm_target=p.path,dry_run=True)
    assert r["status"]=="DRY_RUN"


def test_confirmation_guard():
    p=profile()
    plan=choose_plan(p)
    with pytest.raises(PolicyError):
        execute_plan(plan,confirm_target="/dev/wrong",dry_run=True)


def test_audit(tmp_path):
    p=profile()
    plan=choose_plan(p)
    r=execute_plan(plan,confirm_target=p.path,dry_run=True)
    out=write_audit(tmp_path/"audit.json",profile=p,plan=plan,result=r)
    data=json.loads(out.read_text())
    assert data["method"]=="storage-aware-sanitization-and-fallback"
    assert data["plan"]["method"]=="NVMe Sanitize — Crypto Erase"
