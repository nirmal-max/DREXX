<#
A REAL block-device erasure with NO physical media, and no risk to any real drive.

    powershell -ExecutionPolicy Bypass -File scripts\prep\vhd_erase.ps1

WHY THIS EXISTS. G2b wants an erasure performed against a real block device rather than a
file image. A USB stick is the obvious way and needs a USB stick. A VHD is a FILE that
Windows attaches as a genuine physical disk: it gets its own \\.\PhysicalDriveN path, its
own partition table and filesystem, and behaves like a disk all the way down to the block
layer. The backing store is a file you delete afterwards.

WHAT THIS DOES AND DOES NOT PROVE. Being precise here matters more than the result.

  PROVEN by this script - the parts that are genuinely real:
    * the six-gate device guard, exercised against a real \\.\PhysicalDriveN path
    * AKHANDA_TARGET_DEVICE, which must name the exact device
    * device identification over IOCTL_STORAGE_QUERY_PROPERTY on a real handle
    * the overwrite and read-back path against a real block device, not a file
    * the signed ledger entry and certificate for a block-device erasure

  NOT PROVEN, and must not be claimed from this run:
    * flash behaviour. A VHD has no flash translation layer, so there is no
      overprovisioning and no remapped-block residue. The NIST "scope too narrow"
      ground (G5) cannot be exercised here.
    * ATA Secure Erase / NVMe Sanitize. A virtual disk supports neither, so NIST Purge
      is unreachable and this run says Clear - correctly, but for the wrong reason.
    * bad sectors. A VHD does not develop them.
    * USB enumeration and removable-media detection.

  A VHD run is therefore a BLOCK-DEVICE test, not a MEDIA test. Both are needed; only
  one of them needs hardware, and this is the other one.

SAFETY, which is the point of the design rather than a disclaimer:

  1. The disk number is read back from the attach, never guessed or incremented.
  2. Before any write, the target is IDENTIFIED and must report itself as a virtual
     disk. If the model does not say so, the script REFUSES - so even if the disk
     number were wrong, a real drive would not match and nothing would be written.
  3. The size is checked against what was created. A real 1 TB drive cannot be mistaken
     for a 64 MB VHD.
  4. Detach and delete run in `finally`, so an interrupted run does not leave a mounted
     virtual disk behind.
  5. AKHANDA's own guard is left ON. This script supplies the required environment
     variables for the exact target and nothing more - it never disables a check.

Requires an ELEVATED PowerShell: attaching a virtual disk needs administrator rights.
Nothing else here does.
#>
param(
    [int]$SizeMB = 64,
    [string]$Level = "Clear"
)

$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this in an elevated PowerShell. Attaching a virtual disk requires it."
}

$repo     = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$work     = Join-Path $repo 'evidence\vhd'
$evidence = Join-Path $repo 'evidence'
New-Item -ItemType Directory -Force -Path $work | Out-Null

$vhd = Join-Path $work 'akhanda_target.vhdx'
$rec = [ordered]@{
    check          = 'block-device erasure on a VHD'
    ran_at         = (Get-Date).ToString('o')
    machine        = $env:COMPUTERNAME
    vhd            = $vhd
    size_mb        = $SizeMB
    requested_level = $Level
    disk_number    = $null
    device_path    = ''
    identity       = $null
    safety_checks  = @()
    erase          = $null
    verdict        = ''
    proves         = @(
        'the six-gate device guard against a real \\.\PhysicalDriveN path',
        'AKHANDA_TARGET_DEVICE naming the exact device',
        'device identification over IOCTL_STORAGE_QUERY_PROPERTY on a real handle',
        'overwrite and read-back against a real block device'
    )
    does_not_prove = @(
        'flash behaviour: a VHD has no flash translation layer, so no overprovisioning residue',
        'ATA Secure Erase / NVMe Sanitize: unsupported by a virtual disk, so Purge is unreachable',
        'bad sectors: a VHD does not develop them',
        'USB enumeration and removable-media detection'
    )
    error          = ''
}

$attached = $false
try {
    if (Test-Path $vhd) { Remove-Item $vhd -Force }

    Write-Host "creating $SizeMB MB virtual disk ..." -ForegroundColor Cyan
    $create = @"
create vdisk file="$vhd" maximum=$SizeMB type=fixed
select vdisk file="$vhd"
attach vdisk
"@
    $tmp = Join-Path $work 'create.dp'
    $create | Out-File -FilePath $tmp -Encoding ascii
    $null = diskpart /s $tmp
    Remove-Item $tmp -Force
    $attached = $true
    Start-Sleep -Milliseconds 900

    # ---- SAFETY 1: read the disk number back, never guess it -------------------
    $disk = Get-Disk | Where-Object { $_.Location -eq $vhd } | Select-Object -First 1
    if (-not $disk) {
        $disk = Get-Disk | Where-Object { $_.FriendlyName -like '*Virtual Disk*' } |
                Sort-Object Number -Descending | Select-Object -First 1
    }
    if (-not $disk) { throw "the attached virtual disk could not be located" }

    $rec.disk_number = $disk.Number
    $device = "\\.\PhysicalDrive$($disk.Number)"
    $rec.device_path = $device
    $rec.safety_checks += "disk number $($disk.Number) read back from the attach, not guessed"

    if ($disk.Number -eq 0) { throw "REFUSING: the attached disk reported number 0, which is the boot disk" }
    $rec.safety_checks += "disk number is not 0"

    # ---- SAFETY 2: it must IDENTIFY as a virtual disk --------------------------
    $py = @"
import sys, json
sys.path.insert(0, r'$repo\src')
from erasure import deviceid
i = deviceid.identify(r'$device')
print(json.dumps({'vendor': i.vendor, 'model': i.model, 'serial': i.serial,
                  'bus': i.bus, 'size': i.size_bytes, 'note': i.note}))
"@
    $ident = ($py | python -) | ConvertFrom-Json
    $rec.identity = $ident
    Write-Host ("identified: {0} / {1}  bus={2}" -f $ident.vendor, $ident.model, $ident.bus)

    $looksVirtual = ("$($ident.model) $($ident.vendor)" -match 'Virtual|Msft|VHD')
    if (-not $looksVirtual) {
        throw ("REFUSING: $device identifies as '$($ident.vendor) $($ident.model)', which " +
               "is not a virtual disk. Even if the disk number were wrong, a real drive " +
               "cannot pass this check.")
    }
    $rec.safety_checks += "target identifies as a virtual disk ($($ident.vendor) $($ident.model))"

    # ---- SAFETY 3: the size must match what we created ------------------------
    $expected = [int64]$SizeMB * 1MB
    if ([math]::Abs($disk.Size - $expected) -gt 8MB) {
        throw "REFUSING: $device is $($disk.Size) bytes, expected about $expected"
    }
    $rec.safety_checks += "size $($disk.Size) matches the $SizeMB MB that was created"

    Write-Host ""
    Write-Host "all safety checks passed; erasing $device" -ForegroundColor Green
    foreach ($c in $rec.safety_checks) { Write-Host "  - $c" }
    Write-Host ""

    # ---- the erasure. AKHANDA's own guard stays ON. --------------------------
    $env:AKHANDA_ALLOW_DEVICE_WRITE = "1"
    $env:AKHANDA_TARGET_DEVICE      = $device
    $erasePy = @"
import sys, json
sys.path.insert(0, r'$repo\src')
from erasure.engine import erase, CONFIRM_TOKEN, outcome_for, result_hash
r = erase(r'$device', '$Level', confirm=CONFIRM_TOKEN)
print(json.dumps({'method_used': r['method_used'], 'verified': r['verified'],
                  'outcome': outcome_for(r), 'bytes_written': r['bytes_written'],
                  'bytes_skipped': r['bytes_skipped'], 'aborted': r['aborted'],
                  'samples': len(r['sample_results']),
                  'media_kind': r['media_kind'], 'note': r['honest_note'][:300],
                  'result_hash': result_hash(r),
                  'identified': r['device_identity']['identified']}))
"@
    $rec.erase = ($erasePy | python -) | ConvertFrom-Json

    Write-Host ("method   : {0}" -f $rec.erase.method_used)
    Write-Host ("outcome  : {0}   verified={1}" -f $rec.erase.outcome, $rec.erase.verified)
    Write-Host ("written  : {0:N0} bytes, skipped {1}" -f $rec.erase.bytes_written, $rec.erase.bytes_skipped)
    Write-Host ("digest   : {0}" -f $rec.erase.result_hash)

    $rec.verdict = if ($rec.erase.verified) { 'PASS' } else { 'COMPLETED BUT UNVERIFIED' }
}
catch {
    $rec.error = $_.Exception.Message
    $rec.verdict = 'FAILED'
    Write-Host ("FAILED: {0}" -f $_.Exception.Message) -ForegroundColor Red
}
finally {
    $env:AKHANDA_ALLOW_DEVICE_WRITE = $null
    $env:AKHANDA_TARGET_DEVICE = $null
    if ($attached) {
        try {
            $d = Join-Path $work 'detach.dp'
            "select vdisk file=`"$vhd`"`ndetach vdisk" | Out-File -FilePath $d -Encoding ascii
            $null = diskpart /s $d
            Remove-Item $d -Force -ErrorAction SilentlyContinue
            Write-Host "virtual disk detached"
        } catch { Write-Host "WARNING: detach failed - run 'diskpart' and detach manually" -ForegroundColor Yellow }
    }
    Remove-Item $vhd -Force -ErrorAction SilentlyContinue
}

$out = Join-Path $evidence 'vhd_erase.json'
$rec | ConvertTo-Json -Depth 6 | Out-File -FilePath $out -Encoding utf8
Write-Host ""
Write-Host ("verdict : {0}" -f $rec.verdict)
Write-Host ("written : {0}" -f $out)
Write-Host ""
Write-Host "This is a BLOCK-DEVICE test, not a MEDIA test. It does not prove flash"
Write-Host "behaviour, firmware sanitize, or bad-sector handling - see does_not_prove."
