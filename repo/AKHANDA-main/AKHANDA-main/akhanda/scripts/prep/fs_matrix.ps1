<#
Filesystem detection matrix, on REAL filesystems, with ZERO risk to any real drive.

    powershell -ExecutionPolicy Bypass -File scripts\prep\fs_matrix.ps1

WHY THIS IS SAFE, STATED PLAINLY BEFORE ANYTHING ELSE. Every volume this script creates is
backed by a .vhdx FILE inside evidence\fs_matrix\. Nothing touches a physical disk. The
virtual disks are attached, formatted, tested, detached and deleted; the only bytes written
are inside a file you can delete by hand. It never enumerates, selects or formats a
physical drive, and `diskpart` is driven with an explicit `select vdisk file=` rather than
a disk number, so there is no disk-number arithmetic that could land somewhere else.

WHAT IT PROVES. `detect_filesystem()` is claimed to work across filesystems. Until now it
had only ever run against the NTFS volume this repository lives on, which means the claim
covered one case and was written as though it covered all of them. This runs it against
real NTFS, FAT32, exFAT and ReFS volumes and records what came back.

It matters more than it looks: `detect_filesystem` returning "unknown" DOWNGRADES the
recorded outcome to UNVERIFIED, and ReFS is in COW_OR_JOURNALLED so it must produce
PARTIAL. A detector that silently failed to recognise a filesystem would not crash, it
would quietly record a weaker or stronger claim than the truth.

REQUIRES AN ELEVATED SHELL. Creating and attaching a virtual disk needs administrator
rights. Nothing else here does.
#>
$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this in an elevated PowerShell. Attaching a virtual disk requires it."
}

$repo     = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$work     = Join-Path $repo 'evidence\fs_matrix'
$evidence = Join-Path $repo 'evidence'
New-Item -ItemType Directory -Force -Path $work | Out-Null

# ReFS needs a large cluster and a large volume; the others are happy small.
$cases = @(
    @{ fs = 'NTFS';  sizeMB = 256; cluster = 4096  },
    @{ fs = 'FAT32'; sizeMB = 512; cluster = 4096  },
    @{ fs = 'exFAT'; sizeMB = 256; cluster = 32768 },
    @{ fs = 'ReFS';  sizeMB = 2048; cluster = 4096 }
)

$results = @()

foreach ($case in $cases) {
    $fs   = $case.fs
    $vhd  = Join-Path $work "$fs.vhdx"
    $rec  = [ordered]@{
        filesystem_requested = $fs
        vhd                  = $vhd
        attached             = $false
        drive_letter         = ''
        volume_fs_reported   = ''
        akhanda_detected     = ''
        agrees               = $null
        is_cow_or_journalled = $null
        erase_outcome        = ''
        error                = ''
    }

    try {
        Write-Host "`n=== $fs ===" -ForegroundColor Cyan
        if (Test-Path $vhd) { Remove-Item $vhd -Force }

        # Explicit file path, never a disk number. diskpart cannot wander from here.
        $script = @"
create vdisk file="$vhd" maximum=$($case.sizeMB) type=expandable
select vdisk file="$vhd"
attach vdisk
create partition primary
format fs=$fs unit=$($case.cluster) quick label=AKH$fs
assign
"@
        $tmp = Join-Path $work "$fs.dp.txt"
        $script | Out-File -FilePath $tmp -Encoding ascii
        $null = diskpart /s $tmp
        Remove-Item $tmp -Force
        $rec.attached = $true

        Start-Sleep -Milliseconds 800
        $vol = Get-Volume | Where-Object { $_.FileSystemLabel -eq "AKH$fs" } | Select-Object -First 1
        if (-not $vol -or -not $vol.DriveLetter) { throw "volume did not mount" }

        $letter = "$($vol.DriveLetter):"
        $rec.drive_letter       = $letter
        $rec.volume_fs_reported = $vol.FileSystem

        # Ask AKHANDA what it thinks, against a real file on that real volume.
        $probe = Join-Path $letter 'akhanda_probe.txt'
        'probe' | Out-File -FilePath $probe -Encoding ascii

        $py = @"
import sys, json
sys.path.insert(0, r'$repo\src')
from erasure.file_eraser import detect_filesystem, COW_OR_JOURNALLED, erase_file
fs = detect_filesystem(r'$probe')
r  = erase_file(r'$probe')
print(json.dumps({'detected': fs,
                  'cow': fs in COW_OR_JOURNALLED,
                  'outcome': r.outcome,
                  'reason': r.reason}))
"@
        $out = $py | python -
        $parsed = $out | ConvertFrom-Json
        $rec.akhanda_detected     = $parsed.detected
        $rec.is_cow_or_journalled = $parsed.cow
        $rec.erase_outcome        = $parsed.outcome
        $rec.agrees = ($parsed.detected -eq $vol.FileSystem.ToLower())

        Write-Host ("  volume reports : {0}" -f $vol.FileSystem)
        Write-Host ("  akhanda detects: {0}   agrees={1}" -f $parsed.detected, $rec.agrees)
        Write-Host ("  erase outcome  : {0}" -f $parsed.outcome)
    }
    catch {
        $rec.error = $_.Exception.Message
        Write-Host ("  FAILED: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
    }
    finally {
        # Detach and delete, whatever happened. A leftover attached vdisk is a mounted
        # volume the operator did not ask for.
        try {
            $d = Join-Path $work "$fs.det.txt"
            "select vdisk file=`"$vhd`"`ndetach vdisk" | Out-File -FilePath $d -Encoding ascii
            $null = diskpart /s $d
            Remove-Item $d -Force -ErrorAction SilentlyContinue
        } catch {}
        Remove-Item $vhd -Force -ErrorAction SilentlyContinue
    }

    $results += [pscustomobject]$rec
}

$report = [ordered]@{
    check      = 'filesystem detection matrix on VHD-backed volumes'
    ran_at     = (Get-Date).ToString('o')
    machine    = $env:COMPUTERNAME
    safety     = ('Every volume was backed by a .vhdx file. No physical disk was ' +
                  'enumerated, selected, formatted or written to at any point.')
    results    = $results
    agreed     = ($results | Where-Object { $_.agrees -eq $true }).Count
    total      = $results.Count
}
$out = Join-Path $evidence 'fs_matrix.json'
$report | ConvertTo-Json -Depth 6 | Out-File -FilePath $out -Encoding utf8

Write-Host ""
Write-Host ("agreed  : {0} of {1}" -f $report.agreed, $report.total)
Write-Host ("written : {0}" -f $out)
Write-Host ""
Write-Host "Any row where agrees=False is a real finding: detect_filesystem returning"
Write-Host "'unknown' silently downgrades the recorded outcome to UNVERIFIED."
