<#
Read-only probe of an attached mobile device. Writes nothing to it, ever.

    powershell -ExecutionPolicy Bypass -File validation\device_note10\probe_device.ps1

WHAT THIS IS FOR. A water-damaged Samsung Galaxy Note 10+ was attached to establish
whether it can serve as a real forensic target for AKHANDA - a source to carve, or media to
erase. That question has a factual answer and this script establishes it rather than
assuming either way.

WHAT IT DELIBERATELY DOES NOT DO, and this is a boundary rather than an oversight:

  * It does not write to the device. Not a byte, under any flag.
  * It does not enumerate, open, copy or list the OWNER'S FILES. The device reports
    itself as belonging to a named person. Establishing whether a block device exists
    needs the USB topology and nothing else; reading their photographs to answer a
    question about device classes would be a privacy intrusion with no technical purpose.
  * It takes no backup. Explicitly requested, and consistent with the above.

Everything captured here is DEVICE TOPOLOGY: USB descriptors, device classes, and whether
the operating system exposes a block device. All of it is read-only, and all of it is
information the device broadcasts to any host it is plugged into.
#>
$ErrorActionPreference = 'Continue'

$here     = $PSScriptRoot
$logs     = Join-Path $here 'logs'
$evidence = Join-Path $here 'evidence'
New-Item -ItemType Directory -Force -Path $logs, $evidence | Out-Null

$stamp   = Get-Date -Format 'yyyyMMdd-HHmmss'
$logFile = Join-Path $logs "probe-$stamp.log"
$lines   = New-Object System.Collections.ArrayList

function Log([string]$msg = '') {
    Write-Host $msg
    [void]$lines.Add($msg)
}

Log ('=' * 78)
Log 'AKHANDA - read-only mobile device probe'
Log ("ran at   {0}" -f (Get-Date).ToString('o'))
Log ("host     {0}" -f $env:COMPUTERNAME)
Log 'scope    device topology only. No writes. No file enumeration. No backup.'
Log ('=' * 78)

$report = [ordered]@{
    check        = 'read-only mobile device probe'
    ran_at       = (Get-Date).ToString('o')
    host         = $env:COMPUTERNAME
    boundaries   = @(
        'no write to the device under any flag',
        "no enumeration of the owner's files - topology answers the question, their photographs do not",
        'no backup taken'
    )
    devices      = @()
    block_devices = @()
    verdict      = ''
    reachable    = @{}
}

# ---- 1. every present device that could be the phone ----------------------
Log ''
Log '--- attached mobile / portable devices ---'
$mobile = Get-PnpDevice -PresentOnly |
    Where-Object { $_.InstanceId -match 'VID_04E8|VID_18D1|VID_22B8|VID_2717|VID_05C6' -or
                   $_.Class -eq 'WPD' }
foreach ($d in $mobile) {
    Log ("  [{0,-9}] {1,-45} {2}" -f $d.Class, $d.FriendlyName, $d.Status)
    Log ("              {0}" -f $d.InstanceId)
    $report.devices += [ordered]@{
        class = $d.Class; name = $d.FriendlyName
        status = $d.Status; instance_id = $d.InstanceId
    }
}
if (-not $mobile) { Log '  none found' }

# ---- 2. THE DECIDING QUESTION: is there a block device? -------------------
Log ''
Log '--- block devices the OS exposes (Win32_DiskDrive) ---'
$disks = Get-CimInstance Win32_DiskDrive
foreach ($d in $disks) {
    Log ("  disk {0}  {1,-30} {2,-8} {3:N0} bytes" -f $d.Index, $d.Model, $d.InterfaceType, $d.Size)
    $report.block_devices += [ordered]@{
        index = $d.Index; model = $d.Model
        interface = $d.InterfaceType; size = $d.Size
        device_path = "\\.\PhysicalDrive$($d.Index)"
    }
}

# A phone in MTP mode is a WPD device and NEVER a Win32_DiskDrive. That distinction is
# the whole answer: MTP is a file-transfer protocol spoken over USB, not a block device.
$phone = $mobile | Where-Object { $_.Class -eq 'WPD' } | Select-Object -First 1
$mtp   = $phone -and ($phone.InstanceId -match 'MTP')
$hasBlockDevice = $false
foreach ($d in $disks) {
    if ($d.Model -match 'Samsung|Android|MTP|Portable' -and $d.InterfaceType -eq 'USB') {
        $hasBlockDevice = $true
    }
}

Log ''
Log '--- what this means ---'
if ($phone -and $mtp -and -not $hasBlockDevice) {
    $report.verdict = 'MTP_ONLY_NO_BLOCK_DEVICE'
    Log '  The device is attached in MTP mode (Media Transfer Protocol) and the operating'
    Log '  system exposes NO block device for it. There is no \\.\PhysicalDriveN path.'
    Log ''
    Log '  MTP is a file-transfer protocol spoken over USB. The phone answers requests for'
    Log '  named objects; it does not present sectors. Nothing can address an LBA on it,'
    Log '  so it cannot be imaged, carved, or erased at block level - not by AKHANDA and'
    Log '  not by any other host-side tool. This is a property of the transport, not a'
    Log '  limitation of the software.'
} elseif ($hasBlockDevice) {
    $report.verdict = 'BLOCK_DEVICE_PRESENT'
    Log '  A USB block device is present. Raw access may be possible - identify it before'
    Log '  any operation and confirm the device path against its serial number.'
} else {
    $report.verdict = 'NO_DEVICE_DETECTED'
    Log '  No mobile device detected. Check the cable and that the phone is unlocked.'
}

$report.reachable = [ordered]@{
    block_level_imaging = $false
    block_level_erasure = $false
    file_level_via_mtp  = [bool]$mtp
    note = ('MTP exposes named objects, not sectors. File-level access through it reads ' +
            'what the phone chooses to present, which is not a forensic image and carries ' +
            'no guarantee of completeness.')
}

Log ''
Log ('verdict: {0}' -f $report.verdict)
Log ('=' * 78)

$json = Join-Path $evidence "device_probe-$stamp.json"
$report | ConvertTo-Json -Depth 6 | Out-File -FilePath $json -Encoding utf8
$lines -join "`r`n" | Out-File -FilePath $logFile -Encoding utf8

Write-Host ''
Write-Host ("log  {0}" -f $logFile)
Write-Host ("json {0}" -f $json)
