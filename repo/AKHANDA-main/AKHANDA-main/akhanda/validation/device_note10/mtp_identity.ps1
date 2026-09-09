<#
Device IDENTITY over MTP. Read-only, and deliberately not a file listing.

    powershell -ExecutionPolicy Bypass -File validation\device_note10\mtp_identity.ps1

WHY THIS IS WORTH DOING even though the phone cannot be imaged. BSA 2023 §63(4) Schedule
Part A asks for device particulars - Make & Model, Serial Number, IMEI/UIN/UID/MAC - and
NIST SP 800-88 Rev. 2 Appendix C asks for Vendor/Make, Model Number and Serial Number. Those
are answerable for this phone even though its storage is not. Establishing WHICH DEVICE was
examined is a real forensic act, and it is the half of the certificate that does not need
block access.

THE BOUNDARY, stated because it is easy to cross by accident. This reads DEVICE-LEVEL
properties: what the phone says it is. It does not enumerate, open, or list the owner's
content. The distinction is not cosmetic - `Shell.Application` will happily walk into
DCIM and start naming photographs, and answering "which device is this" does not require
knowing what is on it.

    READ      manufacturer, model, serial, firmware, capacity, free space
    NOT READ  any file, folder, or object the owner put there

Nothing is written to the device. No backup is taken.

WHAT ADB WOULD ADD, AND WHY IT IS NOT USED HERE. `adb shell getprop` would give the same
class of answer with more detail - ro.product.model, ro.serialno, the Android version. It is
not used because adb is not installed, there is no connection to install it, and it would
need USB debugging enabled from inside the phone by a person. It would still not give block
access: reading /dev/block/sda needs root, and rooting a Samsung means unlocking the
bootloader, which wipes the device. So adb is a better identity probe and not a route to
the storage.
#>
$ErrorActionPreference = 'Continue'

$here     = $PSScriptRoot
$logs     = Join-Path $here 'logs'
$evidence = Join-Path $here 'evidence'
New-Item -ItemType Directory -Force -Path $logs, $evidence | Out-Null

$stamp   = Get-Date -Format 'yyyyMMdd-HHmmss'
$logFile = Join-Path $logs "mtp-identity-$stamp.log"
$lines   = New-Object System.Collections.ArrayList
function Log([string]$m = '') { Write-Host $m; [void]$lines.Add($m) }

Log ('=' * 78)
Log 'AKHANDA - MTP device identity (read-only, no file access)'
Log ("ran at   {0}" -f (Get-Date).ToString('o'))
Log 'scope    device-level properties only. No file enumeration. No writes. No backup.'
Log ('=' * 78)

$report = [ordered]@{
    check      = 'MTP device identity'
    ran_at     = (Get-Date).ToString('o')
    host       = $env:COMPUTERNAME
    boundary   = 'device-level properties only; no file, folder or object was enumerated'
    device     = [ordered]@{}
    usb        = [ordered]@{}
    storage    = @()
    bsa_63_4_part_a = [ordered]@{}
    nist_800_88r2   = [ordered]@{}
    unavailable = @()
    verdict    = ''
}

# ---- 1. USB descriptor facts (from the OS, not from the phone's filesystem) ----
$pnp = Get-PnpDevice -PresentOnly -Class WPD -EA SilentlyContinue | Select-Object -First 1
if (-not $pnp) {
    Log 'no MTP device present'
    $report.verdict = 'NO_DEVICE'
} else {
    Log ''
    Log '--- USB descriptor ---'
    $report.device.friendly_name = $pnp.FriendlyName
    $report.device.instance_id   = $pnp.InstanceId
    Log ("  name        {0}" -f $pnp.FriendlyName)
    Log ("  instance    {0}" -f $pnp.InstanceId)

    if ($pnp.InstanceId -match 'VID_([0-9A-F]{4})') {
        $report.usb.vendor_id = $Matches[1]
        $vendors = @{ '04E8' = 'Samsung Electronics'; '18D1' = 'Google'; '22B8' = 'Motorola';
                      '2717' = 'Xiaomi'; '05C6' = 'Qualcomm' }
        $report.usb.vendor_name = $vendors[$Matches[1]]
        Log ("  vendor      {0} ({1})" -f $Matches[1], $vendors[$Matches[1]])
    }
    if ($pnp.InstanceId -match 'PID_([0-9A-F]{4})') {
        $report.usb.product_id = $Matches[1]
        Log ("  product id  {0}" -f $Matches[1])
    }

    # The USB serial is the trailing element of the composite device's instance path. It is
    # the DEVICE serial, from the descriptor - not the IMEI, and not a filesystem read.
    $composite = Get-PnpDevice -PresentOnly -EA SilentlyContinue |
        Where-Object { $_.InstanceId -match '^USB\\VID_[0-9A-F]{4}&PID_[0-9A-F]{4}\\[A-Z0-9]{8,}$' } |
        Select-Object -First 1
    if ($composite -and $composite.InstanceId -match '\\([A-Z0-9]{8,})$') {
        $report.device.usb_serial = $Matches[1]
        Log ("  usb serial  {0}" -f $Matches[1])
    } else {
        $report.unavailable += 'usb_serial'
        Log '  usb serial  unavailable'
    }

    # ---- 2. What the device reports about itself over MTP -------------------
    Log ''
    Log '--- MTP device properties ---'
    try {
        $shell = New-Object -ComObject Shell.Application
        # 17 = ssfDRIVES, "This PC". Portable devices appear here as namespace children.
        $pc = $shell.NameSpace(17)
        $found = $false
        foreach ($item in $pc.Items()) {
            if ($item.Name -eq $pnp.FriendlyName -or $item.Name -like '*Note10*') {
                $found = $true
                $report.device.mtp_name = $item.Name
                Log ("  mtp name    {0}" -f $item.Name)

                # STORAGE CAPACITY ONLY. GetFolder gives access to the object tree; the
                # loop below reads each storage volume's NAME and SIZE and never descends
                # into it. Descending would start naming the owner's files.
                try {
                    $folder = $item.GetFolder
                    foreach ($vol in $folder.Items()) {
                        $entry = [ordered]@{ name = $vol.Name }
                        # Column indices are not stable across shell versions and device
                        # types. Reading column 1 as "total size" returned the string
                        # "Generic hierarchical" on this device - a type description
                        # presented as a capacity. Rather than trust an index, every column
                        # is scanned and only values that actually LOOK like a size are
                        # kept. A plausible wrong number on a certificate is worse than an
                        # absent one, because nobody checks a number that reads correctly.
                        for ($c = 0; $c -lt 12; $c++) {
                            $v = $folder.GetDetailsOf($vol, $c)
                            if ($v -match '^\s*[\d.,]+\s*(KB|MB|GB|TB|bytes)\s*$') {
                                $label = $folder.GetDetailsOf($null, $c)
                                if (-not $label) { $label = "column$c" }
                                $entry[$label] = $v.Trim()
                            }
                        }
                        if ($entry.Keys.Count -eq 1) {
                            $entry['note'] = 'no size-shaped value found in any column'
                            $report.unavailable += "storage_size:$($vol.Name)"
                        }
                        $report.storage += $entry
                        $sizes = ($entry.GetEnumerator() | Where-Object { $_.Key -ne 'name' } |
                                  ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '  '
                        Log ("  storage     {0}   {1}" -f $vol.Name, $sizes)
                    }
                } catch {
                    $report.unavailable += 'storage_capacity'
                    Log ("  storage     unavailable: {0}" -f $_.Exception.Message)
                }
                break
            }
        }
        if (-not $found) {
            $report.unavailable += 'mtp_properties'
            Log '  the device is present in PnP but did not appear in the shell namespace'
            Log '  (usual cause: the phone is locked, or MTP access has not been allowed on it)'
        }
    } catch {
        $report.unavailable += 'mtp_properties'
        Log ("  MTP query failed: {0}" -f $_.Exception.Message)
    }

    # ---- 3. Map onto the two certificates ----------------------------------
    $model  = if ($pnp.FriendlyName) { $pnp.FriendlyName } else { 'unavailable' }
    $serial = if ($report.device.usb_serial) { $report.device.usb_serial } else { 'unavailable' }
    $make   = if ($report.usb.vendor_name) { $report.usb.vendor_name } else { 'unavailable' }

    $report.bsa_63_4_part_a = [ordered]@{
        'Make & Model'              = "$make / $model"
        'Serial Number'             = $serial
        'IMEI/UIN/UID/MAC/Cloud ID' = 'unavailable, the IMEI is not exposed over MTP; it requires adb or the handset UI'
        'Colour'                    = 'requires human entry (physical attribute)'
        'Device source'             = 'Mobile'
    }
    $report.nist_800_88r2 = [ordered]@{
        'Vendor/Make'   = $make
        'Model Number'  = $model
        'Serial Number' = $serial
        'Media Type'    = 'mobile handset, internal UFS, not host-addressable'
    }

    $report.verdict = if ($serial -ne 'unavailable') { 'IDENTIFIED' } else { 'PARTIAL' }
}

Log ''
Log '--- certificate blocks ---'
Log '  BSA 2023 §63(4) Part A:'
foreach ($k in $report.bsa_63_4_part_a.Keys) {
    Log ("    {0,-28} {1}" -f $k, $report.bsa_63_4_part_a[$k])
}
Log '  NIST SP 800-88r2 Appendix C:'
foreach ($k in $report.nist_800_88r2.Keys) {
    Log ("    {0,-28} {1}" -f $k, $report.nist_800_88r2[$k])
}

if ($report.unavailable.Count) {
    Log ''
    Log ("unavailable, named rather than left blank: {0}" -f ($report.unavailable -join ', '))
}

Log ''
Log ("verdict: {0}" -f $report.verdict)
Log ('=' * 78)

$json = Join-Path $evidence "mtp_identity-$stamp.json"
$report | ConvertTo-Json -Depth 6 | Out-File -FilePath $json -Encoding utf8
$lines -join "`r`n" | Out-File -FilePath $logFile -Encoding utf8
Write-Host ''
Write-Host ("log  {0}" -f $logFile)
Write-Host ("json {0}" -f $json)
