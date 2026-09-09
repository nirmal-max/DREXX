<#
Does a laptop-to-laptop data link exist? Read-only, records the answer.

    powershell -ExecutionPolicy Bypass -File scripts\prep\link_detect.ps1

WHY. G24 needs the operator and witness laptops to reach each other. Before trusting any
transport on the day, this establishes whether one exists NOW - the roadmap's own rule is
"test the link once now, not on the day", and this is that test.

WHAT IT CHECKS, and the physics behind each:

  * A plain USB-C to USB-C cable CANNOT link two laptops. USB is host-to-device: both
    laptops want to be the host, and neither will act as a device to the other. A charging
    or data USB-C cable moves power and, at most, DisplayPort/USB-device traffic - not a
    host-to-host network.

  * The ONE exception is Thunderbolt / USB4 networking: if BOTH machines have a Thunderbolt
    or USB4 controller, connecting them creates a "Thunderbolt" network adapter with a
    169.254 or configured address. This script reports whether such a controller and such
    an adapter exist.

  * A USB-to-Ethernet adapter plus an Ethernet cable DOES work, because each adapter is a
    USB DEVICE the laptop hosts, and the two adapters talk Ethernet in between. This is the
    recommended G24 transport and this script tells you when one is present.

It writes nothing to any device and changes no setting. It only reads adapter state.
#>
$ErrorActionPreference = 'Continue'

$repo     = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$evidence = Join-Path $repo 'evidence'
New-Item -ItemType Directory -Force -Path $evidence | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

$report = [ordered]@{
    check      = 'laptop-to-laptop physical link detection'
    ran_at     = (Get-Date).ToString('o')
    host       = $env:COMPUTERNAME
    thunderbolt_controller = $false
    candidate_link_adapters = @()
    usb_ethernet_adapter    = $false
    real_adapters = @()
    verdict    = ''
    guidance   = ''
}

# Thunderbolt / USB4 controller present?
$tb = Get-PnpDevice -PresentOnly -EA SilentlyContinue |
    Where-Object { $_.InstanceId -match 'THUNDERBOLT|USB4' -or
                   $_.FriendlyName -match 'Thunderbolt Controller|USB4' }
$report.thunderbolt_controller = [bool]$tb

# Real (non-virtual) network adapters that are up
$virtual = 'VirtualBox|Hyper-V|TAP-Windows|Wi-Fi Direct|Loopback|WAN Miniport|Bluetooth'
$adapters = Get-NetAdapter -EA SilentlyContinue | Where-Object {
    $_.InterfaceDescription -notmatch $virtual }
foreach ($a in $adapters) {
    $report.real_adapters += [ordered]@{
        name = $a.Name; description = $a.InterfaceDescription
        status = "$($a.Status)"; link_speed = "$($a.LinkSpeed)"
    }
    if ($a.InterfaceDescription -match 'Thunderbolt|USB4') {
        $report.candidate_link_adapters += $a.Name
    }
    if ($a.InterfaceDescription -match 'USB.*Ethernet|Ethernet.*USB|RTL8153|AX88|Realtek USB') {
        $report.usb_ethernet_adapter = $true
    }
}

# A directly-linked pair usually sits on a 169.254 (APIPA) address on both ends because
# there is no DHCP server on a point-to-point cable.
$apipa = Get-NetIPAddress -AddressFamily IPv4 -EA SilentlyContinue |
    Where-Object { $_.IPAddress -like '169.254.*' -and
                   (Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -EA SilentlyContinue
                    ).InterfaceDescription -notmatch $virtual }

Write-Host ('=' * 74)
Write-Host 'AKHANDA - laptop-to-laptop link detection'
Write-Host ('=' * 74)
Write-Host ("Thunderbolt/USB4 controller : {0}" -f ($(if ($tb) {'PRESENT'} else {'absent'})))
Write-Host ("USB-Ethernet adapter        : {0}" -f ($(if ($report.usb_ethernet_adapter) {'PRESENT'} else {'absent'})))
Write-Host ''
Write-Host 'real network adapters (virtual excluded):'
foreach ($a in $report.real_adapters) {
    Write-Host ("  {0,-24} {1,-12} {2}" -f $a.name, $a.status, $a.description)
}

if ($report.candidate_link_adapters.Count -gt 0) {
    $report.verdict = 'THUNDERBOLT_LINK_POSSIBLE'
    $report.guidance = ('A Thunderbolt/USB4 network adapter is present. If the other laptop ' +
        'also has one and the cable is Thunderbolt-rated, set static IPs 192.168.50.1/.2 and ' +
        'run g24_link_check.py.')
} elseif ($report.usb_ethernet_adapter) {
    $report.verdict = 'USB_ETHERNET_PRESENT'
    $report.guidance = ('A USB-to-Ethernet adapter is present - the recommended transport. ' +
        'Connect both laptops through their adapters with an Ethernet cable, set static IPs ' +
        '192.168.50.1/.2, allow TCP 8000 on the Private profile, then run g24_link_check.py.')
} elseif (-not $tb) {
    $report.verdict = 'NO_LINK_USBC_CANNOT_BRIDGE'
    $report.guidance = ('No usable laptop-to-laptop link. This machine has NO Thunderbolt/USB4 ' +
        'controller, and a plain USB-C to USB-C cable cannot connect two hosts (USB is ' +
        'host-to-device; neither laptop will act as a device). Use a USB-to-Ethernet adapter ' +
        '+ Ethernet cable (preferred), OR a phone hotspot joining both laptops (test it once ' +
        'before the day - venue/enterprise Wi-Fi often isolates clients).')
} else {
    $report.verdict = 'THUNDERBOLT_PRESENT_NO_LINK_YET'
    $report.guidance = ('This machine has a Thunderbolt/USB4 controller but no link adapter ' +
        'appeared. Confirm the OTHER laptop also has Thunderbolt/USB4 and that the cable is ' +
        'Thunderbolt-rated, not a plain USB-C cable.')
}

Write-Host ''
Write-Host ("VERDICT : {0}" -f $report.verdict)
Write-Host ("GUIDANCE: {0}" -f $report.guidance)

$json = Join-Path $evidence "link_detect-$stamp.json"
$report | ConvertTo-Json -Depth 5 | Out-File -FilePath $json -Encoding utf8
# Also write a stable-named copy so the task ledger has a fixed artefact to find.
$report | ConvertTo-Json -Depth 5 | Out-File -FilePath (Join-Path $evidence 'link_detect.json') -Encoding utf8
Write-Host ''
Write-Host ("written : {0}" -f $json)
