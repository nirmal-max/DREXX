<#
LB-03 VERIFY, run from the OPERATOR account (the one the tool runs under).

THE CAPTURED FAILURE IS THE EVIDENCE. This script tries, as the operator, to read the
witness's private key. It is a PASS when that read FAILS with Access Denied, and a FAIL
when it succeeds. Writes evidence/lb03_witness_boundary.json either way, a boundary that
turns out not to hold is a finding worth keeping, not a run to repeat until it looks good.

    powershell -ExecutionPolicy Bypass -File scripts\prep\lb03_verify.ps1

If the read SUCCEEDS, do not invent new architecture. Switch to the documented fallback:
a passphrase-derived witness key that is never written to disk (the operator cannot read
a file that does not exist), and record in BUILD_LOG.md that the OS boundary was tried
first and did not hold on this machine.
#>
$ErrorActionPreference = 'Continue'

$repo     = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$evidence = Join-Path $repo 'evidence'
New-Item -ItemType Directory -Force -Path $evidence | Out-Null

$keyPath = 'C:\Users\witness\.akhanda-witness\concur_key.pem'
$dirPath = 'C:\Users\witness\.akhanda-witness'

$result = [ordered]@{
    check          = 'LB-03 witness key boundary'
    ran_at         = (Get-Date).ToString('o')
    ran_as         = "$env:USERDOMAIN\$env:USERNAME"
    machine        = $env:COMPUTERNAME
    witness_key    = $keyPath
    dir_exists     = (Test-Path $dirPath)
    key_exists     = (Test-Path $keyPath)
    read_attempted = $false
    read_succeeded = $null
    error_message  = ''
    acl            = ''
    verdict        = ''
    meaning        = ''
}

if (-not $result.key_exists) {
    $result.verdict = 'INCONCLUSIVE'
    $result.meaning = "The witness key does not exist yet. Run lb03_setup.ps1, then boot the node once as the witness account. A missing file denies reads for the wrong reason and proves nothing about the boundary."
} else {
    try { $result.acl = (icacls $dirPath 2>&1 | Out-String).Trim() } catch { $result.acl = "icacls failed: $_" }

    $result.read_attempted = $true
    try {
        $bytes = [System.IO.File]::ReadAllBytes($keyPath)
        $result.read_succeeded = $true
        $result.verdict = 'FAIL - BOUNDARY DOES NOT HOLD'
        $result.meaning = "The operator account read $($bytes.Length) bytes of the witness private key. The two signatures are NOT independent on this machine: whoever runs the erasure can forge the co-signature. Switch to the passphrase-derived fallback key that is never written to disk, and say so plainly rather than presenting this as a two-party system."
    } catch {
        $result.read_succeeded = $false
        $result.error_message  = $_.Exception.Message
        $denied = $_.Exception -is [System.UnauthorizedAccessException]
        if ($denied) {
            $result.verdict = 'PASS - ACCESS DENIED'
            $result.meaning = "The operator account cannot read the witness private key. Co-signing requires the second account, so the second signature is genuinely independent of the party performing the operation. THIS CAPTURED FAILURE IS THE EVIDENCE."
        } else {
            $result.verdict = 'INCONCLUSIVE'
            $result.meaning = "The read failed, but not with Access Denied: $($_.Exception.GetType().FullName). A read that fails for an unrelated reason is not proof of an access boundary."
        }
    }
}

$out = Join-Path $evidence 'lb03_witness_boundary.json'
$result | ConvertTo-Json -Depth 4 | Out-File -FilePath $out -Encoding utf8

Write-Host ""
Write-Host "verdict : $($result.verdict)" -ForegroundColor $(
    if ($result.verdict -like 'PASS*') { 'Green' }
    elseif ($result.verdict -like 'FAIL*') { 'Red' } else { 'Yellow' })
Write-Host "ran as  : $($result.ran_as)"
Write-Host "meaning : $($result.meaning)"
Write-Host "written : $out"
Write-Host ""
Write-Host "Paste the verdict and the error message into docs\BUILD_LOG.md."
