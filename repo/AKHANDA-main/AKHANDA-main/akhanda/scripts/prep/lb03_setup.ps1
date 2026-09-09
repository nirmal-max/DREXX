<#
LB-03 SETUP, run ONCE, in an ELEVATED PowerShell, on the LOQ.

Creates a separate Windows account for the witness and makes its key unreadable to the
operator account. The point is not that the key is in a different folder; it is that a
DIFFERENT SECURITY PRINCIPAL owns it, so co-signing requires a second login and cannot be
done by the process that performs the erasure.

PATH NOTE: the key is at .akhanda-witness (HYPHEN), matching
src/witness/node.py:54 WITNESS_HOME. An earlier draft of the runbook said
.akhanda_witness with an underscore; icacls on a non-existent path succeeds at doing
nothing, and the boundary would have looked configured while being wide open.

After this, log in as `witness` once so the profile is created, run the node there to
generate the key, then run lb03_verify.ps1 from the OPERATOR account.
#>
$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this in an elevated PowerShell (Run as Administrator)."
}

$user = 'witness'

if (Get-LocalUser -Name $user -ErrorAction SilentlyContinue) {
    Write-Host "[skip] local account '$user' already exists"
} else {
    $pw = Read-Host "Password for the new '$user' account" -AsSecureString
    New-LocalUser -Name $user -Password $pw -FullName 'AKHANDA Witness' `
        -Description 'Independent co-signer. Not the operator.' -PasswordNeverExpires
    Add-LocalGroupMember -Group 'Users' -Member $user
    Write-Host "[ok] created local account '$user' (standard user, not admin)"
}

Write-Host ""
Write-Host "NEXT, IN ORDER:" -ForegroundColor Yellow
Write-Host "  1. Log in as '$user' (or: runas /user:$user powershell)"
Write-Host "  2. In that session, from the repo:  python src\witness\node.py"
Write-Host "     Let it boot once so \$env:USERPROFILE\.akhanda-witness\concur_key.pem exists, then stop it."
Write-Host "  3. Still as '$user', ELEVATED, lock the key down:"
Write-Host ""
Write-Host '     icacls "$env:USERPROFILE\.akhanda-witness" /inheritance:r /grant:r "witness:(OI)(CI)F" /grant:r "SYSTEM:(OI)(CI)F" /T' -ForegroundColor Cyan
Write-Host ""
Write-Host "     /inheritance:r is the load-bearing flag. Without it the inherited"
Write-Host "     Administrators and Users ACEs survive and the operator still reads the key."
Write-Host "  4. Log back in as the OPERATOR and run:  scripts\prep\lb03_verify.ps1"
