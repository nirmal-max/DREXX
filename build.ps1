$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$BuildRoot = Join-Path $ProjectRoot "build"
$DistRoot = Join-Path $BuildRoot "dist"
$PyInstallerRoot = Join-Path $BuildRoot "pyinstaller"
$NativeRoot = Join-Path $ProjectRoot "native_bin"

if (Test-Path $DistRoot) { Remove-Item -LiteralPath $DistRoot -Recurse -Force }
if (Test-Path $PyInstallerRoot) { Remove-Item -LiteralPath $PyInstallerRoot -Recurse -Force }
New-Item -ItemType Directory -Path $BuildRoot -Force | Out-Null

# Build native engines when the required local toolchain exists. Never create
# placeholder binaries: without CMake the application remains usable, but the
# recovery cards correctly remain unavailable.
$cmake = Get-Command cmake -ErrorAction SilentlyContinue
if ($cmake) {
  $nativeModules = @(
    @{ Dir = "Module1_Quick_Recovery_Production_Baseline_v0.1.0\module1_quick_recovery"; Exe = "quickscan.exe" },
    @{ Dir = "Module2_Smart_Recovery_Production_Baseline_v0.1.0\module2_smart_recovery"; Exe = "smartscan.exe" },
    @{ Dir = "Module3_Targeted_Recovery_Production_Baseline_v0.1.0\module3_targeted_recovery"; Exe = "targetedscan.exe" },
    @{ Dir = "Module4_Filesystem_Recovery_Production_Baseline_v0.1.0\module4_filesystem_recovery"; Exe = "fsrecover.exe" },
    @{ Dir = "Module5_Deep_Recovery_Production_Baseline_v0.1.0\module5_deep_recovery"; Exe = "deepscan.exe" },
    @{ Dir = "Module6_Fragment_Recovery_Production_Baseline_v0.1.0\module6_fragment_recovery"; Exe = "fragmentscan.exe" },
    @{ Dir = "Module7_Storage_RAID_Recovery_Production_Baseline_v0.1.0\module7_storage_raid_recovery"; Exe = "raidscan.exe" },
    @{ Dir = "Module8_Damaged_Media_Recovery_Production_Baseline_v0.1.0\module8_damaged_media"; Exe = "mediaimager.exe" },
    @{ Dir = "Module9_Forensic_Recovery_Production_Baseline_v0.1.0\module9_forensic_recovery"; Exe = "forensicctl.exe" }
  )
  New-Item -ItemType Directory -Path $NativeRoot -Force | Out-Null
  foreach ($native in $nativeModules) {
    $source = Join-Path $ProjectRoot ("methods\Recovery\" + $native.Dir)
    if (-not (Test-Path (Join-Path $source "CMakeLists.txt"))) { throw "Missing native module build file: $source" }
    $nativeBuild = Join-Path $BuildRoot ("native\" + ($native.Dir -replace "[\\/]", "_"))
    cmake -S $source -B $nativeBuild -A x64
    if ($LASTEXITCODE -ne 0) { throw "CMake configure failed for $source" }
    cmake --build $nativeBuild --config Release
    if ($LASTEXITCODE -ne 0) { throw "Native build failed for $source" }
    $built = Get-ChildItem $nativeBuild -Recurse -Filter $native.Exe | Select-Object -First 1
    if (-not $built) { throw "Expected native executable was not produced: $($native.Exe)" }
    Copy-Item -LiteralPath $built.FullName -Destination (Join-Path $NativeRoot $native.Exe) -Force
  }
} else {
  Write-Warning "CMake is unavailable; native recovery binaries were not built."
}

py -m py_compile (Join-Path $ProjectRoot "drex_app.py")
$MethodsData = (Join-Path $ProjectRoot "methods") + ";methods"
$NativeBin = Join-Path $ProjectRoot "native_bin"
$DataArgs = @("--add-data", $MethodsData)
if (Test-Path $NativeBin) { $DataArgs += @("--add-data", ($NativeBin + ";native_bin")) }
py -m PyInstaller --noconfirm --clean --windowed --onefile `
  --name DREX `
  @DataArgs `
  --distpath $DistRoot `
  --workpath $PyInstallerRoot `
  --specpath $BuildRoot `
  (Join-Path $ProjectRoot "drex_app.py")

if (-not (Test-Path (Join-Path $DistRoot "DREX.exe"))) { throw "PyInstaller did not produce DREX.exe" }
& (Join-Path $DistRoot "DREX.exe") --self-test
