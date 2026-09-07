$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$BuildRoot = Join-Path $ProjectRoot "build"
$DistRoot = Join-Path $BuildRoot "dist"
$PyInstallerRoot = Join-Path $BuildRoot "pyinstaller"

if (Test-Path $DistRoot) { Remove-Item -LiteralPath $DistRoot -Recurse -Force }
if (Test-Path $PyInstallerRoot) { Remove-Item -LiteralPath $PyInstallerRoot -Recurse -Force }
New-Item -ItemType Directory -Path $BuildRoot -Force | Out-Null

py -m py_compile (Join-Path $ProjectRoot "drex_app.py")
$MethodsData = (Join-Path $ProjectRoot "methods") + ";methods"
py -m PyInstaller --noconfirm --clean --windowed --onefile `
  --name DREX `
  --add-data $MethodsData `
  --distpath $DistRoot `
  --workpath $PyInstallerRoot `
  --specpath $BuildRoot `
  (Join-Path $ProjectRoot "drex_app.py")

if (-not (Test-Path (Join-Path $DistRoot "DREX.exe"))) { throw "PyInstaller did not produce DREX.exe" }
& (Join-Path $DistRoot "DREX.exe") --self-test
