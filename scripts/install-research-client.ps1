param(
    [string]$ApkDir = "work/research-client/apks",
    [string]$Package = "jp.co.bandainamcoent.BNEI0242",
    [string]$Serial = "",
    [switch]$UninstallOriginal
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir

function Resolve-RepoPath {
    param([string]$PathValue)
    if ([System.IO.Path]::IsPathRooted($PathValue)) { return $PathValue }
    return Join-Path $RepoRoot $PathValue
}

function Invoke-Adb {
    param([Parameter(Mandatory = $true)][string[]]$ArgumentList)
    $base = @()
    if ($Serial) { $base += @("-s", $Serial) }
    & adb @base @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "adb command failed: adb $($base -join ' ') $($ArgumentList -join ' ')"
    }
}

if (-not (Get-Command adb -ErrorAction SilentlyContinue)) {
    throw "adb was not found in PATH."
}

$ApkDir = (Resolve-Path (Resolve-RepoPath $ApkDir)).Path
$apks = @(Get-ChildItem -Path $ApkDir -Filter "*.apk" -File | Sort-Object Name)
if ($apks.Count -eq 0) {
    throw "No APKs found under $ApkDir"
}
if (-not ($apks | Where-Object { $_.Name -eq "base.apk" })) {
    throw "The research APK set does not contain base.apk"
}

$installed = $false
try {
    $paths = Invoke-Adb @("shell", "pm", "path", $Package) 2>$null
    $installed = [bool]($paths | Where-Object { $_ -like "package:*" })
} catch {
    $installed = $false
}

if ($installed -and $UninstallOriginal) {
    Write-Warning "Uninstalling $Package removes its app-local data from this device."
    Invoke-Adb @("uninstall", $Package) | Out-Host
    $installed = $false
}

$apkPaths = @($apks | ForEach-Object { $_.FullName })
Write-Host "Installing $($apkPaths.Count) APKs as one split package set..."

try {
    Invoke-Adb (@("install-multiple", "-r") + $apkPaths) | Out-Host
} catch {
    if ($installed -and -not $UninstallOriginal) {
        Write-Host ""
        Write-Warning "The currently installed package is probably signed by the original Play certificate, while the research build uses a local key. Android will not replace it across a signature change."
        Write-Host "Preserve any app-local data you need, then rerun with -UninstallOriginal on the dedicated research device."
    }
    throw
}

Write-Host "Research client installation completed."
