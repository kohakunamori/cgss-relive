param(
    [string]$Package = "jp.co.bandainamcoent.BNEI0242",
    [string]$Serial = "",
    [string]$OutputRoot = "work/apk"
)

$ErrorActionPreference = "Stop"

function Invoke-Adb {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
    $base = @()
    if ($Serial) { $base += @("-s", $Serial) }
    & adb @base @Args
    if ($LASTEXITCODE -ne 0) {
        throw "adb command failed: adb $($base -join ' ') $($Args -join ' ')"
    }
}

if (-not (Get-Command adb -ErrorAction SilentlyContinue)) {
    throw "adb was not found in PATH. Install Android platform-tools first."
}

$state = (Invoke-Adb get-state 2>$null | Select-Object -Last 1).Trim()
if ($state -ne "device") {
    throw "No usable Android device detected by adb. Current state: '$state'"
}

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outDir = Join-Path $OutputRoot $stamp
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

Write-Host "[1/4] Reading package metadata: $Package"
$dumpsys = (Invoke-Adb shell dumpsys package $Package) -join "`n"
if (-not $dumpsys.Trim()) {
    throw "Package '$Package' was not found on the connected device."
}
$dumpsys | Set-Content -Encoding UTF8 (Join-Path $outDir "package-dumpsys.txt")

$versionName = if ($dumpsys -match 'versionName=([^\s]+)') { $Matches[1] } else { $null }
$versionCode = if ($dumpsys -match 'versionCode=(\d+)') { $Matches[1] } else { $null }

Write-Host "[2/4] Enumerating installed APK paths"
$pathLines = Invoke-Adb shell pm path $Package
$remotePaths = @(
    $pathLines |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -like 'package:*' } |
        ForEach-Object { $_.Substring('package:'.Length) }
)

if ($remotePaths.Count -eq 0) {
    throw "No APK paths were returned for '$Package'."
}

$entries = @()
Write-Host "[3/4] Pulling $($remotePaths.Count) APK file(s)"
for ($i = 0; $i -lt $remotePaths.Count; $i++) {
    $remote = $remotePaths[$i]
    $leaf = Split-Path -Leaf $remote
    if (-not $leaf) { $leaf = "split-$i.apk" }

    # Keep names deterministic while avoiding collisions across split locations.
    $localName = if ($i -eq 0 -and $leaf -eq 'base.apk') { 'base.apk' } else { "{0:D2}-{1}" -f $i, $leaf }
    $local = Join-Path $outDir $localName

    Write-Host "  <- $remote"
    Invoke-Adb pull $remote $local | Out-Host

    $file = Get-Item $local
    $sha256 = (Get-FileHash -Algorithm SHA256 $local).Hash.ToLowerInvariant()
    $entries += [ordered]@{
        remote_path = $remote
        file = $localName
        size = $file.Length
        sha256 = $sha256
    }
}

Write-Host "[4/4] Writing acquisition manifest"
$manifest = [ordered]@{
    package = $Package
    version_name = $versionName
    version_code = $versionCode
    adb_serial = if ($Serial) { $Serial } else { (Invoke-Adb get-serialno | Select-Object -Last 1).Trim() }
    acquired_at = (Get-Date).ToUniversalTime().ToString('o')
    files = $entries
}

$manifest | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 (Join-Path $outDir "manifest.json")

Write-Host ""
Write-Host "APK set saved to: $outDir"
Write-Host "Version: $versionName ($versionCode)"
Write-Host "Next: python ./scripts/inspect-apk.py '$outDir'"
