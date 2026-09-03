param(
    [string]$Serial,
    [string]$Package = 'jp.co.bandainamcoent.BNEI0242',
    [string]$Activity = 'jp.co.cygames.stage.StageUnityPlayerActivity',
    [string]$ExpectedVersionName = '11.6.3',
    [int]$ExpectedVersionCode = 438,
    [int]$WaitForProcessSeconds = 120,
    [string]$Python = 'python',
    [string]$RawPath,
    [string]$SanitizedPath,
    [switch]$ClearBuffer,
    [switch]$Launch,
    [switch]$PreserveProcess
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Command adb -ErrorAction SilentlyContinue)) {
    throw 'adb was not found in PATH'
}
if (-not (Get-Command $Python -ErrorAction SilentlyContinue)) {
    throw "Python executable was not found: $Python"
}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$Timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
if (-not $RawPath) {
    $RawPath = Join-Path $RepoRoot "work/private/cgss-logcat-$Timestamp.txt"
}
if (-not $SanitizedPath) {
    $SanitizedPath = Join-Path $RepoRoot "work/runtime-device-$Timestamp.jsonl"
}
$RawPath = [System.IO.Path]::GetFullPath($RawPath)
$SanitizedPath = [System.IO.Path]::GetFullPath($SanitizedPath)
$Sanitizer = Join-Path $RepoRoot 'scripts/sanitize-device-logcat.py'

New-Item -ItemType Directory -Force -Path ([System.IO.Path]::GetDirectoryName($RawPath)) | Out-Null
New-Item -ItemType Directory -Force -Path ([System.IO.Path]::GetDirectoryName($SanitizedPath)) | Out-Null

$AdbPrefix = @()
if ($Serial) { $AdbPrefix = @('-s', $Serial) }

function Invoke-AdbCapture {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [switch]$AllowFailure
    )
    $text = (& adb @AdbPrefix @Arguments 2>$null | Out-String).Trim()
    $code = $LASTEXITCODE
    if (-not $AllowFailure -and $code -ne 0) {
        throw "adb command failed with exit code $code"
    }
    return [pscustomobject]@{ Text = $text; ExitCode = $code }
}

$state = Invoke-AdbCapture -Arguments @('get-state') -AllowFailure
if ($state.ExitCode -ne 0 -or $state.Text -ne 'device') {
    throw 'ADB target is not in device state'
}

if ($Launch) {
    # The Activity default is derived from the exact hash-verified final 11.6.3
    # XAPK with aapt; do not substitute a guessed UnityPlayerActivity name.
    $packageResult = Invoke-AdbCapture -Arguments @('shell', 'dumpsys', 'package', $Package) -AllowFailure
    $versionName = $null
    $versionCode = $null
    if ($packageResult.Text -match '(?m)^\s*versionName=(\S+)\s*$') {
        $versionName = $Matches[1]
    }
    if ($packageResult.Text -match '(?m)^\s*versionCode=(\d+)\b') {
        $versionCode = [int64]$Matches[1]
    }
    if ($versionName -ne $ExpectedVersionName -or $versionCode -ne $ExpectedVersionCode) {
        throw "Installed package is not the expected final $ExpectedVersionName / versionCode $ExpectedVersionCode specimen"
    }

    if (-not $PreserveProcess) {
        $stop = Invoke-AdbCapture -Arguments @('shell', 'am', 'force-stop', $Package) -AllowFailure
        if ($stop.ExitCode -ne 0) {
            throw 'Failed to stop the existing target process before exact launch'
        }
    }
}

if ($ClearBuffer) {
    $clear = Invoke-AdbCapture -Arguments @('logcat', '-c') -AllowFailure
    if ($clear.ExitCode -ne 0) {
        throw 'Failed to clear device logcat buffer'
    }
}

if ($Launch) {
    $component = "$Package/$Activity"
    $start = Invoke-AdbCapture -Arguments @('shell', 'am', 'start', '-W', '-n', $component) -AllowFailure
    if ($start.ExitCode -ne 0) {
        throw "Exact final launchable activity failed to start: $component"
    }
    Write-Host "Started exact final launchable activity: $component"
}

Write-Host "Waiting for target package process: $Package"
$deadline = [DateTimeOffset]::UtcNow.AddSeconds([Math]::Max($WaitForProcessSeconds, 0))
$TargetPid = $null
while ([DateTimeOffset]::UtcNow -le $deadline) {
    $pidResult = Invoke-AdbCapture -Arguments @('shell', 'pidof', '-s', $Package) -AllowFailure
    if ($pidResult.ExitCode -eq 0 -and $pidResult.Text -match '^\d+$') {
        $TargetPid = $pidResult.Text
        break
    }
    Start-Sleep -Milliseconds 250
}
if (-not $TargetPid) {
    throw "Target package process did not appear within $WaitForProcessSeconds seconds"
}

Write-Host 'Capturing package-scoped logcat privately. Press Ctrl+C after reproducing the startup failure/success.'
Write-Host "Raw private capture: $RawPath"
Write-Host "Sanitized evidence: $SanitizedPath"

$captureFailed = $false
try {
    # Do not tee raw lines to the terminal. `work/` is gitignored because raw
    # messages may contain URLs, identifiers, certificate details or headers.
    & adb @AdbPrefix logcat "--pid=$TargetPid" -v epoch 2>$null |
        Out-File -FilePath $RawPath -Encoding utf8
    if ($LASTEXITCODE -ne 0) {
        $captureFailed = $true
    }
}
finally {
    if (Test-Path -LiteralPath $RawPath -PathType Leaf) {
        & $Python $Sanitizer $RawPath -o $SanitizedPath
        if ($LASTEXITCODE -ne 0) {
            throw 'Device logcat sanitizer failed'
        }
        Write-Host 'Sanitized device evidence generated. Share the sanitized JSONL, not the raw capture.'
    }
}

if ($captureFailed) { exit 2 }
exit 0
