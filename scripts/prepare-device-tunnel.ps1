param(
    [string]$Serial,
    [int]$DevicePort = 443,
    [int]$HostPort = 8443,
    [switch]$Remove,
    [switch]$RequireRoot
)

$ErrorActionPreference = 'Stop'

function Invoke-Adb {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Args)
    $base = @()
    if ($Serial) { $base += @('-s', $Serial) }
    & adb @base @Args
    if ($LASTEXITCODE -ne 0) {
        throw "adb failed: adb $($base -join ' ') $($Args -join ' ')"
    }
}

if (-not (Get-Command adb -ErrorAction SilentlyContinue)) {
    throw 'adb was not found in PATH'
}

Invoke-Adb wait-for-device | Out-Null

$state = (& adb $(if ($Serial) { @('-s', $Serial) } else { @() }) get-state 2>$null).Trim()
if ($state -ne 'device') {
    throw "ADB target is not ready (state: $state)"
}

$rootResult = (& adb $(if ($Serial) { @('-s', $Serial) } else { @() }) shell su -c id 2>$null | Out-String).Trim()
$hasRoot = $LASTEXITCODE -eq 0 -and $rootResult -match 'uid=0'
if ($RequireRoot -and -not $hasRoot) {
    throw 'Root check failed: adb shell su -c id did not return uid=0'
}

$spec = "tcp:$DevicePort"
if ($Remove) {
    Invoke-Adb reverse --remove $spec | Out-Null
    Write-Host "Removed ADB reverse $spec"
    exit 0
}

Invoke-Adb reverse $spec "tcp:$HostPort" | Out-Null
$listed = (& adb $(if ($Serial) { @('-s', $Serial) } else { @() }) reverse --list | Out-String)
if ($listed -notmatch [regex]::Escape("tcp:$DevicePort tcp:$HostPort")) {
    throw "ADB reverse did not appear in reverse --list: tcp:$DevicePort -> tcp:$HostPort"
}

Write-Host "ADB reverse ready: device 127.0.0.1:$DevicePort -> host 127.0.0.1:$HostPort"
Write-Host "Root available: $hasRoot"
Write-Host 'The CGSS API hostname must still resolve to 127.0.0.1 on the device.'
Write-Host 'For HTTPS, the test CA must be trusted as a SYSTEM CA on the rooted device.'
