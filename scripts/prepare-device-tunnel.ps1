param(
    [string]$Serial,
    [int]$DevicePort = 443,
    [int]$HostPort = 8445,
    [int]$RootRedirectPort = 8443,
    [switch]$Remove,
    [switch]$RequireRoot
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Command adb -ErrorAction SilentlyContinue)) {
    throw 'adb was not found in PATH'
}

$AdbPrefix = @()
if ($Serial) { $AdbPrefix = @('-s', $Serial) }

function Invoke-Adb {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
    & adb @AdbPrefix @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "adb failed: adb $($AdbPrefix -join ' ') $($Arguments -join ' ')"
    }
}

Invoke-Adb wait-for-device | Out-Null

$state = (& adb @AdbPrefix get-state 2>$null | Out-String).Trim()
if ($LASTEXITCODE -ne 0 -or $state -ne 'device') {
    throw "ADB target is not ready (state: $state)"
}

$rootResult = (& adb @AdbPrefix shell su -c id 2>$null | Out-String).Trim()
$hasRoot = $LASTEXITCODE -eq 0 -and $rootResult -match 'uid=0'
if ($RequireRoot -and -not $hasRoot) {
    throw 'Root check failed: adb shell su -c id did not return uid=0'
}

$spec = "tcp:$DevicePort"
$redirectSpec = "tcp:$RootRedirectPort"

if ($Remove) {
    & adb @AdbPrefix reverse --remove $spec 2>$null | Out-Null
    & adb @AdbPrefix reverse --remove $redirectSpec 2>$null | Out-Null
    if ($hasRoot) {
        & adb @AdbPrefix shell su -c "iptables -t nat -D OUTPUT -p tcp -d 127.0.0.1 --dport $DevicePort -j REDIRECT --to-ports $RootRedirectPort" 2>$null | Out-Null
    }
    Write-Host "Removed CGSS ADB reverse/root redirect for device port $DevicePort"
    exit 0
}

$directOutput = (& adb @AdbPrefix reverse $spec "tcp:$HostPort" 2>&1 | Out-String).Trim()
$directExit = $LASTEXITCODE
if ($directExit -eq 0) {
    $listed = (& adb @AdbPrefix reverse --list | Out-String)
    if ($LASTEXITCODE -ne 0 -or $listed -notmatch [regex]::Escape("tcp:$DevicePort tcp:$HostPort")) {
        throw "ADB reverse did not appear in reverse --list: tcp:$DevicePort -> tcp:$HostPort"
    }
    Write-Host "ADB reverse ready: device 127.0.0.1:$DevicePort -> host 127.0.0.1:$HostPort"
    Write-Host "Root available: $hasRoot"
} else {
    if (-not $hasRoot) {
        throw "ADB reverse failed and root fallback is unavailable: $directOutput"
    }
    if ($RootRedirectPort -eq $DevicePort) {
        throw 'RootRedirectPort must differ from DevicePort when low-port fallback is required'
    }

    Invoke-Adb reverse $redirectSpec "tcp:$HostPort" | Out-Null
    $check = "iptables -t nat -C OUTPUT -p tcp -d 127.0.0.1 --dport $DevicePort -j REDIRECT --to-ports $RootRedirectPort"
    & adb @AdbPrefix shell su -c $check 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        $add = "iptables -t nat -A OUTPUT -p tcp -d 127.0.0.1 --dport $DevicePort -j REDIRECT --to-ports $RootRedirectPort"
        & adb @AdbPrefix shell su -c $add | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw 'Failed to install root iptables redirect for the privileged device port'
        }
    }

    $listed = (& adb @AdbPrefix reverse --list | Out-String)
    if ($LASTEXITCODE -ne 0 -or $listed -notmatch [regex]::Escape("tcp:$RootRedirectPort tcp:$HostPort")) {
        throw "ADB reverse fallback did not appear in reverse --list: tcp:$RootRedirectPort -> tcp:$HostPort"
    }
    Write-Host "Root tunnel ready: device 127.0.0.1:$DevicePort -> iptables REDIRECT :$RootRedirectPort -> adb reverse -> host 127.0.0.1:$HostPort"
    Write-Host "Direct reverse failure: $directOutput"
}
Write-Host 'Both original hostnames must resolve to 127.0.0.1 on the device:'
Write-Host '  apis.game.starlight-stage.jp'
Write-Host '  storages.game.starlight-stage.jp'
Write-Host 'For HTTPS, the generated test CA must be trusted as a SYSTEM CA on the rooted device.'
