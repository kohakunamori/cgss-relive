param(
    [string]$Serial,
    [string]$Package = 'jp.co.bandainamcoent.BNEI0242',
    [string]$ExpectedActivity = 'jp.co.cygames.stage.StageUnityPlayerActivity',
    [string]$ExpectedVersionName = '11.6.3',
    [int]$ExpectedVersionCode = 438,
    [int]$DevicePort = 443,
    [int]$HostPort = 8445,
    [string]$CaCert = '.\work\tls\ca.cert.pem'
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Command adb -ErrorAction SilentlyContinue)) {
    throw 'adb was not found in PATH'
}

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

function Get-LoopbackHostSet {
    param([string]$HostsText)
    $result = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($line in ($HostsText -split "`r?`n")) {
        $clean = ($line -split '#', 2)[0].Trim()
        if (-not $clean) { continue }
        $parts = @($clean -split '\s+' | Where-Object { $_ })
        if ($parts.Count -lt 2 -or $parts[0] -ne '127.0.0.1') { continue }
        for ($i = 1; $i -lt $parts.Count; $i++) {
            [void]$result.Add($parts[$i])
        }
    }
    return $result
}

$stateResult = Invoke-AdbCapture -Arguments @('get-state') -AllowFailure
$adbReady = $stateResult.ExitCode -eq 0 -and $stateResult.Text -eq 'device'

$rootResult = Invoke-AdbCapture -Arguments @('shell', 'su', '-c', 'id') -AllowFailure
$rootAvailable = $rootResult.ExitCode -eq 0 -and $rootResult.Text -match 'uid=0'

$packageResult = Invoke-AdbCapture -Arguments @('shell', 'dumpsys', 'package', $Package) -AllowFailure
$packagePresent = $packageResult.ExitCode -eq 0 -and $packageResult.Text -match [regex]::Escape("Package [$Package]")
$versionName = $null
$versionCode = $null
if ($packageResult.Text -match '(?m)^\s*versionName=(\S+)\s*$') {
    $versionName = $Matches[1]
}
if ($packageResult.Text -match '(?m)^\s*versionCode=(\d+)\b') {
    $versionCode = [int64]$Matches[1]
}
$versionNameMatches = $versionName -eq $ExpectedVersionName
$versionCodeMatches = $versionCode -eq $ExpectedVersionCode

# Runtime cross-check of the exact launchable activity independently extracted
# from the hash-verified final XAPK. Keep this read-only: PackageManager resolves
# the installed MAIN/LAUNCHER component; no activity is started here.
$launcherResult = Invoke-AdbCapture -Arguments @(
    'shell', 'cmd', 'package', 'resolve-activity', '--brief',
    '-a', 'android.intent.action.MAIN',
    '-c', 'android.intent.category.LAUNCHER',
    $Package
) -AllowFailure
$expectedComponent = "$Package/$ExpectedActivity"
$launcherMatches = $false
if ($launcherResult.ExitCode -eq 0) {
    foreach ($line in ($launcherResult.Text -split "`r?`n")) {
        if ($line.Trim() -eq $expectedComponent) {
            $launcherMatches = $true
            break
        }
    }
}

$reverseResult = Invoke-AdbCapture -Arguments @('reverse', '--list') -AllowFailure
$reverseNeedle = "tcp:$DevicePort tcp:$HostPort"
$reverseReady = $reverseResult.ExitCode -eq 0 -and $reverseResult.Text -match [regex]::Escape($reverseNeedle)

$hostsResult = if ($rootAvailable) {
    Invoke-AdbCapture -Arguments @('shell', 'su', '-c', 'cat /system/etc/hosts 2>/dev/null || cat /etc/hosts 2>/dev/null') -AllowFailure
} else {
    Invoke-AdbCapture -Arguments @('shell', 'cat', '/system/etc/hosts') -AllowFailure
}
$loopbackHosts = Get-LoopbackHostSet -HostsText $hostsResult.Text
$apiHost = 'apis.game.starlight-stage.jp'
$resourceHost = 'storages.game.starlight-stage.jp'
$apiHostReady = $loopbackHosts.Contains($apiHost)
$resourceHostReady = $loopbackHosts.Contains($resourceHost)

$caExactBytesPresent = $null
$caExactBytesChecked = $false
if ($CaCert -and (Test-Path -LiteralPath $CaCert -PathType Leaf) -and $rootAvailable) {
    $localCaHash = (Get-FileHash -LiteralPath $CaCert -Algorithm SHA256).Hash.ToLowerInvariant()
    $caCommand = 'for d in /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts; do [ -d "$d" ] || continue; for f in "$d"/*; do [ -f "$f" ] && sha256sum "$f"; done; done'
    $caResult = Invoke-AdbCapture -Arguments @('shell', 'su', '-c', $caCommand) -AllowFailure
    if ($caResult.ExitCode -eq 0) {
        $caExactBytesChecked = $true
        $caExactBytesPresent = $false
        foreach ($line in ($caResult.Text -split "`r?`n")) {
            $parts = @($line.Trim() -split '\s+' | Where-Object { $_ })
            if ($parts.Count -ge 1 -and $parts[0].ToLowerInvariant() -eq $localCaHash) {
                $caExactBytesPresent = $true
                break
            }
        }
    }
}

$ready = (
    $adbReady -and
    $rootAvailable -and
    $packagePresent -and
    $versionNameMatches -and
    $versionCodeMatches -and
    $launcherMatches -and
    $reverseReady -and
    $apiHostReady -and
    $resourceHostReady
)

$report = [ordered]@{
    schema = 2
    adb_state_ready = $adbReady
    root_available = $rootAvailable
    package_present = $packagePresent
    version_name_matches = $versionNameMatches
    version_code_matches = $versionCodeMatches
    launchable_activity_matches = $launcherMatches
    reverse_443_to_tls_mux = $reverseReady
    api_host_loopback = $apiHostReady
    resource_host_loopback = $resourceHostReady
    ca_exact_bytes_checked = $caExactBytesChecked
    ca_exact_bytes_present = $caExactBytesPresent
    ready = $ready
}

$report | ConvertTo-Json -Depth 4
if (-not $caExactBytesChecked) {
    Write-Warning 'Exact-byte system-CA presence was not confirmed. This does not prove the CA is absent; Android/root-manager certificate representation may differ.'
} elseif (-not $caExactBytesPresent) {
    Write-Warning 'The exact local CA bytes were not found in the checked system CA directories. Confirm system-trust installation before client launch.'
}

if ($ready) { exit 0 }
exit 2
