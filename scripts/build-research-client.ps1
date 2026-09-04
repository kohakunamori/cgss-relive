param(
    [Parameter(Mandatory = $true)]
    [string]$SpecimenDir,
    [string]$OutputDir = "work/research-client",
    [string]$Keystore = "",
    [string]$KeyAlias = "cgss-research",
    [string]$StorePass = "android",
    [string]$KeyPass = "android"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
$AndroidNs = "http://schemas.android.com/apk/res/android"
$ExpectedPackage = "jp.co.bandainamcoent.BNEI0242"
$ExpectedVersionName = "11.6.3"
$ExpectedVersionCode = "438"

function Resolve-RepoPath {
    param([string]$PathValue)
    if ([System.IO.Path]::IsPathRooted($PathValue)) {
        return $PathValue
    }
    return Join-Path $RepoRoot $PathValue
}

function Require-Command {
    param([string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "$Name was not found in PATH."
    }
}

function Invoke-Checked {
    param(
        [string]$Exe,
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$Args
    )
    & $Exe @Args
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed ($LASTEXITCODE): $Exe $($Args -join ' ')"
    }
}

Require-Command "apktool"
Require-Command "zipalign"
Require-Command "apksigner"
Require-Command "keytool"

$SpecimenDir = (Resolve-Path (Resolve-RepoPath $SpecimenDir)).Path
$manifestPath = Join-Path $SpecimenDir "manifest.json"
if (-not (Test-Path $manifestPath)) {
    throw "manifest.json is required. Acquire the APK set with scripts/pull-installed-apk.ps1 first."
}

$manifest = Get-Content -Raw $manifestPath | ConvertFrom-Json
if ($manifest.package -ne $ExpectedPackage) {
    throw "Unexpected package '$($manifest.package)'; expected '$ExpectedPackage'."
}
if ([string]$manifest.version_name -ne $ExpectedVersionName) {
    throw "Unexpected versionName '$($manifest.version_name)'; expected '$ExpectedVersionName'."
}
if ([string]$manifest.version_code -ne $ExpectedVersionCode) {
    throw "Unexpected versionCode '$($manifest.version_code)'; expected '$ExpectedVersionCode'."
}

$baseEntry = @($manifest.files | Where-Object { $_.file -eq "base.apk" }) | Select-Object -First 1
if (-not $baseEntry) {
    throw "The specimen manifest does not contain base.apk."
}
$baseApk = Join-Path $SpecimenDir $baseEntry.file
if (-not (Test-Path $baseApk)) {
    throw "base.apk is missing: $baseApk"
}

$OutputDir = Resolve-RepoPath $OutputDir
$staging = Join-Path $OutputDir "staging"
$decoded = Join-Path $staging "base-decoded"
$unsignedDir = Join-Path $staging "unsigned"
$alignedDir = Join-Path $staging "aligned"
$signedDir = Join-Path $OutputDir "apks"

if (Test-Path $OutputDir) {
    Remove-Item -Recurse -Force $OutputDir
}
New-Item -ItemType Directory -Force -Path $decoded, $unsignedDir, $alignedDir, $signedDir | Out-Null

if (-not $Keystore) {
    $Keystore = Join-Path $OutputDir "cgss-research.jks"
} else {
    $Keystore = Resolve-RepoPath $Keystore
}

if (-not (Test-Path $Keystore)) {
    Write-Host "Generating local research signing key: $Keystore"
    Invoke-Checked keytool `
        -genkeypair `
        -keystore $Keystore `
        -storepass $StorePass `
        -keypass $KeyPass `
        -alias $KeyAlias `
        -keyalg RSA `
        -keysize 2048 `
        -validity 10000 `
        -dname "CN=CGSS Relive Research, OU=Research, O=Local, L=Local, ST=Local, C=US"
}

Write-Host "[1/6] Decoding base APK without decompiling DEX"
Invoke-Checked apktool d -f -s $baseApk -o $decoded

$decodedManifestPath = Join-Path $decoded "AndroidManifest.xml"
if (-not (Test-Path $decodedManifestPath)) {
    throw "apktool did not produce AndroidManifest.xml"
}

Write-Host "[2/6] Enabling research-only Android network/debug configuration"
[xml]$xml = Get-Content -Raw $decodedManifestPath
$app = $xml.manifest.application
if (-not $app) {
    throw "Decoded manifest does not contain <application>."
}
$app.SetAttribute("debuggable", $AndroidNs, "true")
$app.SetAttribute("usesCleartextTraffic", $AndroidNs, "true")
$app.SetAttribute("networkSecurityConfig", $AndroidNs, "@xml/relive_network_security_config")
$xml.Save($decodedManifestPath)

$resXml = Join-Path $decoded "res/xml"
New-Item -ItemType Directory -Force -Path $resXml | Out-Null
@'
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>
'@ | Set-Content -Encoding UTF8 (Join-Path $resXml "relive_network_security_config.xml")

Write-Host "[3/6] Rebuilding modified base APK"
$rebuiltBase = Join-Path $unsignedDir "base.apk"
Invoke-Checked apktool b $decoded -o $rebuiltBase

foreach ($entry in @($manifest.files)) {
    if ($entry.file -eq "base.apk") { continue }
    $source = Join-Path $SpecimenDir $entry.file
    if (-not (Test-Path $source)) {
        throw "Split listed in manifest is missing: $source"
    }
    Copy-Item -Force $source (Join-Path $unsignedDir $entry.file)
}

Write-Host "[4/6] Aligning base and split APKs"
$unsignedApks = @(Get-ChildItem -Path $unsignedDir -Filter "*.apk" -File | Sort-Object Name)
foreach ($apk in $unsignedApks) {
    $aligned = Join-Path $alignedDir $apk.Name
    Invoke-Checked zipalign -f 4 $apk.FullName $aligned
}

Write-Host "[5/6] Re-signing the entire APK set with one local research key"
$records = @()
foreach ($apk in @(Get-ChildItem -Path $alignedDir -Filter "*.apk" -File | Sort-Object Name)) {
    $signed = Join-Path $signedDir $apk.Name
    Invoke-Checked apksigner sign `
        --ks $Keystore `
        --ks-key-alias $KeyAlias `
        --ks-pass "pass:$StorePass" `
        --key-pass "pass:$KeyPass" `
        --out $signed `
        $apk.FullName
    Invoke-Checked apksigner verify --verbose $signed

    $sourceEntry = @($manifest.files | Where-Object { $_.file -eq $apk.Name }) | Select-Object -First 1
    $records += [ordered]@{
        file = $apk.Name
        source_sha256 = if ($sourceEntry) { [string]$sourceEntry.sha256 } else { $null }
        research_sha256 = (Get-FileHash -Algorithm SHA256 $signed).Hash.ToLowerInvariant()
        size = (Get-Item $signed).Length
    }
}

Write-Host "[6/6] Writing local build manifest"
$buildManifest = [ordered]@{
    schema = 1
    purpose = "research-fixed instrumentation client; not an untouched-client acceptance artifact"
    source_package = $ExpectedPackage
    source_version_name = $ExpectedVersionName
    source_version_code = [int]$ExpectedVersionCode
    modifications = @(
        "android:debuggable=true",
        "android:usesCleartextTraffic=true",
        "android:networkSecurityConfig=@xml/relive_network_security_config",
        "network security config trusts system and user certificate stores",
        "all APK splits re-signed with one local research key"
    )
    files = $records
}
$buildManifest | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 (Join-Path $OutputDir "research-build.json")

Write-Host ""
Write-Host "Research APK set built successfully:"
Write-Host "  $signedDir"
Write-Host ""
Write-Warning "The APK set is signed with a local research key. It cannot replace the Play-signed original package without uninstalling the original installation first. Preserve any local data you need before doing that."
Write-Host "Install all APKs together with scripts/install-research-client.ps1."
