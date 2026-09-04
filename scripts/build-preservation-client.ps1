param(
    [Parameter(Mandatory = $true)]
    [string]$SpecimenDir,
    [string]$PatchManifest = "client/preservation/native-patches.json",
    [string]$OutputDir = "work/preservation-client",
    [string]$NativeSplit = "01-config.arm64_v8a.apk",
    [string]$NativeMember = "lib/arm64-v8a/libunity.so",
    [string]$Keystore = "",
    [string]$KeyAlias = "cgss-preservation",
    [string]$StorePass = "android",
    [string]$KeyPass = "android"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir
$ExpectedPackage = "jp.co.bandainamcoent.BNEI0242"
$ExpectedVersionName = "11.6.3"
$ExpectedVersionCode = "438"
$ExpectedXapkSha256 = "609868c5a4cf5ce78ed653be448717e426410b4df03ca9e0356a046afc0d465d"

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
        [Parameter(Mandatory = $true)]
        [string]$Exe,
        [Parameter(Mandatory = $true)]
        [string[]]$ArgumentList
    )
    & $Exe @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed ($LASTEXITCODE): $Exe $($ArgumentList -join ' ')"
    }
}

Require-Command "python"
Require-Command "zipalign"
Require-Command "apksigner"
Require-Command "keytool"

$SpecimenDir = (Resolve-Path (Resolve-RepoPath $SpecimenDir)).Path
$PatchManifest = (Resolve-Path (Resolve-RepoPath $PatchManifest)).Path
$OutputDir = Resolve-RepoPath $OutputDir

$manifestPath = Join-Path $SpecimenDir "manifest.json"
if (-not (Test-Path $manifestPath)) {
    throw "manifest.json is required in the specimen directory."
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
if (-not $manifest.baseline_exact) {
    throw "Preservation builds require a specimen with baseline_exact=true."
}
if ([string]$manifest.source_xapk_sha256 -ne $ExpectedXapkSha256) {
    throw "Unexpected frozen XAPK hash '$($manifest.source_xapk_sha256)'."
}

$patchConfig = Get-Content -Raw $PatchManifest | ConvertFrom-Json
$patchCount = @($patchConfig.patches).Count
$patchIds = @($patchConfig.patches | ForEach-Object { [string]$_.id })

$staging = Join-Path $OutputDir "staging"
$unsignedDir = Join-Path $staging "unsigned"
$alignedDir = Join-Path $staging "aligned"
$signedDir = Join-Path $OutputDir "apks"
if (Test-Path $OutputDir) {
    Remove-Item -Recurse -Force $OutputDir
}
New-Item -ItemType Directory -Force -Path $unsignedDir, $alignedDir, $signedDir | Out-Null

if (-not $Keystore) {
    $Keystore = Resolve-RepoPath "work/preservation-signing/cgss-preservation.jks"
} else {
    $Keystore = Resolve-RepoPath $Keystore
}
$keystoreDir = Split-Path -Parent $Keystore
if ($keystoreDir) {
    New-Item -ItemType Directory -Force -Path $keystoreDir | Out-Null
}
if (-not (Test-Path $Keystore)) {
    Write-Host "Generating local preservation signing key: $Keystore"
    Invoke-Checked "keytool" @(
        "-genkeypair",
        "-keystore", $Keystore,
        "-storepass", $StorePass,
        "-keypass", $KeyPass,
        "-alias", $KeyAlias,
        "-keyalg", "RSA",
        "-keysize", "2048",
        "-validity", "10000",
        "-dname", "CN=CGSS Relive Preservation, OU=Preservation, O=Local, L=Local, ST=Local, C=US"
    )
}

Write-Host "[1/5] Copying exact frozen APK set"
foreach ($entry in @($manifest.files)) {
    $source = Join-Path $SpecimenDir $entry.file
    if (-not (Test-Path $source)) {
        throw "APK listed in specimen manifest is missing: $source"
    }
    Copy-Item -Force $source (Join-Path $unsignedDir $entry.file)
}

Write-Host "[2/5] Applying declared preservation native patches"
$nativeSplitPath = Join-Path $unsignedDir $NativeSplit
if (-not (Test-Path $nativeSplitPath)) {
    throw "Native split is missing from specimen: $NativeSplit"
}
if ($patchCount -gt 0) {
    $patchedSplitPath = Join-Path $staging "patched-$NativeSplit"
    Invoke-Checked "python" @(
        (Join-Path $ScriptDir "patch-apk-native.py"),
        $nativeSplitPath,
        $patchedSplitPath,
        $PatchManifest,
        "--member", $NativeMember,
        "--repo-root", $RepoRoot
    )
    Move-Item -Force $patchedSplitPath $nativeSplitPath
} else {
    Write-Host "No active native patches; preserving original split bytes before signing."
}

Write-Host "[3/5] Aligning base and split APKs"
foreach ($apk in @(Get-ChildItem -Path $unsignedDir -Filter "*.apk" -File | Sort-Object Name)) {
    Invoke-Checked "zipalign" @("-f", "4", $apk.FullName, (Join-Path $alignedDir $apk.Name))
}

Write-Host "[4/5] Signing the entire preservation APK set"
$records = @()
foreach ($apk in @(Get-ChildItem -Path $alignedDir -Filter "*.apk" -File | Sort-Object Name)) {
    $signed = Join-Path $signedDir $apk.Name
    Invoke-Checked "apksigner" @(
        "sign",
        "--ks", $Keystore,
        "--ks-key-alias", $KeyAlias,
        "--ks-pass", "pass:$StorePass",
        "--key-pass", "pass:$KeyPass",
        "--out", $signed,
        $apk.FullName
    )
    Invoke-Checked "apksigner" @("verify", "--verbose", $signed)
    $sourceEntry = @($manifest.files | Where-Object { $_.file -eq $apk.Name }) | Select-Object -First 1
    $records += [ordered]@{
        file = $apk.Name
        source_sha256 = if ($sourceEntry) { [string]$sourceEntry.sha256 } else { $null }
        preservation_sha256 = (Get-FileHash -Algorithm SHA256 $signed).Hash.ToLowerInvariant()
        size = (Get-Item $signed).Length
    }
}

Write-Host "[5/5] Writing preservation build manifest"
$buildManifest = [ordered]@{
    schema = 1
    purpose = "thin preservation client; environment compatibility only"
    source_package = $ExpectedPackage
    source_version_name = $ExpectedVersionName
    source_version_code = [int]$ExpectedVersionCode
    source_xapk_sha256 = $ExpectedXapkSha256
    patch_manifest_sha256 = (Get-FileHash -Algorithm SHA256 $PatchManifest).Hash.ToLowerInvariant()
    patch_count = $patchCount
    patch_ids = $patchIds
    modifications = @(
        "no Android debug/cleartext/network-security research flags",
        $(if ($patchCount -gt 0) { "declared hash-guarded preservation native patches" } else { "no active native patches" }),
        "all APK splits re-signed with one stable local preservation key"
    )
    files = $records
}
$buildManifest | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 (Join-Path $OutputDir "preservation-build.json")

Write-Host ""
Write-Host "Preservation APK set built successfully:"
Write-Host "  $signedDir"
Write-Warning "This locally signed preservation set cannot update a Play-signed original installation."
