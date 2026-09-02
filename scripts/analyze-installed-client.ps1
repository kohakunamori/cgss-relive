param(
    [string]$Package = "jp.co.bandainamcoent.BNEI0242",
    [string]$Serial = "",
    [string]$OutputRoot = "work/apk",
    [string]$SpecimenDir = "",
    [switch]$SkipPull,
    [switch]$Decompile
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir

function Resolve-Python {
    if (Get-Command python -ErrorAction SilentlyContinue) {
        return @("python")
    }
    if (Get-Command py -ErrorAction SilentlyContinue) {
        return @("py", "-3")
    }
    throw "Python 3 was not found in PATH."
}

function Invoke-PythonScript {
    param(
        [string]$Script,
        [string[]]$Arguments
    )
    $py = Resolve-Python
    $exe = $py[0]
    $prefix = @()
    if ($py.Count -gt 1) { $prefix = $py[1..($py.Count - 1)] }
    & $exe @prefix $Script @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Python helper failed: $Script"
    }
}

function Resolve-RootPath {
    param([string]$PathValue)
    if ([System.IO.Path]::IsPathRooted($PathValue)) {
        return $PathValue
    }
    return (Join-Path $RepoRoot $PathValue)
}

function Get-LatestSpecimenDirectory {
    param([string]$Root)
    $rootPath = Resolve-RootPath $Root
    if (-not (Test-Path $rootPath)) {
        throw "Specimen root does not exist: $rootPath"
    }
    $dirs = @(Get-ChildItem -Path $rootPath -Directory | Sort-Object LastWriteTimeUtc -Descending)
    if ($dirs.Count -eq 0) {
        throw "No specimen directories found under: $rootPath"
    }
    return $dirs[0].FullName
}

function Record-ToolVersions {
    param([string]$Destination)
    $lines = @()
    $commands = @(
        @{ Name = "adb"; Args = @("version") },
        @{ Name = "java"; Args = @("-version") },
        @{ Name = "jadx"; Args = @("--version") },
        @{ Name = "apktool"; Args = @("--version") },
        @{ Name = "apksigner"; Args = @("version") },
        @{ Name = "python"; Args = @("--version") }
    )

    foreach ($cmd in $commands) {
        $lines += "===== $($cmd.Name) ====="
        if (Get-Command $cmd.Name -ErrorAction SilentlyContinue) {
            $output = & $cmd.Name @($cmd.Args) 2>&1
            $lines += ($output | ForEach-Object { $_.ToString() })
        } else {
            $lines += "not found in PATH"
        }
        $lines += ""
    }
    $lines | Set-Content -Encoding UTF8 $Destination
}

Push-Location $RepoRoot
try {
    if (-not $SkipPull) {
        Write-Host "=== Phase 1: acquire installed APK specimen ==="
        $pullArgs = @("-Package", $Package, "-OutputRoot", $OutputRoot)
        if ($Serial) { $pullArgs += @("-Serial", $Serial) }
        # The acquisition helper uses $ErrorActionPreference=Stop and throws on adb failure,
        # so do not inspect the native-command $LASTEXITCODE left over from inside it.
        & (Join-Path $ScriptDir "pull-installed-apk.ps1") @pullArgs
        $SpecimenDir = Get-LatestSpecimenDirectory -Root $OutputRoot
    } elseif (-not $SpecimenDir) {
        $SpecimenDir = Get-LatestSpecimenDirectory -Root $OutputRoot
    } else {
        $SpecimenDir = Resolve-RootPath $SpecimenDir
    }

    $SpecimenDir = (Resolve-Path $SpecimenDir).Path
    Write-Host "Specimen: $SpecimenDir"

    Write-Host "=== Phase 2: fingerprint APK set ==="
    Invoke-PythonScript `
        -Script (Join-Path $ScriptDir "inspect-apk.py") `
        -Arguments @($SpecimenDir, "-o", (Join-Path $SpecimenDir "inspection.json"))

    Write-Host "=== Phase 3: extract minimal reverse-engineering targets ==="
    $analysisDir = Join-Path $SpecimenDir "analysis-targets"
    Invoke-PythonScript `
        -Script (Join-Path $ScriptDir "extract-analysis-targets.py") `
        -Arguments @($SpecimenDir, "-o", $analysisDir)

    Write-Host "=== Phase 4: scan protocol/resource indicators ==="
    Invoke-PythonScript `
        -Script (Join-Path $ScriptDir "scan-analysis-targets.py") `
        -Arguments @($analysisDir, "-o", (Join-Path $analysisDir "string-scan.json"))

    Write-Host "=== Phase 5: record signer/tool provenance ==="
    Record-ToolVersions -Destination (Join-Path $SpecimenDir "tool-versions.txt")

    $apkFiles = @(Get-ChildItem -Path $SpecimenDir -Filter "*.apk" -File | Sort-Object Name)
    if ($apkFiles.Count -eq 0) {
        throw "No APK files remain in specimen directory: $SpecimenDir"
    }

    $certPath = Join-Path $SpecimenDir "signing-certificates.txt"
    if (Get-Command apksigner -ErrorAction SilentlyContinue) {
        $certLines = @()
        foreach ($apk in $apkFiles) {
            $certLines += "===== $($apk.Name) ====="
            $certLines += (& apksigner verify --print-certs $apk.FullName 2>&1 | ForEach-Object { $_.ToString() })
            $certLines += ""
        }
        $certLines | Set-Content -Encoding UTF8 $certPath
        Write-Host "Signing certificate report: $certPath"
    } else {
        "apksigner not found in PATH; install Android SDK Build-Tools and rerun signer verification." |
            Set-Content -Encoding UTF8 $certPath
        Write-Warning "apksigner not found; signer fingerprint was not collected."
    }

    if ($Decompile) {
        Write-Host "=== Optional Phase 6: bulk decompilation ==="
        if (Get-Command jadx -ErrorAction SilentlyContinue) {
            $jadxOut = Join-Path $SpecimenDir "jadx-out"
            New-Item -ItemType Directory -Force -Path $jadxOut | Out-Null
            $apkPaths = @($apkFiles | ForEach-Object { $_.FullName })
            & jadx -d $jadxOut @apkPaths
            if ($LASTEXITCODE -ne 0) { Write-Warning "jadx returned exit code $LASTEXITCODE" }
        } else {
            Write-Warning "jadx not found; skipping DEX decompilation."
        }

        $baseApk = $apkFiles | Where-Object { $_.Name -eq "base.apk" } | Select-Object -First 1
        if (-not $baseApk) { $baseApk = $apkFiles | Select-Object -First 1 }
        if ($baseApk -and (Get-Command apktool -ErrorAction SilentlyContinue)) {
            $apktoolOut = Join-Path $SpecimenDir "apktool-out"
            & apktool d -f $baseApk.FullName -o $apktoolOut
            if ($LASTEXITCODE -ne 0) { Write-Warning "apktool returned exit code $LASTEXITCODE" }
        } else {
            Write-Warning "apktool not found or no APK found; skipping resources/smali decode."
        }
    }

    Write-Host ""
    Write-Host "=== Analysis complete ==="
    Write-Host "Share/review these metadata outputs first (not the APKs):"
    Write-Host "  $SpecimenDir\manifest.json"
    Write-Host "  $SpecimenDir\inspection.json"
    Write-Host "  $analysisDir\analysis-targets.json"
    Write-Host "  $analysisDir\string-scan.json"
    Write-Host "  $certPath"
    Write-Host "  $SpecimenDir\tool-versions.txt"
} finally {
    Pop-Location
}
