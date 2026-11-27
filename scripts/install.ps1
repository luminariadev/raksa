[CmdletBinding()]
param(
    [string]$Version = "v0.2.0",
    [string]$InstallDir = (Join-Path $HOME ".raksa\bin")
)

$ErrorActionPreference = "Stop"

$Arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    "ARM64" { "arm64" }
    default { "amd64" }
}

$Pkg = "raksa-$Version-windows-$Arch"
$BaseUrl = "https://github.com/luminariadev/raksa/releases/download/$Version"
$TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("raksa-install-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $TmpDir | Out-Null

try {
    $SumsPath = Join-Path $TmpDir "SHA256SUMS.txt"
    $ZipPath = Join-Path $TmpDir "$Pkg.zip"

    Write-Host "Downloading $Pkg.zip and SHA256SUMS.txt ..."
    Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/SHA256SUMS.txt" -OutFile $SumsPath
    Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/$Pkg.zip" -OutFile $ZipPath

    $ExpectedLine = Get-Content $SumsPath | Where-Object { $_ -match "$Pkg\.zip$" } | Select-Object -First 1
    if (-not $ExpectedLine) {
        throw "Checksum entry for $Pkg.zip not found in SHA256SUMS.txt"
    }
    $ExpectedHash = ($ExpectedLine -split "\s+")[0].ToLowerInvariant()
    $ActualHash = (Get-FileHash -Path $ZipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ActualHash -ne $ExpectedHash) {
        throw "SHA-256 verification failed: expected $ExpectedHash got $ActualHash"
    }

    Expand-Archive -Path $ZipPath -DestinationPath $TmpDir -Force
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Copy-Item -Path (Join-Path $TmpDir "$Pkg\raksa.exe") -Destination (Join-Path $InstallDir "raksa.exe") -Force
    Write-Host "Verified SHA-256 and installed raksa $Version to $InstallDir\raksa.exe"
    Write-Host "Run 'raksa doctor' after ensuring '$InstallDir' is on PATH."
}
finally {
    Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue
}
