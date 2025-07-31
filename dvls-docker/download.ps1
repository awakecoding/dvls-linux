# download.ps1 - Download Devolutions DVLS tarball for Docker build context
param(
    [string]$Version,
    [ValidateSet('x64','arm64')]
    [string]$Arch = 'x64'
)

$ErrorActionPreference = 'Stop'


# Fetch product info
Write-Host "Fetching DVLS product info..."
$productInfo = Invoke-RestMethod -Uri 'https://devolutions.net/productinfo.json'

if ($Version) {
    $file = $productInfo.DVLS.Files | Where-Object { $_.Type -eq 'tar.gz' -and $_.Arch -eq $Arch -and $_.Version -eq $Version } | Select-Object -First 1
    if (-not $file) {
        Write-Error "Could not find DVLS tarball for version $Version and arch $Arch."
        exit 1
    }
} else {
    $file = $productInfo.DVLS.Current.Files | Where-Object { $_.Type -eq 'tar.gz' -and $_.Arch -eq $Arch } | Select-Object -First 1
    $Version = if ($file.Version) { $file.Version } else { $productInfo.DVLS.Current.Version }
}

$downloadUrl = $file.Url
$expectedHash = $file.Hash
$filename = "DVLS.$Version.linux-$Arch.tar.gz"

Write-Host "Downloading $downloadUrl ..."
Invoke-WebRequest -Uri $downloadUrl -OutFile $filename

Write-Host "Verifying SHA256 hash..."
$actualHash = (Get-FileHash -Path $filename -Algorithm SHA256).Hash.ToUpper()
if ($actualHash -ne $expectedHash) {
    Write-Error "Hash mismatch! Expected: $expectedHash, Got: $actualHash"
    exit 1
}
Write-Host "✅ Downloaded and verified: $filename"
