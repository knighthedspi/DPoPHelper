<#
.SYNOPSIS
    Builds, tests and packages DPoPHelper into the ZIP that ODC's External Logic
    upload expects.

.DESCRIPTION
    Produces dist/DPoPHelper.zip containing the library assembly and every runtime
    dependency, flat at the archive root. Upload it in the ODC Portal under
    External logic, then publish and deploy to the Development stage.
#>
[CmdletBinding()]
param(
    [string]$Configuration = 'Release',
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$publishDir = Join-Path $root 'artifacts/publish'
$distDir = Join-Path $root 'dist'
$zipPath = Join-Path $distDir 'DPoPHelper.zip'

Write-Host '==> Building' -ForegroundColor Cyan
dotnet build (Join-Path $root 'DPoPHelper.slnx') -c $Configuration --nologo
if ($LASTEXITCODE -ne 0) { throw "Build failed with exit code $LASTEXITCODE." }

if (-not $SkipTests) {
    Write-Host '==> Testing' -ForegroundColor Cyan
    dotnet test (Join-Path $root 'DPoPHelper.slnx') -c $Configuration --nologo --no-build
    if ($LASTEXITCODE -ne 0) { throw "Tests failed with exit code $LASTEXITCODE. Not packaging." }
}

Write-Host '==> Publishing' -ForegroundColor Cyan
if (Test-Path $publishDir) { Remove-Item $publishDir -Recurse -Force }
dotnet publish (Join-Path $root 'src/DPoPHelper/DPoPHelper.csproj') `
    -c $Configuration -o $publishDir --nologo
if ($LASTEXITCODE -ne 0) { throw "Publish failed with exit code $LASTEXITCODE." }

# ODC reads the assemblies from the archive root; it does not want the build's
# satellite folders or debug symbols.
Get-ChildItem $publishDir -Include '*.pdb' -Recurse | Remove-Item -Force

Write-Host '==> Packaging' -ForegroundColor Cyan
if (-not (Test-Path $distDir)) { New-Item -ItemType Directory -Path $distDir | Out-Null }
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }

Compress-Archive -Path (Join-Path $publishDir '*') -DestinationPath $zipPath -Force

$size = [math]::Round((Get-Item $zipPath).Length / 1KB, 1)
Write-Host ''
Write-Host "Package ready: $zipPath ($size KB)" -ForegroundColor Green
Write-Host 'Contents:' -ForegroundColor Green
Get-ChildItem $publishDir | ForEach-Object { Write-Host "  $($_.Name)" }
