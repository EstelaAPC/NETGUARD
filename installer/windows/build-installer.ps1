$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$source = Join-Path $scriptDir "NetGuardInstaller.ps1"
$outputDir = Join-Path $scriptDir "dist"
$output = Join-Path $outputDir "NetGuardInstaller.exe"

New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

if (-not (Get-Command Invoke-ps2exe -ErrorAction SilentlyContinue)) {
    Write-Host "PS2EXE nao encontrado. Instalando modulo no usuario atual..."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force | Out-Null
    }
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    Install-Module ps2exe -Scope CurrentUser -Force -AllowClobber
}

Invoke-ps2exe `
    -InputFile $source `
    -OutputFile $output `
    -Title "NetGuard Installer" `
    -Description "Instalador Windows do NetGuard" `
    -Company "NetGuard" `
    -Product "NetGuard" `
    -Version "1.0.0" `
    -NoConsole

Write-Host "Gerado: $output"
