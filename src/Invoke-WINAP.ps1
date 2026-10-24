[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'config\baseline.example.json'),
    [switch]$Preview,
    [switch]$RemediateSMB1,
    [switch]$AcknowledgeSMB1Impact,
    [switch]$InstallFeatures
)

$ErrorActionPreference = 'Stop'
$modulePath = Join-Path $PSScriptRoot 'WINAP\WINAP.psm1'
if (-not (Test-Path -LiteralPath $modulePath -PathType Leaf)) {
    throw "WINAP module not found: $modulePath"
}
Import-Module -Name $modulePath -Force -ErrorAction Stop

if (-not [IO.Path]::IsPathRooted($ConfigPath)) {
    $ConfigPath = Join-Path (Split-Path -Parent $PSScriptRoot) $ConfigPath
}

$null = Invoke-WINAP -ConfigPath $ConfigPath -Preview:$Preview -RemediateSMB1:$RemediateSMB1 -AcknowledgeSMB1Impact:$AcknowledgeSMB1Impact -InstallFeatures:$InstallFeatures
