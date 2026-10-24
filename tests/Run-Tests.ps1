[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$modulePath = Join-Path $root 'src\WINAP\WINAP.psm1'
$configPath = Join-Path $root 'config\baseline.example.json'
Import-Module $modulePath -Force

$script:Passed = 0
$script:Failed = 0
function Assert-True {
    param([string]$Name,[bool]$Condition,[string]$Details='')
    if ($Condition) { $script:Passed++; Write-Host "PASS: $Name" -ForegroundColor Green }
    else { $script:Failed++; Write-Host "FAIL: $Name $Details" -ForegroundColor Red }
}
function Assert-Throws {
    param([string]$Name,[scriptblock]$Action)
    try { & $Action; $script:Failed++; Write-Host "FAIL: $Name (expected exception)" -ForegroundColor Red }
    catch { $script:Passed++; Write-Host "PASS: $Name" -ForegroundColor Green }
}

Write-Host 'WINAP built-in tests (no server changes will be made)' -ForegroundColor Cyan
$cfg = Import-WINAPConfiguration -Path $configPath
Assert-True 'Sample JSON configuration loads' ($cfg.schemaVersion -eq '1.0')
Assert-True 'Audit mode is the default' ($cfg.mode -eq 'Audit')
Assert-True 'Feature installation is disabled by default' (-not $cfg.features.enabled)
Assert-True 'Remediation is disabled by default' (-not $cfg.remediation.enabled)
Assert-True 'Hostname changes are not a configuration option' ($null -eq $cfg.PSObject.Properties['changeHostname'])


# Phase 3: baseline audit structure and honest state reporting.
$auditResults = @(Invoke-WINAPAudit -Configuration $cfg)
$expectedAuditChecks = @(
    'SMBv1 server protocol',
    'Domain profile',
    'Private profile',
    'Public profile',
    'TLS 1.0 server protocol indicator',
    'TLS 1.1 server protocol indicator',
    'TLS 1.2 server protocol indicator'
)
foreach ($checkName in $expectedAuditChecks) {
    $found = @($auditResults | Where-Object { $_.Check -eq $checkName }).Count -eq 1
    Assert-True "Audit includes exactly one '$checkName' result" $found
}

$validStatuses = @('PASS','FAIL','WARN','UNKNOWN','SKIPPED','INFO')
$statusesValid = @($auditResults | Where-Object { $_.Status -notin $validStatuses }).Count -eq 0
Assert-True 'Audit results use supported status values' $statusesValid

$tlsAuditOnlyResults = @($auditResults | Where-Object { $_.Category -eq 'TLS' })
$tlsAuditOnlyStatusesValid = ($tlsAuditOnlyResults.Count -eq 3) -and (@($tlsAuditOnlyResults | Where-Object { $_.Status -notin @('INFO','UNKNOWN') }).Count -eq 0)
Assert-True 'AuditOnly TLS indicators are observational and never claim baseline PASS/FAIL' $tlsAuditOnlyStatusesValid

$unknownsHonest = @($auditResults | Where-Object {
    ($_.Category -eq 'SMB' -or $_.Category -eq 'Firewall' -or $_.Category -eq 'TLS') -and
    $_.Status -eq 'UNKNOWN' -and [string]::IsNullOrWhiteSpace([string]$_.Actual)
}).Count -eq 0
Assert-True 'Unknown audit results include an explanatory actual-state label' $unknownsHonest

$temp = Join-Path $env:TEMP ('WINAP-invalid-' + [guid]::NewGuid().ToString('N') + '.json')
try {
    $invalid = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    $invalid.features.requested = @('Unapproved-Arbitrary-Feature')
    $invalid | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $temp -Encoding UTF8
    Assert-Throws 'Rejects a feature outside the allowlist' { Import-WINAPConfiguration -Path $temp }

    $invalid = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    $invalid.mode = 'RemediateEverything'
    $invalid | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $temp -Encoding UTF8
    Assert-Throws 'Rejects an unsupported execution mode' { Import-WINAPConfiguration -Path $temp }

    $invalid = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    $invalid.remediation.target = 'Firewall'
    $invalid | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $temp -Encoding UTF8
    Assert-Throws 'Rejects remediation targets other than SMB1Server' { Import-WINAPConfiguration -Path $temp }

    $invalid = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    $invalid | Add-Member -MemberType NoteProperty -Name 'extraDangerousSetting' -Value $true
    $invalid | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $temp -Encoding UTF8
    Assert-Throws 'Rejects unknown top-level configuration keys' { Import-WINAPConfiguration -Path $temp }
} finally {
    Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
}

$testResults = @(
    (New-Object PSObject -Property @{Timestamp='now';Category='Test';Check='HTML escape';Status='PASS';Message='<script>alert(1)</script>';Expected='';Actual=''})
)
$reportPath = Join-Path $env:TEMP ('WINAP-test-' + [guid]::NewGuid().ToString('N') + '.html')
try {
    $inventory = [PSCustomObject]@{ComputerName='TESTHOST';Domain='WORKGROUP';OperatingSystem='Test OS';OSBuild='1';PowerShellVersion='5.1';CDriveFreeGB=1;IsAdministrator=$false;LastBootTime='Unknown'}
    Write-WINAPHtmlReport -Path $reportPath -Results $testResults -Inventory $inventory -RunId 'TEST' -Mode 'Audit'
    $html = Get-Content -LiteralPath $reportPath -Raw
    Assert-True 'HTML report is generated' (Test-Path -LiteralPath $reportPath -PathType Leaf)
    Assert-True 'HTML report escapes untrusted content' ($html -notmatch '<script>alert\(1\)</script>')
} finally {
    Remove-Item -LiteralPath $reportPath -Force -ErrorAction SilentlyContinue
}

Write-Host "`nTest summary: $script:Passed passed; $script:Failed failed." -ForegroundColor Cyan
if ($script:Failed -gt 0) { exit 1 }
exit 0
