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
$script:WinapModule = Get-Module WINAP

function Invoke-SimulatedSMB1Core {
    param([hashtable]$Parameters)
    & $script:WinapModule {
        param($CoreParameters)
        Invoke-WINAPSMB1RemediationCore @CoreParameters
    } $Parameters
}

function New-SMB1CoreTestParameters {
    param(
        [bool]$ConfigurationEnabled = $true,
        [bool]$CommandLineOptIn = $true,
        [bool]$ImpactAcknowledged = $true,
        [bool]$Preview = $false,
        [bool]$IsAdministrator = $true,
        [bool]$EnvironmentSupported = $true,
        [bool]$CmdletsAvailable = $true,
        [scriptblock]$GetServerConfiguration = { [PSCustomObject]@{ EnableSMB1Protocol = $true } },
        [scriptblock]$SetServerConfiguration = { param($enabled) },
        [scriptblock]$GetOperatingSystem = { [PSCustomObject]@{ Caption = 'Microsoft Windows Server 2022 Standard' } }
    )
    return @{
        ConfigurationEnabled = $ConfigurationEnabled
        CommandLineOptIn = $CommandLineOptIn
        ImpactAcknowledged = $ImpactAcknowledged
        Preview = $Preview
        IsAdministrator = $IsAdministrator
        EnvironmentSupported = $EnvironmentSupported
        CmdletsAvailable = $CmdletsAvailable
        GetServerConfiguration = $GetServerConfiguration
        SetServerConfiguration = $SetServerConfiguration
        GetOperatingSystem = $GetOperatingSystem
    }
}
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

# Phase 4: controlled-operation gates are tested with injected in-memory operations.
# No test in this harness invokes Set-SmbServerConfiguration or Install-WindowsFeature.
$script:SimulatedSetCalls = 0
$script:PostCheckIndex = 0
$baseCore = New-SMB1CoreTestParameters
$baseCore.GetServerConfiguration = {
    $script:PostCheckIndex = $script:PostCheckIndex + 1
    if ($script:PostCheckIndex -eq 1) { [PSCustomObject]@{ EnableSMB1Protocol = $true } }
    else { [PSCustomObject]@{ EnableSMB1Protocol = $false } }
}
$baseCore.SetServerConfiguration = { param($enabled) $script:SimulatedSetCalls = $script:SimulatedSetCalls + 1 }
$result = @(Invoke-SimulatedSMB1Core -Parameters $baseCore)
Assert-True 'SMB1 core can verify a simulated successful post-change state' ($result.Count -eq 1 -and $result[0].Status -eq 'PASS' -and $result[0].Actual -eq 'Disabled and verified' -and $script:SimulatedSetCalls -eq 1)

$script:SimulatedSetCalls = 0
$p = New-SMB1CoreTestParameters -ConfigurationEnabled $false
$p.SetServerConfiguration = { param($enabled) $script:SimulatedSetCalls = $script:SimulatedSetCalls + 1 }
$r = @(Invoke-SimulatedSMB1Core -Parameters $p)
Assert-True 'Blocks SMB1 remediation when configuration opt-in is disabled' ($r[0].Status -eq 'SKIPPED' -and $script:SimulatedSetCalls -eq 0)

$p = New-SMB1CoreTestParameters -CommandLineOptIn $false
$p.SetServerConfiguration = { param($enabled) $script:SimulatedSetCalls = $script:SimulatedSetCalls + 1 }
$r = @(Invoke-SimulatedSMB1Core -Parameters $p)
Assert-True 'Blocks SMB1 remediation when command-line opt-in is absent' ($r[0].Status -eq 'SKIPPED' -and $script:SimulatedSetCalls -eq 0)

$p = New-SMB1CoreTestParameters -ImpactAcknowledged $false
$p.SetServerConfiguration = { param($enabled) $script:SimulatedSetCalls = $script:SimulatedSetCalls + 1 }
$r = @(Invoke-SimulatedSMB1Core -Parameters $p)
Assert-True 'Blocks SMB1 remediation without impact acknowledgement' ($r[0].Status -eq 'SKIPPED' -and $script:SimulatedSetCalls -eq 0)

$p = New-SMB1CoreTestParameters -Preview $true
$p.SetServerConfiguration = { param($enabled) $script:SimulatedSetCalls = $script:SimulatedSetCalls + 1 }
$r = @(Invoke-SimulatedSMB1Core -Parameters $p)
Assert-True 'Preview never invokes the SMB1 change operation' ($r[0].Status -eq 'INFO' -and $script:SimulatedSetCalls -eq 0)

$p = New-SMB1CoreTestParameters -IsAdministrator $false
$p.SetServerConfiguration = { param($enabled) $script:SimulatedSetCalls = $script:SimulatedSetCalls + 1 }
$r = @(Invoke-SimulatedSMB1Core -Parameters $p)
Assert-True 'Blocks SMB1 remediation without administrator permissions' ($r[0].Status -eq 'FAIL' -and $script:SimulatedSetCalls -eq 0)

$p = New-SMB1CoreTestParameters -EnvironmentSupported $false
$p.SetServerConfiguration = { param($enabled) $script:SimulatedSetCalls = $script:SimulatedSetCalls + 1 }
$r = @(Invoke-SimulatedSMB1Core -Parameters $p)
Assert-True 'Blocks SMB1 remediation on an unsupported or unverified OS' ($r[0].Status -eq 'SKIPPED' -and $script:SimulatedSetCalls -eq 0)

$p = New-SMB1CoreTestParameters -CmdletsAvailable $false
$p.SetServerConfiguration = { param($enabled) $script:SimulatedSetCalls = $script:SimulatedSetCalls + 1 }
$r = @(Invoke-SimulatedSMB1Core -Parameters $p)
Assert-True 'Blocks SMB1 remediation when required cmdlets are unavailable' ($r[0].Status -eq 'SKIPPED' -and $script:SimulatedSetCalls -eq 0)

$p = New-SMB1CoreTestParameters -GetOperatingSystem { [PSCustomObject]@{ Caption = 'Microsoft Windows Server 2019 Standard' } }
$p.SetServerConfiguration = { param($enabled) $script:SimulatedSetCalls = $script:SimulatedSetCalls + 1 }
$r = @(Invoke-SimulatedSMB1Core -Parameters $p)
Assert-True 'Rechecks the operating system immediately before mutation' ($r[0].Status -eq 'SKIPPED' -and $script:SimulatedSetCalls -eq 0)

$p = New-SMB1CoreTestParameters -GetServerConfiguration { throw 'simulated initial read failure' }
$p.SetServerConfiguration = { param($enabled) $script:SimulatedSetCalls = $script:SimulatedSetCalls + 1 }
$r = @(Invoke-SimulatedSMB1Core -Parameters $p)
Assert-True 'Skips remediation when the initial SMB1 state cannot be read' ($r[0].Status -eq 'SKIPPED' -and $script:SimulatedSetCalls -eq 0)

$p = New-SMB1CoreTestParameters -GetServerConfiguration { [PSCustomObject]@{ EnableSMB1Protocol = 'unknown' } }
$p.SetServerConfiguration = { param($enabled) $script:SimulatedSetCalls = $script:SimulatedSetCalls + 1 }
$r = @(Invoke-SimulatedSMB1Core -Parameters $p)
Assert-True 'Skips SMB1 remediation for ambiguous non-Boolean state' ($r[0].Status -eq 'SKIPPED' -and $script:SimulatedSetCalls -eq 0)

$p = New-SMB1CoreTestParameters -GetServerConfiguration { [PSCustomObject]@{ OtherSetting = $true } }
$p.SetServerConfiguration = { param($enabled) $script:SimulatedSetCalls = $script:SimulatedSetCalls + 1 }
$r = @(Invoke-SimulatedSMB1Core -Parameters $p)
Assert-True 'Skips SMB1 remediation when the state property is missing' ($r[0].Status -eq 'SKIPPED' -and $script:SimulatedSetCalls -eq 0)

$p = New-SMB1CoreTestParameters -GetServerConfiguration { [PSCustomObject]@{ EnableSMB1Protocol = $false } }
$p.SetServerConfiguration = { param($enabled) $script:SimulatedSetCalls = $script:SimulatedSetCalls + 1 }
$r = @(Invoke-SimulatedSMB1Core -Parameters $p)
Assert-True 'Already-disabled SMB1 state is reported without a change' ($r[0].Status -eq 'PASS' -and $r[0].Actual -eq 'Already disabled' -and $script:SimulatedSetCalls -eq 0)

$p = New-SMB1CoreTestParameters -GetServerConfiguration { [PSCustomObject]@{ EnableSMB1Protocol = $true } } -SetServerConfiguration { param($enabled) throw 'simulated set failure' }
$r = @(Invoke-SimulatedSMB1Core -Parameters $p)
Assert-True 'Reports a failed SMB1 change without falsely claiming success' ($r[0].Status -eq 'FAIL')

$script:PostCheckIndex = 0
$p = New-SMB1CoreTestParameters -GetServerConfiguration {
    $script:PostCheckIndex = $script:PostCheckIndex + 1
    [PSCustomObject]@{ EnableSMB1Protocol = $true }
} -SetServerConfiguration { param($enabled) $script:SimulatedSetCalls = $script:SimulatedSetCalls + 1 }
$r = @(Invoke-SimulatedSMB1Core -Parameters $p)
Assert-True 'Does not claim success when SMB1 remains enabled after a change attempt' ($r[0].Status -eq 'FAIL' -and $r[0].Actual -eq 'Still enabled after attempt')

$script:PostCheckIndex = 0
$p = New-SMB1CoreTestParameters -GetServerConfiguration {
    $script:PostCheckIndex = $script:PostCheckIndex + 1
    if ($script:PostCheckIndex -eq 1) { [PSCustomObject]@{ EnableSMB1Protocol = $true } }
    else { [PSCustomObject]@{ EnableSMB1Protocol = $null } }
} -SetServerConfiguration { param($enabled) $script:SimulatedSetCalls = $script:SimulatedSetCalls + 1 }
$r = @(Invoke-SimulatedSMB1Core -Parameters $p)
Assert-True 'Reports ambiguous post-change state as UNKNOWN, not success' ($r[0].Status -eq 'UNKNOWN' -and $r[0].Actual -eq 'Post-check ambiguous')

$script:PostCheckIndex = 0
$p = New-SMB1CoreTestParameters -GetServerConfiguration {
    $script:PostCheckIndex = $script:PostCheckIndex + 1
    if ($script:PostCheckIndex -eq 1) { [PSCustomObject]@{ EnableSMB1Protocol = $true } }
    else { throw 'simulated post-check read failure' }
} -SetServerConfiguration { param($enabled) $script:SimulatedSetCalls = $script:SimulatedSetCalls + 1 }
$r = @(Invoke-SimulatedSMB1Core -Parameters $p)
Assert-True 'Reports an unreadable post-change state as UNKNOWN' ($r[0].Status -eq 'UNKNOWN' -and $r[0].Actual -eq 'Post-check read error')

$script:PostCheckIndex = 0
$p = New-SMB1CoreTestParameters -GetServerConfiguration {
    $script:PostCheckIndex = $script:PostCheckIndex + 1
    if ($script:PostCheckIndex -eq 1) { [PSCustomObject]@{ EnableSMB1Protocol = $true } }
    else { [PSCustomObject]@{ EnableSMB1Protocol = $false } }
} -SetServerConfiguration { param($enabled) $script:SimulatedSetCalls = $script:SimulatedSetCalls + 1 }
$r = @(Invoke-SimulatedSMB1Core -Parameters $p)
Assert-True 'Reports simulated SMB1 post-change verification accurately' ($r[0].Status -eq 'PASS' -and $r[0].Actual -eq 'Disabled and verified')

$disabledFeatureConfig = Import-WINAPConfiguration -Path $configPath
$featureResult = @(& $script:WinapModule { param($featureConfiguration) Invoke-WINAPFeatureInstallation -Configuration $featureConfiguration -InstallFeatures } $disabledFeatureConfig)
Assert-True 'Feature installation remains blocked when configuration opt-in is disabled' (@($featureResult | Where-Object { $_.Status -eq 'SKIPPED' }).Count -gt 0)

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
