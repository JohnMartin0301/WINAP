Set-StrictMode -Version 2.0

$script:WINAPVersion = '1.0.0'
$script:AllowedFeatures = @('RSAT-AD-PowerShell', 'GPMC')

function New-WINAPResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidateSet('PASS','FAIL','WARN','UNKNOWN','SKIPPED','INFO')][string]$Status,
        [Parameter(Mandatory)][string]$Message,
        [AllowNull()][object]$Expected = $null,
        [AllowNull()][object]$Actual = $null
    )
    [PSCustomObject]@{
        Timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ssK')
        Category = $Category
        Check = $Check
        Status = $Status
        Message = $Message
        Expected = if ($null -eq $Expected) { '' } else { [string]$Expected }
        Actual = if ($null -eq $Actual) { '' } else { [string]$Actual }
    }
}

function Test-WINAPAdministrator {
    [CmdletBinding()]
    param()
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

function Test-WINAPEnvironment {
    [CmdletBinding()]
    param()
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $psMajor = $PSVersionTable.PSVersion.Major
    $psMinor = $PSVersionTable.PSVersion.Minor
    $isServer2022 = ($os.Caption -match 'Windows Server 2022')
    $isWindowsPowerShell51 = ($psMajor -eq 5 -and $psMinor -eq 1)
    if (-not $isServer2022) {
        throw "Unsupported operating system '$($os.Caption)'. WINAP V1 targets Windows Server 2022."
    }
    if (-not $isWindowsPowerShell51) {
        throw "Unsupported PowerShell version '$($PSVersionTable.PSVersion)'. Run WINAP in Windows PowerShell 5.1 (powershell.exe), not PowerShell 7."
    }
    [PSCustomObject]@{
        ComputerName = $env:COMPUTERNAME
        OperatingSystem = $os.Caption
        Version = $os.Version
        BuildNumber = $os.BuildNumber
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        IsAdministrator = (Test-WINAPAdministrator)
    }
}

function Import-WINAPConfiguration {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Configuration file not found: $Path"
    }
    try {
        $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        $cfg = ConvertFrom-Json -InputObject $raw -ErrorAction Stop
    } catch {
        throw "Configuration JSON could not be read: $($_.Exception.Message)"
    }
    if ($null -eq $cfg -or $cfg -isnot [System.Management.Automation.PSCustomObject]) {
        throw 'Configuration root must be a JSON object.'
    }
    $allowedRoot = @('schemaVersion','mode','baseline','features','remediation','reporting')
    foreach ($p in $cfg.PSObject.Properties) {
        if ($p.Name -notin $allowedRoot) { throw "Unknown configuration key '$($p.Name)'." }
    }
    foreach ($required in $allowedRoot) {
        if ($null -eq $cfg.PSObject.Properties[$required]) { throw "Required configuration key '$required' is missing." }
    }
    if ([string]$cfg.schemaVersion -ne '1.0') { throw "Unsupported schemaVersion '$($cfg.schemaVersion)'. Expected '1.0'." }
    if ([string]$cfg.mode -notin @('Audit','Preview')) { throw "mode must be 'Audit' or 'Preview'." }
    if ($cfg.baseline -isnot [System.Management.Automation.PSCustomObject]) { throw 'baseline must be a JSON object.' }
    if ($cfg.features -isnot [System.Management.Automation.PSCustomObject]) { throw 'features must be a JSON object.' }
    if ($cfg.remediation -isnot [System.Management.Automation.PSCustomObject]) { throw 'remediation must be a JSON object.' }
    if ($cfg.reporting -isnot [System.Management.Automation.PSCustomObject]) { throw 'reporting must be a JSON object.' }

    $baselineKeys = @('smb1ServerEnabled','firewallProfiles','tlsProtocols')
    foreach ($p in $cfg.baseline.PSObject.Properties) { if ($p.Name -notin $baselineKeys) { throw "Unknown baseline key '$($p.Name)'." } }
    if ($null -eq $cfg.baseline.PSObject.Properties['smb1ServerEnabled'] -or $cfg.baseline.smb1ServerEnabled -isnot [bool]) { throw 'baseline.smb1ServerEnabled must be true or false.' }
    if ($null -eq $cfg.baseline.PSObject.Properties['firewallProfiles']) { throw 'baseline.firewallProfiles is required.' }
    foreach ($profileProperty in $cfg.baseline.firewallProfiles.PSObject.Properties) { if ($profileProperty.Name -notin @('Domain','Private','Public')) { throw "Unknown firewall profile baseline '$($profileProperty.Name)'." } }
    foreach ($profile in @('Domain','Private','Public')) {
        if ($null -eq $cfg.baseline.firewallProfiles.PSObject.Properties[$profile] -or $cfg.baseline.firewallProfiles.$profile -isnot [bool]) {
            throw "baseline.firewallProfiles.$profile must be true or false."
        }
    }
    if ($null -eq $cfg.baseline.PSObject.Properties['tlsProtocols']) { throw 'baseline.tlsProtocols is required.' }
    foreach ($p in $cfg.baseline.tlsProtocols.PSObject.Properties) {
        if ($p.Name -notin @('TLS 1.0','TLS 1.1','TLS 1.2')) { throw "Unsupported TLS protocol baseline '$($p.Name)'. Supported keys: TLS 1.0, TLS 1.1, TLS 1.2." }
        if ($p.Value -notin @('Enabled','Disabled','AuditOnly')) { throw "TLS baseline '$($p.Name)' must be Enabled, Disabled, or AuditOnly." }
    }

    foreach ($p in $cfg.features.PSObject.Properties) { if ($p.Name -notin @('enabled','requested')) { throw "Unknown features key '$($p.Name)'." } }
    if ($cfg.features.enabled -isnot [bool]) { throw 'features.enabled must be true or false.' }
    if ($cfg.features.requested -isnot [System.Array]) { throw 'features.requested must be a JSON array.' }
    foreach ($feature in $cfg.features.requested) {
        if ([string]$feature -notin $script:AllowedFeatures) { throw "Feature '$feature' is not on the WINAP allowlist. Allowed: $($script:AllowedFeatures -join ', ')." }
    }
    foreach ($p in $cfg.remediation.PSObject.Properties) { if ($p.Name -notin @('enabled','target')) { throw "Unknown remediation key '$($p.Name)'." } }
    if ($cfg.remediation.enabled -isnot [bool]) { throw 'remediation.enabled must be true or false.' }
    if ([string]$cfg.remediation.target -ne 'SMB1Server') { throw "remediation.target must be 'SMB1Server'." }
    if ($cfg.remediation.enabled -and $cfg.baseline.smb1ServerEnabled) { throw 'Configuration conflict: remediation.enabled=true requires baseline.smb1ServerEnabled=false.' }
    foreach ($p in $cfg.reporting.PSObject.Properties) { if ($p.Name -notin @('outputDirectory','htmlReport','logFile')) { throw "Unknown reporting key '$($p.Name)'." } }
    foreach ($name in @('outputDirectory','htmlReport','logFile')) {
        if ([string]::IsNullOrWhiteSpace([string]$cfg.reporting.$name)) { throw "reporting.$name must be a non-empty path/name." }
    }
    if ([IO.Path]::IsPathRooted([string]$cfg.reporting.htmlReport) -or [IO.Path]::GetFileName([string]$cfg.reporting.htmlReport) -ne [string]$cfg.reporting.htmlReport) { throw 'reporting.htmlReport must be a file name, not a path.' }
    if ([IO.Path]::IsPathRooted([string]$cfg.reporting.logFile) -or [IO.Path]::GetFileName([string]$cfg.reporting.logFile) -ne [string]$cfg.reporting.logFile) { throw 'reporting.logFile must be a file name, not a path.' }
    return $cfg
}


function Get-WINAPInventory {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Environment)

    $computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction SilentlyContinue

    # Safely collect the last boot time.
    $lastBootTime = 'Unknown'

    if ($os -and $null -ne $os.LastBootUpTime) {
        try {
            if ($os.LastBootUpTime -is [datetime]) {
                $lastBootTime = $os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss')
            }
            else {
                $lastBootTime = [Management.ManagementDateTimeConverter]::ToDateTime(
                    [string]$os.LastBootUpTime
                ).ToString('yyyy-MM-dd HH:mm:ss')
            }
        }
        catch {
            $lastBootTime = 'Unknown'
        }
    }

    [PSCustomObject]@{
        ComputerName      = $env:COMPUTERNAME
        Domain            = if ($computer) { [string]$computer.Domain } else { 'Unknown' }
        Manufacturer      = if ($computer) { [string]$computer.Manufacturer } else { 'Unknown' }
        Model             = if ($computer) { [string]$computer.Model } else { 'Unknown' }
        OperatingSystem   = $Environment.OperatingSystem
        OSVersion         = $Environment.Version
        OSBuild           = $Environment.BuildNumber
        PowerShellVersion = $Environment.PowerShellVersion
        LastBootTime      = $lastBootTime
        CDriveFreeGB      = if ($disk) { [math]::Round($disk.FreeSpace / 1GB, 2) } else { $null }
        IsAdministrator   = $Environment.IsAdministrator
    }
}

function Invoke-WINAPAudit {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Configuration)
    $results = New-Object System.Collections.Generic.List[object]

    # SMBv1 server protocol: only read the server-side setting.
    try {
        $smbCmd = Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue
        if (-not $smbCmd) {
            $results.Add((New-WINAPResult -Category 'SMB' -Check 'SMBv1 server protocol' -Status 'UNKNOWN' -Expected ([string]$Configuration.baseline.smb1ServerEnabled) -Actual 'Unavailable' -Message 'Get-SmbServerConfiguration is unavailable; state could not be verified.'))
        } else {
            $smb = Get-SmbServerConfiguration -ErrorAction Stop
            $actual = [bool]$smb.EnableSMB1Protocol
            $status = if ($actual -eq [bool]$Configuration.baseline.smb1ServerEnabled) { 'PASS' } else { 'FAIL' }
            $results.Add((New-WINAPResult -Category 'SMB' -Check 'SMBv1 server protocol' -Status $status -Expected ([string]$Configuration.baseline.smb1ServerEnabled) -Actual ([string]$actual) -Message 'Read the SMB server protocol setting. No change was made.'))
        }
    } catch { $results.Add((New-WINAPResult -Category 'SMB' -Check 'SMBv1 server protocol' -Status 'UNKNOWN' -Expected ([string]$Configuration.baseline.smb1ServerEnabled) -Actual 'Read error' -Message $_.Exception.Message)) }

    # Firewall is audit-only.
    try {
        $fwCmd = Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue
        if (-not $fwCmd) {
            $results.Add((New-WINAPResult -Category 'Firewall' -Check 'Windows Firewall profiles' -Status 'UNKNOWN' -Expected 'Configured profile states' -Actual 'Unavailable' -Message 'Get-NetFirewallProfile is unavailable.'))
        } else {
            $profiles = @(Get-NetFirewallProfile -ErrorAction Stop)
            foreach ($profileName in @('Domain','Private','Public')) {
                $p = $profiles | Where-Object { $_.Name -eq $profileName } | Select-Object -First 1
                if ($null -eq $p) {
                    $results.Add((New-WINAPResult -Category 'Firewall' -Check "$profileName profile" -Status 'UNKNOWN' -Expected ([string]$Configuration.baseline.firewallProfiles.$profileName) -Actual 'Unavailable' -Message 'Profile was not returned by Get-NetFirewallProfile.'))
                } else {
                    $actual = [bool]$p.Enabled
                    $expected = [bool]$Configuration.baseline.firewallProfiles.$profileName
                    $status = if ($actual -eq $expected) { 'PASS' } else { 'FAIL' }
                    $results.Add((New-WINAPResult -Category 'Firewall' -Check "$profileName profile" -Status $status -Expected ([string]$expected) -Actual ([string]$actual) -Message 'Read firewall profile state. WINAP does not modify firewall settings.'))
                }
            }
        }
    } catch { $results.Add((New-WINAPResult -Category 'Firewall' -Check 'Windows Firewall profiles' -Status 'UNKNOWN' -Expected 'Configured profile states' -Actual 'Read error' -Message $_.Exception.Message)) }

    # TLS registry indicators are read-only. Missing values remain UNKNOWN.
    foreach ($tlsName in @('TLS 1.0','TLS 1.1','TLS 1.2')) {
        $expectedProperty = $Configuration.baseline.tlsProtocols.PSObject.Properties[$tlsName]
        $expected = if ($null -ne $expectedProperty) { [string]$expectedProperty.Value } else { 'AuditOnly' }
        if ($expected -eq 'AuditOnly') {
            $results.Add((New-WINAPResult -Category 'TLS' -Check "$tlsName server protocol indicator" -Status 'INFO' -Expected 'AuditOnly' -Actual 'Not evaluated against baseline' -Message 'This protocol is included for observation only by configuration.'))
            continue
        }
        $version = $tlsName.Replace('TLS ','')
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS $version\Server"
        try {
            if (-not (Test-Path -LiteralPath $regPath)) {
                $results.Add((New-WINAPResult -Category 'TLS' -Check "$tlsName server protocol indicator" -Status 'UNKNOWN' -Expected $expected -Actual 'Registry key absent' -Message 'The explicit registry key is absent. Windows defaults or policy may apply; absence is not treated as enabled or disabled.'))
                continue
            }
            $values = Get-ItemProperty -LiteralPath $regPath -ErrorAction Stop
            $hasEnabled = $null -ne $values.PSObject.Properties['Enabled']
            $hasDisabled = $null -ne $values.PSObject.Properties['DisabledByDefault']
            if (-not ($hasEnabled -and $hasDisabled)) {
                $results.Add((New-WINAPResult -Category 'TLS' -Check "$tlsName server protocol indicator" -Status 'UNKNOWN' -Expected $expected -Actual 'Incomplete registry values' -Message 'Enabled and DisabledByDefault were not both explicitly set. No conclusion is inferred.'))
                continue
            }
            $actual = if ([int]$values.Enabled -eq 1 -and [int]$values.DisabledByDefault -eq 0) { 'Enabled' } elseif ([int]$values.Enabled -eq 0 -and [int]$values.DisabledByDefault -eq 1) { 'Disabled' } else { 'Ambiguous' }
            $status = if ($actual -eq 'Ambiguous') { 'UNKNOWN' } elseif ($actual -eq $expected) { 'PASS' } else { 'FAIL' }
            $results.Add((New-WINAPResult -Category 'TLS' -Check "$tlsName server protocol indicator" -Status $status -Expected $expected -Actual $actual -Message 'Read explicit Schannel server registry indicators only. WINAP does not modify TLS settings.'))
        } catch { $results.Add((New-WINAPResult -Category 'TLS' -Check "$tlsName server protocol indicator" -Status 'UNKNOWN' -Expected $expected -Actual 'Read error' -Message $_.Exception.Message)) }
    }
    return @($results.ToArray())
}

function Get-WINAPFeaturePlan {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Configuration)
    $plan = New-Object System.Collections.Generic.List[object]
    if (-not $Configuration.features.enabled) {
        foreach ($feature in $Configuration.features.requested) { $plan.Add((New-WINAPResult -Category 'Features' -Check ([string]$feature) -Status 'SKIPPED' -Expected 'Installed only with opt-in' -Actual 'Not changed' -Message 'Feature management is disabled in configuration.')) }
        if (@($Configuration.features.requested).Count -eq 0) { $plan.Add((New-WINAPResult -Category 'Features' -Check 'Allowlisted feature management' -Status 'INFO' -Expected 'Disabled by default' -Actual 'Disabled' -Message 'No feature changes requested.')) }
        return @($plan.ToArray())
    }
    if (@($Configuration.features.requested).Count -eq 0) {
        $plan.Add((New-WINAPResult -Category 'Features' -Check 'Allowlisted feature management' -Status 'INFO' -Expected 'Explicit allowlisted request' -Actual 'No features requested' -Message 'Feature management is enabled but the requested list is empty.'))
        return @($plan.ToArray())
    }
    $cmd = Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue
    if (-not $cmd) {
        foreach ($feature in $Configuration.features.requested) { $plan.Add((New-WINAPResult -Category 'Features' -Check ([string]$feature) -Status 'UNKNOWN' -Expected 'Allowlisted feature' -Actual 'Get-WindowsFeature unavailable' -Message 'Cannot safely verify feature availability. No installation attempted.')) }
        return @($plan.ToArray())
    }
    foreach ($feature in $Configuration.features.requested) {
        try {
            $found = Get-WindowsFeature -Name $feature -ErrorAction Stop
            if ($null -eq $found) { $plan.Add((New-WINAPResult -Category 'Features' -Check $feature -Status 'FAIL' -Expected 'Known allowlisted feature' -Actual 'Not found' -Message 'Feature is not available on this server.')) }
            elseif ($found.Installed) { $plan.Add((New-WINAPResult -Category 'Features' -Check $feature -Status 'PASS' -Expected 'Installed' -Actual 'Installed' -Message 'Feature already installed; no action needed.')) }
            else { $plan.Add((New-WINAPResult -Category 'Features' -Check $feature -Status 'INFO' -Expected 'Installed' -Actual 'Not installed' -Message 'Feature is allowlisted. Installation still requires the command-line opt-in and administrator rights.')) }
        } catch { $plan.Add((New-WINAPResult -Category 'Features' -Check $feature -Status 'UNKNOWN' -Expected 'Known allowlisted feature' -Actual 'Query error' -Message $_.Exception.Message)) }
    }
    return @($plan.ToArray())
}

function Invoke-WINAPFeatureInstallation {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Configuration,[switch]$InstallFeatures,[switch]$Preview)
    $results = New-Object System.Collections.Generic.List[object]
    $plan = @(Get-WINAPFeaturePlan -Configuration $Configuration)
    if (-not $InstallFeatures) {
        foreach ($p in $plan) {
            if ($p.Status -eq 'INFO' -and $p.Actual -eq 'Not installed') { $results.Add((New-WINAPResult -Category 'Features' -Check $p.Check -Status 'SKIPPED' -Expected $p.Expected -Actual $p.Actual -Message 'Installation was not attempted: pass -InstallFeatures explicitly to authorize allowlisted feature installation.')) }
            else { $results.Add($p) }
        }
        return @($results.ToArray())
    }
    if (-not $Configuration.features.enabled) {
        return @((New-WINAPResult -Category 'Features' -Check 'Feature installation' -Status 'SKIPPED' -Expected 'features.enabled=true' -Actual 'false' -Message 'Both configuration opt-in and -InstallFeatures are required.'))
    }
    if ($Preview) {
        foreach ($p in $plan) {
            if ($p.Status -eq 'INFO' -and $p.Actual -eq 'Not installed') { $results.Add((New-WINAPResult -Category 'Features' -Check $p.Check -Status 'INFO' -Expected 'Would install' -Actual 'Preview only' -Message 'Preview mode; no installation was attempted.')) } else { $results.Add($p) }
        }
        return @($results.ToArray())
    }
    if (-not (Test-WINAPAdministrator)) { return @((New-WINAPResult -Category 'Features' -Check 'Feature installation' -Status 'FAIL' -Expected 'Administrator privileges' -Actual 'Not elevated' -Message 'Run in an elevated Windows PowerShell session. No feature installation attempted.')) }
    foreach ($p in $plan) {
        if ($p.Status -ne 'INFO' -or $p.Actual -ne 'Not installed') { $results.Add($p); continue }
        try {
            $install = Install-WindowsFeature -Name $p.Check -ErrorAction Stop
            $verify = Get-WindowsFeature -Name $p.Check -ErrorAction Stop
            if ($verify.Installed) {
                $msg = 'Feature installation was verified.'
                if ($install.RestartNeeded -and $install.RestartNeeded -ne 'No') { $msg += ' Windows reports a restart may be needed; WINAP will not reboot automatically.' }
                $results.Add((New-WINAPResult -Category 'Features' -Check $p.Check -Status 'PASS' -Expected 'Installed' -Actual 'Installed' -Message $msg))
            } else { $results.Add((New-WINAPResult -Category 'Features' -Check $p.Check -Status 'FAIL' -Expected 'Installed' -Actual 'Not installed after attempt' -Message 'Installation command returned, but post-check did not verify the feature.')) }
        } catch { $results.Add((New-WINAPResult -Category 'Features' -Check $p.Check -Status 'FAIL' -Expected 'Installed' -Actual 'Installation error' -Message $_.Exception.Message)) }
    }
    return @($results.ToArray())
}

function Invoke-WINAPSMB1Remediation {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Configuration,[switch]$RemediateSMB1,[switch]$AcknowledgeSMB1Impact,[switch]$Preview)
    if (-not $RemediateSMB1) { return @((New-WINAPResult -Category 'Remediation' -Check 'Disable SMBv1 server protocol' -Status 'SKIPPED' -Expected 'Explicit CLI opt-in and configuration opt-in' -Actual 'Not authorized' -Message 'Audit-only default. No remediation attempted.')) }
    if (-not $Configuration.remediation.enabled) { return @((New-WINAPResult -Category 'Remediation' -Check 'Disable SMBv1 server protocol' -Status 'SKIPPED' -Expected 'remediation.enabled=true' -Actual 'false' -Message 'Both configuration opt-in and -RemediateSMB1 are required.')) }
    if (-not $AcknowledgeSMB1Impact) { return @((New-WINAPResult -Category 'Remediation' -Check 'Disable SMBv1 server protocol' -Status 'SKIPPED' -Expected 'Impact acknowledgement' -Actual 'Not acknowledged' -Message 'No change made. Review legacy dependency impact and rerun with -AcknowledgeSMB1Impact only in an isolated, assessed lab.')) }
    if ($Preview) { return @((New-WINAPResult -Category 'Remediation' -Check 'Disable SMBv1 server protocol' -Status 'INFO' -Expected 'SMBv1 server disabled' -Actual 'Preview only' -Message 'All CLI acknowledgements are present, but preview mode never changes the server.')) }
    if (-not (Test-WINAPAdministrator)) { return @((New-WINAPResult -Category 'Remediation' -Check 'Disable SMBv1 server protocol' -Status 'FAIL' -Expected 'Administrator privileges' -Actual 'Not elevated' -Message 'No change attempted. Run an elevated Windows PowerShell session.')) }
    if (-not (Get-Command Get-SmbServerConfiguration -ErrorAction SilentlyContinue) -or -not (Get-Command Set-SmbServerConfiguration -ErrorAction SilentlyContinue)) { return @((New-WINAPResult -Category 'Remediation' -Check 'Disable SMBv1 server protocol' -Status 'SKIPPED' -Expected 'Supported SMB server cmdlets' -Actual 'Unavailable' -Message 'Required cmdlets are unavailable; no change attempted.')) }
    try {
        $before = Get-SmbServerConfiguration -ErrorAction Stop
        if ($null -eq $before.EnableSMB1Protocol -or $before.EnableSMB1Protocol -isnot [bool]) { return @((New-WINAPResult -Category 'Remediation' -Check 'Disable SMBv1 server protocol' -Status 'SKIPPED' -Expected 'Readable Boolean state' -Actual 'Ambiguous' -Message 'Current state cannot be reliably interpreted; no change attempted.')) }
        if (-not $before.EnableSMB1Protocol) { return @((New-WINAPResult -Category 'Remediation' -Check 'Disable SMBv1 server protocol' -Status 'PASS' -Expected 'Disabled' -Actual 'Already disabled' -Message 'No change needed; SMBv1 server protocol was already disabled.')) }
        # Verify server OS again immediately before the mutation.
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        if ($os.Caption -notmatch 'Windows Server 2022') { return @((New-WINAPResult -Category 'Remediation' -Check 'Disable SMBv1 server protocol' -Status 'SKIPPED' -Expected 'Windows Server 2022' -Actual $os.Caption -Message 'Operating system safety check failed; no change attempted.')) }
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
        $after = Get-SmbServerConfiguration -ErrorAction Stop
        if ($after.EnableSMB1Protocol -eq $false) {
            return @((New-WINAPResult -Category 'Remediation' -Check 'Disable SMBv1 server protocol' -Status 'PASS' -Expected 'Disabled' -Actual 'Disabled and verified' -Message 'SMBv1 server protocol disablement was verified. No reboot was initiated.'))
        }
        return @((New-WINAPResult -Category 'Remediation' -Check 'Disable SMBv1 server protocol' -Status 'UNKNOWN' -Expected 'Disabled' -Actual 'Post-check did not confirm' -Message 'A change was attempted, but the resulting state could not be verified.'))
    } catch {
        $detail = $_.Exception.Message
        try {
            $state = Get-SmbServerConfiguration -ErrorAction Stop
            if ($state.EnableSMB1Protocol -eq $false) { return @((New-WINAPResult -Category 'Remediation' -Check 'Disable SMBv1 server protocol' -Status 'WARN' -Expected 'Disabled' -Actual 'Disabled after reported error' -Message "Command reported an error but post-check shows disabled: $detail")) }
        } catch { }
        return @((New-WINAPResult -Category 'Remediation' -Check 'Disable SMBv1 server protocol' -Status 'FAIL' -Expected 'Disabled' -Actual 'Not verified' -Message $detail))
    }
}

function Write-WINAPLog {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][object[]]$Results,[Parameter(Mandatory)][string]$RunId)
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add("WINAP $script:WINAPVersion execution log")
    $lines.Add("Run ID: $RunId")
    $lines.Add("Started/recorded: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ssK')")
    foreach ($r in $Results) { $lines.Add(('[{0}] [{1}] {2} — {3}' -f $r.Status,$r.Category,$r.Check,$r.Message)) }
    $lines | Set-Content -LiteralPath $Path -Encoding UTF8
}

function ConvertTo-WINAPHtmlEncoded {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Write-WINAPHtmlReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path,[Parameter(Mandatory)][object[]]$Results,[Parameter(Mandatory)][object]$Inventory,[Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$Mode)
    $counts = @{}
    foreach ($status in @('PASS','FAIL','WARN','UNKNOWN','SKIPPED','INFO')) { $counts[$status] = @($Results | Where-Object { $_.Status -eq $status }).Count }
    $rows = New-Object System.Collections.Generic.List[string]
    foreach ($r in $Results) {
        $rows.Add('<tr><td class="status status-' + (ConvertTo-WINAPHtmlEncoded $r.Status) + '">' + (ConvertTo-WINAPHtmlEncoded $r.Status) + '</td><td>' + (ConvertTo-WINAPHtmlEncoded $r.Category) + '</td><td>' + (ConvertTo-WINAPHtmlEncoded $r.Check) + '</td><td>' + (ConvertTo-WINAPHtmlEncoded $r.Expected) + '</td><td>' + (ConvertTo-WINAPHtmlEncoded $r.Actual) + '</td><td>' + (ConvertTo-WINAPHtmlEncoded $r.Message) + '</td></tr>')
    }
    $html = @"
<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>WINAP Audit Report</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;margin:2rem;color:#17202a;background:#f7f9fb}h1{margin-bottom:.2rem}.muted{color:#5d6d7e}.summary{display:flex;flex-wrap:wrap;gap:.7rem;margin:1.2rem 0}.tile{background:white;border:1px solid #d5dbe1;border-radius:8px;padding:.8rem 1rem;min-width:80px}.tile b{display:block;font-size:1.5rem}table{width:100%;border-collapse:collapse;background:white}th,td{padding:.65rem;text-align:left;border:1px solid #d5dbe1;vertical-align:top}th{background:#eaf0f6}.status{font-weight:700}.status-PASS{color:#196f3d}.status-FAIL{color:#922b21}.status-WARN{color:#9a7d0a}.status-UNKNOWN{color:#566573}.status-SKIPPED{color:#5b2c6f}.status-INFO{color:#2471a3}code{word-break:break-all}@media(max-width:900px){table{font-size:.85rem}body{margin:.5rem}}
</style></head><body>
<h1>WINAP — Windows Infrastructure Automation Platform</h1><p class="muted">Execution report · Version $script:WINAPVersion · Run ID $(ConvertTo-WINAPHtmlEncoded $RunId)</p>
<h2>Run summary</h2><p><b>Mode:</b> $(ConvertTo-WINAPHtmlEncoded $Mode) &nbsp; <b>Computer:</b> $(ConvertTo-WINAPHtmlEncoded $Inventory.ComputerName) &nbsp; <b>OS:</b> $(ConvertTo-WINAPHtmlEncoded $Inventory.OperatingSystem) &nbsp; <b>Generated:</b> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ssK')</p>
<div class="summary"><div class="tile"><b>$($Results.Count)</b>Total checks/results</div><div class="tile"><b>$($counts.PASS)</b>Pass</div><div class="tile"><b>$($counts.FAIL)</b>Fail</div><div class="tile"><b>$($counts.WARN)</b>Warning</div><div class="tile"><b>$($counts.UNKNOWN)</b>Unknown</div><div class="tile"><b>$($counts.SKIPPED)</b>Skipped</div></div>
<h2>Inventory</h2><table><tbody>
<tr><th>Computer name</th><td>$(ConvertTo-WINAPHtmlEncoded $Inventory.ComputerName)</td><th>Domain/workgroup</th><td>$(ConvertTo-WINAPHtmlEncoded $Inventory.Domain)</td></tr>
<tr><th>Operating system</th><td>$(ConvertTo-WINAPHtmlEncoded $Inventory.OperatingSystem)</td><th>Build</th><td>$(ConvertTo-WINAPHtmlEncoded $Inventory.OSBuild)</td></tr>
<tr><th>PowerShell</th><td>$(ConvertTo-WINAPHtmlEncoded $Inventory.PowerShellVersion)</td><th>Free C: space (GB)</th><td>$(ConvertTo-WINAPHtmlEncoded $Inventory.CDriveFreeGB)</td></tr>
<tr><th>Administrator</th><td>$(ConvertTo-WINAPHtmlEncoded $Inventory.IsAdministrator)</td><th>Last boot</th><td>$(ConvertTo-WINAPHtmlEncoded $Inventory.LastBootTime)</td></tr>
</tbody></table>
<h2>Checks, actions, and outcomes</h2><table><thead><tr><th>Status</th><th>Category</th><th>Check</th><th>Expected</th><th>Actual</th><th>Details</th></tr></thead><tbody>
$($rows -join "`n")
</tbody></table><p class="muted">WINAP is a learning/portfolio utility, not a certified vulnerability scanner. UNKNOWN means the available evidence was insufficient to reach a reliable conclusion. Review findings before making operational decisions.</p></body></html>
"@
    Set-Content -LiteralPath $Path -Value $html -Encoding UTF8
}

function Invoke-WINAP {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ConfigPath,
        [switch]$Preview,
        [switch]$RemediateSMB1,
        [switch]$AcknowledgeSMB1Impact,
        [switch]$InstallFeatures
    )
    $started = Get-Date
    $cfg = $null
    $runId = [guid]::NewGuid().ToString('N').Substring(0,12)
    $root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $allResults = New-Object System.Collections.Generic.List[object]
    $mode = if ($Preview) { 'Preview' } else { 'Audit' }
    try {
        $envInfo = Test-WINAPEnvironment
        $allResults.Add((New-WINAPResult -Category 'Environment' -Check 'Supported OS and PowerShell' -Status 'PASS' -Expected 'Windows Server 2022 / Windows PowerShell 5.1' -Actual "$($envInfo.OperatingSystem) / $($envInfo.PowerShellVersion)" -Message 'Supported execution environment confirmed.'))
        $cfg = Import-WINAPConfiguration -Path $ConfigPath
        if ($cfg.mode -eq 'Preview') { $mode = 'Preview' }
        $inventory = Get-WINAPInventory -Environment $envInfo
        $allResults.Add((New-WINAPResult -Category 'Inventory' -Check 'Read-only server inventory' -Status 'PASS' -Expected 'Collect inventory only' -Actual $inventory.ComputerName -Message 'Inventory collected. Hostname and system configuration were not changed.'))
        $auditResults = @(Invoke-WINAPAudit -Configuration $cfg)
        foreach ($r in $auditResults) { $allResults.Add($r) }
        $featureResults = @(Invoke-WINAPFeatureInstallation -Configuration $cfg -InstallFeatures:$InstallFeatures -Preview:($Preview -or $mode -eq 'Preview'))
        foreach ($r in $featureResults) { $allResults.Add($r) }
        $remediationResults = @(Invoke-WINAPSMB1Remediation -Configuration $cfg -RemediateSMB1:$RemediateSMB1 -AcknowledgeSMB1Impact:$AcknowledgeSMB1Impact -Preview:($Preview -or $mode -eq 'Preview'))
        foreach ($r in $remediationResults) { $allResults.Add($r) }
    } catch {
        $allResults.Add((New-WINAPResult -Category 'Execution' -Check 'WINAP execution' -Status 'FAIL' -Expected 'Validated configuration and supported environment' -Actual 'Execution stopped' -Message $_.Exception.Message))
        $inventory = [PSCustomObject]@{ ComputerName=$env:COMPUTERNAME; Domain='Unknown'; OperatingSystem='Unknown'; OSBuild='Unknown'; PowerShellVersion=$PSVersionTable.PSVersion.ToString(); CDriveFreeGB=$null; IsAdministrator=(Test-WINAPAdministrator); LastBootTime='Unknown' }
    }

    # Report paths are resolved relative to the project root unless outputDirectory is absolute.
    $outputDir = Join-Path $root 'output'
    if ($null -ne $cfg -and -not [string]::IsNullOrWhiteSpace([string]$cfg.reporting.outputDirectory)) {
        if ([IO.Path]::IsPathRooted([string]$cfg.reporting.outputDirectory)) { $outputDir = [string]$cfg.reporting.outputDirectory }
        else { $outputDir = Join-Path $root ([string]$cfg.reporting.outputDirectory) }
    }
    try {
        if (-not (Test-Path -LiteralPath $outputDir -PathType Container)) { New-Item -ItemType Directory -Path $outputDir -Force | Out-Null }
        $logName = if ($null -ne $cfg) { [string]$cfg.reporting.logFile } else { "WINAP-$runId.log" }
        $reportName = if ($null -ne $cfg) { [string]$cfg.reporting.htmlReport } else { "WINAP-$runId.html" }
        $logPath = Join-Path $outputDir $logName
        $reportPath = Join-Path $outputDir $reportName
        Write-WINAPLog -Path $logPath -Results @($allResults.ToArray()) -RunId $runId
        Write-WINAPHtmlReport -Path $reportPath -Results @($allResults.ToArray()) -Inventory $inventory -RunId $runId -Mode $mode
        Write-Host "`nWINAP run complete ($mode)." -ForegroundColor Cyan
        Write-Host "Results: $($allResults.Count) | PASS: $(@($allResults | Where-Object Status -eq 'PASS').Count) | FAIL: $(@($allResults | Where-Object Status -eq 'FAIL').Count) | UNKNOWN: $(@($allResults | Where-Object Status -eq 'UNKNOWN').Count)"
        Write-Host "HTML report: $reportPath"
        Write-Host "Log file:    $logPath"
        $allResults | Select-Object Status,Category,Check,Actual,Message | Format-Table -Wrap -AutoSize
    } catch {
        Write-Error "WINAP generated results but failed to write report/log: $($_.Exception.Message)"
    }
    return @($allResults.ToArray())
}

Export-ModuleMember -Function Invoke-WINAP, Import-WINAPConfiguration, Invoke-WINAPAudit, Get-WINAPInventory, Test-WINAPEnvironment, Get-WINAPFeaturePlan, Invoke-WINAPSMB1Remediation, Write-WINAPHtmlReport
