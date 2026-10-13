#requires -Version 5.1
<#
.SYNOPSIS
    Server Health Manager - configurable, read-only Windows Server health checks.

.DESCRIPTION
    Checks configurable Windows Server health items and presents results in a Windows Forms UI.

    PUBLIC-SAFE DEFAULTS:
      - Read-only checks only; no automatic remediation is implemented.
      - Windows activation/KMS status is inspected and reported only.
      - Date/time and timezone are inspected and reported only.
      - Optional environment-specific checks can be enabled in configuration.
      - Reports are written locally to the Reports folder; do not commit reports.

.NOTES
    Version: 1.0
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ============================================================
# USER CONFIGURATION
# ============================================================

$Policy = [ordered]@{
    # Leave empty to report the current timezone without judging it.
    # Example: 'UTC' or a Windows timezone ID such as 'Eastern Standard Time'.
    ExpectedTimezone = ''

    # Optional policy checks. Leave blank/empty until you know the correct values.
    ApprovedStableOSBuilds = @()
    ExpectedDomain = ''
    ComputerNameRegex = ''
    CPUAlertPercent = 50
    RAMAlertPercent = 80
    AllowedLocalUsers = @()
    RequiredDisabledLocalUsers = @('Guest')
    VSSScheduleConfigured = $false

    # EDR is optional. Add one or more regex patterns matching the service Name
    # or DisplayName used by your security product, then enable EDR below.
    # Example: @('VendorAgentService', 'Vendor Endpoint Protection')
    EDRServicePatterns = @()
}

# Toggle each check independently. Checks that depend on a particular product
# or infrastructure are OFF by default to avoid false alarms on other systems.
$EnabledChecks = [ordered]@{
    OperatingSystem = $true
    WindowsUpdate   = $true
    DateTime        = $true
    Resources       = $true
    ComputerName    = $true
    Domain          = $true
    LocalUsers      = $true
    WindowsActivation = $true
    VMwareTools     = $false
    VSS             = $true
    Zabbix          = $false
    TLS             = $true
    ExtraSoftware   = $true
    Splunk          = $false
    EDR             = $false
}

# This public version is read-only. No timezone changes, KMS activation,
# service changes, domain changes, or other remediation commands are performed.

# ============================================================
# GLOBAL STATE
# ============================================================

$script:Results = New-Object System.Collections.Generic.List[object]
$script:LogLines = New-Object System.Collections.Generic.List[string]
$script:LastRun = $null
$script:LogDirectory = Join-Path $PSScriptRoot 'Reports'

if (-not (Test-Path $script:LogDirectory)) {
    New-Item -ItemType Directory -Path $script:LogDirectory -Force | Out-Null
}

function Add-Result {
    param(
        [string]$Category,
        [string]$Check,
        [ValidateSet('PASS','WARNING','ERROR','MANUAL','INFO','FIXED','FIX_FAILED','PENDING')]
        [string]$Status,
        [string]$Details,
        [string]$Action = '',
        [string]$ErrorDetail = ''
    )

    $script:Results.Add([pscustomobject]@{
        Category   = $Category
        Check      = $Check
        Status     = $Status
        Details    = $Details
        Action     = $Action
        Error      = $ErrorDetail
        Timestamp  = Get-Date
    })
}

function Add-Log {
    param([string]$Message)

    $line = '{0}  {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    $script:LogLines.Add($line)
}

function Get-OverallStatus {
    if ($script:Results.Status -contains 'ERROR' -or $script:Results.Status -contains 'FIX_FAILED') {
        return 'CRITICAL'
    }
    if ($script:Results.Status -contains 'WARNING' -or $script:Results.Status -contains 'MANUAL') {
        return 'WARNING'
    }
    if ($script:Results.Status -contains 'PENDING') {
        return 'WARNING'
    }
    return 'PASS'
}

function Get-ServiceMatches {
    param([string]$Pattern)

    try {
        @(Get-CimInstance Win32_Service | Where-Object {
            $_.Name -match $Pattern -or $_.DisplayName -match $Pattern
        })
    }
    catch {
        @()
    }
}

function Get-InstalledApplications {
    $paths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    $items = New-Object System.Collections.Generic.List[object]

    foreach ($path in $paths) {
        try {
            foreach ($item in @(Get-ItemProperty -Path $path -ErrorAction SilentlyContinue)) {
                if ($null -ne $item.PSObject.Properties['DisplayName']) {
                    $name = [string]$item.DisplayName
                    if (-not [string]::IsNullOrWhiteSpace($name)) {
                        $version = ''
                        if ($null -ne $item.PSObject.Properties['DisplayVersion']) {
                            $version = [string]$item.DisplayVersion
                        }

                        $items.Add([pscustomobject]@{
                            DisplayName = $name
                            DisplayVersion = $version
                        })
                    }
                }
            }
        }
        catch {
            Add-Log "Software inventory warning: $($_.Exception.Message)"
        }
    }

    $items | Sort-Object DisplayName -Unique
}

function Test-Property {
    param(
        [object]$Object,
        [string]$Name
    )
    return $null -ne $Object -and $null -ne $Object.PSObject.Properties[$Name]
}

# ============================================================
# CHECKS
# ============================================================

function Check-OperatingSystem {
    Add-Log 'Checking operating system version.'

    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $build = [string]$os.BuildNumber
        $caption = [string]$os.Caption

        if ($Policy.ApprovedStableOSBuilds.Count -eq 0) {
            Add-Result 'System' 'Approved Stable OS Version' 'PENDING' `
                "$caption, build $build. Approved stable builds are not configured yet." `
                'MANUAL POLICY CONFIGURATION'
            return
        }

        if ($Policy.ApprovedStableOSBuilds -contains $build) {
            Add-Result 'System' 'Approved Stable OS Version' 'PASS' `
                "$caption, build $build."
        }
        else {
            Add-Result 'System' 'Approved Stable OS Version' 'WARNING' `
                "$caption, build $build is not in the approved stable-build list." `
                'MANUAL REVIEW'
        }
    }
    catch {
        Add-Result 'System' 'Approved Stable OS Version' 'ERROR' 'Unable to read OS information.' `
            'MANUAL REVIEW' $_.Exception.Message
    }
}

function Check-WindowsUpdate {
    Add-Log 'Checking Windows Update. No restart will be performed.'

    try {
        $service = Get-Service -Name wuauserv -ErrorAction Stop

        if ($service.Status -ne 'Running') {
            Add-Result 'System' 'Windows Update Service' 'WARNING' `
                "Windows Update service is $($service.Status)." 'MANUAL REVIEW'
        }
        else {
            Add-Result 'System' 'Windows Update Service' 'PASS' 'Windows Update service is running.'
        }

        try {
            $session = New-Object -ComObject Microsoft.Update.Session
            $searcher = $session.CreateUpdateSearcher()
            $result = $searcher.Search("IsInstalled=0 and IsHidden=0")
            $count = [int]$result.Updates.Count

            if ($count -eq 0) {
                Add-Result 'System' 'Pending Windows Updates' 'PASS' 'No pending non-hidden updates detected.'
            }
            else {
                Add-Result 'System' 'Pending Windows Updates' 'WARNING' `
                    "$count pending update(s) detected." 'MANUAL REVIEW'
            }
        }
        catch {
            Add-Result 'System' 'Pending Windows Updates' 'MANUAL' `
                'Windows Update search could not be completed.' 'MANUAL REVIEW' $_.Exception.Message
        }

        $rebootPending = $false
        $rebootPaths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        )

        foreach ($path in $rebootPaths) {
            if (Test-Path $path) {
                $rebootPending = $true
            }
        }

        if ($rebootPending) {
            Add-Result 'System' 'Pending Restart' 'WARNING' `
                'Windows reports that a restart is pending. This script will NOT restart the server.' `
                'MANUAL RESTART'
        }
        else {
            Add-Result 'System' 'Pending Restart' 'PASS' 'No standard pending-restart indicators detected.'
        }
    }
    catch {
        Add-Result 'System' 'Windows Update' 'ERROR' 'Unable to check Windows Update.' `
            'MANUAL REVIEW' $_.Exception.Message
    }
}

function Check-DateTime {
    Add-Log 'Checking current date, time, timezone and time synchronization (read-only).'

    try {
        $tz = Get-TimeZone
        $now = Get-Date
        $source = ''

        try {
            $w32 = & w32tm.exe /query /source 2>&1
            $source = ($w32 -join ' ').Trim()
        }
        catch {
            $source = 'Unable to query time source'
        }

        if ([string]::IsNullOrWhiteSpace([string]$Policy.ExpectedTimezone)) {
            Add-Result 'System' 'Timezone' 'INFO' `
                "Current timezone: $($tz.Id). No expected timezone is configured; no change was made."
        }
        elseif ($tz.Id -eq [string]$Policy.ExpectedTimezone) {
            Add-Result 'System' 'Timezone' 'PASS' "Timezone matches configured value: $($tz.Id)."
        }
        else {
            Add-Result 'System' 'Timezone' 'WARNING' `
                "Current timezone: $($tz.Id). Configured expected timezone: $($Policy.ExpectedTimezone). No change was made." `
                'MANUAL REVIEW'
        }

        Add-Result 'System' 'System Date/Time' 'INFO' "Current system time: $($now.ToString('yyyy-MM-dd HH:mm:ss'))."
        Add-Result 'System' 'Time Source' 'INFO' "Time source: $source"
    }
    catch {
        Add-Result 'System' 'Date/Time' 'ERROR' 'Unable to read date/time configuration.' `
            'MANUAL REVIEW' $_.Exception.Message
    }
}

function Check-Resources {
    Add-Log 'Sampling CPU and RAM.'

    $samples = @()
    $sampleCount = 12
    $intervalSeconds = 5

    try {
        for ($i = 1; $i -le $sampleCount; $i++) {
            $cpu = [math]::Round((Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples[0].CookedValue, 1)
            $os = Get-CimInstance Win32_OperatingSystem
            $ram = [math]::Round((1 - ($os.FreePhysicalMemory / $os.TotalVisibleMemorySize)) * 100, 1)

            $samples += [pscustomobject]@{
                CPU = $cpu
                RAM = $ram
            }

            if ($i -lt $sampleCount) {
                Start-Sleep -Seconds $intervalSeconds
            }
        }

        $cpuMax = [math]::Round((($samples | Measure-Object CPU -Maximum).Maximum), 1)
        $cpuAvg = [math]::Round((($samples | Measure-Object CPU -Average).Average), 1)
        $ramMax = [math]::Round((($samples | Measure-Object RAM -Maximum).Maximum), 1)
        $ramAvg = [math]::Round((($samples | Measure-Object RAM -Average).Average), 1)

        $cpuStatus = if ($cpuMax -gt $Policy.CPUAlertPercent) { 'WARNING' } else { 'PASS' }
        $ramStatus = if ($ramMax -gt $Policy.RAMAlertPercent) { 'WARNING' } else { 'PASS' }

        Add-Result 'Resources' 'CPU' $cpuStatus `
            "Average: $cpuAvg%, Maximum: $cpuMax%, Alert threshold: >$($Policy.CPUAlertPercent)%." 'MONITOR'
        Add-Result 'Resources' 'RAM' $ramStatus `
            "Average: $ramAvg%, Maximum: $ramMax%, Alert threshold: >$($Policy.RAMAlertPercent)%." 'MONITOR'
    }
    catch {
        Add-Result 'Resources' 'CPU/RAM' 'ERROR' 'Resource sampling failed.' `
            'MANUAL REVIEW' $_.Exception.Message
    }
}

function Check-ComputerName {
    try {
        $name = $env:COMPUTERNAME

        if ([string]::IsNullOrWhiteSpace($Policy.ComputerNameRegex)) {
            Add-Result 'Identity' 'Computer Name Policy' 'PENDING' `
                "Computer name is $name. Naming regex is not configured." 'MANUAL POLICY CONFIGURATION'
            return
        }

        if ($name -match $Policy.ComputerNameRegex) {
            Add-Result 'Identity' 'Computer Name Policy' 'PASS' "Computer name $name matches policy."
        }
        else {
            Add-Result 'Identity' 'Computer Name Policy' 'WARNING' `
                "Computer name $name does not match the configured naming policy." 'MANUAL REVIEW'
        }
    }
    catch {
        Add-Result 'Identity' 'Computer Name Policy' 'ERROR' 'Unable to evaluate computer name.' `
            'MANUAL REVIEW' $_.Exception.Message
    }
}

function Check-Domain {
    try {
        $cs = Get-CimInstance Win32_ComputerSystem
        if ($cs.PartOfDomain) {
            $domain = [string]$cs.Domain

            if ([string]::IsNullOrWhiteSpace($Policy.ExpectedDomain)) {
                Add-Result 'Identity' 'Domain Membership' 'INFO' "Joined to domain: $domain. ExpectedDomain is not configured, so membership was not policy-validated."
            }
            elseif ($domain -ieq $Policy.ExpectedDomain) {
                Add-Result 'Identity' 'Domain Membership' 'PASS' "Joined to expected domain: $domain."
            }
            else {
                Add-Result 'Identity' 'Domain Membership' 'WARNING' `
                    "Joined to $domain, expected $($Policy.ExpectedDomain)." 'MANUAL REVIEW'
            }
        }
        else {
            Add-Result 'Identity' 'Domain Membership' 'ERROR' `
                'Server is not joined to a domain.' 'MANUAL DOMAIN JOIN'
        }
    }
    catch {
        Add-Result 'Identity' 'Domain Membership' 'ERROR' 'Unable to read domain membership.' `
            'MANUAL REVIEW' $_.Exception.Message
    }
}

function Check-LocalUsers {
    try {
        $users = @(Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True")
        $userNames = @($users | Select-Object -ExpandProperty Name)

        $missingDisabled = @()
        foreach ($required in $Policy.RequiredDisabledLocalUsers) {
            $u = $users | Where-Object { $_.Name -ieq $required }
            if ($null -ne $u -and -not $u.Disabled) {
                $missingDisabled += $required
            }
        }

        if ($missingDisabled.Count -gt 0) {
            Add-Result 'Security' 'Local User Policy' 'WARNING' `
                "Required-disabled local user(s) are enabled: $($missingDisabled -join ', ')." 'MANUAL REVIEW'
        }
        elseif ($Policy.AllowedLocalUsers.Count -eq 0) {
            Add-Result 'Security' 'Local User Policy' 'PENDING' `
                "Local users detected: $($userNames -join ', '). Allowed-user policy is not configured." `
                'MANUAL POLICY CONFIGURATION'
        }
        else {
            $unexpected = @($userNames | Where-Object { $Policy.AllowedLocalUsers -notcontains $_ })
            if ($unexpected.Count -gt 0) {
                Add-Result 'Security' 'Local User Policy' 'WARNING' `
                    "Unexpected local user(s): $($unexpected -join ', ')." 'MANUAL REVIEW'
            }
            else {
                Add-Result 'Security' 'Local User Policy' 'PASS' 'Local users match configured policy.'
            }
        }
    }
    catch {
        Add-Result 'Security' 'Local User Policy' 'ERROR' 'Unable to inspect local users.' `
            'MANUAL REVIEW' $_.Exception.Message
    }
}

function Get-WindowsActivationState {
    try {
        $products = @(Get-CimInstance SoftwareLicensingProduct -ErrorAction Stop | Where-Object {
            $_.PartialProductKey -and
            $_.Name -like 'Windows*' -and
            $_.ApplicationID -eq '55c92734-d682-4d71-983e-d6ec3f16059f'
        })

        $licensed = $products | Where-Object { $_.LicenseStatus -eq 1 } | Select-Object -First 1
        return $null -ne $licensed
    }
    catch {
        return $null
    }
}

function Check-Activation {
    try {
        $active = Get-WindowsActivationState
        $licensing = Get-CimInstance SoftwareLicensingService -ErrorAction SilentlyContinue
        $kmsHost = ''
        if ($null -ne $licensing -and $licensing.PSObject.Properties['KeyManagementServiceMachine']) {
            $kmsHost = [string]$licensing.KeyManagementServiceMachine
        }

        $windowsProducts = @(Get-CimInstance SoftwareLicensingProduct -ErrorAction SilentlyContinue | Where-Object {
            $_.PartialProductKey -and $_.Name -like 'Windows*' -and
            $_.ApplicationID -eq '55c92734-d682-4d71-983e-d6ec3f16059f'
        })
        $channel = ($windowsProducts | Select-Object -First 1 -ExpandProperty Description -ErrorAction SilentlyContinue)
        if ([string]::IsNullOrWhiteSpace([string]$channel)) { $channel = 'Not available' }
        if ([string]::IsNullOrWhiteSpace($kmsHost)) { $kmsHost = 'Not reported/configured' }

        if ($null -eq $active) {
            Add-Result 'Security' 'Windows Activation / KMS Status' 'MANUAL' `
                "Windows activation state could not be determined. Licensing description: $channel. KMS host reported by Windows: $kmsHost. No activation command was run." `
                'MANUAL REVIEW'
        }
        elseif ($active) {
            Add-Result 'Security' 'Windows Activation / KMS Status' 'PASS' `
                "Windows reports activated. Licensing description: $channel. KMS host reported by Windows: $kmsHost. Read-only check; no activation command was run."
        }
        else {
            Add-Result 'Security' 'Windows Activation / KMS Status' 'WARNING' `
                "Windows was not detected as activated. Licensing description: $channel. KMS host reported by Windows: $kmsHost. No KMS server was contacted or configured by this script." `
                'MANUAL REVIEW'
        }
    }
    catch {
        Add-Result 'Security' 'Windows Activation / KMS Status' 'MANUAL' `
            'Unable to determine Windows activation/KMS status.' 'MANUAL REVIEW' $_.Exception.Message
    }
}

function Check-VMwareTools {
    $services = Get-ServiceMatches 'VMware.*Tools|VMTools'
    if ($services.Count -gt 0) {
        $running = @($services | Where-Object { $_.State -eq 'Running' })
        if ($running.Count -gt 0) {
            Add-Result 'Software' 'VMware Tools' 'PASS' 'VMware Tools service is installed and running.'
        }
        else {
            Add-Result 'Software' 'VMware Tools' 'WARNING' 'VMware Tools service exists but is not running.' 'MANUAL REVIEW'
        }
        return
    }

    $apps = @(Get-InstalledApplications | Where-Object { $_.DisplayName -match 'VMware Tools' })
    if ($apps.Count -gt 0) {
        Add-Result 'Software' 'VMware Tools' 'WARNING' 'VMware Tools appears installed but its service was not found/running.' 'MANUAL REVIEW'
    }
    else {
        Add-Result 'Software' 'VMware Tools' 'ERROR' 'VMware Tools was not detected.' 'MANUAL INSTALL / REVIEW'
    }
}

function Check-Zabbix {
    $services = Get-ServiceMatches 'zabbix'
    if ($services.Count -eq 0) {
        Add-Result 'Monitoring' 'Zabbix Agent' 'ERROR' 'No Zabbix service was detected.' 'MANUAL INSTALL / REVIEW'
        return
    }

    $running = @($services | Where-Object { $_.State -eq 'Running' })
    if ($running.Count -gt 0) {
        Add-Result 'Monitoring' 'Zabbix Agent' 'PASS' `
            "Zabbix service running: $($running[0].DisplayName)."
    }
    else {
        Add-Result 'Monitoring' 'Zabbix Agent' 'ERROR' `
            'Zabbix service exists but is not running.' 'MANUAL REVIEW'
    }
}

function Check-Splunk {
    $services = Get-ServiceMatches 'splunkforwarder|splunk forwarder'
    if ($services.Count -eq 0) {
        Add-Result 'Monitoring' 'Splunk Forwarder' 'ERROR' 'Splunk Forwarder service was not detected.' 'MANUAL INSTALL / REVIEW'
        return
    }

    $running = @($services | Where-Object { $_.State -eq 'Running' })
    if ($running.Count -gt 0) {
        Add-Result 'Monitoring' 'Splunk Forwarder' 'PASS' 'Splunk Forwarder service is running.'
    }
    else {
        Add-Result 'Monitoring' 'Splunk Forwarder' 'ERROR' `
            'Splunk Forwarder service exists but is not running.' 'MANUAL REVIEW'
    }
}

function Check-EDR {
    $patterns = @($Policy.EDRServicePatterns | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($patterns.Count -eq 0) {
        Add-Result 'Security' 'EDR / Endpoint Security' 'PENDING' `
            'EDR check is enabled but no service-name patterns are configured. Add the expected product service pattern(s) to Policy.EDRServicePatterns.' `
            'CONFIGURE EDR PATTERNS'
        return
    }

    $matches = @()
    foreach ($pattern in $patterns) {
        $matches += @(Get-ServiceMatches ([string]$pattern))
    }
    $matches = @($matches | Sort-Object Name -Unique)

    if ($matches.Count -eq 0) {
        Add-Result 'Security' 'EDR / Endpoint Security' 'WARNING' `
            "No service matched configured EDR patterns: $($patterns -join ', '). Verify service names and product installation." `
            'MANUAL REVIEW'
        return
    }

    $running = @($matches | Where-Object { $_.State -eq 'Running' })
    if ($running.Count -gt 0) {
        Add-Result 'Security' 'EDR / Endpoint Security' 'PASS' `
            "Configured endpoint security service detected and running: $($running[0].DisplayName)."
    }
    else {
        Add-Result 'Security' 'EDR / Endpoint Security' 'WARNING' `
            "Configured endpoint security service(s) found but none is running: $((@($matches | ForEach-Object { $_.DisplayName }) -join ', '))." `
            'MANUAL REVIEW'
    }
}

function Check-VSS {
    try {
        $service = Get-Service -Name VSS -ErrorAction SilentlyContinue
        if ($null -eq $service) {
            Add-Result 'Storage' 'VSS Service' 'ERROR' 'VSS service was not found.' 'MANUAL REVIEW'
        }
        else {
            Add-Result 'Storage' 'VSS Service' 'INFO' "VSS service state: $($service.Status)."
        }

        $shadows = & vssadmin.exe list shadows /for=C: 2>&1
        $storage = & vssadmin.exe list shadowstorage /for=C: 2>&1

        $shadowText = ($shadows -join "`n")
        $storageText = ($storage -join "`n")

        if ($shadowText -match 'No items found') {
            Add-Result 'Storage' 'C: Shadow Copies' 'WARNING' `
                'No existing C: shadow copies were detected.' 'MANUAL REVIEW'
        }
        else {
            Add-Result 'Storage' 'C: Shadow Copies' 'PASS' `
                'C: shadow-copy information was detected. See detailed report for vssadmin output.'
        }

        if ($storageText -match 'No shadow copy storage') {
            Add-Result 'Storage' 'C: Shadow Storage' 'WARNING' `
                'No configured shadow-copy storage was detected.' 'MANUAL REVIEW'
        }
        else {
            Add-Result 'Storage' 'C: Shadow Storage' 'PASS' 'Shadow-copy storage information is available.'
        }

        if ($Policy.VSSScheduleConfigured) {
            Add-Result 'Storage' 'VSS Schedule' 'INFO' `
                'VSS schedule policy is marked configured. Detailed schedule verification should be matched to the approved organization schedule.'
        }
        else {
            Add-Result 'Storage' 'VSS Schedule' 'PENDING' `
                'VSS schedule policy has not been supplied yet.' 'MANUAL POLICY CONFIGURATION'
        }

        $script:VSSDetail = @($shadowText, $storageText) -join "`r`n`r`n"
    }
    catch {
        Add-Result 'Storage' 'VSS' 'ERROR' 'Unable to inspect VSS configuration.' `
            'MANUAL REVIEW' $_.Exception.Message
    }
}

function Get-ProtocolState {
    param(
        [string]$Protocol,
        [string]$Role
    )

    $base = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$Protocol\$Role"
    $result = [ordered]@{
        Exists = $false
        Enabled = $null
        DisabledByDefault = $null
    }

    try {
        if (Test-Path $base) {
            $result.Exists = $true
            $p = Get-ItemProperty -Path $base -ErrorAction SilentlyContinue
            if (Test-Property $p 'Enabled') { $result.Enabled = [int]$p.Enabled }
            if (Test-Property $p 'DisabledByDefault') { $result.DisabledByDefault = [int]$p.DisabledByDefault }
        }
    }
    catch {}

    return [pscustomobject]$result
}

function Check-TLS {
    # Read-only validation against the requested policy. Missing registry values
    # are reported as not explicitly configured; Windows defaults vary by OS version.
    $expectedByProtocol = @{
        'TLS 1.0' = @{ Enabled = 0; DisabledByDefault = 1 }
        'TLS 1.1' = @{ Enabled = 0; DisabledByDefault = 1 }
        'TLS 1.2' = @{ Enabled = 1; DisabledByDefault = 0 }
    }

    foreach ($protocol in @('TLS 1.0','TLS 1.1','TLS 1.2')) {
        $server = Get-ProtocolState -Protocol $protocol -Role 'Server'
        $client = Get-ProtocolState -Protocol $protocol -Role 'Client'
        $expected = $expectedByProtocol[$protocol]

        $serverMatches = ($null -ne $server.Enabled -and
                          $null -ne $server.DisabledByDefault -and
                          $server.Enabled -eq $expected.Enabled -and
                          $server.DisabledByDefault -eq $expected.DisabledByDefault)
        $clientMatches = ($null -ne $client.Enabled -and
                          $null -ne $client.DisabledByDefault -and
                          $client.Enabled -eq $expected.Enabled -and
                          $client.DisabledByDefault -eq $expected.DisabledByDefault)

        $details = "Expected: Enabled=$($expected.Enabled), DisabledByDefault=$($expected.DisabledByDefault). " +
                   "Server: keyExists=$($server.Exists), Enabled=$($server.Enabled), DisabledByDefault=$($server.DisabledByDefault). " +
                   "Client: keyExists=$($client.Exists), Enabled=$($client.Enabled), DisabledByDefault=$($client.DisabledByDefault). " +
                   'Read-only check; no registry values were changed.'

        if ($serverMatches -and $clientMatches) {
            Add-Result 'Security' $protocol 'PASS' "$protocol matches the configured policy for both Server and Client. $details"
        }
        else {
            Add-Result 'Security' $protocol 'WARNING' `
                "$protocol does not explicitly match the requested policy for both Server and Client, or one or more registry values are missing. Review OS defaults and organizational requirements before changing anything. $details" `
                'MANUAL REVIEW'
        }
    }
}

function Check-ExtraSoftware {
    try {
        $apps = @(Get-InstalledApplications)
        $desktopPaths = @(
            [Environment]::GetFolderPath('Desktop'),
            [Environment]::GetFolderPath('CommonDesktopDirectory')
        ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

        $desktopItems = New-Object System.Collections.Generic.List[string]
        foreach ($path in $desktopPaths) {
            foreach ($item in @(Get-ChildItem -Path $path -Force -ErrorAction SilentlyContinue)) {
                $desktopItems.Add($item.Name)
            }
        }

        Add-Result 'Software' 'Installed Software Inventory' 'INFO' `
            "$($apps.Count) installed application entries found. No applications will be removed automatically."

        if ($desktopItems.Count -gt 0) {
            Add-Result 'Software' 'Desktop Inventory' 'INFO' `
                "$($desktopItems.Count) desktop item(s) found. No desktop items will be removed automatically."
        }
        else {
            Add-Result 'Software' 'Desktop Inventory' 'PASS' 'No desktop items detected in checked locations.'
        }

        $script:InstalledApps = $apps
        $script:DesktopItems = @($desktopItems)
    }
    catch {
        Add-Result 'Software' 'Software Inventory' 'ERROR' 'Unable to inventory installed software.' `
            'MANUAL REVIEW' $_.Exception.Message
    }
}

# Invoke one check only when its user-configurable toggle is enabled.
function Invoke-ConfiguredCheck {
    param(
        [Parameter(Mandatory=$true)][string]$Key,
        [Parameter(Mandatory=$true)][string]$Label,
        [Parameter(Mandatory=$true)][scriptblock]$Check
    )

    if ($EnabledChecks.Contains($Key) -and $EnabledChecks[$Key]) {
        Add-Log "Running check: $Label"
        & $Check
    }
    else {
        Add-Result 'Configuration' $Label 'INFO' "Check '$Key' is disabled in configuration and was skipped." 'SKIPPED BY CONFIGURATION'
        Add-Log "Skipped disabled check: $Label"
    }
}

# ============================================================
# MAIN READ-ONLY CHECKS
# ============================================================

function Invoke-HealthCheck {
    $script:Results.Clear()
    $script:LogLines.Clear()
    $script:LastRun = Get-Date
    $script:VSSDetail = ''
    $script:InstalledApps = @()
    $script:DesktopItems = @()

    Add-Log '============================================================'
    Add-Log "Read-only health check started on $env:COMPUTERNAME."
    Add-Log 'No automatic remediation is available in this public version.'
    Add-Log 'Windows activation/KMS and date/time are report-only checks.'
    Add-Log '============================================================'

    Invoke-ConfiguredCheck 'OperatingSystem' 'Operating System' { Check-OperatingSystem }
    Invoke-ConfiguredCheck 'WindowsUpdate' 'Windows Update' { Check-WindowsUpdate }
    Invoke-ConfiguredCheck 'DateTime' 'Date / Time / Timezone' { Check-DateTime }
    Invoke-ConfiguredCheck 'Resources' 'CPU / RAM Resources' { Check-Resources }
    Invoke-ConfiguredCheck 'ComputerName' 'Computer Name Policy' { Check-ComputerName }
    Invoke-ConfiguredCheck 'Domain' 'Domain Membership' { Check-Domain }
    Invoke-ConfiguredCheck 'LocalUsers' 'Local User Policy' { Check-LocalUsers }
    Invoke-ConfiguredCheck 'WindowsActivation' 'Windows Activation / KMS Status' { Check-Activation }
    Invoke-ConfiguredCheck 'VMwareTools' 'VMware Tools' { Check-VMwareTools }
    Invoke-ConfiguredCheck 'VSS' 'Volume Shadow Copy' { Check-VSS }
    Invoke-ConfiguredCheck 'Zabbix' 'Zabbix Agent' { Check-Zabbix }
    Invoke-ConfiguredCheck 'TLS' 'TLS Configuration' { Check-TLS }
    Invoke-ConfiguredCheck 'ExtraSoftware' 'Software Inventory' { Check-ExtraSoftware }
    Invoke-ConfiguredCheck 'Splunk' 'Splunk Forwarder' { Check-Splunk }
    Invoke-ConfiguredCheck 'EDR' 'EDR / Endpoint Security' { Check-EDR }

    Add-Log "Health check completed. Overall status: $(Get-OverallStatus)."
    Save-Report
    return $script:Results
}

function Save-Report {
    try {
        $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $base = Join-Path $script:LogDirectory "$env:COMPUTERNAME`_$stamp"

        $script:Results | Export-Csv -Path "$base.csv" -NoTypeInformation -Encoding UTF8

        $summary = @(
            "SERVER HEALTH REPORT"
            "===================="
            "Server: $env:COMPUTERNAME"
            "Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            "Overall: $(Get-OverallStatus)"
            ""
            "RESULTS"
            "-------"
        )

        foreach ($r in $script:Results) {
            $summary += "[{0}] {1} | {2} | {3}" -f $r.Status, $r.Category, $r.Check, $r.Details
            if ($r.Action) { $summary += "    Action: $($r.Action)" }
            if ($r.Error) { $summary += "    Error: $($r.Error)" }
        }

        if ($script:VSSDetail) {
            $summary += ""
            $summary += "VSS DETAIL"
            $summary += "----------"
            $summary += $script:VSSDetail
        }

        $summary | Set-Content -Path "$base.txt" -Encoding UTF8
        $script:LogLines | Add-Content -Path "$base.log" -Encoding UTF8

        $script:LastReportPath = "$base.txt"
    }
    catch {
        $script:LastReportPath = ''
    }
}

# ============================================================
# UI
# ============================================================

$form = New-Object System.Windows.Forms.Form
$form.Text = 'Server Health Manager'
$form.StartPosition = 'CenterScreen'
$form.Size = New-Object System.Drawing.Size(1180, 760)
$form.MinimumSize = New-Object System.Drawing.Size(1000, 650)
$form.BackColor = [System.Drawing.Color]::FromArgb(245,247,250)

$font = New-Object System.Drawing.Font('Segoe UI', 9)
$fontBold = New-Object System.Drawing.Font('Segoe UI Semibold', 9)
$fontTitle = New-Object System.Drawing.Font('Segoe UI Semibold', 18)
$fontStatus = New-Object System.Drawing.Font('Segoe UI Semibold', 13)

function New-Label {
    param([string]$Text,[int]$X,[int]$Y,[int]$W,[int]$H,[System.Drawing.Font]$Font=$font)
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $Text
    $l.Location = New-Object System.Drawing.Point($X,$Y)
    $l.Size = New-Object System.Drawing.Size($W,$H)
    $l.Font = $Font
    $l.ForeColor = [System.Drawing.Color]::FromArgb(35,40,45)
    return $l
}

$title = New-Label 'SERVER HEALTH MANAGER' 25 18 500 35 $fontTitle
$form.Controls.Add($title)

$serverLabel = New-Label "Server: $env:COMPUTERNAME" 28 57 400 25 $fontBold
$form.Controls.Add($serverLabel)

$statusLabel = New-Label 'Status: NOT CHECKED' 760 25 360 32 $fontStatus
$statusLabel.TextAlign = 'MiddleRight'
$form.Controls.Add($statusLabel)

$infoPanel = New-Object System.Windows.Forms.Panel
$infoPanel.Location = New-Object System.Drawing.Point(25,90)
$infoPanel.Size = New-Object System.Drawing.Size(1110,70)
$infoPanel.BackColor = [System.Drawing.Color]::White
$form.Controls.Add($infoPanel)

$domainInfo = New-Label 'Domain: -' 18 12 500 22 $font
$timeInfo = New-Label 'Last Check: -' 18 38 500 22 $font
$policyInfo = New-Label 'Mode: READ-ONLY CHECKS' 600 24 470 25 $fontBold
$policyInfo.TextAlign = 'MiddleRight'
$infoPanel.Controls.Add($domainInfo)
$infoPanel.Controls.Add($timeInfo)
$infoPanel.Controls.Add($policyInfo)

$grid = New-Object System.Windows.Forms.DataGridView
$grid.Location = New-Object System.Drawing.Point(25,175)
$grid.Size = New-Object System.Drawing.Size(1110,365)
$grid.Anchor = 'Top,Bottom,Left,Right'
$grid.BackgroundColor = [System.Drawing.Color]::White
$grid.BorderStyle = 'FixedSingle'
$grid.AllowUserToAddRows = $false
$grid.AllowUserToDeleteRows = $false
$grid.ReadOnly = $true
$grid.SelectionMode = 'FullRowSelect'
$grid.AutoSizeRowsMode = 'AllCells'
$grid.RowHeadersVisible = $false
$grid.Font = $font

[void]$grid.Columns.Add('Status','STATUS')
[void]$grid.Columns.Add('Category','CATEGORY')
[void]$grid.Columns.Add('Check','CHECK')
[void]$grid.Columns.Add('Details','DETAILS')
[void]$grid.Columns.Add('Action','ACTION')

$grid.Columns['Status'].Width = 90
$grid.Columns['Category'].Width = 105
$grid.Columns['Check'].Width = 190
$grid.Columns['Details'].Width = 485
$grid.Columns['Action'].Width = 210
$form.Controls.Add($grid)

$logLabel = New-Label 'Activity Log' 25 555 200 25 $fontBold
$logLabel.Anchor = 'Bottom,Left'
$form.Controls.Add($logLabel)

$logBox = New-Object System.Windows.Forms.TextBox
$logBox.Location = New-Object System.Drawing.Point(25,580)
$logBox.Size = New-Object System.Drawing.Size(1110,90)
$logBox.Anchor = 'Bottom,Left,Right'
$logBox.Multiline = $true
$logBox.ReadOnly = $true
$logBox.ScrollBars = 'Vertical'
$logBox.BackColor = [System.Drawing.Color]::White
$logBox.Font = New-Object System.Drawing.Font('Consolas',8.5)
$form.Controls.Add($logBox)

$runButton = New-Object System.Windows.Forms.Button
$runButton.Text = 'RUN READ-ONLY CHECKS'
$runButton.Location = New-Object System.Drawing.Point(25,680)
$runButton.Size = New-Object System.Drawing.Size(180,38)
$runButton.Anchor = 'Bottom,Left'
$runButton.Font = $fontBold
$form.Controls.Add($runButton)

$reportButton = New-Object System.Windows.Forms.Button
$reportButton.Text = 'OPEN REPORT FOLDER'
$reportButton.Location = New-Object System.Drawing.Point(405,680)
$reportButton.Size = New-Object System.Drawing.Size(180,38)
$reportButton.Anchor = 'Bottom,Left'
$reportButton.Font = $fontBold
$form.Controls.Add($reportButton)

$detailsButton = New-Object System.Windows.Forms.Button
$detailsButton.Text = 'VIEW SELECTED'
$detailsButton.Location = New-Object System.Drawing.Point(595,680)
$detailsButton.Size = New-Object System.Drawing.Size(160,38)
$detailsButton.Anchor = 'Bottom,Left'
$detailsButton.Font = $fontBold
$form.Controls.Add($detailsButton)

function Refresh-Grid {
    $grid.Rows.Clear()

    foreach ($r in $script:Results) {
        $idx = $grid.Rows.Add($r.Status,$r.Category,$r.Check,$r.Details,$r.Action)
        $row = $grid.Rows[$idx]

        switch ($r.Status) {
            'PASS' {
                $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::Honeydew
            }
            'WARNING' {
                $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::Moccasin
            }
            'ERROR' {
                $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::MistyRose
            }
            'FIXED' {
                $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::PaleGreen
            }
            'FIX_FAILED' {
                $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::Salmon
            }
            'MANUAL' {
                $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::LightYellow
            }
            'PENDING' {
                $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::LightYellow
            }
            default {
                $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::White
            }
        }
    }

    $overall = Get-OverallStatus
    $statusLabel.Text = "Status: $overall"

    switch ($overall) {
        'PASS' { $statusLabel.ForeColor = [System.Drawing.Color]::DarkGreen }
        'WARNING' { $statusLabel.ForeColor = [System.Drawing.Color]::DarkOrange }
        'CRITICAL' { $statusLabel.ForeColor = [System.Drawing.Color]::DarkRed }
        default { $statusLabel.ForeColor = [System.Drawing.Color]::DimGray }
    }

    try {
        $cs = Get-CimInstance Win32_ComputerSystem
        $domainInfo.Text = if ($cs.PartOfDomain) { "Domain: $($cs.Domain)" } else { 'Domain: NOT JOINED' }
    }
    catch {
        $domainInfo.Text = 'Domain: unavailable'
    }

    $timeInfo.Text = if ($script:LastRun) {
        "Last Check: $($script:LastRun.ToString('yyyy-MM-dd HH:mm:ss'))"
    } else {
        'Last Check: -'
    }

    $logBox.Lines = @($script:LogLines)
    if ($logBox.Lines.Count -gt 0) {
        $logBox.SelectionStart = $logBox.TextLength
        $logBox.ScrollToCaret()
    }
}

$runButton.Add_Click({
    $runButton.Enabled = $false
    try {
        $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
        [System.Windows.Forms.Application]::DoEvents()
        Invoke-HealthCheck
        Refresh-Grid
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show(
            "Health check failed:`r`n$($_.Exception.Message)",
            'Server Health Manager',
            'OK',
            'Error'
        ) | Out-Null
    }
    finally {
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
        $runButton.Enabled = $true
    }
})

$reportButton.Add_Click({
    try {
        if (-not (Test-Path $script:LogDirectory)) {
            New-Item -ItemType Directory -Path $script:LogDirectory -Force | Out-Null
        }
        Start-Process explorer.exe -ArgumentList "`"$script:LogDirectory`""
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show(
            $_.Exception.Message,
            'Unable to open Reports',
            'OK',
            'Error'
        ) | Out-Null
    }
})

$detailsButton.Add_Click({
    if ($grid.SelectedRows.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            'Select a result row first.',
            'Details',
            'OK',
            'Information'
        ) | Out-Null
        return
    }

    $row = $grid.SelectedRows[0]
    $check = [string]$row.Cells['Check'].Value
    $status = [string]$row.Cells['Status'].Value

    $item = $script:Results | Where-Object {
        $_.Check -eq $check -and $_.Status -eq $status
    } | Select-Object -First 1

    if ($null -eq $item) { return }

    $detailText = @(
        "CHECK: $($item.Check)"
        "STATUS: $($item.Status)"
        "CATEGORY: $($item.Category)"
        ""
        "DETAILS:"
        $item.Details
        ""
        "ACTION:"
        $item.Action
        ""
        "ERROR:"
        $item.Error
    ) -join "`r`n"

    [System.Windows.Forms.MessageBox]::Show(
        $detailText,
        'Check Details',
        'OK',
        'Information'
    ) | Out-Null
})

$form.Add_Shown({
    $form.Activate()
})

[void]$form.ShowDialog()
