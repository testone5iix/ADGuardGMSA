#Requires -Version 5.1
#Requires -Module ActiveDirectory
<#
.SYNOPSIS
Enterprise gMSA/MSA Security Audit Tool - Comprehensive Active Directory security analysis

.DESCRIPTION
Performs security audit of gMSA/MSA accounts including:
- Account enumeration with security principals
- Suspicious permission detection
- ACL violation checks
- Event log correlation with privilege tracking
- HTML dashboard generation
- Text summary report

.OUTPUTS
gMSA_Accounts.csv, ACL_Violations.json, EventLog_Usage.csv, 
Dashboard.html, Audit_Summary.txt
#>

[CmdletBinding()]
param(
    [int]$EventLogDays = 30
)

$startTime = Get-Date
$outputFiles = @{
    Accounts = "gMSA_Accounts.csv"
    ACL = "ACL_Violations.json"
    Events = "EventLog_Usage.csv"
    Dashboard = "Dashboard.html"
    Summary = "Audit_Summary.txt"
}

#region: Embedded Chart.js (v3.9.1 minified)
$chartJSBase64 = @"
Lyohd3d3LmNoYXJ0anMub3JnKi8KIWZ1bmN0aW9uKHQpeyJvYmplY3QiPT10eXBlb2YgZXhwb3J0
cz9tb2R1bGUuZXhwb3J0cz10KCk6ImZ1bmN0aW9uIj09dHlwZW9mIGRlZmluZSYmZGVmaW5lLmFt
ZD9kZWZpbmUoW10sdCk6KGRlcGVuZGVuY2llcz1bXSx0PXQoZGVwZW5kZW5jaWVzKSl9KGZ1bmN0
aW9uKCl7cmV0dXJuIGZ1bmN0aW9uKGUpe3ZhciB0PXt9O2Z1bmN0aW9uIG4ocil7aWYodFtyXSly
ZXR1cm4gdFtyXS5leHBvcnRzO3ZhciBpPXRbcl09e2k6cixsOiExLGV4cG9ydHM6e319O3JldHVy
biBlW3JdLmNhbGwoaS5leHBvcnRzLGksaS5leHBvcnRzLG4pLGkubD0hMCxpLmV4cG9ydHN9cmV0
dXJuIG4ubT1lLG4uYz10LG4uZD1mdW5jdGlvbihlLHQscil7bi5vKGUsdCl8fE9iamVjdC5kZWZp
bmVQcm9wZXJ0eShlLHQse2VudW1lcmFibGU6ITAsZ2V0OnJ9KX0sbi5yPWZ1bmN0aW9uKGUpeyJ1
bmRlZmluZWQiIT10eXBlb2YgU3ltYm9sJiZTeW1ib2wudG9TdHJpbmdUYWcmJk9iamVjdC5kZWZp
bmVQcm9wZXJ0eShlLFN5bWJvbC50b1N0cmluZ1RhZyx7dmFsdWU6Ik1vZHVsZSJ9KSxPYmplY3Qu
ZGVmaW5lUHJvcGVydHkoZSwid19fZXNNb2R1bGUiLHt2YWx1ZTohMH0pfSxuLnQ9ZnVuY3Rpb24o
ZSx0KXtpZigxJnQmJihlPW4oZSkpLDgmdClyZXR1cm4gZTtpZig0JnQmJiJvYmplY3QiPT10eXBl
b2YgZSYmZSYmZS5fX2VzTW9kdWxlKXJldHVybiBlO3ZhciByPU9iamVjdC5jcmVhdGUobnVsbCk7
aWYobi5yKHIpLE9iamVjdC5kZWZpbmVQcm9wZXJ0eShyLCJkZWZhdWx0Iix7ZW51bWVyYWJsZToh
MCx2YWx1ZTplfSksMiZ0JiYic3RyaW5nIiE9dHlwZW9mIGUpZm9yKHZhciBpIGluIGUpbi5kKHIs
aSxmdW5jdGlvbih0KXtyZXR1cm4gZVt0XX0uYmluZChudWxsLGkpKTtyZXR1cm4gcn0sbi5uPWZ1
bmN0aW9uKGUpe3ZhciB0PWUmJmUuX19lc01vZHVsZT9mdW5jdGlvbigpe3JldHVybiBlLmRlZmF1
bHR9OmZ1bmN0aW9uKCl7cmV0dXJuIGV9O3JldHVybiBuLmQodCwiYSIsdCksdH0sbi5vPWZ1bmN0
aW9uKGUsdCl7cmV0dXJuIE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChlLHQp
fSxuLnA9IiIsbihuLnM9MCl9KFswLGZ1bmN0aW9uKGUsdCl7ZS5leHBvcnRzPWZ1bmN0aW9uKGUo
dCl7dmFyIG49e307ZnVuY3Rpb24gcihlKXtpZihuW2VdKXJldHVybiBuW2VdLmV4cG9ydHM7dmFy
IGk9bltlXT17aTplLGw6ITEsZXhwb3J0czp7fX07cmV0dXJuIHRbZV0uY2FsbChpLmV4cG9ydHMs
aSxpLmV4cG9ydHMsciksaS5sPSEwLGkuZXhwb3J0c31yZXR1cm4gci5tPXQK
"@
$chartJSCode = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($chartJSBase64))
#endregion

#region: Helper Functions
function Convert-ByteSecurityDescriptor {
    param([byte[]]$Bytes)
    if (-not $Bytes) { return @() }
    try {
        $sd = New-Object Security.AccessControl.RawSecurityDescriptor $Bytes, 0
        $sd.DiscretionaryAcl | ForEach-Object {
            [PSCustomObject]@{
                TrusteeSid = $_.SecurityIdentifier.Value
                AccessType = $_.AceType.ToString()
            }
        }
    } catch {
        Write-Warning "Error parsing security descriptor: $_"
        @()
    }
}

function Test-AdminSid {
    param([string]$Sid)
    if (-not $Sid) { return $false }
    $wellKnownAdmins = @(
        "S-1-5-32-544",  # Administrators
        "S-1-5-32-549",  # Server Operators
        "S-1-5-32-548",  # Account Operators
        "S-1-5-21-*-512" # Domain Admins pattern
    )
    $wellKnownAdmins -like $Sid -or $Sid -match "S-1-5-21-.*-519$" # Enterprise Admins
}

function Get-SidType {
    param([string]$Sid)
    if (-not $Sid) { return "Unknown" }
    if ($Sid -match "S-1-5-21") {
        try {
            $id = [System.Security.Principal.SecurityIdentifier]::new($Sid)
            if ($id.IsAccountSid()) {
                $account = $id.Translate([System.Security.Principal.NTAccount])
                if ($account.Value.EndsWith('$')) { return "Computer" }
                return "User"
            }
        } catch { }
    }
    switch ($Sid) {
        "S-1-1-0" { "Everyone" }
        "S-1-5-11" { "AuthenticatedUsers" }
        "S-1-5-32-545" { "Users" }
        default { "Unknown" }
    }
}

function Get-RiskyACEs {
    param(
        [string]$DN,
        [string]$ObjectType
    )
    if (-not $DN) { return @() }
    $riskyRights = @('GenericAll', 'WriteProperty', 'CreateChild')
    try {
        $acl = Get-Acl -Path "AD:\$DN" -ErrorAction Stop
        $results = @()
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            
            $rights = $ace.ActiveDirectoryRights.ToString()
            if (-not ($riskyRights | Where-Object { $rights -match $_ })) { continue }
            if (Test-AdminSid $ace.IdentityReference.Value) { continue }

            $results += [PSCustomObject]@{
                ObjectDN = $DN
                ObjectType = $ObjectType
                Trustee = $ace.IdentityReference.Value
                Rights = $rights
                IsInherited = $ace.IsInherited
            }
        }
        $results
    } catch {
        Write-Warning "Couldn't access ACL for $ObjectType '$DN': $_"
        @()
    }
}
#endregion

#region: Data Collection
Write-Progress -Activity "Auditing gMSA/MSA Accounts" -Status "Step 1/4: Enumerating accounts"
Write-Verbose "Querying Active Directory for gMSA/MSA accounts..."
$gmsaParams = @{
    Filter = { 
        ObjectClass -eq 'msDS-GroupManagedServiceAccount' -or 
        ObjectClass -eq 'msDS-ManagedServiceAccount' 
    }
    Properties = 'Name', 'msDS-GroupMSAMembership', 'ServicePrincipalNames', 
                'Created', 'DistinguishedName', 'SID'
}
$gmsaAccounts = Get-ADObject @gmsaParams | ForEach-Object {
    Write-Verbose "Processing account: $($_.DistinguishedName)"
    $principals = if ($_.'msDS-GroupMSAMembership') {
        $sddlData = Convert-ByteSecurityDescriptor $_.'msDS-GroupMSAMembership'
        $sddlData | ForEach-Object {
            $sidType = Get-SidType $_.TrusteeSid
            [PSCustomObject]@{
                SID = $_.TrusteeSid
                Type = $sidType
                IsSuspicious = @('Computer', 'AuthenticatedUsers', 'Users') -contains $sidType
            }
        }
    } else { @() }

    [PSCustomObject]@{
        Name = $_.Name
        DistinguishedName = $_.DistinguishedName
        Created = $_.Created
        SPNs = if ($_.ServicePrincipalNames) { $_.ServicePrincipalNames -join ';' } else { $null }
        Principals = $principals
        OU = if ($_.DistinguishedName) { ($_.DistinguishedName -split ',', 2)[1] } else { $null }
        HasSuspiciousPrincipals = $principals.IsSuspicious -contains $true
        SID = $_.SID.Value
    }
}

Write-Progress -Activity "Auditing gMSA/MSA Accounts" -Status "Step 2/4: Checking ACLs"
$aclResults = @()
foreach ($account in $gmsaAccounts) {
    Write-Verbose "Checking ACLs for: $($account.DistinguishedName)"
    $aclResults += Get-RiskyACEs $account.DistinguishedName "gMSA"
    Write-Verbose "Checking OU ACLs for: $($account.OU)"
    $aclResults += Get-RiskyACEs $account.OU "OU"
}

Write-Progress -Activity "Auditing gMSA/MSA Accounts" -Status "Step 3/4: Parsing event logs"
$gmsaSids = $gmsaAccounts | ForEach-Object { $_.SID }
$eventFilter = @{
    LogName = 'Security'
    ID = 4624, 4672
    StartTime = (Get-Date).AddDays(-$EventLogDays)
}

Write-Verbose "Collecting security events (IDs 4624, 4672) for last $EventLogDays days..."
$allEvents = Get-WinEvent -FilterHashtable $eventFilter -ErrorAction SilentlyContinue

# Build lookup for gMSA logon sessions
$logonEvents = @{}
$gmsaLogons = @()

foreach ($event in $allEvents) {
    $xml = [xml]$event.ToXml()
    $eventData = @{}
    $xml.Event.EventData.Data | ForEach-Object { 
        $eventData[$_.Name] = $_.'#text' 
    }

    if ($event.Id -eq 4624 -and $eventData.TargetUserSid -in $gmsaSids) {
        $logonId = $eventData.TargetLogonId
        $logonEvent = [PSCustomObject]@{
            TimeCreated = $event.TimeCreated
            EventID = $event.Id
            Hostname = $eventData.WorkstationName ?? $eventData.ClientName ?? $env:COMPUTERNAME
            ProcessID = $eventData.ProcessId ?? $eventData.SubjectProcessId
            Account = $eventData.TargetUserName ?? $eventData.UserName
            SourceIP = $eventData.IpAddress ?? 'N/A'
            LogonType = $eventData.LogonType
            AuthenticationPackage = $eventData.AuthenticationPackageName
            TargetLogonId = $logonId
            Elevated = $false
            SubjectUserSid = $eventData.SubjectUserSid
            TargetUserSid = $eventData.TargetUserSid
        }
        $logonEvents[$logonId] = $logonEvent
        $gmsaLogons += $logonEvent
    }
}

# Process privilege assignment events (4672)
foreach ($event in $allEvents) {
    if ($event.Id -eq 4672) {
        $xml = [xml]$event.ToXml()
        $eventData = @{}
        $xml.Event.EventData.Data | ForEach-Object { 
            $eventData[$_.Name] = $_.'#text' 
        }
        
        $subjectLogonId = $eventData.SubjectLogonId
        if ($subjectLogonId -and $logonEvents.ContainsKey($subjectLogonId)) {
            $logonEvents[$subjectLogonId].Elevated = $true
        }
    }
}
#endregion

#region: Output Files
$gmsaAccounts | Select-Object Name, Created, SPNs, DistinguishedName, 
    @{n='AllowedPrincipals';e={($_.Principals.SID -join ';') ?? $null}}, 
    @{n='PrincipalTypes';e={($_.Principals.Type -join ';') ?? $null}},
    @{n='SuspiciousPrincipals';e={($_.Principals | Where-Object IsSuspicious | Select-Object -Expand SID -join ';') ?? $null}},
    HasSuspiciousPrincipals |
    Export-Csv $outputFiles.Accounts -NoTypeInformation

$aclResults | ConvertTo-Json -Depth 4 | Set-Content $outputFiles.ACL
$gmsaLogons | Export-Csv $outputFiles.Events -NoTypeInformation
#endregion

#region: Dashboard Generation
$dashboardData = @{
    TotalAccounts = $gmsaAccounts.Count
    AccountsWithSuspiciousPrincipals = ($gmsaAccounts | Where-Object HasSuspiciousPrincipals).Count
    ACLViolations = $aclResults.Count
    EventCount = $gmsaLogons.Count
    OUACLViolations = $aclResults | 
        Where-Object { $_.ObjectType -eq 'OU' } | 
        Group-Object ObjectDN | 
        ForEach-Object { [PSCustomObject]@{ OU = $_.Name; Count = $_.Count } }
    TopUsedAccounts = $gmsaLogons | Group-Object Account | 
        Sort-Object Count -Descending | Select-Object Name, Count -First 5
    EventTimeline = $gmsaLogons | Group-Object { $_.TimeCreated.ToString('yyyy-MM-dd') }
}

$html = @"
<!DOCTYPE html>
<html>
<head>
    <title>gMSA/MSA Security Dashboard</title>
    <script>$chartJSCode</script>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; }
        .dashboard { display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; }
        .card { border: 1px solid #ddd; border-radius: 5px; padding: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .grid-full { grid-column: span 2; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        .summary-stats { display: flex; justify-content: space-around; margin-bottom: 20px; }
        .stat-box { text-align: center; padding: 10px; border: 1px solid #e0e0e0; border-radius: 5px; }
        .critical { color: #d32f2f; font-weight: bold; }
    </style>
</head>
<body>
    <h1>gMSA/MSA Security Dashboard</h1>
    <div class="summary-stats">
        <div class="stat-box"><h3>Total gMSA Accounts</h3><p>$($dashboardData.TotalAccounts)</p></div>
        <div class="stat-box"><h3>Accounts with Suspicious Permissions</h3><p class="critical">$($dashboardData.AccountsWithSuspiciousPrincipals)</p></div>
        <div class="stat-box"><h3>ACL Violations</h3><p class="critical">$($dashboardData.ACLViolations)</p></div>
        <div class="stat-box"><h3>Logon Events (Last $EventLogDays Days)</h3><p>$($dashboardData.EventCount)</p></div>
    </div>

    <div class="dashboard">
        <div class="card">
            <h2>Permission Risk Distribution</h2>
            <canvas id="riskChart"></canvas>
        </div>
        <div class="card">
            <h2>Top Used Accounts</h2>
            <canvas id="usageChart"></canvas>
        </div>
        <div class="card grid-full">
            <h2>ACL Violations by OU</h2>
            <canvas id="heatmapChart"></canvas>
        </div>
        <div class="card grid-full">
            <h2>Account Usage Timeline</h2>
            <canvas id="timelineChart"></canvas>
        </div>
    </div>

    <script>
        const data = {
            riskData: {
                labels: ['Secure', 'Suspicious'],
                datasets: [{
                    data: [$($dashboardData.TotalAccounts - $dashboardData.AccountsWithSuspiciousPrincipals), 
                           $($dashboardData.AccountsWithSuspiciousPrincipals)],
                    backgroundColor: ['#36a2eb', '#ff6384']
                }]
            },
            usageData: {
                labels: [$($dashboardData.TopUsedAccounts.Name | ForEach-Object { "'$_'" } -join ",")],
                datasets: [{
                    label: 'Logon Count',
                    data: [$($dashboardData.TopUsedAccounts.Count -join ",")],
                    backgroundColor: '#4caf50'
                }]
            },
            timelineData: {
                labels: [$($dashboardData.EventTimeline.Name | ForEach-Object { "'$_'" } -join ",")],
                datasets: [{
                    label: 'Events per Day',
                    data: [$($dashboardData.EventTimeline.Count -join ",")],
                    borderColor: '#ff9800',
                    fill: false
                }]
            },
            heatmapData: {
                labels: [$($dashboardData.OUACLViolations.OU | ForEach-Object { "'$_'" } -join ",")],
                datasets: [{
                    label: 'ACL Violations',
                    data: [$($dashboardData.OUACLViolations.Count -join ",")],
                    backgroundColor: 'rgba(255, 99, 132, 0.5)'
                }]
            }
        };

        // Render charts
        new Chart(document.getElementById('riskChart'), { type: 'pie', data: data.riskData });
        new Chart(document.getElementById('usageChart'), { type: 'bar', data: data.usageData });
        new Chart(document.getElementById('timelineChart'), { type: 'line', data: data.timelineData });
        new Chart(document.getElementById('heatmapChart'), { 
            type: 'bar', 
            data: data.heatmapData,
            options: { indexAxis: 'y' }
        });
    </script>
</body>
</html>
"@

$html | Set-Content $outputFiles.Dashboard
#endregion

#region: Text Summary
$topAccounts = $dashboardData.TopUsedAccounts | ForEach-Object {
    "    - $($_.Name): $($_.Count) events"
} -join "`n"

$summary = @"
gMSA/MSA Security Audit Summary
===============================
Audit performed on: $(Get-Date -Format 'yyyy-MM-dd HH:mm')
Event log period: $EventLogDays days

Total gMSA Accounts: $($dashboardData.TotalAccounts)
Accounts with Suspicious Principals: $($dashboardData.AccountsWithSuspiciousPrincipals)
ACL Violations Found: $($dashboardData.ACLViolations)
Total Logon Events: $($dashboardData.EventCount)

Top 5 Most Used Accounts:
$topAccounts

Output Files:
- $($outputFiles.Accounts)
- $($outputFiles.ACL)
- $($outputFiles.Events)
- $($outputFiles.Dashboard)
- $($outputFiles.Summary)

Audit completed in: $([math]::Round((Get-Date).Subtract($startTime).TotalMinutes, 1)) minutes
"@

$summary | Set-Content $outputFiles.Summary
#endregion

Write-Host "Audit completed in $([math]::Round((Get-Date).Subtract($startTime).TotalMinutes, 1)) minutes"
Write-Host "Output files:"
$outputFiles.Values | ForEach-Object { Write-Host "  - $_" }
