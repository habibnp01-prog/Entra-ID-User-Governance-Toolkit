<#
.SYNOPSIS
    Exports a consolidated Microsoft Entra ID governance report.

.DESCRIPTION
    Script 12 is the reporting component of the
    Entra ID User Governance Toolkit.

    It consolidates the latest governance reports generated
    by Scripts 02-08 and correlates them with remediation
    activity recorded by Script 11.

    The report provides:

      - Governance findings
      - Priority / severity
      - Finding count
      - Remediation status
      - Last remediation action
      - Last remediation result
      - Last remediation timestamp
      - Audit activity
      - CSV export
      - HTML administrator dashboard

    This script is READ-ONLY.

    It does not modify Microsoft Entra ID objects.

.VERSION
    3.0.0
#>

[CmdletBinding()]
param(
    [string]$ReportsPath = (Join-Path $PSScriptRoot "..\Reports"),

    [string]$LogsPath = (Join-Path $PSScriptRoot "..\Logs"),

    [string]$OutputPath = (Join-Path $PSScriptRoot "..\Reports"),

    [ValidateSet("CSV", "HTML", "Both")]
    [string]$Format = "Both"
)

$ErrorActionPreference = "Stop"

# ============================================================
# INITIALIZATION
# ============================================================

$ReportsPath = [System.IO.Path]::GetFullPath($ReportsPath)
$LogsPath    = [System.IO.Path]::GetFullPath($LogsPath)
$OutputPath  = [System.IO.Path]::GetFullPath($OutputPath)

if (-not (Test-Path $ReportsPath)) {
    throw "Reports directory not found: $ReportsPath"
}

if (-not (Test-Path $LogsPath)) {
    Write-Warning "Logs directory not found: $LogsPath"
}

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

$CsvOutput  = Join-Path $OutputPath "EntraGovernanceReport_$Timestamp.csv"
$HtmlOutput = Join-Path $OutputPath "EntraGovernanceReport_$Timestamp.html"

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " Entra ID Governance Report Export" -ForegroundColor Cyan
Write-Host " Version 3.0.0" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Reports path : $ReportsPath"
Write-Host "Logs path    : $LogsPath"
Write-Host "Output path  : $OutputPath"
Write-Host ""

# ============================================================
# HELPER - GET LATEST REPORT
# ============================================================

function Get-LatestReport {
    param(
        [Parameter(Mandatory)]
        [string]$Prefix
    )

    $files = Get-ChildItem `
        -Path $ReportsPath `
        -Filter "$Prefix*.csv" `
        -File `
        -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending

    if (-not $files) {
        return $null
    }

    return $files[0]
}

# ============================================================
# HELPER - BOOLEAN CONVERSION
# ============================================================

function Convert-ToBoolean {
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return $false
    }

    return ([string]$Value).Trim() -eq "True"
}

# ============================================================
# HELPER - PRIORITY NORMALIZATION
# ============================================================

function Normalize-Priority {
    param(
        [AllowNull()]
        [string]$Priority
    )

    if ([string]::IsNullOrWhiteSpace($Priority)) {
        return "None"
    }

    switch -Regex ($Priority.Trim()) {

        "^Critical$" { return "Critical" }

        "^High$" { return "High" }

        "^Medium$" { return "Medium" }

        "^Low$" { return "Low" }

        "^Review$" { return "Review" }

        "^None$" { return "None" }

        default { return $Priority.Trim() }
    }
}

# ============================================================
# HELPER - FIND PROPERTY
# ============================================================

function Get-PropertyValue {
    param(
        [Parameter(Mandatory)]
        [object]$Object,

        [Parameter(Mandatory)]
        [string]$PropertyName
    )

    $property = $Object.PSObject.Properties |
        Where-Object Name -eq $PropertyName |
        Select-Object -First 1

    if ($property) {
        return $property.Value
    }

    return $null
}

# ============================================================
# REPORT DEFINITIONS
# ============================================================

$ReportMap = [ordered]@{
    Inactive        = "InactiveUsers_"
    Expired         = "ExpiredUsers_"
    Guests          = "GuestUsers_"
    Disabled        = "DisabledUsers_"
    Licensed        = "LicenseGovernance_"
    Privileged      = "PrivilegedUsers_"
    GroupMembership = "ExcessiveGroupMembership_"
}

# ============================================================
# LOAD GOVERNANCE REPORTS
# ============================================================

Write-Host "Loading latest governance reports..." -ForegroundColor Yellow
Write-Host ""

$LoadedReports = @{}

foreach ($key in $ReportMap.Keys) {

    $file = Get-LatestReport -Prefix $ReportMap[$key]

    if ($file) {

        try {

            $data = @(Import-Csv -Path $file.FullName)

            $LoadedReports[$key] = [PSCustomObject]@{
                File = $file
                Data = $data
            }

            Write-Host (
                "{0,-18} {1,5} records  {2}" -f `
                $key,
                $data.Count,
                $file.Name
            ) -ForegroundColor Green
        }
        catch {

            Write-Warning `
                "Unable to read $($file.Name): $($_.Exception.Message)"
        }
    }
    else {

        Write-Host (
            "{0,-18} NOT FOUND" -f $key
        ) -ForegroundColor DarkYellow
    }
}

# ============================================================
# LOAD AUDIT LOG
# ============================================================

$AuditLogPath = Join-Path $LogsPath "EntraGovernanceAudit.csv"

$AuditEvents = @()

if (Test-Path $AuditLogPath) {

    try {

        $AuditEvents = @(Import-Csv -Path $AuditLogPath)

        Write-Host ""
        Write-Host "Audit events loaded: $($AuditEvents.Count)" `
            -ForegroundColor Green
    }
    catch {

        Write-Warning `
            "Unable to read audit log: $($_.Exception.Message)"
    }
}
else {

    Write-Host ""
    Write-Host "Audit log not found." `
        -ForegroundColor DarkYellow
}

# ============================================================
# BUILD AUDIT INDEX
# ============================================================

$AuditIndex = @{}

foreach ($event in $AuditEvents) {

    $upn = [string]$event.UserPrincipalName

    if ([string]::IsNullOrWhiteSpace($upn)) {
        continue
    }

    $upn = $upn.Trim().ToLowerInvariant()

    if (-not $AuditIndex.ContainsKey($upn)) {

        $AuditIndex[$upn] = @()
    }

    $AuditIndex[$upn] += $event
}

# ============================================================
# USER INDEX
# ============================================================

$UserIndex = @{}

function Ensure-User {
    param(
        [string]$UPN,
        [string]$DisplayName,
        [string]$UserId
    )

    if ([string]::IsNullOrWhiteSpace($UPN)) {
        return
    }

    $normalizedUPN = $UPN.Trim().ToLowerInvariant()

    if (-not $UserIndex.ContainsKey($normalizedUPN)) {

        $UserIndex[$normalizedUPN] = [ordered]@{

            UserPrincipalName = $UPN

            DisplayName = $DisplayName

            UserId = $UserId

            Findings =
                [System.Collections.Generic.List[string]]::new()

            Priorities =
                [System.Collections.Generic.List[string]]::new()
        }
    }
    else {

        if ($DisplayName -and
            [string]::IsNullOrWhiteSpace(
                $UserIndex[$normalizedUPN].DisplayName
            )) {

            $UserIndex[$normalizedUPN].DisplayName = $DisplayName
        }

        if ($UserId -and
            [string]::IsNullOrWhiteSpace(
                $UserIndex[$normalizedUPN].UserId
            )) {

            $UserIndex[$normalizedUPN].UserId = $UserId
        }
    }
}

function Add-Finding {
    param(
        [string]$UPN,

        [string]$DisplayName,

        [string]$UserId,

        [string]$Finding,

        [string]$Priority
    )

    if ([string]::IsNullOrWhiteSpace($UPN)) {
        return
    }

    Ensure-User `
        -UPN $UPN `
        -DisplayName $DisplayName `
        -UserId $UserId

    $normalizedUPN = $UPN.Trim().ToLowerInvariant()

    if (-not $UserIndex[$normalizedUPN].Findings.Contains($Finding)) {

        $UserIndex[$normalizedUPN].Findings.Add($Finding)
    }

    $normalizedPriority = Normalize-Priority $Priority

    if ($normalizedPriority -ne "None" -and
        -not $UserIndex[$normalizedUPN].Priorities.Contains(
            $normalizedPriority
        )) {

        $UserIndex[$normalizedUPN].Priorities.Add(
            $normalizedPriority
        )
    }
}

# ============================================================
# PROCESS INACTIVE REPORT
# ============================================================

if ($LoadedReports.ContainsKey("Inactive")) {

    foreach ($item in $LoadedReports.Inactive.Data) {

        if (-not (Convert-ToBoolean $item.GovernanceCandidate)) {
            continue
        }

        $category = [string]$item.Category

        $priority = "Medium"

        if ($category -eq "NeverSignedIn") {
            $priority = "High"
        }

        Add-Finding `
            -UPN $item.UserPrincipalName `
            -DisplayName $item.DisplayName `
            -UserId $item.Id `
            -Finding $category `
            -Priority $priority
    }
}

# ============================================================
# PROCESS EXPIRED REPORT
# ============================================================

if ($LoadedReports.ContainsKey("Expired")) {

    foreach ($item in $LoadedReports.Expired.Data) {

        if (-not (Convert-ToBoolean $item.GovernanceCandidate)) {
            continue
        }

        $category = [string]$item.Category

        switch ($category) {

            "ExpiredEnabled" {
                $priority = "Critical"
            }

            "ExpiredDisabled" {
                $priority = "High"
            }

            default {
                $priority = "Review"
            }
        }

        Add-Finding `
            -UPN $item.UserPrincipalName `
            -DisplayName $item.DisplayName `
            -UserId $item.Id `
            -Finding $category `
            -Priority $priority
    }
}

# ============================================================
# PROCESS GUEST REPORT
# ============================================================

if ($LoadedReports.ContainsKey("Guests")) {

    foreach ($item in $LoadedReports.Guests.Data) {

        if ($item.Category -eq "NoGuestUsers") {
            continue
        }

        if (-not (Convert-ToBoolean $item.GovernanceCandidate)) {
            continue
        }

        $priority = Normalize-Priority `
            $item.GovernancePriority

        if ($priority -eq "None") {
            $priority = "Review"
        }

        Add-Finding `
            -UPN $item.UserPrincipalName `
            -DisplayName $item.DisplayName `
            -UserId $item.Id `
            -Finding ([string]$item.Category) `
            -Priority $priority
    }
}

# ============================================================
# PROCESS DISABLED REPORT
# ============================================================

if ($LoadedReports.ContainsKey("Disabled")) {

    foreach ($item in $LoadedReports.Disabled.Data) {

        if (-not (Convert-ToBoolean $item.GovernanceCandidate)) {
            continue
        }

        $category = [string]$item.Category

        $priority = "Review"

        if ($category -eq "DisabledWithLicenseAndExpired") {
            $priority = "Critical"
        }
        elseif ($category -eq "DisabledWithLicense") {
            $priority = "High"
        }
        elseif ($category -eq "DisabledWithRecentActivity") {
            $priority = "Medium"
        }

        Add-Finding `
            -UPN $item.UserPrincipalName `
            -DisplayName $item.DisplayName `
            -UserId $item.Id `
            -Finding $category `
            -Priority $priority
    }
}

# ============================================================
# PROCESS LICENSE GOVERNANCE REPORT
# ============================================================

if ($LoadedReports.ContainsKey("Licensed")) {

    foreach ($item in $LoadedReports.Licensed.Data) {

        if (-not (Convert-ToBoolean $item.GovernanceCandidate)) {
            continue
        }

        $priority = Normalize-Priority `
            $item.GovernancePriority

        if ($priority -eq "None") {
            $priority = "Review"
        }

        Add-Finding `
            -UPN $item.UserPrincipalName `
            -DisplayName $item.DisplayName `
            -UserId $item.Id `
            -Finding ([string]$item.Category) `
            -Priority $priority
    }
}

# ============================================================
# PROCESS PRIVILEGED REPORT
# ============================================================

if ($LoadedReports.ContainsKey("Privileged")) {

    foreach ($item in $LoadedReports.Privileged.Data) {

        if (-not (Convert-ToBoolean $item.GovernanceCandidate)) {
            continue
        }

        $priority = Normalize-Priority `
            $item.GovernancePriority

        if ($priority -eq "None") {
            $priority = "Review"
        }

        $finding = "Privileged: $($item.Category)"

        if ($item.RoleName) {

            $finding = "$finding - $($item.RoleName)"
        }

        Add-Finding `
            -UPN $item.UserPrincipalName `
            -DisplayName $item.DisplayName `
            -UserId $item.UserId `
            -Finding $finding `
            -Priority $priority
    }
}

# ============================================================
# PROCESS GROUP MEMBERSHIP REPORT
# ============================================================

if ($LoadedReports.ContainsKey("GroupMembership")) {

    foreach ($item in $LoadedReports.GroupMembership.Data) {

        if (-not (Convert-ToBoolean $item.GovernanceCandidate)) {
            continue
        }

        $priority = Normalize-Priority `
            $item.GovernancePriority

        if ($priority -eq "None") {
            $priority = "Review"
        }

        $finding = "Excessive direct group membership"

        if ($item.DirectGroupCount) {

            $finding = "$finding ($($item.DirectGroupCount) groups)"
        }

        Add-Finding `
            -UPN $item.UserPrincipalName `
            -DisplayName $item.DisplayName `
            -UserId $item.UserId `
            -Finding $finding `
            -Priority $priority
    }
}

# ============================================================
# BUILD CONSOLIDATED REPORT
# ============================================================

$PriorityOrder = @{
    Critical = 1
    High     = 2
    Medium   = 3
    Review   = 4
    Low      = 5
    None     = 6
}

$GovernanceRows = foreach ($entry in $UserIndex.GetEnumerator()) {

    $user = $entry.Value

    $priority = "None"

    if ($user.Priorities -contains "Critical") {
        $priority = "Critical"
    }
    elseif ($user.Priorities -contains "High") {
        $priority = "High"
    }
    elseif ($user.Priorities -contains "Medium") {
        $priority = "Medium"
    }
    elseif ($user.Priorities -contains "Review") {
        $priority = "Review"
    }
    elseif ($user.Priorities -contains "Low") {
        $priority = "Low"
    }

    # --------------------------------------------------------
    # Correlate remediation activity
    # --------------------------------------------------------

    $normalizedUPN =
        $user.UserPrincipalName.Trim().ToLowerInvariant()

    $userAuditEvents = @()

    if ($AuditIndex.ContainsKey($normalizedUPN)) {

        $userAuditEvents = @(
            $AuditIndex[$normalizedUPN]
        )
    }

    $lastRemediation = $null

    if ($userAuditEvents.Count -gt 0) {

        $lastRemediation = $userAuditEvents |
            Sort-Object Timestamp -Descending |
            Select-Object -First 1
    }

    $remediationStatus = "Not Remediated"
    $lastAction = ""
    $lastResult = ""
    $lastRemediationTimestamp = ""
    $remediationCount = 0

    if ($userAuditEvents.Count -gt 0) {

        $remediationCount = $userAuditEvents.Count

        if ($lastRemediation) {

            $lastAction = [string]$lastRemediation.Action

            $lastResult = [string]$lastRemediation.Result

            $lastRemediationTimestamp =
                [string]$lastRemediation.Timestamp

            switch ($lastResult) {

                "Success" {
                    $remediationStatus = "Remediated"
                }

                "Failed" {
                    $remediationStatus = "Remediation Failed"
                }

                "WhatIf" {
                    $remediationStatus = "WhatIf Only"
                }

                "Skipped" {
                    $remediationStatus = "Skipped"
                }

                "Cancelled" {
                    $remediationStatus = "Cancelled"
                }

                default {
                    $remediationStatus = "Action Recorded"
                }
            }
        }
    }

    [PSCustomObject]@{

        DisplayName =
            $user.DisplayName

        UserPrincipalName =
            $user.UserPrincipalName

        UserId =
            $user.UserId

        Priority =
            $priority

        FindingCount =
            $user.Findings.Count

        Findings =
            ($user.Findings -join "; ")

        RemediationStatus =
            $remediationStatus

        RemediationCount =
            $remediationCount

        LastRemediationAction =
            $lastAction

        LastRemediationResult =
            $lastResult

        LastRemediationTimestamp =
            $lastRemediationTimestamp

        GeneratedAt =
            (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    }
}

$GovernanceRows = @(
    $GovernanceRows |
        Sort-Object `
            @{Expression = {
                $PriorityOrder[$_.Priority]
            }},
            UserPrincipalName
)

# ============================================================
# GLOBAL STATISTICS
# ============================================================

$TotalUsers = $GovernanceRows.Count

$CriticalCount = @(
    $GovernanceRows |
        Where-Object Priority -eq "Critical"
).Count

$HighCount = @(
    $GovernanceRows |
        Where-Object Priority -eq "High"
).Count

$MediumCount = @(
    $GovernanceRows |
        Where-Object Priority -eq "Medium"
).Count

$ReviewCount = @(
    $GovernanceRows |
        Where-Object Priority -eq "Review"
).Count

$LowCount = @(
    $GovernanceRows |
        Where-Object Priority -eq "Low"
).Count

$RemediatedUsers = @(
    $GovernanceRows |
        Where-Object RemediationStatus -eq "Remediated"
).Count

$UnremediatedUsers = @(
    $GovernanceRows |
        Where-Object RemediationStatus -eq "Not Remediated"
).Count

$FailedRemediationUsers = @(
    $GovernanceRows |
        Where-Object RemediationStatus -eq "Remediation Failed"
).Count

$WhatIfUsers = @(
    $GovernanceRows |
        Where-Object RemediationStatus -eq "WhatIf Only"
).Count

$SuccessfulAuditEvents = @(
    $AuditEvents |
        Where-Object Result -eq "Success"
).Count

$FailedAuditEvents = @(
    $AuditEvents |
        Where-Object Result -eq "Failed"
).Count

$DisableEvents = @(
    $AuditEvents |
        Where-Object Action -eq "DisableUser"
).Count

$LicenseEvents = @(
    $AuditEvents |
        Where-Object Action -match "License"
).Count

$GroupEvents = @(
    $AuditEvents |
        Where-Object Action -match "Group"
).Count

# ============================================================
# CONSOLE SUMMARY
# ============================================================

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " Governance Report Summary" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

Write-Host ""

Write-Host "Users with findings : $TotalUsers"

Write-Host "Critical            : $CriticalCount"

Write-Host "High                : $HighCount"

Write-Host "Medium              : $MediumCount"

Write-Host "Review              : $ReviewCount"

Write-Host "Low                 : $LowCount"

Write-Host ""

Write-Host "Remediation status"

Write-Host "Remediated          : $RemediatedUsers"

Write-Host "Not remediated      : $UnremediatedUsers"

Write-Host "Remediation failed  : $FailedRemediationUsers"

Write-Host "WhatIf only         : $WhatIfUsers"

Write-Host ""

Write-Host "Audit events        : $($AuditEvents.Count)"

Write-Host "Successful events   : $SuccessfulAuditEvents"

Write-Host "Failed events       : $FailedAuditEvents"

Write-Host "Disable events      : $DisableEvents"

Write-Host "License events      : $LicenseEvents"

Write-Host "Group events        : $GroupEvents"

# ============================================================
# CSV EXPORT
# ============================================================

if ($Format -in @("CSV", "Both")) {

    $GovernanceRows |
        Export-Csv `
            -Path $CsvOutput `
            -NoTypeInformation `
            -Encoding UTF8

    Write-Host ""

    Write-Host "CSV report exported:" `
        -ForegroundColor Green

    Write-Host $CsvOutput
}

# ============================================================
# HTML EXPORT
# ============================================================

if ($Format -in @("HTML", "Both")) {

    $GeneratedDate =
        Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $RowsHtml = ""

    foreach ($row in $GovernanceRows) {

        $priorityClass = switch ($row.Priority) {

            "Critical" { "critical" }

            "High" { "high" }

            "Medium" { "medium" }

            "Review" { "review" }

            "Low" { "low" }

            default { "none" }
        }

        $remediationClass = switch (
            $row.RemediationStatus
        ) {

            "Remediated" {
                "remediated"
            }

            "Remediation Failed" {
                "failed"
            }

            "WhatIf Only" {
                "whatif"
            }

            default {
                "notremediated"
            }
        }

        $RowsHtml += @"
<tr>

<td>$($row.DisplayName)</td>

<td>$($row.UserPrincipalName)</td>

<td>
<span class="priority $priorityClass">
$($row.Priority)
</span>
</td>

<td>$($row.FindingCount)</td>

<td>$($row.Findings)</td>

<td>
<span class="remediation $remediationClass">
$($row.RemediationStatus)
</span>
</td>

<td>$($row.LastRemediationAction)</td>

<td>$($row.LastRemediationResult)</td>

<td>$($row.LastRemediationTimestamp)</td>

</tr>
"@
    }

    if (-not $RowsHtml) {

        $RowsHtml = @"
<tr>
<td colspan="9">
No governance findings were identified.
</td>
</tr>
"@
    }

    $Html = @"
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<title>
Microsoft Entra ID Governance Report
</title>

<style>

body {

    font-family:
        Segoe UI,
        Arial,
        sans-serif;

    margin: 40px;

    background: #f5f7fa;

    color: #1f2937;
}

h1 {

    margin-bottom: 5px;
}

.subtitle {

    color: #6b7280;

    margin-bottom: 30px;
}

.dashboard {

    display: grid;

    grid-template-columns:
        repeat(6, 1fr);

    gap: 15px;

    margin-bottom: 30px;
}

.card {

    background: white;

    padding: 20px;

    border-radius: 10px;

    box-shadow:
        0 2px 8px
        rgba(0,0,0,0.08);
}

.card-title {

    font-size: 13px;

    color: #6b7280;
}

.card-value {

    font-size: 28px;

    font-weight: 600;

    margin-top: 5px;
}

table {

    width: 100%;

    border-collapse: collapse;

    background: white;

    box-shadow:
        0 2px 8px
        rgba(0,0,0,0.08);
}

th {

    background: #1f2937;

    color: white;

    padding: 12px;

    text-align: left;

    position: sticky;

    top: 0;
}

td {

    padding: 12px;

    border-bottom:
        1px solid #e5e7eb;

    vertical-align: top;
}

.priority,
.remediation {

    display: inline-block;

    padding: 4px 9px;

    border-radius: 12px;

    font-size: 12px;

    font-weight: 600;
}

.critical {

    background: #fee2e2;

    color: #991b1b;
}

.high {

    background: #ffedd5;

    color: #9a3412;
}

.medium {

    background: #fef3c7;

    color: #92400e;
}

.review {

    background: #e0e7ff;

    color: #3730a3;
}

.low {

    background: #dcfce7;

    color: #166534;
}

.none {

    background: #e5e7eb;

    color: #374151;
}

.remediated {

    background: #dcfce7;

    color: #166534;
}

.failed {

    background: #fee2e2;

    color: #991b1b;
}

.whatif {

    background: #fef3c7;

    color: #92400e;
}

.notremediated {

    background: #e5e7eb;

    color: #374151;
}

.section {

    margin-top: 35px;

    margin-bottom: 15px;
}

.footer {

    margin-top: 30px;

    color: #6b7280;

    font-size: 12px;
}

.summary-table {

    width: 500px;

    margin-bottom: 30px;
}

</style>

</head>

<body>

<h1>
Microsoft Entra ID Governance Report
</h1>

<div class="subtitle">

Generated:
$GeneratedDate

</div>

<div class="dashboard">

<div class="card">

<div class="card-title">
Users With Findings
</div>

<div class="card-value">
$TotalUsers
</div>

</div>

<div class="card">

<div class="card-title">
Critical
</div>

<div class="card-value">
$CriticalCount
</div>

</div>

<div class="card">

<div class="card-title">
High
</div>

<div class="card-value">
$HighCount
</div>

</div>

<div class="card">

<div class="card-title">
Medium
</div>

<div class="card-value">
$MediumCount
</div>

</div>

<div class="card">

<div class="card-title">
Remediated
</div>

<div class="card-value">
$RemediatedUsers
</div>

</div>

<div class="card">

<div class="card-title">
Not Remediated
</div>

<div class="card-value">
$UnremediatedUsers
</div>

</div>

</div>

<h2 class="section">
Governance Findings & Remediation Status
</h2>

<table>

<thead>

<tr>

<th>
Display Name
</th>

<th>
User Principal Name
</th>

<th>
Priority
</th>

<th>
Finding Count
</th>

<th>
Findings
</th>

<th>
Remediation Status
</th>

<th>
Last Action
</th>

<th>
Last Result
</th>

<th>
Last Remediation
</th>

</tr>

</thead>

<tbody>

$RowsHtml

</tbody>

</table>

<h2 class="section">
Remediation Summary
</h2>

<table class="summary-table">

<thead>

<tr>

<th>
Metric
</th>

<th>
Count
</th>

</tr>

</thead>

<tbody>

<tr>

<td>
Users with findings
</td>

<td>
$TotalUsers
</td>

</tr>

<tr>

<td>
Remediated users
</td>

<td>
$RemediatedUsers
</td>

</tr>

<tr>

<td>
Not remediated
</td>

<td>
$UnremediatedUsers
</td>

</tr>

<tr>

<td>
Remediation failed
</td>

<td>
$FailedRemediationUsers
</td>

</tr>

<tr>

<td>
WhatIf only
</td>

<td>
$WhatIfUsers
</td>

</tr>

</tbody>

</table>

<h2 class="section">
Audit Activity
</h2>

<table class="summary-table">

<thead>

<tr>

<th>
Metric
</th>

<th>
Count
</th>

</tr>

</thead>

<tbody>

<tr>

<td>
Total audit events
</td>

<td>
$($AuditEvents.Count)
</td>

</tr>

<tr>

<td>
Successful events
</td>

<td>
$SuccessfulAuditEvents
</td>

</tr>

<tr>

<td>
Failed events
</td>

<td>
$FailedAuditEvents
</td>

</tr>

<tr>

<td>
Disable events
</td>

<td>
$DisableEvents
</td>

</tr>

<tr>

<td>
License events
</td>

<td>
$LicenseEvents
</td>

</tr>

<tr>

<td>
Group membership events
</td>

<td>
$GroupEvents
</td>

</tr>

</tbody>

</table>

<div class="footer">

Generated by
Entra ID User Governance Toolkit.

<br>

This report is read-only and does not modify
Microsoft Entra ID objects.

</div>

</body>

</html>
"@

    Set-Content `
        -Path $HtmlOutput `
        -Value $Html `
        -Encoding UTF8

    Write-Host ""

    Write-Host "HTML report exported:" `
        -ForegroundColor Green

    Write-Host $HtmlOutput
}

# ============================================================
# COMPLETE
# ============================================================

Write-Host ""

Write-Host "=============================================" `
    -ForegroundColor Green

Write-Host " Report export completed successfully." `
    -ForegroundColor Green

Write-Host "=============================================" `
    -ForegroundColor Green

Write-Host ""