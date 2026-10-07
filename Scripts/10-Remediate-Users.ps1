<#
.SYNOPSIS
    Controlled Entra ID governance remediation toolkit.

.DESCRIPTION
    Provides an interactive, approval-based remediation workflow for
    governance findings identified by Scripts 02-08.

    Supported remediation actions:
      1. Disable an expired enabled user
      2. Remove direct licenses from a user
      3. Remove a user from a selected direct group

    Safety controls:
      - Interactive user selection
      - Read/review before action
      - WhatIf support through SupportsShouldProcess
      - Explicit confirmation
      - CONFIRM keyword for high-impact actions
      - Live state re-validation before modification
      - No automatic bulk remediation
      - Audit logging through Script 11

.NOTES
    Version : 1.0.1
    Author  : Entra ID User Governance Toolkit
    Requires:
      Microsoft.Graph.Authentication
      Microsoft.Graph.Users
      Microsoft.Graph.Groups
      Microsoft.Graph.Identity.DirectoryManagement
#>

[CmdletBinding(SupportsShouldProcess)]
param()

$ErrorActionPreference = "Stop"

# ============================================================
# CONFIGURATION
# ============================================================

$ScriptRoot = Split-Path -Parent $PSScriptRoot
$ReportsPath = Join-Path $ScriptRoot "Reports"
$LogsPath = Join-Path $ScriptRoot "Logs"

$InactiveReportPattern = "InactiveUsers_*.csv"
$ExpiredReportPattern = "ExpiredUsers_*.csv"
$GuestReportPattern = "GuestUsers_*.csv"
$DisabledReportPattern = "DisabledUsers_*.csv"
$LicenseReportPattern = "LicenseGovernance_*.csv"
$PrivilegedReportPattern = "PrivilegedUsers_*.csv"
$GroupReportPattern = "ExcessiveGroupMembership_*.csv"

# ============================================================
# REQUIRED MODULES
# ============================================================

$RequiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Groups",
    "Microsoft.Graph.Identity.DirectoryManagement"
)

foreach ($Module in $RequiredModules) {

    if (-not (Get-Module -ListAvailable -Name $Module)) {
        throw "Required Microsoft Graph module not installed: $Module"
    }

    Import-Module $Module -ErrorAction Stop
}

# ============================================================
# HELPER FUNCTIONS
# ============================================================

function Get-LatestReport {

    param(
        [Parameter(Mandatory)]
        [string]$Pattern
    )

    $File = Get-ChildItem `
        -Path $ReportsPath `
        -Filter $Pattern `
        -File `
        -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    return $File
}

function Get-SafeValue {

    param(
        [Parameter(Mandatory)]
        $Object,

        [Parameter(Mandatory)]
        [string[]]$Names
    )

    foreach ($Name in $Names) {

        $Property = $Object.PSObject.Properties[$Name]

        if ($null -ne $Property) {

            $Value = $Property.Value

            if ($null -ne $Value -and "$Value".Trim() -ne "") {
                return $Value
            }
        }
    }

    return $null
}

function Get-UserIdFromRow {

    param(
        [Parameter(Mandatory)]
        $Row
    )

    return Get-SafeValue `
        -Object $Row `
        -Names @(
            "UserId",
            "Id",
            "ObjectId"
        )
}

function Get-UserPrincipalNameFromRow {

    param(
        [Parameter(Mandatory)]
        $Row
    )

    return Get-SafeValue `
        -Object $Row `
        -Names @(
            "UserPrincipalName",
            "UPN"
        )
}

function Get-DisplayNameFromRow {

    param(
        [Parameter(Mandatory)]
        $Row
    )

    return Get-SafeValue `
        -Object $Row `
        -Names @(
            "DisplayName",
            "Name"
        )
}

# ============================================================
# AUDIT LOGGING
# ============================================================

function Write-RemediationAudit {

    param(
        [Parameter(Mandatory)]
        [string]$Action,

        [Parameter(Mandatory)]
        [string]$UserId,

        [string]$DisplayName,

        [string]$UserPrincipalName,

        [string]$Result,

        [string]$Details,

        [string]$PreviousAccountStatus,

        [string]$NewAccountStatus,

        [string]$NotificationStatus = "NotSent"
    )

    $AuditScript = Join-Path `
        $PSScriptRoot `
        "11-Write-AuditLog.ps1"

    if (-not (Test-Path $AuditScript)) {

        Write-Warning `
            "Script 11 was not found. Remediation completed but audit logging could not be invoked."

        return
    }

    try {

        & $AuditScript `
            -Action $Action `
            -UserId $UserId `
            -DisplayName $DisplayName `
            -UserPrincipalName $UserPrincipalName `
            -Result $Result `
            -Details $Details `
            -PreviousAccountStatus $PreviousAccountStatus `
            -NewAccountStatus $NewAccountStatus `
            -NotificationStatus $NotificationStatus

        Write-Host `
            "Audit event written successfully." `
            -ForegroundColor DarkGreen
    }
    catch {

        Write-Warning `
            "Remediation completed, but Script 11 returned an audit logging error: $($_.Exception.Message)"
    }
}

# ============================================================
# GRAPH CONNECTION
# ============================================================

function Connect-EntraGraph {

    Write-Host ""
    Write-Host `
        "Connecting to Microsoft Graph..." `
        -ForegroundColor Cyan

    $Scopes = @(
        "User.Read.All",
        "User.ReadWrite.All",
        "Group.Read.All",
        "GroupMember.ReadWrite.All",
        "Directory.Read.All",
        "LicenseAssignment.ReadWrite.All"
    )

    Connect-MgGraph `
        -Scopes $Scopes `
        -NoWelcome

    $Context = Get-MgContext

    if ($null -eq $Context) {
        throw "Microsoft Graph connection could not be established."
    }

    Write-Host `
        "Connected successfully." `
        -ForegroundColor Green

    Write-Host `
        "Account : $($Context.Account)" `
        -ForegroundColor Gray

    Write-Host `
        "Tenant  : $($Context.TenantId)" `
        -ForegroundColor Gray
}

# ============================================================
# LOAD GOVERNANCE DATA
# ============================================================

function Get-GovernanceUsers {

    $Index = @{}

    $ReportPatterns = @(
        $InactiveReportPattern,
        $ExpiredReportPattern,
        $GuestReportPattern,
        $DisabledReportPattern,
        $LicenseReportPattern,
        $PrivilegedReportPattern,
        $GroupReportPattern
    )

    foreach ($Pattern in $ReportPatterns) {

        $Report = Get-LatestReport -Pattern $Pattern

        if ($null -eq $Report) {
            continue
        }

        try {

            $Rows = @(Import-Csv -Path $Report.FullName)
        }
        catch {

            Write-Warning `
                "Unable to read report: $($Report.Name)"

            continue
        }

        foreach ($Row in $Rows) {

            $UserId = Get-UserIdFromRow -Row $Row

            if ([string]::IsNullOrWhiteSpace("$UserId")) {
                continue
            }

            if (-not $Index.ContainsKey("$UserId")) {

                $DisplayName = Get-DisplayNameFromRow -Row $Row
                $UPN = Get-UserPrincipalNameFromRow -Row $Row

                $Index["$UserId"] = [PSCustomObject]@{

                    UserId            = "$UserId"
                    DisplayName       = "$DisplayName"
                    UserPrincipalName = "$UPN"

                    Inactive          = $false
                    Expired           = $false
                    Guest             = $false
                    Disabled          = $false
                    Licensed          = $false
                    Privileged        = $false
                    ExcessiveGroups   = $false

                    Findings = New-Object `
                        System.Collections.Generic.List[string]
                }
            }

            $User = $Index["$UserId"]

            if ($Pattern -like "InactiveUsers_*") {

                $User.Inactive = $true

                if (-not $User.Findings.Contains("Inactive user")) {
                    [void]$User.Findings.Add("Inactive user")
                }
            }

            elseif ($Pattern -like "ExpiredUsers_*") {

                $User.Expired = $true

                if (-not $User.Findings.Contains("Expired user")) {
                    [void]$User.Findings.Add("Expired user")
                }
            }

            elseif ($Pattern -like "GuestUsers_*") {

                $User.Guest = $true

                if (-not $User.Findings.Contains("Guest user")) {
                    [void]$User.Findings.Add("Guest user")
                }
            }

            elseif ($Pattern -like "DisabledUsers_*") {

                $User.Disabled = $true

                if (-not $User.Findings.Contains("Disabled user")) {
                    [void]$User.Findings.Add("Disabled user")
                }
            }

            elseif ($Pattern -like "LicenseGovernance_*") {

                $User.Licensed = $true

                if (-not $User.Findings.Contains("License governance finding")) {
                    [void]$User.Findings.Add("License governance finding")
                }
            }

            elseif ($Pattern -like "PrivilegedUsers_*") {

                $User.Privileged = $true

                if (-not $User.Findings.Contains("Privileged user")) {
                    [void]$User.Findings.Add("Privileged user")
                }
            }

            elseif ($Pattern -like "ExcessiveGroupMembership_*") {

                $User.ExcessiveGroups = $true

                if (-not $User.Findings.Contains("Excessive group membership")) {
                    [void]$User.Findings.Add("Excessive group membership")
                }
            }
        }
    }

    return $Index
}

# ============================================================
# USER DETAILS
# ============================================================

function Show-UserDetails {

    param(
        [Parameter(Mandatory)]
        $User
    )

    Write-Host ""
    Write-Host `
        "=============================================" `
        -ForegroundColor Cyan

    Write-Host `
        " User Governance Profile" `
        -ForegroundColor Cyan

    Write-Host `
        "=============================================" `
        -ForegroundColor Cyan

    Write-Host ""

    Write-Host `
        "Display Name       : $($User.DisplayName)"

    Write-Host `
        "UPN                : $($User.UserPrincipalName)"

    Write-Host `
        "Object ID          : $($User.UserId)"

    Write-Host ""

    Write-Host `
        "Governance Findings:" `
        -ForegroundColor Yellow

    if ($User.Findings.Count -eq 0) {

        Write-Host `
            "  None" `
            -ForegroundColor Green
    }
    else {

        foreach ($Finding in $User.Findings) {

            Write-Host `
                "  - $Finding"
        }
    }

    Write-Host ""
}

# ============================================================
# USER SELECTION
# ============================================================

function Select-GovernanceUser {

    param(
        [Parameter(Mandatory)]
        [hashtable]$Users
    )

    Write-Host ""
    Write-Host `
        "Available Governance Users" `
        -ForegroundColor Cyan

    Write-Host ""

    $Candidates = @(
        $Users.Values |
        Where-Object {
            $_.Expired -or
            $_.Licensed -or
            $_.Disabled -or
            $_.Inactive -or
            $_.Privileged -or
            $_.ExcessiveGroups
        } |
        Sort-Object DisplayName
    )

    if ($Candidates.Count -eq 0) {

        Write-Host `
            "No governance candidates are available." `
            -ForegroundColor Yellow

        return $null
    }

    $Number = 1

    foreach ($Candidate in $Candidates) {

        Write-Host `
            "[$Number] $($Candidate.DisplayName) <$($Candidate.UserPrincipalName)>"

        $Number++
    }

    Write-Host ""
    Write-Host "[0] Cancel"

    $Selection = Read-Host "Select a user"

    if ($Selection -eq "0") {
        return $null
    }

    $SelectionNumber = 0

    if (-not [int]::TryParse(
        $Selection,
        [ref]$SelectionNumber
    )) {

        Write-Host `
            "Invalid selection." `
            -ForegroundColor Yellow

        return $null
    }

    if (
        $SelectionNumber -lt 1 -or
        $SelectionNumber -gt $Candidates.Count
    ) {

        Write-Host `
            "Invalid selection." `
            -ForegroundColor Yellow

        return $null
    }

    return $Candidates[$SelectionNumber - 1]
}

# ============================================================
# CONFIRMATION
# ============================================================

function Request-Confirmation {

    param(
        [Parameter(Mandatory)]
        [string]$ActionDescription,

        [switch]$HighImpact
    )

    Write-Host ""
    Write-Host `
        "=============================================" `
        -ForegroundColor Yellow

    Write-Host `
        " CONFIRMATION REQUIRED" `
        -ForegroundColor Yellow

    Write-Host `
        "=============================================" `
        -ForegroundColor Yellow

    Write-Host ""

    Write-Host `
        "Proposed action:" `
        -ForegroundColor White

    Write-Host `
        "  $ActionDescription" `
        -ForegroundColor Yellow

    Write-Host ""

    if ($HighImpact) {

        Write-Host `
            "This is a HIGH-IMPACT operation." `
            -ForegroundColor Red

        Write-Host ""

        Write-Host `
            "Type CONFIRM to continue." `
            -ForegroundColor Red

        $Confirmation = Read-Host

        return ($Confirmation -ceq "CONFIRM")
    }

    $Confirmation = Read-Host `
        "Type YES to continue"

    return ($Confirmation -ceq "YES")
}

# ============================================================
# ACTION 1
# DISABLE EXPIRED USER
# ============================================================

function Invoke-DisableExpiredUser {

    param(
        [Parameter(Mandatory)]
        $User
    )

    Write-Host ""
    Write-Host `
        "Checking current Entra ID state..." `
        -ForegroundColor Cyan

    $CurrentUser = Get-MgUser `
        -UserId $User.UserId `
        -Property @(
            "id",
            "displayName",
            "userPrincipalName",
            "accountEnabled",
            "employeeLeaveDateTime"
        )

    if ($null -eq $CurrentUser) {
        throw "User could not be retrieved."
    }

    $Today = (Get-Date).Date

    if (-not $CurrentUser.AccountEnabled) {

        Write-Host `
            "User is already disabled. No action required." `
            -ForegroundColor Green

        return
    }

    if ($null -eq $CurrentUser.EmployeeLeaveDateTime) {

        Write-Host `
            "User has no leave date. Remediation blocked." `
            -ForegroundColor Yellow

        return
    }

    if ($CurrentUser.EmployeeLeaveDateTime.Date -ge $Today) {

        Write-Host `
            "User leave date has not expired. Remediation blocked." `
            -ForegroundColor Yellow

        return
    }

    $Description = `
        "Disable expired enabled user '$($CurrentUser.UserPrincipalName)'."

    if ($WhatIfPreference) {

        Write-Host ""
        Write-Host `
            "[WHATIF] $Description" `
            -ForegroundColor Cyan

        Write-Host `
            "[WHATIF] No change was made." `
            -ForegroundColor Cyan

        return
    }

    if (-not (Request-Confirmation `
        -ActionDescription $Description)) {

        Write-Host `
            "Operation cancelled." `
            -ForegroundColor Yellow

        return
    }

    if ($PSCmdlet.ShouldProcess(
        $CurrentUser.UserPrincipalName,
        "Disable expired Entra ID user"
    )) {

        Update-MgUser `
            -UserId $CurrentUser.Id `
            -AccountEnabled:$false

        Write-Host ""
        Write-Host `
            "User disabled successfully." `
            -ForegroundColor Green

        Write-RemediationAudit `
            -Action "DisableUser" `
            -UserId $CurrentUser.Id `
            -DisplayName $CurrentUser.DisplayName `
            -UserPrincipalName $CurrentUser.UserPrincipalName `
            -Result "Success" `
            -Details "Expired user account disabled by governance remediation." `
            -PreviousAccountStatus "Enabled" `
            -NewAccountStatus "Disabled"
    }
}

# ============================================================
# ACTION 2
# REMOVE DIRECT LICENSES
# ============================================================

function Invoke-RemoveDirectLicenses {

    param(
        [Parameter(Mandatory)]
        $User
    )

    Write-Host ""
    Write-Host `
        "Checking current license assignments..." `
        -ForegroundColor Cyan

    $CurrentUser = Get-MgUser `
        -UserId $User.UserId `
        -Property @(
            "id",
            "displayName",
            "userPrincipalName",
            "accountEnabled",
            "assignedLicenses"
        )

    if ($null -eq $CurrentUser) {
        throw "User could not be retrieved."
    }

    $LicenseDetails = @(
        Get-MgUserLicenseDetail `
            -UserId $CurrentUser.Id `
            -All
    )

    if ($LicenseDetails.Count -eq 0) {

        Write-Host `
            "No licenses are currently assigned." `
            -ForegroundColor Green

        return
    }

    Write-Host ""
    Write-Host `
        "Current licenses:" `
        -ForegroundColor Cyan

    foreach ($License in $LicenseDetails) {

        Write-Host `
            "  - $($License.SkuPartNumber) [$($License.SkuId)]"
    }

    Write-Host ""

    Write-Host `
        "Important: This action removes only licenses that are directly assigned." `
        -ForegroundColor Yellow

    Write-Host `
        "Group-based licensing is not modified." `
        -ForegroundColor Yellow

    $DirectLicenseIds = @()

    foreach ($License in $CurrentUser.AssignedLicenses) {

        if ($null -ne $License.SkuId) {
            $DirectLicenseIds += $License.SkuId
        }
    }

    if ($DirectLicenseIds.Count -eq 0) {

        Write-Host `
            "No directly assigned licenses were found." `
            -ForegroundColor Green

        return
    }

    $Description = `
        "Remove $($DirectLicenseIds.Count) direct license assignment(s) from '$($CurrentUser.UserPrincipalName)'."

    if ($WhatIfPreference) {

        Write-Host ""

        Write-Host `
            "[WHATIF] $Description" `
            -ForegroundColor Cyan

        foreach ($SkuId in $DirectLicenseIds) {

            Write-Host `
                "[WHATIF] Remove license: $SkuId" `
                -ForegroundColor Cyan
        }

        Write-Host `
            "[WHATIF] No change was made." `
            -ForegroundColor Cyan

        return
    }

    if (-not (Request-Confirmation `
        -ActionDescription $Description `
        -HighImpact)) {

        Write-Host `
            "Operation cancelled." `
            -ForegroundColor Yellow

        return
    }

    if ($PSCmdlet.ShouldProcess(
        $CurrentUser.UserPrincipalName,
        "Remove direct license assignments"
    )) {

        $RemoveLicenses = @()

        foreach ($SkuId in $DirectLicenseIds) {

            $RemoveLicenses += @{
                SkuId = [Guid]$SkuId
            }
        }

        Set-MgUserLicense `
            -UserId $CurrentUser.Id `
            -AddLicenses @() `
            -RemoveLicenses $RemoveLicenses |
            Out-Null

        Write-Host ""
        Write-Host `
            "Direct license assignments removed successfully." `
            -ForegroundColor Green

        $AccountStatus = if ($CurrentUser.AccountEnabled) {
            "Enabled"
        }
        else {
            "Disabled"
        }

        Write-RemediationAudit `
            -Action "RemoveDirectLicenses" `
            -UserId $CurrentUser.Id `
            -DisplayName $CurrentUser.DisplayName `
            -UserPrincipalName $CurrentUser.UserPrincipalName `
            -Result "Success" `
            -Details "Direct license assignments removed by governance remediation." `
            -PreviousAccountStatus $AccountStatus `
            -NewAccountStatus $AccountStatus
    }
}

# ============================================================
# ACTION 3
# REMOVE DIRECT GROUP MEMBERSHIP
# ============================================================

function Invoke-RemoveDirectGroupMembership {

    param(
        [Parameter(Mandatory)]
        $User
    )

    Write-Host ""
    Write-Host `
        "Retrieving direct group memberships..." `
        -ForegroundColor Cyan

    $Groups = @(
        Get-MgUserMemberOfAsGroup `
            -UserId $User.UserId `
            -All `
            -Property @(
                "id",
                "displayName",
                "groupTypes",
                "securityEnabled",
                "mailEnabled"
            )
    )

    if ($Groups.Count -eq 0) {

        Write-Host `
            "User has no direct group memberships." `
            -ForegroundColor Green

        return
    }

    Write-Host ""
    Write-Host `
        "Direct group memberships:" `
        -ForegroundColor Cyan

    $Number = 1

    foreach ($Group in $Groups) {

        Write-Host `
            "[$Number] $($Group.DisplayName) [$($Group.Id)]"

        $Number++
    }

    Write-Host ""
    Write-Host "[0] Cancel"

    $Selection = Read-Host `
        "Select the group to remove"

    if ($Selection -eq "0") {

        Write-Host `
            "Operation cancelled." `
            -ForegroundColor Yellow

        return
    }

    $SelectionNumber = 0

    if (-not [int]::TryParse(
        $Selection,
        [ref]$SelectionNumber
    )) {

        Write-Host `
            "Invalid selection." `
            -ForegroundColor Yellow

        return
    }

    if (
        $SelectionNumber -lt 1 -or
        $SelectionNumber -gt $Groups.Count
    ) {

        Write-Host `
            "Invalid selection." `
            -ForegroundColor Yellow

        return
    }

    $SelectedGroup = $Groups[$SelectionNumber - 1]

    Write-Host ""
    Write-Host `
        "Selected group:" `
        -ForegroundColor Yellow

    Write-Host `
        "  $($SelectedGroup.DisplayName)"

    Write-Host `
        "  $($SelectedGroup.Id)"

    $Description = `
        "Remove '$($User.UserPrincipalName)' from direct group '$($SelectedGroup.DisplayName)'."

    if ($WhatIfPreference) {

        Write-Host ""

        Write-Host `
            "[WHATIF] $Description" `
            -ForegroundColor Cyan

        Write-Host `
            "[WHATIF] No change was made." `
            -ForegroundColor Cyan

        return
    }

    if (-not (Request-Confirmation `
        -ActionDescription $Description `
        -HighImpact)) {

        Write-Host `
            "Operation cancelled." `
            -ForegroundColor Yellow

        return
    }

    if ($PSCmdlet.ShouldProcess(
        $SelectedGroup.DisplayName,
        "Remove user from direct group"
    )) {

        Remove-MgGroupMemberByRef `
            -GroupId $SelectedGroup.Id `
            -DirectoryObjectId $User.UserId

        Write-Host ""
        Write-Host `
            "User removed from the group successfully." `
            -ForegroundColor Green

        Write-RemediationAudit `
            -Action "RemoveGroupMembership" `
            -UserId $User.UserId `
            -DisplayName $User.DisplayName `
            -UserPrincipalName $User.UserPrincipalName `
            -Result "Success" `
            -Details "Removed from direct group '$($SelectedGroup.DisplayName)'." `
            -PreviousAccountStatus "Unchanged" `
            -NewAccountStatus "Unchanged"
    }
}

# ============================================================
# REMEDIATION MENU
# ============================================================

function Show-RemediationMenu {

    Write-Host ""

    Write-Host `
        "=============================================" `
        -ForegroundColor Cyan

    Write-Host `
        " Entra ID Governance Remediation" `
        -ForegroundColor Cyan

    Write-Host `
        "=============================================" `
        -ForegroundColor Cyan

    Write-Host ""

    Write-Host "1. Disable expired user"
    Write-Host "2. Remove direct licenses"
    Write-Host "3. Remove direct group membership"
    Write-Host "0. Exit"

    Write-Host ""
}

# ============================================================
# MAIN
# ============================================================

try {

    Write-Host ""

    Write-Host `
        "=============================================" `
        -ForegroundColor Green

    Write-Host `
        " Entra ID Governance Remediation Toolkit" `
        -ForegroundColor Green

    Write-Host `
        " Version 1.0.1" `
        -ForegroundColor Green

    Write-Host `
        "=============================================" `
        -ForegroundColor Green

    Write-Host ""

    Write-Host `
        "IMPORTANT:" `
        -ForegroundColor Yellow

    Write-Host `
        "This script can modify Entra ID objects." `
        -ForegroundColor Yellow

    Write-Host `
        "Review every proposed action before approval." `
        -ForegroundColor Yellow

    if ($WhatIfPreference) {

        Write-Host ""

        Write-Host `
            "WHATIF MODE: No Entra ID modifications will be made." `
            -ForegroundColor Cyan
    }

    Write-Host ""

    Connect-EntraGraph

    Write-Host ""

    Write-Host `
        "Loading governance reports..." `
        -ForegroundColor Cyan

    $GovernanceUsers = Get-GovernanceUsers

    if (
        $null -eq $GovernanceUsers -or
        $GovernanceUsers.Count -eq 0
    ) {

        Write-Host ""

        Write-Host `
            "No governance users were found." `
            -ForegroundColor Yellow

        return
    }

    Write-Host `
        "Governance users loaded: $($GovernanceUsers.Count)" `
        -ForegroundColor Green

    $ExitRequested = $false

    while (-not $ExitRequested) {

        Show-RemediationMenu

        $Choice = Read-Host `
            "Select an option"

        switch ($Choice) {

            # ------------------------------------------------
            # DISABLE EXPIRED USER
            # ------------------------------------------------

            "1" {

                $User = Select-GovernanceUser `
                    -Users $GovernanceUsers

                if ($null -ne $User) {

                    Show-UserDetails `
                        -User $User

                    try {

                        Invoke-DisableExpiredUser `
                            -User $User
                    }
                    catch {

                        Write-Host ""

                        Write-Host `
                            "Remediation failed: $($_.Exception.Message)" `
                            -ForegroundColor Red

                        Write-RemediationAudit `
                            -Action "DisableUser" `
                            -UserId $User.UserId `
                            -DisplayName $User.DisplayName `
                            -UserPrincipalName $User.UserPrincipalName `
                            -Result "Failed" `
                            -Details $_.Exception.Message `
                            -PreviousAccountStatus "Unknown" `
                            -NewAccountStatus "Unknown"
                    }
                }
            }

            # ------------------------------------------------
            # REMOVE DIRECT LICENSES
            # ------------------------------------------------

            "2" {

                $User = Select-GovernanceUser `
                    -Users $GovernanceUsers

                if ($null -ne $User) {

                    Show-UserDetails `
                        -User $User

                    try {

                        Invoke-RemoveDirectLicenses `
                            -User $User
                    }
                    catch {

                        Write-Host ""

                        Write-Host `
                            "License remediation failed: $($_.Exception.Message)" `
                            -ForegroundColor Red

                        Write-RemediationAudit `
                            -Action "RemoveDirectLicenses" `
                            -UserId $User.UserId `
                            -DisplayName $User.DisplayName `
                            -UserPrincipalName $User.UserPrincipalName `
                            -Result "Failed" `
                            -Details $_.Exception.Message `
                            -PreviousAccountStatus "Unknown" `
                            -NewAccountStatus "Unknown"
                    }
                }
            }

            # ------------------------------------------------
            # REMOVE GROUP MEMBERSHIP
            # ------------------------------------------------

            "3" {

                $User = Select-GovernanceUser `
                    -Users $GovernanceUsers

                if ($null -ne $User) {

                    Show-UserDetails `
                        -User $User

                    try {

                        Invoke-RemoveDirectGroupMembership `
                            -User $User
                    }
                    catch {

                        Write-Host ""

                        Write-Host `
                            "Group remediation failed: $($_.Exception.Message)" `
                            -ForegroundColor Red

                        Write-RemediationAudit `
                            -Action "RemoveGroupMembership" `
                            -UserId $User.UserId `
                            -DisplayName $User.DisplayName `
                            -UserPrincipalName $User.UserPrincipalName `
                            -Result "Failed" `
                            -Details $_.Exception.Message `
                            -PreviousAccountStatus "Unknown" `
                            -NewAccountStatus "Unknown"
                    }
                }
            }

            # ------------------------------------------------
            # EXIT
            # ------------------------------------------------

            "0" {

                $ExitRequested = $true
            }

            default {

                Write-Host `
                    "Invalid option. Please select 0-3." `
                    -ForegroundColor Yellow
            }
        }
    }

    Clear-Host

    Write-Host ""

    Write-Host `
        "=============================================" `
        -ForegroundColor Green

    Write-Host `
        " Governance Remediation Closed" `
        -ForegroundColor Green

    Write-Host `
        "=============================================" `
        -ForegroundColor Green

    Write-Host ""

    if ($WhatIfPreference) {

        Write-Host `
            "WhatIf mode was used. No Entra ID objects were modified." `
            -ForegroundColor Cyan
    }
    else {

        Write-Host `
            "Remediation workflow completed." `
            -ForegroundColor Green
    }

    Write-Host ""

    Write-Host `
        "Review Script 11 audit records for executed actions." `
        -ForegroundColor Gray

    Write-Host ""

    Write-Host `
        "Script completed successfully." `
        -ForegroundColor Green

    Write-Host ""
}
catch {

    Write-Host ""

    Write-Host `
        "=============================================" `
        -ForegroundColor Red

    Write-Host `
        " Remediation Script Failed" `
        -ForegroundColor Red

    Write-Host `
        "=============================================" `
        -ForegroundColor Red

    Write-Host ""

    Write-Host `
        $_.Exception.Message `
        -ForegroundColor Red

    Write-Host ""

    exit 1
}