#requires -Version 5.1

<#
.SYNOPSIS
    Retrieves Microsoft Entra ID users and exports a governance-ready CSV report.

.DESCRIPTION
    Read-only discovery script for Microsoft Entra ID User Governance Toolkit.

    Collects:
    - User identity
    - Account status
    - User type
    - Department / Job Title / Company
    - Employee information
    - Employee leave date
    - Sign-in activity
    - Assigned license count

    The script does NOT modify users.

.NOTES
    Project:
        Entra ID User Governance Toolkit

    Script:
        01-Get-EntraUsers.ps1

    Version:
        1.0.0

    Required:
        Microsoft Graph PowerShell SDK 2.x

    Required permissions:
        User.Read.All
        AuditLog.Read.All

    Important:
        signInActivity requires appropriate Microsoft Entra licensing.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

# ============================================================
# PROJECT PATH
# ============================================================

$ProjectRoot = Split-Path -Parent $PSScriptRoot

$ReportsPath = Join-Path $ProjectRoot "Reports"

if (-not (Test-Path $ReportsPath)) {
    New-Item -Path $ReportsPath -ItemType Directory -Force | Out-Null
}

# ============================================================
# MODULE PATH
# ============================================================

$PrimaryModulePath = Join-Path $HOME "Documents\PowerShell\Modules"

if (Test-Path $PrimaryModulePath) {
    $env:PSModulePath = "$PrimaryModulePath;$env:PSModulePath"
}

# ============================================================
# REQUIRED MODULES
# ============================================================

$RequiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Users"
)

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " Entra ID User Governance Toolkit" -ForegroundColor Cyan
Write-Host " 01 - Get Entra Users" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[1/6] Checking Microsoft Graph modules..." -ForegroundColor Yellow

foreach ($ModuleName in $RequiredModules) {

    $AvailableModule = Get-Module -ListAvailable -Name $ModuleName |
        Sort-Object Version -Descending |
        Select-Object -First 1

    if (-not $AvailableModule) {

        Write-Host "Module not found: $ModuleName" -ForegroundColor Yellow
        Write-Host "Installing module..." -ForegroundColor Yellow

        Install-Module `
            -Name $ModuleName `
            -Scope CurrentUser `
            -Repository PSGallery `
            -Force `
            -AllowClobber

        $AvailableModule = Get-Module -ListAvailable -Name $ModuleName |
            Sort-Object Version -Descending |
            Select-Object -First 1
    }

    if (-not $AvailableModule) {
        throw "Unable to locate or install module: $ModuleName"
    }

    Write-Host "  $ModuleName : $($AvailableModule.Version)" -ForegroundColor Green

    Import-Module `
        -Name $AvailableModule.Path `
        -Force `
        -ErrorAction Stop
}

# ============================================================
# CONNECT TO MICROSOFT GRAPH
# ============================================================

Write-Host ""
Write-Host "[2/6] Checking Microsoft Graph connection..." -ForegroundColor Yellow

$RequiredScopes = @(
    "User.Read.All",
    "AuditLog.Read.All"
)

$Context = Get-MgContext

$NeedsConnection = $true

if ($Context) {

    $CurrentScopes = @($Context.Scopes)

    $MissingScopes = $RequiredScopes |
        Where-Object {
            $_ -notin $CurrentScopes
        }

    if ($MissingScopes.Count -eq 0) {
        $NeedsConnection = $false
    }
}

if ($NeedsConnection) {

    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow

    Connect-MgGraph `
        -Scopes $RequiredScopes `
        -NoWelcome

} else {

    Write-Host "Existing Graph session is valid." -ForegroundColor Green
}

$Context = Get-MgContext

if (-not $Context) {
    throw "Microsoft Graph connection could not be established."
}

Write-Host "  Account : $($Context.Account)" -ForegroundColor Green
Write-Host "  Tenant  : $($Context.TenantId)" -ForegroundColor Green

# ============================================================
# GRAPH PROPERTY SELECTION
# ============================================================

Write-Host ""
Write-Host "[3/6] Preparing user properties..." -ForegroundColor Yellow

$SelectProperties = @(
    "id",
    "displayName",
    "userPrincipalName",
    "mail",
    "accountEnabled",
    "userType",
    "createdDateTime",
    "employeeId",
    "department",
    "jobTitle",
    "companyName",
    "officeLocation",
    "employeeHireDate",
    "employeeLeaveDateTime",
    "signInActivity",
    "assignedLicenses"
)

# ============================================================
# RETRIEVE USERS
# ============================================================

Write-Host ""
Write-Host "[4/6] Retrieving Microsoft Entra ID users..." -ForegroundColor Yellow

$Users = @(
    Get-MgUser `
        -All `
        -Property $SelectProperties
)

Write-Host "  Users retrieved: $($Users.Count)" -ForegroundColor Green

if ($Users.Count -eq 0) {

    Write-Warning "No users were returned from Microsoft Graph."

    exit 0
}

# ============================================================
# BUILD REPORT
# ============================================================

Write-Host ""
Write-Host "[5/6] Building governance report..." -ForegroundColor Yellow

$Report = foreach ($User in $Users) {

    $LastSuccessfulSignIn = $null
    $LastInteractiveSignIn = $null
    $LastNonInteractiveSignIn = $null

    if ($User.SignInActivity) {

        $LastSuccessfulSignIn =
            $User.SignInActivity.LastSuccessfulSignInDateTime

        $LastInteractiveSignIn =
            $User.SignInActivity.LastSignInDateTime

        $LastNonInteractiveSignIn =
            $User.SignInActivity.LastNonInteractiveSignInDateTime
    }

    $LicenseCount = 0

    if ($User.AssignedLicenses) {
        $LicenseCount = @($User.AssignedLicenses).Count
    }

    [PSCustomObject]@{
        Id                          = $User.Id
        DisplayName                = $User.DisplayName
        UserPrincipalName          = $User.UserPrincipalName
        Mail                        = $User.Mail
        AccountEnabled              = $User.AccountEnabled
        UserType                   = $User.UserType
        CreatedDateTime             = $User.CreatedDateTime
        EmployeeId                 = $User.EmployeeId
        Department                 = $User.Department
        JobTitle                   = $User.JobTitle
        CompanyName                = $User.CompanyName
        OfficeLocation             = $User.OfficeLocation
        EmployeeHireDate           = $User.EmployeeHireDate
        EmployeeLeaveDateTime      = $User.EmployeeLeaveDateTime
        LastSuccessfulSignInDateTime = $LastSuccessfulSignIn
        LastSignInDateTime         = $LastInteractiveSignIn
        LastNonInteractiveSignIn   = $LastNonInteractiveSignIn
        AssignedLicenseCount       = $LicenseCount
    }
}

# ============================================================
# EXPORT REPORT
# ============================================================

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

$ReportPath = Join-Path `
    $ReportsPath `
    "EntraUsers_$Timestamp.csv"

$Report |
    Export-Csv `
        -Path $ReportPath `
        -NoTypeInformation `
        -Encoding UTF8

# ============================================================
# SUMMARY
# ============================================================

Write-Host ""
Write-Host "[6/6] Report generated successfully." -ForegroundColor Yellow
Write-Host ""

$TotalUsers = @($Report).Count

$EnabledUsers = @(
    $Report |
    Where-Object {
        $_.AccountEnabled -eq $true
    }
).Count

$DisabledUsers = @(
    $Report |
    Where-Object {
        $_.AccountEnabled -eq $false
    }
).Count

$GuestUsers = @(
    $Report |
    Where-Object {
        $_.UserType -eq "Guest"
    }
).Count

$LicensedUsers = @(
    $Report |
    Where-Object {
        $_.AssignedLicenseCount -gt 0
    }
).Count

$NeverSuccessfulSignIn = @(
    $Report |
    Where-Object {
        [string]::IsNullOrWhiteSpace(
            [string]$_.LastSuccessfulSignInDateTime
        )
    }
).Count

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " Entra ID User Discovery Summary" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "Total Users              : $TotalUsers"
Write-Host "Enabled Users            : $EnabledUsers"
Write-Host "Disabled Users           : $DisabledUsers"
Write-Host "Guest Users              : $GuestUsers"
Write-Host "Licensed Users           : $LicensedUsers"
Write-Host "Never Successful Sign-In: $NeverSuccessfulSignIn"
Write-Host ""
Write-Host "Report:" -ForegroundColor Green
Write-Host $ReportPath -ForegroundColor Green
Write-Host ""
Write-Host "Read-only discovery completed successfully." -ForegroundColor Green
Write-Host ""