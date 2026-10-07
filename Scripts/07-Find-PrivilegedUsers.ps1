#requires -Version 5.1

<#
.SYNOPSIS
    Identifies Microsoft Entra ID privileged directory role assignments
    and evaluates privileged users for governance.

.DESCRIPTION
    Queries Microsoft Graph for Microsoft Entra directory role assignments.

    The script resolves each role assignment principal and identifies
    whether the principal is:

        - User
        - Group
        - Service Principal
        - Other directory object
        - Unresolved / deleted object

    User principals are evaluated for:

        - Account enabled / disabled state
        - Last successful sign-in
        - Inactivity
        - Employee leave date
        - Assigned license count
        - Governance priority

    Non-user principals are retained in the report and are NOT silently
    discarded.

    The script is READ-ONLY.

    No role assignments are added, removed, or modified.

.PARAMETER InactiveDays
    Number of days without a successful sign-in before an enabled
    privileged user is considered inactive.

    Default:
        90 days

.EXAMPLE
    .\07-Find-PrivilegedUsers.ps1

.EXAMPLE
    .\07-Find-PrivilegedUsers.ps1 -InactiveDays 30

.NOTES
    Project:
        Entra ID User Governance Toolkit

    Script:
        07-Find-PrivilegedUsers.ps1

    Version:
        2.0.0

    Required Graph modules:
        Microsoft.Graph.Authentication
        Microsoft.Graph.Users
        Microsoft.Graph.Identity.DirectoryManagement

    Required Graph permissions:
        User.Read.All
        RoleManagement.Read.Directory
        Directory.Read.All
        AuditLog.Read.All

    Action:
        Read-only
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 3650)]
    [int]$InactiveDays = 90
)

$ErrorActionPreference = "Stop"

# ============================================================
# PROJECT PATH
# ============================================================

$ProjectRoot = Split-Path -Parent $PSScriptRoot

$ReportsPath = Join-Path $ProjectRoot "Reports"

if (-not (Test-Path $ReportsPath)) {

    New-Item `
        -Path $ReportsPath `
        -ItemType Directory `
        -Force |
        Out-Null
}

# ============================================================
# HEADER
# ============================================================

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " Entra ID User Governance Toolkit" -ForegroundColor Cyan
Write-Host " 07 - Find Privileged Users" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Privileged inactivity threshold: $InactiveDays days" -ForegroundColor Yellow
Write-Host ""

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

Write-Host "[1/9] Checking Microsoft Graph modules..." -ForegroundColor Yellow

$RequiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Identity.DirectoryManagement"
)

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
# GRAPH CONNECTION
# ============================================================

Write-Host ""
Write-Host "[2/9] Checking Microsoft Graph connection..." -ForegroundColor Yellow

$RequiredScopes = @(
    "User.Read.All",
    "RoleManagement.Read.Directory",
    "Directory.Read.All",
    "AuditLog.Read.All"
)

$Context = Get-MgContext

$NeedsConnection = $true

if ($Context) {

    $CurrentScopes = @($Context.Scopes)

    $MissingScopes = @(
        $RequiredScopes |
        Where-Object {
            $_ -notin $CurrentScopes
        }
    )

    if ($MissingScopes.Count -eq 0) {

        $NeedsConnection = $false
    }
}

if ($NeedsConnection) {

    Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Yellow

    Connect-MgGraph `
        -Scopes $RequiredScopes `
        -NoWelcome

}
else {

    Write-Host "Existing Graph session has the required scopes." -ForegroundColor Green
}

$Context = Get-MgContext

if (-not $Context) {

    throw "Microsoft Graph connection could not be established."
}

Write-Host "  Account : $($Context.Account)" -ForegroundColor Green
Write-Host "  Tenant  : $($Context.TenantId)" -ForegroundColor Green

# ============================================================
# DATE INFORMATION
# ============================================================

$Today = (Get-Date).Date

$InactiveThresholdDate = $Today.AddDays(-$InactiveDays)

Write-Host ""
Write-Host "[3/9] Preparing privileged-account analysis..." -ForegroundColor Yellow
Write-Host ""
Write-Host "Today:" -ForegroundColor DarkGray
Write-Host "  $($Today.ToString('yyyy-MM-dd'))" -ForegroundColor DarkGray
Write-Host ""
Write-Host "Inactive threshold:" -ForegroundColor DarkGray
Write-Host "  $($InactiveThresholdDate.ToString('yyyy-MM-dd'))" -ForegroundColor DarkGray

# ============================================================
# GET DIRECTORY ROLE ASSIGNMENTS
# ============================================================

Write-Host ""
Write-Host "[4/9] Retrieving Entra directory role assignments..." -ForegroundColor Yellow

$RoleAssignments = @(
    Get-MgRoleManagementDirectoryRoleAssignment -All
)

Write-Host "Role assignments found: $($RoleAssignments.Count)" -ForegroundColor Green

if ($RoleAssignments.Count -eq 0) {

    Write-Host ""
    Write-Host "No directory role assignments were found." -ForegroundColor Yellow

    $Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

    $EmptyReportPath = Join-Path `
        $ReportsPath `
        "PrivilegedUsers_$Timestamp.csv"

    @(
        [PSCustomObject]@{
            UserId                        = ""
            PrincipalId                   = ""
            PrincipalType                 = ""
            DisplayName                   = ""
            UserPrincipalName             = ""
            Mail                          = ""
            RoleId                        = ""
            RoleName                      = ""
            RoleTemplateId                = ""
            AccountEnabled                = ""
            UserType                      = ""
            AssignedLicenseCount          = ""
            LastSuccessfulSignInDateTime  = ""
            DaysSinceLastSuccessfulSignIn = ""
            EmployeeLeaveDateTime         = ""
            DaysSinceLeaveDate            = ""
            Category                      = "NoRoleAssignments"
            GovernancePriority            = "None"
            GovernanceCandidate           = $false
            ResolutionStatus              = "NoRoleAssignments"
            Reason                        = "No directory role assignments were found."
        }
    ) |
    Export-Csv `
        -Path $EmptyReportPath `
        -NoTypeInformation `
        -Encoding UTF8

    Write-Host ""
    Write-Host "Report:" -ForegroundColor Green
    Write-Host $EmptyReportPath -ForegroundColor Green
    Write-Host ""
    Write-Host "Script completed successfully." -ForegroundColor Green

    exit 0
}

# ============================================================
# GET ROLE DEFINITIONS
# ============================================================

Write-Host ""
Write-Host "[5/9] Resolving directory role definitions..." -ForegroundColor Yellow

$RoleDefinitions = @(
    Get-MgRoleManagementDirectoryRoleDefinition -All
)

$RoleDefinitionLookup = @{}

foreach ($RoleDefinition in $RoleDefinitions) {

    $RoleDefinitionLookup[$RoleDefinition.Id] = $RoleDefinition
}

Write-Host "Role definitions available: $($RoleDefinitions.Count)" -ForegroundColor Green

# ============================================================
# GET ALL ENTRA USERS
# ============================================================

Write-Host ""
Write-Host "[6/9] Loading Entra users for principal resolution..." -ForegroundColor Yellow

$AllUsers = @(
    Get-MgUser `
        -All `
        -Property @(
            "id",
            "displayName",
            "userPrincipalName",
            "mail",
            "accountEnabled",
            "userType",
            "department",
            "jobTitle",
            "companyName",
            "employeeId",
            "employeeLeaveDateTime",
            "signInActivity",
            "assignedLicenses"
        )
)

$UserLookup = @{}

foreach ($User in $AllUsers) {

    if ($User.Id) {

        $UserLookup[$User.Id] = $User
    }
}

Write-Host "Users loaded: $($AllUsers.Count)" -ForegroundColor Green

# ============================================================
# PRINCIPAL RESOLUTION FUNCTION
# ============================================================

function Resolve-DirectoryPrincipal {

    param(
        [Parameter(Mandatory = $true)]
        [string]$PrincipalId
    )

    # --------------------------------------------------------
    # USER
    # --------------------------------------------------------

    if ($UserLookup.ContainsKey($PrincipalId)) {

        $User = $UserLookup[$PrincipalId]

        return [PSCustomObject]@{

            PrincipalId        = $PrincipalId

            PrincipalType      = "User"

            ResolutionStatus   = "Resolved"

            DisplayName        = $User.DisplayName

            UserPrincipalName  = $User.UserPrincipalName

            Mail               = $User.Mail

            UserObject         = $User

            DirectoryObject    = $null
        }
    }

    # --------------------------------------------------------
    # OTHER DIRECTORY OBJECT
    # --------------------------------------------------------

    try {

        $Uri = "https://graph.microsoft.com/v1.0/directoryObjects/$PrincipalId"

        $DirectoryObject = Invoke-MgGraphRequest `
            -Method GET `
            -Uri $Uri `
            -OutputType PSObject

        if ($DirectoryObject) {

            $OdataType = [string]$DirectoryObject.'@odata.type'

            $PrincipalType = switch -Regex ($OdataType) {

                "group" {
                    "Group"
                    break
                }

                "servicePrincipal" {
                    "ServicePrincipal"
                    break
                }

                "device" {
                    "Device"
                    break
                }

                "organizationalContact" {
                    "OrganizationalContact"
                    break
                }

                default {
                    "Other"
                }
            }

            return [PSCustomObject]@{

                PrincipalId        = $PrincipalId

                PrincipalType      = $PrincipalType

                ResolutionStatus   = "Resolved"

                DisplayName        = $DirectoryObject.displayName

                UserPrincipalName  = $null

                Mail               = $null

                UserObject         = $null

                DirectoryObject    = $DirectoryObject
            }
        }
    }
    catch {

        return [PSCustomObject]@{

            PrincipalId        = $PrincipalId

            PrincipalType      = "Unknown"

            ResolutionStatus   = "Unresolved"

            DisplayName        = ""

            UserPrincipalName  = ""

            Mail               = ""

            UserObject         = $null

            DirectoryObject    = $null
        }
    }

    return [PSCustomObject]@{

        PrincipalId        = $PrincipalId

        PrincipalType      = "Unknown"

        ResolutionStatus   = "Unresolved"

        DisplayName        = ""

        UserPrincipalName  = ""

        Mail               = ""

        UserObject         = $null

        DirectoryObject    = $null
    }
}

# ============================================================
# RESOLVE PRINCIPALS
# ============================================================

Write-Host ""
Write-Host "[7/9] Resolving role-assignment principals..." -ForegroundColor Yellow

$PrincipalIds = @(
    $RoleAssignments |
    Where-Object {
        $_.PrincipalId
    } |
    Select-Object -ExpandProperty PrincipalId -Unique
)

Write-Host "Unique role-assigned principals: $($PrincipalIds.Count)" -ForegroundColor Green

$PrincipalLookup = @{}

foreach ($PrincipalId in $PrincipalIds) {

    Write-Host "  Resolving $PrincipalId ..." -ForegroundColor DarkGray

    $ResolvedPrincipal = Resolve-DirectoryPrincipal `
        -PrincipalId $PrincipalId

    $PrincipalLookup[$PrincipalId] = $ResolvedPrincipal

    if ($ResolvedPrincipal.ResolutionStatus -eq "Resolved") {

        Write-Host "    Type : $($ResolvedPrincipal.PrincipalType)" -ForegroundColor Green
        Write-Host "    Name : $($ResolvedPrincipal.DisplayName)" -ForegroundColor Green
    }
    else {

        Write-Host "    Unable to resolve principal." -ForegroundColor Yellow
    }
}

# ============================================================
# BUILD REPORT
# ============================================================

Write-Host ""
Write-Host "[8/9] Evaluating privileged-account governance..." -ForegroundColor Yellow

$Results = foreach ($Assignment in $RoleAssignments) {

    $PrincipalId = $Assignment.PrincipalId

    if (-not $PrincipalLookup.ContainsKey($PrincipalId)) {

        continue
    }

    $Principal = $PrincipalLookup[$PrincipalId]

    # --------------------------------------------------------
    # ROLE INFORMATION
    # --------------------------------------------------------

    $RoleName = "Unknown Role"

    $RoleTemplateId = $null

    if (
        $Assignment.RoleDefinitionId -and
        $RoleDefinitionLookup.ContainsKey(
            $Assignment.RoleDefinitionId
        )
    ) {

        $RoleDefinition = $RoleDefinitionLookup[
            $Assignment.RoleDefinitionId
        ]

        $RoleName = $RoleDefinition.DisplayName

        $RoleTemplateId = $RoleDefinition.TemplateId
    }

    # --------------------------------------------------------
    # DEFAULT VALUES
    # --------------------------------------------------------

    $User = $Principal.UserObject

    $AccountEnabled = $null

    $LicenseCount = 0

    $LastSuccessfulSignIn = $null

    $DaysSinceLastSuccessfulSignIn = $null

    $LeaveDate = $null

    $DaysSinceLeaveDate = $null

    $Category = "NonUserPrincipal"

    $GovernancePriority = "Review"

    $GovernanceCandidate = $true

    $Reason = ""

    # --------------------------------------------------------
    # NON-USER PRINCIPAL
    # --------------------------------------------------------

    if ($Principal.PrincipalType -ne "User") {

        if ($Principal.ResolutionStatus -eq "Resolved") {

            $Category = "PrivilegedNonUserPrincipal"

            $GovernancePriority = "Review"

            $GovernanceCandidate = $true

            $Reason =
                "Privileged directory role is assigned to a $($Principal.PrincipalType). Review whether this assignment is required."

        }
        else {

            $Category = "PrivilegedUnresolvedPrincipal"

            $GovernancePriority = "High"

            $GovernanceCandidate = $true

            $Reason =
                "Privileged role assignment references a principal that could not be resolved. Investigate the assignment."
        }

    }

    # --------------------------------------------------------
    # USER PRINCIPAL
    # --------------------------------------------------------

    else {

        # ----------------------------------------------------
        # ACCOUNT STATUS
        # ----------------------------------------------------

        $AccountEnabled = $false

        if ($User.AccountEnabled -eq $true) {

            $AccountEnabled = $true
        }

        # ----------------------------------------------------
        # LICENSE COUNT
        # ----------------------------------------------------

        if ($User.AssignedLicenses) {

            $LicenseCount = @(
                $User.AssignedLicenses
            ).Count
        }

        # ----------------------------------------------------
        # LAST SUCCESSFUL SIGN-IN
        # ----------------------------------------------------

        if ($User.SignInActivity) {

            $RawSignInDate =
                $User.SignInActivity.LastSuccessfulSignInDateTime

            if (
                -not [string]::IsNullOrWhiteSpace(
                    [string]$RawSignInDate
                )
            ) {

                $ParsedSignInDate = [datetime]::MinValue

                $DateParsed = [datetime]::TryParse(
                    [string]$RawSignInDate,
                    [ref]$ParsedSignInDate
                )

                if ($DateParsed) {

                    $LastSuccessfulSignIn = $ParsedSignInDate

                    $DaysSinceLastSuccessfulSignIn = (
                        $Today - $LastSuccessfulSignIn.Date
                    ).Days
                }
            }
        }

        # ----------------------------------------------------
        # EMPLOYEE LEAVE DATE
        # ----------------------------------------------------

        if (
            -not [string]::IsNullOrWhiteSpace(
                [string]$User.EmployeeLeaveDateTime
            )
        ) {

            $ParsedLeaveDate = [datetime]::MinValue

            $LeaveDateParsed = [datetime]::TryParse(
                [string]$User.EmployeeLeaveDateTime,
                [ref]$ParsedLeaveDate
            )

            if ($LeaveDateParsed) {

                $LeaveDate = $ParsedLeaveDate.Date

                if ($LeaveDate -lt $Today) {

                    $DaysSinceLeaveDate = (
                        $Today - $LeaveDate
                    ).Days
                }
            }
        }

        # ====================================================
        # USER CLASSIFICATION
        # ====================================================

        if (
            $AccountEnabled -and
            $LeaveDate -ne $null -and
            $LeaveDate -lt $Today
        ) {

            $Category = "PrivilegedExpiredEnabled"

            $GovernancePriority = "Critical"

            $GovernanceCandidate = $true

            $Reason =
                "Privileged account is enabled although the employee leave date has expired."
        }

        elseif (-not $AccountEnabled) {

            $Category = "PrivilegedDisabled"

            $GovernancePriority = "High"

            $GovernanceCandidate = $true

            $Reason =
                "Privileged directory role is assigned to a disabled account."
        }

        elseif ($LastSuccessfulSignIn -eq $null) {

            $Category = "PrivilegedNeverSignedIn"

            $GovernancePriority = "High"

            $GovernanceCandidate = $true

            $Reason =
                "Enabled privileged account has no recorded successful sign-in."
        }

        elseif (
            $LastSuccessfulSignIn.Date -lt
            $InactiveThresholdDate
        ) {

            $Category = "PrivilegedInactive"

            $GovernancePriority = "High"

            $GovernanceCandidate = $true

            $Reason =
                "Privileged account has no successful sign-in within the configured inactivity threshold."
        }

        else {

            $Category = "PrivilegedActive"

            $GovernancePriority = "Low"

            $GovernanceCandidate = $false

            $Reason =
                "Privileged account is enabled and has recent successful sign-in activity."
        }
    }

    # --------------------------------------------------------
    # RESULT OBJECT
    # --------------------------------------------------------

    [PSCustomObject]@{

        UserId                         = if ($User) {
            $User.Id
        }
        else {
            ""
        }

        PrincipalId                    = $PrincipalId

        PrincipalType                  = $Principal.PrincipalType

        ResolutionStatus               = $Principal.ResolutionStatus

        DisplayName                    = $Principal.DisplayName

        UserPrincipalName              = $Principal.UserPrincipalName

        Mail                           = $Principal.Mail

        RoleId                         = $Assignment.RoleDefinitionId

        RoleName                       = $RoleName

        RoleTemplateId                 = $RoleTemplateId

        AccountEnabled                 = $AccountEnabled

        UserType                       = if ($User) {
            $User.UserType
        }
        else {
            ""
        }

        Department                     = if ($User) {
            $User.Department
        }
        else {
            ""
        }

        JobTitle                       = if ($User) {
            $User.JobTitle
        }
        else {
            ""
        }

        CompanyName                    = if ($User) {
            $User.CompanyName
        }
        else {
            ""
        }

        EmployeeId                     = if ($User) {
            $User.EmployeeId
        }
        else {
            ""
        }

        AssignedLicenseCount           = $LicenseCount

        LastSuccessfulSignInDateTime   = $LastSuccessfulSignIn

        DaysSinceLastSuccessfulSignIn  = $DaysSinceLastSuccessfulSignIn

        EmployeeLeaveDateTime          = $LeaveDate

        DaysSinceLeaveDate             = $DaysSinceLeaveDate

        InactivityThresholdDays        = $InactiveDays

        InactivityThresholdDate        = $InactiveThresholdDate

        Category                       = $Category

        GovernancePriority             = $GovernancePriority

        GovernanceCandidate            = $GovernanceCandidate

        Reason                         = $Reason
    }
}

# ============================================================
# EXPORT REPORT
# ============================================================

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

$OutputPath = Join-Path `
    $ReportsPath `
    "PrivilegedUsers_$Timestamp.csv"

$Results |
    Export-Csv `
        -Path $OutputPath `
        -NoTypeInformation `
        -Encoding UTF8

# ============================================================
# SUMMARY
# ============================================================

Write-Host ""
Write-Host "[9/9] Analysis completed." -ForegroundColor Yellow
Write-Host ""

$TotalAssignments = @(
    $Results
).Count

$UniquePrincipals = @(
    $Results |
    Select-Object -ExpandProperty PrincipalId -Unique
).Count

$UserAssignments = @(
    $Results |
    Where-Object {
        $_.PrincipalType -eq "User"
    }
).Count

$UniquePrivilegedUsers = @(
    $Results |
    Where-Object {
        $_.PrincipalType -eq "User"
    } |
    Select-Object -ExpandProperty UserId -Unique
).Count

$GroupAssignments = @(
    $Results |
    Where-Object {
        $_.PrincipalType -eq "Group"
    }
).Count

$ServicePrincipalAssignments = @(
    $Results |
    Where-Object {
        $_.PrincipalType -eq "ServicePrincipal"
    }
).Count

$OtherAssignments = @(
    $Results |
    Where-Object {
        $_.PrincipalType -eq "Other"
    }
).Count

$UnresolvedAssignments = @(
    $Results |
    Where-Object {
        $_.ResolutionStatus -eq "Unresolved"
    }
).Count

$ActivePrivileged = @(
    $Results |
    Where-Object {
        $_.Category -eq "PrivilegedActive"
    }
).Count

$InactivePrivileged = @(
    $Results |
    Where-Object {
        $_.Category -eq "PrivilegedInactive"
    }
).Count

$NeverSignedInPrivileged = @(
    $Results |
    Where-Object {
        $_.Category -eq "PrivilegedNeverSignedIn"
    }
).Count

$DisabledPrivileged = @(
    $Results |
    Where-Object {
        $_.Category -eq "PrivilegedDisabled"
    }
).Count

$ExpiredEnabledPrivileged = @(
    $Results |
    Where-Object {
        $_.Category -eq "PrivilegedExpiredEnabled"
    }
).Count

$NonUserPrincipals = @(
    $Results |
    Where-Object {
        $_.Category -eq "PrivilegedNonUserPrincipal"
    }
).Count

$CriticalCandidates = @(
    $Results |
    Where-Object {
        $_.GovernancePriority -eq "Critical"
    }
).Count

$HighCandidates = @(
    $Results |
    Where-Object {
        $_.GovernancePriority -eq "High"
    }
).Count

$ReviewCandidates = @(
    $Results |
    Where-Object {
        $_.GovernancePriority -eq "Review"
    }
).Count

$GovernanceCandidates = @(
    $Results |
    Where-Object {
        $_.GovernanceCandidate -eq $true
    }
).Count

# ============================================================
# DISPLAY SUMMARY
# ============================================================

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " Privileged User Governance Summary" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

Write-Host "Role Assignments                  : $TotalAssignments"
Write-Host "Unique Principals                 : $UniquePrincipals"

Write-Host ""
Write-Host "Principal Types:" -ForegroundColor Cyan
Write-Host "  User Assignments                : $UserAssignments"
Write-Host "  Unique Privileged Users         : $UniquePrivilegedUsers"
Write-Host "  Group Assignments               : $GroupAssignments"
Write-Host "  Service Principal Assignments   : $ServicePrincipalAssignments"
Write-Host "  Other Assignments               : $OtherAssignments"
Write-Host "  Unresolved Assignments          : $UnresolvedAssignments"

Write-Host ""
Write-Host "User Governance Findings:" -ForegroundColor Cyan
Write-Host "  Active Privileged               : $ActivePrivileged"
Write-Host "  Inactive Privileged             : $InactivePrivileged"
Write-Host "  Never-Signed-In Privileged      : $NeverSignedInPrivileged"
Write-Host "  Disabled Privileged             : $DisabledPrivileged"
Write-Host "  Expired + Enabled Privileged    : $ExpiredEnabledPrivileged"

Write-Host ""
Write-Host "Non-User Privileged Principals    : $NonUserPrincipals"

Write-Host ""
Write-Host "Governance Priority:" -ForegroundColor Cyan
Write-Host "  Critical                        : $CriticalCandidates"
Write-Host "  High                            : $HighCandidates"
Write-Host "  Review                          : $ReviewCandidates"

Write-Host ""
Write-Host "Governance Candidates              : $GovernanceCandidates"

Write-Host ""
Write-Host "Report:" -ForegroundColor Green
Write-Host $OutputPath -ForegroundColor Green

Write-Host ""
Write-Host "Classification:" -ForegroundColor Cyan
Write-Host "  PrivilegedActive"
Write-Host "      Enabled privileged user with recent activity"
Write-Host ""
Write-Host "  PrivilegedInactive"
Write-Host "      No successful sign-in within configured threshold"
Write-Host ""
Write-Host "  PrivilegedNeverSignedIn"
Write-Host "      No successful sign-in recorded"
Write-Host ""
Write-Host "  PrivilegedDisabled"
Write-Host "      Privileged role assigned to disabled user"
Write-Host ""
Write-Host "  PrivilegedExpiredEnabled"
Write-Host "      Privileged account remains enabled after leave date"
Write-Host ""
Write-Host "  PrivilegedNonUserPrincipal"
Write-Host "      Privileged role assigned to group/service principal/other object"
Write-Host ""
Write-Host "  PrivilegedUnresolvedPrincipal"
Write-Host "      Role assignment references an unresolved directory object"

Write-Host ""
Write-Host "This script is READ-ONLY." -ForegroundColor Yellow
Write-Host "No role assignments were modified." -ForegroundColor Green
Write-Host "No accounts were enabled or disabled." -ForegroundColor Green
Write-Host ""
Write-Host "Script completed successfully." -ForegroundColor Green
Write-Host ""