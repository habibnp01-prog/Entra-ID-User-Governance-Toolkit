#requires -Version 5.1

<#
.SYNOPSIS
    Identifies potentially excessive Microsoft Entra ID group memberships.

.DESCRIPTION
    Retrieves direct group memberships for Entra ID users and identifies
    users whose direct group membership count exceeds configurable
    governance thresholds.

    The script also identifies:

        - Security-enabled groups
        - Microsoft 365 groups
        - Distribution groups
        - Dynamic groups
        - Mail-enabled groups
        - Privileged users with group memberships
        - Unresolved directory objects

    The script is READ-ONLY.

    No group memberships are added or removed.

.PARAMETER ReviewThreshold
    Number of direct group memberships at which a user becomes a
    governance review candidate.

    Default:
        10

.PARAMETER HighThreshold
    Number of direct group memberships at which a user receives
    High governance priority.

    Default:
        20

.PARAMETER CriticalThreshold
    Number of direct group memberships at which a user receives
    Critical governance priority.

    Default:
        30

.EXAMPLE
    .\08-Find-ExcessiveGroupMembership.ps1

.EXAMPLE
    .\08-Find-ExcessiveGroupMembership.ps1 -ReviewThreshold 5

.EXAMPLE
    .\08-Find-ExcessiveGroupMembership.ps1 `
        -ReviewThreshold 10 `
        -HighThreshold 20 `
        -CriticalThreshold 30

.NOTES
    Project:
        Entra ID User Governance Toolkit

    Script:
        08-Find-ExcessiveGroupMembership.ps1

    Version:
        1.0.0

    Required Graph modules:
        Microsoft.Graph.Authentication
        Microsoft.Graph.Users
        Microsoft.Graph.Groups

    Required Graph permissions:
        User.Read.All
        Group.Read.All
        Directory.Read.All

    Action:
        Read-only
#>

[CmdletBinding()]
param(

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 1000)]
    [int]$ReviewThreshold = 10,

    [Parameter(Mandatory = $false)]
    [ValidateRange(2, 1000)]
    [int]$HighThreshold = 20,

    [Parameter(Mandatory = $false)]
    [ValidateRange(3, 1000)]
    [int]$CriticalThreshold = 30
)

$ErrorActionPreference = "Stop"

# ============================================================
# VALIDATE THRESHOLDS
# ============================================================

if ($HighThreshold -le $ReviewThreshold) {

    throw "HighThreshold must be greater than ReviewThreshold."
}

if ($CriticalThreshold -le $HighThreshold) {

    throw "CriticalThreshold must be greater than HighThreshold."
}

# ============================================================
# PROJECT PATH
# ============================================================

$ProjectRoot = Split-Path -Parent $PSScriptRoot

$ReportsPath = Join-Path `
    $ProjectRoot `
    "Reports"

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
Write-Host " 08 - Find Excessive Group Membership" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Governance thresholds:" -ForegroundColor Yellow
Write-Host "  Review    : $ReviewThreshold direct groups"
Write-Host "  High      : $HighThreshold direct groups"
Write-Host "  Critical  : $CriticalThreshold direct groups"
Write-Host ""

# ============================================================
# MODULE PATH
# ============================================================

$PrimaryModulePath = Join-Path `
    $HOME `
    "Documents\PowerShell\Modules"

if (Test-Path $PrimaryModulePath) {

    $env:PSModulePath = "$PrimaryModulePath;$env:PSModulePath"
}

# ============================================================
# REQUIRED MODULES
# ============================================================

Write-Host "[1/8] Checking Microsoft Graph modules..." -ForegroundColor Yellow

$RequiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Users",
    "Microsoft.Graph.Groups"
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

    Write-Host `
        "  $ModuleName : $($AvailableModule.Version)" `
        -ForegroundColor Green

    Import-Module `
        -Name $AvailableModule.Path `
        -Force `
        -ErrorAction Stop
}

# ============================================================
# GRAPH CONNECTION
# ============================================================

Write-Host ""
Write-Host "[2/8] Checking Microsoft Graph connection..." -ForegroundColor Yellow

$RequiredScopes = @(
    "User.Read.All",
    "Group.Read.All",
    "Directory.Read.All"
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

    Write-Host `
        "Existing Graph session has the required scopes." `
        -ForegroundColor Green
}

$Context = Get-MgContext

if (-not $Context) {

    throw "Microsoft Graph connection could not be established."
}

Write-Host "  Account : $($Context.Account)" -ForegroundColor Green
Write-Host "  Tenant  : $($Context.TenantId)" -ForegroundColor Green

# ============================================================
# LOAD USERS
# ============================================================

Write-Host ""
Write-Host "[3/8] Loading Entra users..." -ForegroundColor Yellow

$Users = @(
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
            "employeeId",
            "employeeLeaveDateTime"
        )
)

Write-Host "Users loaded: $($Users.Count)" -ForegroundColor Green

if ($Users.Count -eq 0) {

    Write-Host ""
    Write-Host "No Entra users were returned." -ForegroundColor Yellow
    exit 0
}

# ============================================================
# BUILD GROUP CACHE
# ============================================================

Write-Host ""
Write-Host "[4/8] Loading Entra groups..." -ForegroundColor Yellow

$Groups = @(
    Get-MgGroup `
        -All `
        -Property @(
            "id",
            "displayName",
            "description",
            "mail",
            "mailEnabled",
            "securityEnabled",
            "groupTypes",
            "membershipRule",
            "membershipRuleProcessingState"
        )
)

Write-Host "Groups loaded: $($Groups.Count)" -ForegroundColor Green

$GroupLookup = @{}

foreach ($Group in $Groups) {

    if ($Group.Id) {

        $GroupLookup[$Group.Id] = $Group
    }
}

# ============================================================
# HELPER: GROUP TYPE
# ============================================================

function Get-GroupType {

    param(
        [Parameter(Mandatory = $true)]
        $Group
    )

    $GroupTypes = @($Group.GroupTypes)

    $IsDynamic = (
        $GroupTypes -contains "DynamicMembership"
    )

    $IsUnified = (
        $GroupTypes -contains "Unified"
    )

    $IsMailEnabled = (
        $Group.MailEnabled -eq $true
    )

    $IsSecurityEnabled = (
        $Group.SecurityEnabled -eq $true
    )

    if ($IsDynamic -and $IsUnified) {

        return "DynamicMicrosoft365Group"
    }

    if ($IsDynamic -and $IsSecurityEnabled) {

        return "DynamicSecurityGroup"
    }

    if ($IsUnified) {

        return "Microsoft365Group"
    }

    if ($IsSecurityEnabled -and $IsMailEnabled) {

        return "MailEnabledSecurityGroup"
    }

    if ($IsSecurityEnabled) {

        return "SecurityGroup"
    }

    if ($IsMailEnabled) {

        return "DistributionGroup"
    }

    return "OtherGroup"
}

# ============================================================
# PROCESS USERS
# ============================================================

Write-Host ""
Write-Host "[5/8] Analyzing direct group memberships..." -ForegroundColor Yellow

$Results = New-Object System.Collections.Generic.List[object]

$UserIndex = 0

foreach ($User in $Users) {

    $UserIndex++

    Write-Progress `
        -Activity "Analyzing Entra group memberships" `
        -Status "$($UserIndex) / $($Users.Count) - $($User.DisplayName)" `
        -PercentComplete (
            ($UserIndex / $Users.Count) * 100
        )

    $Memberships = @()

    try {

        $Memberships = @(
            Get-MgUserMemberOf `
                -UserId $User.Id `
                -All `
                -ErrorAction Stop
        )
    }
    catch {

        Write-Warning `
            "Unable to retrieve memberships for $($User.UserPrincipalName): $($_.Exception.Message)"

        $Results.Add(
            [PSCustomObject]@{

                UserId                       = $User.Id

                DisplayName                  = $User.DisplayName

                UserPrincipalName            = $User.UserPrincipalName

                Mail                         = $User.Mail

                AccountEnabled               = $User.AccountEnabled

                UserType                     = $User.UserType

                Department                   = $User.Department

                JobTitle                     = $User.JobTitle

                EmployeeId                   = $User.EmployeeId

                DirectGroupCount             = 0

                SecurityGroupCount           = 0

                Microsoft365GroupCount       = 0

                DistributionGroupCount       = 0

                DynamicGroupCount            = 0

                OtherGroupCount              = 0

                GroupMembershipsRetrieved    = $false

                ResolutionStatus             = "Failed"

                GovernanceCategory           = "MembershipRetrievalFailed"

                GovernancePriority           = "High"

                GovernanceCandidate          = $true

                Reason                       =
                    "Unable to retrieve direct group memberships."

                GroupNames                   = ""

                GroupIds                     = ""
            }
        )

        continue
    }

    # --------------------------------------------------------
    # Resolve only group objects
    # --------------------------------------------------------

    $UserGroups = New-Object System.Collections.Generic.List[object]

    foreach ($Membership in $Memberships) {

        if (-not $Membership.Id) {

            continue
        }

        $GroupId = $Membership.Id

        if ($GroupLookup.ContainsKey($GroupId)) {

            $UserGroups.Add(
                $GroupLookup[$GroupId]
            )

            continue
        }

        # ----------------------------------------------------
        # Fallback generic directory object resolution
        # ----------------------------------------------------

        try {

            $Uri =
                "https://graph.microsoft.com/v1.0/directoryObjects/$GroupId"

            $DirectoryObject = Invoke-MgGraphRequest `
                -Method GET `
                -Uri $Uri `
                -OutputType PSObject

            if (
                $DirectoryObject.'@odata.type' -eq
                "#microsoft.graph.group"
            ) {

                $UserGroups.Add(
                    $DirectoryObject
                )
            }
        }
        catch {

            # Do not fail the entire user because one membership
            # cannot be resolved.
            continue
        }
    }

    # --------------------------------------------------------
    # GROUP COUNTS
    # --------------------------------------------------------

    $DirectGroupCount = $UserGroups.Count

    $SecurityGroupCount = @(
        $UserGroups |
        Where-Object {
            $_.SecurityEnabled -eq $true
        }
    ).Count

    $Microsoft365GroupCount = @(
        $UserGroups |
        Where-Object {
            @($_.GroupTypes) -contains "Unified"
        }
    ).Count

    $DistributionGroupCount = @(
        $UserGroups |
        Where-Object {
            $_.MailEnabled -eq $true -and
            $_.SecurityEnabled -ne $true -and
            @($_.GroupTypes) -notcontains "Unified"
        }
    ).Count

    $DynamicGroupCount = @(
        $UserGroups |
        Where-Object {
            @($_.GroupTypes) -contains "DynamicMembership"
        }
    ).Count

    $OtherGroupCount =
        $DirectGroupCount -
        (
            $SecurityGroupCount +
            $Microsoft365GroupCount +
            $DistributionGroupCount
        )

    if ($OtherGroupCount -lt 0) {

        $OtherGroupCount = 0
    }

    # --------------------------------------------------------
    # GROUP NAMES / IDS
    # --------------------------------------------------------

    $GroupNames = @(
        $UserGroups |
        ForEach-Object {
            $_.DisplayName
        } |
        Where-Object {
            -not [string]::IsNullOrWhiteSpace($_)
        } |
        Sort-Object
    )

    $GroupIds = @(
        $UserGroups |
        ForEach-Object {
            $_.Id
        } |
        Where-Object {
            -not [string]::IsNullOrWhiteSpace($_)
        } |
        Sort-Object
    )

    # --------------------------------------------------------
    # GOVERNANCE CLASSIFICATION
    # --------------------------------------------------------

    $GovernanceCategory = "NormalGroupMembership"

    $GovernancePriority = "None"

    $GovernanceCandidate = $false

    $Reason = "Group membership count is below the configured review threshold."

    if ($DirectGroupCount -ge $CriticalThreshold) {

        $GovernanceCategory =
            "ExcessiveGroupMembershipCritical"

        $GovernancePriority = "Critical"

        $GovernanceCandidate = $true

        $Reason =
            "User has $DirectGroupCount direct group memberships, exceeding the critical threshold of $CriticalThreshold."
    }

    elseif ($DirectGroupCount -ge $HighThreshold) {

        $GovernanceCategory =
            "ExcessiveGroupMembershipHigh"

        $GovernancePriority = "High"

        $GovernanceCandidate = $true

        $Reason =
            "User has $DirectGroupCount direct group memberships, exceeding the high threshold of $HighThreshold."
    }

    elseif ($DirectGroupCount -ge $ReviewThreshold) {

        $GovernanceCategory =
            "ExcessiveGroupMembershipReview"

        $GovernancePriority = "Review"

        $GovernanceCandidate = $true

        $Reason =
            "User has $DirectGroupCount direct group memberships, exceeding the review threshold of $ReviewThreshold."
    }

    # --------------------------------------------------------
    # SPECIAL CASE: NO GROUP MEMBERSHIPS
    # --------------------------------------------------------

    if ($DirectGroupCount -eq 0) {

        $GovernanceCategory =
            "NoDirectGroupMembership"

        $GovernancePriority = "None"

        $GovernanceCandidate = $false

        $Reason =
            "User has no direct group memberships."
    }

    # --------------------------------------------------------
    # RESULT
    # --------------------------------------------------------

    $Results.Add(
        [PSCustomObject]@{

            UserId                       = $User.Id

            DisplayName                  = $User.DisplayName

            UserPrincipalName            = $User.UserPrincipalName

            Mail                         = $User.Mail

            AccountEnabled               = $User.AccountEnabled

            UserType                     = $User.UserType

            Department                   = $User.Department

            JobTitle                     = $User.JobTitle

            EmployeeId                   = $User.EmployeeId

            DirectGroupCount             = $DirectGroupCount

            SecurityGroupCount           = $SecurityGroupCount

            Microsoft365GroupCount       = $Microsoft365GroupCount

            DistributionGroupCount       = $DistributionGroupCount

            DynamicGroupCount            = $DynamicGroupCount

            OtherGroupCount              = $OtherGroupCount

            GroupMembershipsRetrieved    = $true

            ResolutionStatus             = "Resolved"

            GovernanceCategory           = $GovernanceCategory

            GovernancePriority           = $GovernancePriority

            GovernanceCandidate          = $GovernanceCandidate

            Reason                       = $Reason

            GroupNames                   = (
                $GroupNames -join "; "
            )

            GroupIds                     = (
                $GroupIds -join "; "
            )
        }
    )
}

Write-Progress `
    -Activity "Analyzing Entra group memberships" `
    -Completed

# ============================================================
# EXPORT DETAILED REPORT
# ============================================================

Write-Host ""
Write-Host "[6/8] Generating group-membership governance report..." -ForegroundColor Yellow

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

$OutputPath = Join-Path `
    $ReportsPath `
    "ExcessiveGroupMembership_$Timestamp.csv"

$Results |
    Export-Csv `
        -Path $OutputPath `
        -NoTypeInformation `
        -Encoding UTF8

# ============================================================
# SUMMARY
# ============================================================

Write-Host ""
Write-Host "[7/8] Calculating governance summary..." -ForegroundColor Yellow

$TotalUsers = $Results.Count

$SuccessfulUsers = @(
    $Results |
    Where-Object {
        $_.GroupMembershipsRetrieved -eq $true
    }
).Count

$FailedUsers = @(
    $Results |
    Where-Object {
        $_.GroupMembershipsRetrieved -ne $true
    }
).Count

$UsersWithGroups = @(
    $Results |
    Where-Object {
        $_.DirectGroupCount -gt 0
    }
).Count

$UsersWithNoGroups = @(
    $Results |
    Where-Object {
        $_.DirectGroupCount -eq 0
    }
).Count

$ReviewCandidates = @(
    $Results |
    Where-Object {
        $_.GovernancePriority -eq "Review"
    }
).Count

$HighCandidates = @(
    $Results |
    Where-Object {
        $_.GovernancePriority -eq "High"
    }
).Count

$CriticalCandidates = @(
    $Results |
    Where-Object {
        $_.GovernancePriority -eq "Critical"
    }
).Count

$GovernanceCandidates = @(
    $Results |
    Where-Object {
        $_.GovernanceCandidate -eq $true
    }
).Count

$TotalDirectMemberships = (
    $Results |
    Measure-Object `
        -Property DirectGroupCount `
        -Sum
).Sum

$AverageMemberships = 0

if ($SuccessfulUsers -gt 0) {

    $AverageMemberships = [math]::Round(
        (
            $TotalDirectMemberships /
            $SuccessfulUsers
        ),
        2
    )
}

$MaximumMemberships = 0

if ($Results.Count -gt 0) {

    $MaximumMemberships = (
        $Results |
        Measure-Object `
            -Property DirectGroupCount `
            -Maximum
    ).Maximum
}

$SecurityMemberships = (
    $Results |
    Measure-Object `
        -Property SecurityGroupCount `
        -Sum
).Sum

$Microsoft365Memberships = (
    $Results |
    Measure-Object `
        -Property Microsoft365GroupCount `
        -Sum
).Sum

$DistributionMemberships = (
    $Results |
    Measure-Object `
        -Property DistributionGroupCount `
        -Sum
).Sum

$DynamicMemberships = (
    $Results |
    Measure-Object `
        -Property DynamicGroupCount `
        -Sum
).Sum

# ============================================================
# DISPLAY SUMMARY
# ============================================================

Write-Host ""
Write-Host "[8/8] Analysis completed." -ForegroundColor Yellow
Write-Host ""

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " Group Membership Governance Summary" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

Write-Host "Total Users                     : $TotalUsers"
Write-Host "Memberships Retrieved           : $SuccessfulUsers"
Write-Host "Membership Retrieval Failures   : $FailedUsers"

Write-Host ""
Write-Host "Membership Statistics:" -ForegroundColor Cyan
Write-Host "  Users With Direct Groups      : $UsersWithGroups"
Write-Host "  Users With No Direct Groups   : $UsersWithNoGroups"
Write-Host "  Total Direct Memberships      : $TotalDirectMemberships"
Write-Host "  Average Per User              : $AverageMemberships"
Write-Host "  Maximum Per User              : $MaximumMemberships"

Write-Host ""
Write-Host "Group Membership Types:" -ForegroundColor Cyan
Write-Host "  Security Group Memberships    : $SecurityMemberships"
Write-Host "  Microsoft 365 Groups          : $Microsoft365Memberships"
Write-Host "  Distribution Groups           : $DistributionMemberships"
Write-Host "  Dynamic Group Memberships     : $DynamicMemberships"

Write-Host ""
Write-Host "Governance Priority:" -ForegroundColor Cyan
Write-Host "  Critical                      : $CriticalCandidates"
Write-Host "  High                          : $HighCandidates"
Write-Host "  Review                        : $ReviewCandidates"

Write-Host ""
Write-Host "Governance Candidates           : $GovernanceCandidates"

Write-Host ""
Write-Host "Thresholds:" -ForegroundColor Cyan
Write-Host "  Review                        : $ReviewThreshold"
Write-Host "  High                          : $HighThreshold"
Write-Host "  Critical                      : $CriticalThreshold"

Write-Host ""
Write-Host "Report:" -ForegroundColor Green
Write-Host $OutputPath -ForegroundColor Green

Write-Host ""
Write-Host "Classification:" -ForegroundColor Cyan

Write-Host "  NormalGroupMembership"
Write-Host "      User is below the review threshold."

Write-Host ""
Write-Host "  ExcessiveGroupMembershipReview"
Write-Host "      User has reached the review threshold."

Write-Host ""
Write-Host "  ExcessiveGroupMembershipHigh"
Write-Host "      User has reached the high threshold."

Write-Host ""
Write-Host "  ExcessiveGroupMembershipCritical"
Write-Host "      User has reached the critical threshold."

Write-Host ""
Write-Host "  MembershipRetrievalFailed"
Write-Host "      Group membership retrieval failed and requires review."

Write-Host ""
Write-Host "This script is READ-ONLY." -ForegroundColor Yellow
Write-Host "No users were removed from groups." -ForegroundColor Green
Write-Host "No group memberships were modified." -ForegroundColor Green
Write-Host ""
Write-Host "Script completed successfully." -ForegroundColor Green
Write-Host ""