<#
.SYNOPSIS
    Writes and manages Entra ID governance remediation audit events.

.DESCRIPTION
    Centralized audit logging for the Entra ID User Governance Toolkit.

    Supports:
      - Writing audit events
      - Viewing audit events
      - Clearing the audit log with confirmation
      - Automatic EventId generation
      - Windows user, computer and Graph tenant context
      - Preservation of existing audit records

.NOTES
    Version : 1.0.0
    Author  : Entra ID User Governance Toolkit

    This script does NOT modify Entra ID objects.
#>

[CmdletBinding()]
param(
    [ValidateSet("Write","Show","Clear")]
    [string]$Mode = "Write",

    [string]$Action,

    [string]$UserId,

    [string]$DisplayName,

    [string]$UserPrincipalName,

    [string]$EmployeeLeaveDate,

    [string]$PreviousAccountStatus,

    [string]$NewAccountStatus,

    [ValidateSet(
        "Success",
        "Failed",
        "Skipped",
        "Cancelled",
        "WhatIf"
    )]
    [string]$Result,

    [string]$Details,

    [string]$PerformedBy,

    [string]$WindowsUser,

    [string]$ComputerName,

    [string]$TenantId,

    [string]$NotificationStatus = "NotSent",

    [string]$NotificationTimestamp,

    [switch]$ShowLog,

    [switch]$ClearLog
)

$ErrorActionPreference = "Stop"

# ============================================================
# CONFIGURATION
# ============================================================

$ScriptRoot = Split-Path -Parent $PSScriptRoot

$LogsPath = Join-Path `
    $ScriptRoot `
    "Logs"

$AuditLogPath = Join-Path `
    $LogsPath `
    "EntraGovernanceAudit.csv"

# ============================================================
# AUDIT SCHEMA
# ============================================================

$AuditColumns = @(
    "EventId",
    "Timestamp",
    "Action",
    "UserId",
    "DisplayName",
    "UserPrincipalName",
    "EmployeeLeaveDate",
    "PreviousAccountStatus",
    "NewAccountStatus",
    "Result",
    "Details",
    "PerformedBy",
    "WindowsUser",
    "ComputerName",
    "TenantId",
    "NotificationStatus",
    "NotificationTimestamp"
)

# ============================================================
# INITIALIZE LOG DIRECTORY
# ============================================================

if (-not (Test-Path -LiteralPath $LogsPath)) {

    New-Item `
        -Path $LogsPath `
        -ItemType Directory `
        -Force |
        Out-Null
}

# ============================================================
# GET WINDOWS IDENTITY
# ============================================================

function Get-CurrentWindowsUser {

    try {

        return [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    }
    catch {

        return $env:USERNAME
    }
}

# ============================================================
# GET COMPUTER NAME
# ============================================================

function Get-CurrentComputerName {

    if (-not [string]::IsNullOrWhiteSpace($env:COMPUTERNAME)) {

        return $env:COMPUTERNAME
    }

    return [System.Net.Dns]::GetHostName()
}

# ============================================================
# GET GRAPH CONTEXT
# ============================================================

function Get-CurrentGraphContext {

    try {

        if (Get-Command Get-MgContext -ErrorAction SilentlyContinue) {

            $Context = Get-MgContext `
                -ErrorAction SilentlyContinue

            if ($null -ne $Context) {

                return $Context
            }
        }
    }
    catch {

        # Graph context is optional.
    }

    return $null
}

# ============================================================
# INITIALIZE AUDIT LOG
# ============================================================

function Initialize-AuditLog {

    if (-not (Test-Path -LiteralPath $AuditLogPath)) {

        $HeaderObject = [ordered]@{}

        foreach ($Column in $AuditColumns) {

            $HeaderObject[$Column] = $null
        }

        [PSCustomObject]$HeaderObject |
            Export-Csv `
                -Path $AuditLogPath `
                -NoTypeInformation `
                -Encoding UTF8

        return
    }

    # --------------------------------------------------------
    # Validate existing schema
    # --------------------------------------------------------

    try {

        $ExistingRows = @(
            Import-Csv `
                -Path $AuditLogPath `
                -ErrorAction Stop
        )

        if ($ExistingRows.Count -gt 0) {

            $ExistingColumns = @(
                $ExistingRows[0].PSObject.Properties.Name
            )

            $MissingColumns = @(
                $AuditColumns |
                Where-Object {
                    $_ -notin $ExistingColumns
                }
            )

            if ($MissingColumns.Count -gt 0) {

                Write-Warning `
                    "Audit log is missing columns: $($MissingColumns -join ', ')"
            }
        }
    }
    catch {

        Write-Warning `
            "Existing audit log could not be validated: $($_.Exception.Message)"
    }
}

# ============================================================
# SHOW AUDIT LOG
# ============================================================

function Show-AuditLog {

    Initialize-AuditLog

    $Rows = @(
        Import-Csv `
            -Path $AuditLogPath `
            -ErrorAction Stop
    )

    Write-Host ""

    Write-Host `
        "=============================================" `
        -ForegroundColor Cyan

    Write-Host `
        " Entra Governance Audit Log" `
        -ForegroundColor Cyan

    Write-Host `
        "=============================================" `
        -ForegroundColor Cyan

    Write-Host ""

    Write-Host `
        "Log file:" `
        -ForegroundColor Gray

    Write-Host `
        $AuditLogPath `
        -ForegroundColor Gray

    Write-Host ""

    if ($Rows.Count -eq 0) {

        Write-Host `
            "No audit events have been recorded." `
            -ForegroundColor Yellow

        return
    }

    Write-Host `
        "Total audit events: $($Rows.Count)" `
        -ForegroundColor Green

    Write-Host ""

    $Rows |
        Select-Object `
            EventId,
            Timestamp,
            Action,
            UserPrincipalName,
            Result,
            PerformedBy |
        Format-Table -AutoSize

    Write-Host ""
}

# ============================================================
# CLEAR AUDIT LOG
# ============================================================

function Clear-AuditLog {

    Initialize-AuditLog

    Write-Host ""

    Write-Host `
        "=============================================" `
        -ForegroundColor Red

    Write-Host `
        " CLEAR AUDIT LOG" `
        -ForegroundColor Red

    Write-Host `
        "=============================================" `
        -ForegroundColor Red

    Write-Host ""

    Write-Host `
        "This will remove all existing audit events." `
        -ForegroundColor Yellow

    Write-Host ""

    Write-Host `
        "A backup will be created before clearing." `
        -ForegroundColor Gray

    Write-Host ""

    $Confirmation = Read-Host `
        "Type CLEAR to continue"

    if ($Confirmation -cne "CLEAR") {

        Write-Host ""

        Write-Host `
            "Operation cancelled. Audit log was not changed." `
            -ForegroundColor Yellow

        return
    }

    $BackupPath = Join-Path `
        $LogsPath `
        (
            "EntraGovernanceAudit_Backup_{0}.csv" -f `
            (Get-Date -Format "yyyyMMdd_HHmmss")
        )

    Copy-Item `
        -Path $AuditLogPath `
        -Destination $BackupPath `
        -Force

    $HeaderObject = [ordered]@{}

    foreach ($Column in $AuditColumns) {

        $HeaderObject[$Column] = $null
    }

    [PSCustomObject]$HeaderObject |
        Export-Csv `
            -Path $AuditLogPath `
            -NoTypeInformation `
            -Encoding UTF8

    Write-Host ""

    Write-Host `
        "Audit log cleared successfully." `
        -ForegroundColor Green

    Write-Host `
        "Backup created:" `
        -ForegroundColor Gray

    Write-Host `
        $BackupPath `
        -ForegroundColor Gray

    Write-Host ""
}

# ============================================================
# WRITE AUDIT EVENT
# ============================================================

function Write-AuditEvent {

    Initialize-AuditLog

    $Context = Get-CurrentGraphContext

    # --------------------------------------------------------
    # Automatic context
    # --------------------------------------------------------

    if ([string]::IsNullOrWhiteSpace($PerformedBy)) {

        if (
            $null -ne $Context -and
            -not [string]::IsNullOrWhiteSpace($Context.Account)
        ) {

            $PerformedBy = $Context.Account
        }
        else {

            $PerformedBy = Get-CurrentWindowsUser
        }
    }

    if ([string]::IsNullOrWhiteSpace($WindowsUser)) {

        $WindowsUser = Get-CurrentWindowsUser
    }

    if ([string]::IsNullOrWhiteSpace($ComputerName)) {

        $ComputerName = Get-CurrentComputerName
    }

    if ([string]::IsNullOrWhiteSpace($TenantId)) {

        if ($null -ne $Context) {

            $TenantId = $Context.TenantId
        }
    }

    if ([string]::IsNullOrWhiteSpace($NotificationStatus)) {

        $NotificationStatus = "NotSent"
    }

    # --------------------------------------------------------
    # Generate event information
    # --------------------------------------------------------

    $EventId = [guid]::NewGuid().ToString()

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # --------------------------------------------------------
    # Build audit record
    # --------------------------------------------------------

    $AuditEvent = [PSCustomObject][ordered]@{

        EventId                 = $EventId

        Timestamp               = $Timestamp

        Action                  = $Action

        UserId                  = $UserId

        DisplayName             = $DisplayName

        UserPrincipalName       = $UserPrincipalName

        EmployeeLeaveDate       = $EmployeeLeaveDate

        PreviousAccountStatus   = $PreviousAccountStatus

        NewAccountStatus        = $NewAccountStatus

        Result                  = $Result

        Details                 = $Details

        PerformedBy             = $PerformedBy

        WindowsUser             = $WindowsUser

        ComputerName            = $ComputerName

        TenantId                = $TenantId

        NotificationStatus      = $NotificationStatus

        NotificationTimestamp   = $NotificationTimestamp
    }

    # --------------------------------------------------------
    # Append event
    # --------------------------------------------------------

    $AuditEvent |
        Export-Csv `
            -Path $AuditLogPath `
            -NoTypeInformation `
            -Append `
            -Encoding UTF8

    Write-Host ""

    Write-Host `
        "Audit event recorded." `
        -ForegroundColor Green

    Write-Host `
        "Event ID : $EventId" `
        -ForegroundColor Gray

    Write-Host `
        "Action   : $Action" `
        -ForegroundColor Gray

    Write-Host `
        "Result   : $Result" `
        -ForegroundColor Gray

    Write-Host `
        "Log      : $AuditLogPath" `
        -ForegroundColor Gray

    Write-Host ""
}

# ============================================================
# MAIN
# ============================================================

try {

    # --------------------------------------------------------
    # CLEAR
    # --------------------------------------------------------

    if ($ClearLog) {

        Clear-AuditLog
        return
    }

    # --------------------------------------------------------
    # SHOW
    # --------------------------------------------------------

    if ($ShowLog) {

        Show-AuditLog
        return
    }

    # --------------------------------------------------------
    # MODE
    # --------------------------------------------------------

    switch ($Mode) {

        "Show" {

            Show-AuditLog
            return
        }

        "Clear" {

            Clear-AuditLog
            return
        }

        "Write" {

            if (
                [string]::IsNullOrWhiteSpace($Action) -and
                [string]::IsNullOrWhiteSpace($Details)
            ) {

                Write-Host ""

                Write-Host `
                    "No audit event information was supplied." `
                    -ForegroundColor Yellow

                Write-Host ""

                Write-Host `
                    "Use -ShowLog to view the audit log." `
                    -ForegroundColor Gray

                return
            }

            Write-AuditEvent
            return
        }
    }
}
catch {

    Write-Host ""

    Write-Host `
        "=============================================" `
        -ForegroundColor Red

    Write-Host `
        " Audit Logging Failed" `
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