@'
#requires -Version 5.1

<#
.SYNOPSIS
    Interactive launcher for the Entra ID User Governance Toolkit.

.DESCRIPTION
    Provides a central menu for running the toolkit's discovery,
    review, remediation, audit and reporting components.

    This launcher does not contain governance logic itself.
    It starts the existing toolkit scripts.

.NOTES
    Version : 1.0.0
    Author  : Entra ID User Governance Toolkit

    The launcher does not directly modify Microsoft Entra ID.
    Any modification is performed only by the selected remediation workflow.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

$Scripts = @{
    DiscoveryUsers      = Join-Path $ScriptRoot '01-Get-EntraUsers.ps1'
    InactiveUsers       = Join-Path $ScriptRoot '02-Find-InactiveUsers.ps1'
    ExpiredUsers        = Join-Path $ScriptRoot '03-Find-ExpiredUsers.ps1'
    GuestUsers          = Join-Path $ScriptRoot '04-Find-GuestUsers.ps1'
    DisabledUsers       = Join-Path $ScriptRoot '05-Find-DisabledUsers.ps1'
    LicensedUsers       = Join-Path $ScriptRoot '06-Find-LicensedUsers.ps1'
    PrivilegedUsers     = Join-Path $ScriptRoot '07-Find-PrivilegedUsers.ps1'
    GroupMembership     = Join-Path $ScriptRoot '08-Find-ExcessiveGroupMembership.ps1'
    Review              = Join-Path $ScriptRoot '09-Review-Users.ps1'
    Remediation         = Join-Path $ScriptRoot '10-Remediate-Users.ps1'
    AuditLog            = Join-Path $ScriptRoot '11-Write-AuditLog.ps1'
    GovernanceReport    = Join-Path $ScriptRoot '12-Export-GovernanceReport.ps1'
}

function Show-Menu {
    Clear-Host

    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host '        Entra ID User Governance Toolkit' -ForegroundColor Cyan
    Write-Host '============================================================' -ForegroundColor Cyan
    Write-Host ''
    Write-Host 'Discovery'
    Write-Host '  1. Run user discovery'
    Write-Host '  2. Run all governance discovery checks'
    Write-Host ''
    Write-Host 'Review & Remediation'
    Write-Host '  3. Open governance review'
    Write-Host '  4. Open controlled remediation'
    Write-Host ''
    Write-Host 'Audit & Reporting'
    Write-Host '  5. View audit log'
    Write-Host '  6. Export governance report'
    Write-Host ''
    Write-Host 'Complete Workflow'
    Write-Host '  7. Run complete read-only assessment'
    Write-Host ''
    Write-Host '  0. Exit'
    Write-Host ''
}

function Test-ScriptPath {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Write-Host ''
        Write-Host "Script not found: $Path" -ForegroundColor Red
        return $false
    }

    return $true
}

function Invoke-ToolkitScript {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-ScriptPath -Path $Path)) {
        return
    }

    Write-Host ''
    Write-Host "Starting: $(Split-Path $Path -Leaf)" -ForegroundColor Cyan
    Write-Host ''

    & $Path

    Write-Host ''
    Write-Host 'Script execution completed.' -ForegroundColor Green
    Read-Host 'Press Enter to continue'
}

function Invoke-DiscoverySuite {
    $DiscoveryScripts = @(
        $Scripts.DiscoveryUsers
        $Scripts.InactiveUsers
        $Scripts.ExpiredUsers
        $Scripts.GuestUsers
        $Scripts.DisabledUsers
        $Scripts.LicensedUsers
        $Scripts.PrivilegedUsers
        $Scripts.GroupMembership
    )

    foreach ($scriptPath in $DiscoveryScripts) {
        if (-not (Test-ScriptPath -Path $scriptPath)) {
            return
        }
    }

    foreach ($scriptPath in $DiscoveryScripts) {
        Write-Host ''
        Write-Host '============================================================' -ForegroundColor DarkCyan
        Write-Host "Running $(Split-Path $scriptPath -Leaf)" -ForegroundColor Cyan
        Write-Host '============================================================' -ForegroundColor DarkCyan
        Write-Host ''

        & $scriptPath

        if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
            Write-Host ''
            Write-Host "The script returned exit code $LASTEXITCODE." -ForegroundColor Yellow
        }
    }

    Write-Host ''
    Write-Host 'All governance discovery checks have completed.' -ForegroundColor Green
    Read-Host 'Press Enter to continue'
}

function Invoke-ReadOnlyAssessment {
    Invoke-DiscoverySuite

    if (Test-ScriptPath -Path $Scripts.Review) {
        Write-Host ''
        Write-Host 'Opening governance review...' -ForegroundColor Cyan
        Write-Host ''

        & $Scripts.Review

        Write-Host ''
        Read-Host 'Press Enter to continue'
    }
}

do {
    Show-Menu

    $Choice = Read-Host 'Select an option'

    switch ($Choice) {

        '1' {
            Invoke-ToolkitScript -Path $Scripts.DiscoveryUsers
        }

        '2' {
            Invoke-DiscoverySuite
        }

        '3' {
            Invoke-ToolkitScript -Path $Scripts.Review
        }

        '4' {
            Invoke-ToolkitScript -Path $Scripts.Remediation
        }

        '5' {
            if (Test-ScriptPath -Path $Scripts.AuditLog) {
                & $Scripts.AuditLog -Mode Show
                Write-Host ''
                Read-Host 'Press Enter to continue'
            }
        }

        '6' {
            Invoke-ToolkitScript -Path $Scripts.GovernanceReport
        }

        '7' {
            Invoke-ReadOnlyAssessment
        }

        '0' {
            Write-Host ''
            Write-Host 'Exiting Entra ID User Governance Toolkit.' -ForegroundColor Cyan
            Write-Host ''
            break
        }

        default {
            Write-Host ''
            Write-Host 'Invalid selection. Please choose a valid option.' -ForegroundColor Yellow
            Start-Sleep -Seconds 1
        }
    }

} while ($true)
'@ | Set-Content -Path .\Scripts\Start-EntraGovernance.ps1 -Encoding UTF8