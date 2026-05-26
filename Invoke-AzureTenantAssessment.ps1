<#
.SYNOPSIS
    Full Azure Tenant Assessment — exports tenant configuration to CSV for review.

.DESCRIPTION
    Connects to Microsoft Graph and exports:
      - Users, Groups, Guest Users
      - Conditional Access Policies + Named Locations
      - MFA Registration Details
      - Intune Device Configurations + Compliance Policies
      - Autopilot Devices
      - Managed Apps
      - User Licensing
      - Legacy Authentication Sign-ins
      - Admin Role Assignments
      - Risky Users (Identity Protection)

.PARAMETER OutputDir
    Folder where CSV files are written. Defaults to .\AssessmentOutput\<timestamp>.

.EXAMPLE
    .\Invoke-AzureTenantAssessment.ps1
    .\Invoke-AzureTenantAssessment.ps1 -OutputDir "C:\Reports\Contoso"

.NOTES
    Requires: Microsoft.Graph PowerShell SDK
    Install:  Install-Module Microsoft.Graph -Scope CurrentUser -Force
#>

[CmdletBinding()]
param(
    [string]$OutputDir = ""
)

#region --- Setup ---

# Resolve output directory
if (-not $OutputDir) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $OutputDir = Join-Path $PSScriptRoot "AssessmentOutput\$timestamp"
}

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

Write-Host "`n=== Azure Tenant Assessment ===" -ForegroundColor Cyan
Write-Host "Output directory: $OutputDir`n" -ForegroundColor Gray

# Ensure Microsoft.Graph is available
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Write-Host "[!] Microsoft.Graph module not found. Installing..." -ForegroundColor Yellow
    Install-Module Microsoft.Graph -Scope CurrentUser -Force
}

# Connect with required scopes
Write-Host "[*] Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -Scopes @(
    "Directory.Read.All"
    "Policy.Read.All"
    "UserAuthenticationMethod.Read.All"
    "DeviceManagementConfiguration.Read.All"
    "DeviceManagementCompliance.Read.All"
    "DeviceManagementApps.Read.All"
    "DeviceManagementServiceConfig.Read.All"
    "AuditLog.Read.All"
    "Reports.Read.All"
    "IdentityRiskyUser.Read.All"
    "RoleManagement.Read.Directory"
)

$context = Get-MgContext
Write-Host "[+] Connected as: $($context.Account) | Tenant: $($context.TenantId)`n" -ForegroundColor Green

#endregion

#region --- Helper ---

function Export-Section {
    param(
        [string]$Label,
        [string]$FileName,
        [scriptblock]$Command
    )
    Write-Host "[*] $Label..." -ForegroundColor Cyan
    try {
        $data = & $Command
        if ($data) {
            $outPath = Join-Path $OutputDir $FileName
            $data | Export-Csv $outPath -NoTypeInformation -Encoding UTF8
            Write-Host "    [+] $($data.Count) record(s) -> $FileName" -ForegroundColor Green
        } else {
            Write-Host "    [-] No data returned." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "    [!] Error: $_" -ForegroundColor Red
    }
}

#endregion

#region --- Identity & Users ---

Export-Section -Label "Users (all)" -FileName "users.csv" -Command {
    Get-MgUser -All -Property DisplayName,UserPrincipalName,AccountEnabled,CreatedDateTime,LastPasswordChangeDateTime,UserType,JobTitle,Department,UsageLocation,AssignedLicenses
}

Export-Section -Label "Guest Users" -FileName "guest_users.csv" -Command {
    Get-MgUser -All -Filter "userType eq 'Guest'" -Property DisplayName,UserPrincipalName,Mail,CreatedDateTime,ExternalUserState,AccountEnabled
}

Export-Section -Label "Groups" -FileName "groups.csv" -Command {
    Get-MgGroup -All -Property DisplayName,Description,GroupTypes,MailEnabled,SecurityEnabled,CreatedDateTime,MembershipRule
}

#endregion

#region --- Admin Roles ---

Export-Section -Label "Admin Role Assignments" -FileName "admin_roles.csv" -Command {
    $roles = Get-MgDirectoryRole -All
    $assignments = foreach ($role in $roles) {
        $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All
        foreach ($member in $members) {
            [PSCustomObject]@{
                RoleDisplayName = $role.DisplayName
                RoleId          = $role.Id
                MemberId        = $member.Id
                MemberType      = $member.AdditionalProperties['@odata.type']
                DisplayName     = $member.AdditionalProperties['displayName']
                UPN             = $member.AdditionalProperties['userPrincipalName']
            }
        }
    }
    $assignments
}

#endregion

#region --- Conditional Access ---

Export-Section -Label "Conditional Access Policies" -FileName "ca_policies.csv" -Command {
    Get-MgIdentityConditionalAccessPolicy -All | Select-Object DisplayName,State,CreatedDateTime,ModifiedDateTime,
        @{N='IncludeUsers';E={$_.Conditions.Users.IncludeUsers -join ','}},
        @{N='ExcludeUsers';E={$_.Conditions.Users.ExcludeUsers -join ','}},
        @{N='IncludeGroups';E={$_.Conditions.Users.IncludeGroups -join ','}},
        @{N='IncludeApps';E={$_.Conditions.Applications.IncludeApplications -join ','}},
        @{N='GrantControls';E={$_.GrantControls.BuiltInControls -join ','}}
}

Export-Section -Label "Named Locations" -FileName "named_locations.csv" -Command {
    Get-MgIdentityConditionalAccessNamedLocation -All | Select-Object DisplayName,
        @{N='Type';E={$_.'@odata.type'}},
        @{N='IsTrusted';E={$_.AdditionalProperties['isTrusted']}},
        @{N='IPRanges';E={($_.AdditionalProperties['ipRanges'].cidrAddress) -join ','}}
}

#endregion

#region --- MFA & Authentication ---

Export-Section -Label "MFA Registration Details" -FileName "mfa_registration.csv" -Command {
    Get-MgReportAuthenticationMethodUserRegistrationDetail -All | Select-Object UserDisplayName,UserPrincipalName,
        IsAdmin,IsMfaCapable,IsMfaRegistered,IsPasswordlessCapable,IsSsprCapable,IsSsprRegistered,
        @{N='MethodsRegistered';E={$_.MethodsRegistered -join ','}}
}

#endregion

#region --- Intune / Endpoint Manager ---

Export-Section -Label "Intune Device Configurations" -FileName "intune_device_configs.csv" -Command {
    Get-MgDeviceManagementDeviceConfiguration -All | Select-Object DisplayName,Description,
        @{N='ODataType';E={$_.'@odata.type'}},CreatedDateTime,LastModifiedDateTime
}

Export-Section -Label "Compliance Policies" -FileName "compliance_policies.csv" -Command {
    Get-MgDeviceManagementDeviceCompliancePolicy -All | Select-Object DisplayName,Description,
        @{N='ODataType';E={$_.'@odata.type'}},CreatedDateTime,LastModifiedDateTime
}

Export-Section -Label "Windows Autopilot Devices" -FileName "autopilot_devices.csv" -Command {
    Get-MgDeviceManagementWindowsAutopilotDeviceIdentity -All | Select-Object DisplayName,SerialNumber,
        Model,Manufacturer,GroupTag,EnrollmentState,LastContactedDateTime,ManagedDeviceId,AzureAdDeviceId
}

Export-Section -Label "Managed Mobile Apps" -FileName "managed_apps.csv" -Command {
    Get-MgDeviceAppManagementMobileApp -All | Select-Object DisplayName,Publisher,
        @{N='ODataType';E={$_.'@odata.type'}},IsAssigned,CreatedDateTime,LastModifiedDateTime
}

#endregion

#region --- Licensing ---

Export-Section -Label "User Licensing" -FileName "user_licensing.csv" -Command {
    Get-MgUser -All -Property DisplayName,UserPrincipalName,AssignedLicenses,LicenseAssignmentStates |
        Select-Object DisplayName,UserPrincipalName,
            @{N='LicenseSkuIds';E={$_.AssignedLicenses.SkuId -join ','}},
            @{N='AssignedViaGroup';E={($_.LicenseAssignmentStates | Where-Object {$_.AssignedByGroup} | Select-Object -Expand AssignedByGroup) -join ','}}
}

#endregion

#region --- Sign-in / Audit Logs ---

Export-Section -Label "Legacy Authentication Sign-ins (last 30 days)" -FileName "legacy_auth_signins.csv" -Command {
    $cutoff = (Get-Date).AddDays(-30).ToString("yyyy-MM-ddTHH:mm:ssZ")
    Get-MgAuditLogSignIn -All `
        -Filter "clientAppUsed ne 'Browser' and clientAppUsed ne 'Mobile Apps and Desktop clients' and createdDateTime ge $cutoff" |
        Select-Object UserDisplayName,UserPrincipalName,ClientAppUsed,AppDisplayName,
            CreatedDateTime,IPAddress,Location,Status,ConditionalAccessStatus
}

Export-Section -Label "Risky Users (Identity Protection)" -FileName "risky_users.csv" -Command {
    Get-MgRiskyUser -All | Select-Object UserDisplayName,UserPrincipalName,
        RiskLevel,RiskState,RiskDetail,RiskLastUpdatedDateTime,IsDeleted,IsProcessing
}

#endregion

#region --- Summary Report ---

Write-Host "`n=== Assessment Complete ===" -ForegroundColor Cyan
Write-Host "Files written to: $OutputDir" -ForegroundColor Green

$csvFiles = Get-ChildItem $OutputDir -Filter "*.csv"
Write-Host "`nExported files:" -ForegroundColor Gray
$csvFiles | ForEach-Object {
    $rows = (Import-Csv $_.FullName | Measure-Object).Count
    Write-Host ("  {0,-45} {1,6} rows" -f $_.Name, $rows) -ForegroundColor White
}

# Write summary manifest
$manifest = [PSCustomObject]@{
    AssessmentDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    TenantId       = $context.TenantId
    RunBy          = $context.Account
    OutputDir      = $OutputDir
    FilesExported  = $csvFiles.Count
}
$manifest | Export-Csv (Join-Path $OutputDir "00_manifest.csv") -NoTypeInformation

Write-Host "`n[+] Manifest saved to 00_manifest.csv" -ForegroundColor Green
Disconnect-MgGraph | Out-Null
Write-Host "[*] Disconnected from Microsoft Graph.`n" -ForegroundColor Gray

#endregion
