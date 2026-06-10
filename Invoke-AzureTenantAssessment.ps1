<#
.SYNOPSIS
    Comprehensive Azure Tenant Security Assessment — generates a professional HTML report.

.DESCRIPTION
    Covers 10 assessment domains:
      1. Entra ID Configuration
      2. Conditional Access Policy Audit
      3. MFA Posture Assessment
      4. Intune Configuration Profile Review
      5. Device Compliance Policy Assessment
      6. Windows Autopilot Registration Status
      7. Application Deployment Review
      8. Microsoft 365 Licensing Audit
      9. Legacy Authentication Analysis
      10. Emergency Access Account Review

.PARAMETER OutputDir
    Folder for output files. Defaults to .\AssessmentOutput\<timestamp>.

.PARAMETER SkipSignInLogs
    Skip sign-in log collection (can be slow on large tenants).

.PARAMETER SignInLogDays
    Days of sign-in history to pull (default: 7; max retention is 30).

.PARAMETER TenantDomain
    The domain or tenant ID of the target tenant (e.g. contoso.onmicrosoft.com or a GUID).
    If omitted the script will prompt interactively. Prevents accidentally running against
    a tenant you already manage.

.PARAMETER SkipAppSummary
    Skip per-app install summary collection (slow for large app catalogs).

.EXAMPLE
    # Tenant without Intune (default — safe for any tenant, never hits AADSTS650053)
    .\Invoke-AzureTenantAssessment.ps1 -TenantDomain contoso.onmicrosoft.com

    # Tenant WITH Intune — pass -WithIntune to include sections 4-7
    .\Invoke-AzureTenantAssessment.ps1 -TenantDomain contoso.onmicrosoft.com -WithIntune

    # Azure Cloud Shell
    pwsh ~/clouddrive/azureassessment/Invoke-AzureTenantAssessment.ps1 -TenantDomain contoso.onmicrosoft.com
    pwsh ~/clouddrive/azureassessment/Invoke-AzureTenantAssessment.ps1 -TenantDomain contoso.onmicrosoft.com -WithIntune
#>

[CmdletBinding()]
param(
    [string]$TenantDomain  = "",
    [string]$OutputDir     = "",
    [switch]$WithIntune,          # Include Intune sections (4-7). Only use when target tenant has Intune licensed.
    [switch]$SkipSignInLogs,
    [int]   $SignInLogDays = 7,
    [switch]$SkipAppSummary
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# Detect Azure Cloud Shell
$script:InCloudShell = ($env:AZUREPS_HOST_ENVIRONMENT -like 'cloud-shell*') -or ($env:ACC_CLOUD -ne $null)

#region ── SETUP ──────────────────────────────────────────────────────────────

$script:Findings = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-Finding([string]$Section, [string]$Severity, [string]$Title, [string]$Detail) {
    $script:Findings.Add([PSCustomObject]@{
        Section  = $Section
        Severity = $Severity   # Critical | Warning | Good | Info
        Title    = $Title
        Detail   = $Detail
    })
}

function HE([string]$s) {
    # Minimal HTML-encode (no System.Web dependency)
    $s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;'
}

if (-not $OutputDir) {
    $ts = Get-Date -Format "yyyyMMdd_HHmmss"
    # In Cloud Shell write to persistent clouddrive so the report survives the session
    $OutputDir = if ($script:InCloudShell) {
        Join-Path $HOME "clouddrive/AzureAssessment/$ts"
    } else {
        Join-Path ($PSScriptRoot ? $PSScriptRoot : $PWD) "AssessmentOutput/$ts"
    }
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

Write-Host "`n╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host   "║   Azure Tenant Comprehensive Security Assessment     ║" -ForegroundColor Cyan
Write-Host   "╚══════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan
if ($script:InCloudShell) {
    Write-Host "  Running in Azure Cloud Shell" -ForegroundColor Yellow
}
Write-Host "Output: $OutputDir`n" -ForegroundColor Gray

if (-not (Get-Module -ListAvailable -Name Microsoft.Graph)) {
    Write-Host "[!] Installing Microsoft.Graph module..." -ForegroundColor Yellow
    Install-Module Microsoft.Graph -Scope CurrentUser -Force
}

# ── Prompt for target tenant ──
if (-not $TenantDomain) {
    Write-Host "  Enter the target tenant domain or tenant ID." -ForegroundColor Yellow
    Write-Host "  Examples: contoso.onmicrosoft.com | 3a1b2c3d-... " -ForegroundColor Gray
    Write-Host ""
    do {
        $TenantDomain = (Read-Host "  Target tenant").Trim()
    } while (-not $TenantDomain)
}
Write-Host ""
Write-Host "[*] Target tenant : $TenantDomain" -ForegroundColor Cyan

# Core scopes — work on every tenant, no Intune required
$coreScopes = @(
    "Directory.Read.All"
    "Policy.Read.All"
    "UserAuthenticationMethod.Read.All"
    "AuditLog.Read.All"
    "Reports.Read.All"
    "IdentityRiskyUser.Read.All"
    "RoleManagement.Read.Directory"
    "Organization.Read.All"
)

# Intune scopes — only available when Intune is licensed in the target tenant.
# Requesting these on a tenant without Intune causes AADSTS650053, which is why
# they are NEVER requested unless the caller explicitly passes -WithIntune.
$intuneScopes = @(
    "DeviceManagementConfiguration.Read.All"
    "DeviceManagementCompliance.Read.All"
    "DeviceManagementApps.Read.All"
    "DeviceManagementServiceConfig.Read.All"
    "DeviceManagementManagedDevices.Read.All"
)

$script:HasIntuneAccess = $false
$scopesToRequest = if ($WithIntune) { $coreScopes + $intuneScopes } else { $coreScopes }

# ── Phase 1: Connect ──
# Always starts with core scopes so auth never fails with AADSTS650053.
# -WithIntune adds the DeviceManagement scopes to the same request.
if ($script:InCloudShell) {
    Write-Host "[*] Connecting via device code — a code will appear below..." -ForegroundColor Cyan
    Connect-MgGraph -TenantId $TenantDomain -Scopes $scopesToRequest -UseDeviceCode -NoWelcome -ContextScope Process
} else {
    Write-Host "[*] Connecting to Microsoft Graph (browser sign-in will open)..." -ForegroundColor Cyan
    Connect-MgGraph -TenantId $TenantDomain -Scopes $scopesToRequest -NoWelcome -ContextScope Process
}

# Verify the connection actually succeeded
$ctx = Get-MgContext
if (-not $ctx -or -not $ctx.TenantId) {
    Write-Host ""
    Write-Host "[!] Authentication did not complete. Common reasons:" -ForegroundColor Red
    Write-Host "    • Browser window was closed without signing in" -ForegroundColor Yellow
    Write-Host "    • Conditional Access policy blocked the sign-in" -ForegroundColor Yellow
    Write-Host "    • Tenant domain / ID is incorrect" -ForegroundColor Yellow
    if ($WithIntune) {
        Write-Host "    • AADSTS650053: Intune is not licensed in this tenant." -ForegroundColor Yellow
        Write-Host "      Remove -WithIntune and re-run. Sections 4-7 will be skipped." -ForegroundColor Yellow
    }
    Write-Host ""
    exit 1
}

# Mark Intune access based on whether scopes were successfully granted
if ($WithIntune) {
    $grantedScopes = $ctx.Scopes
    $script:HasIntuneAccess = ($grantedScopes -contains 'DeviceManagementCompliance.Read.All')
    if (-not $script:HasIntuneAccess) {
        Write-Host "[!] -WithIntune was set but DeviceManagement scopes were not granted." -ForegroundColor Yellow
        Write-Host "    Sections 4-7 will be skipped. Verify Intune is licensed in this tenant." -ForegroundColor Yellow
    } else {
        Write-Host "[+] Intune scopes granted — sections 4-7 will be included." -ForegroundColor Green
    }
}

# Confirm we are on the right tenant before pulling any data
Write-Host ""
Write-Host "[+] Connected : $($ctx.Account)" -ForegroundColor Green
Write-Host "    Tenant ID : $($ctx.TenantId)" -ForegroundColor Green
Write-Host ""
Write-Host "    Confirm this is the correct tenant before continuing." -ForegroundColor Yellow
$confirm = Read-Host "    Proceed with assessment? (yes/no)"
if ($confirm.Trim().ToLower() -notin @('yes','y')) {
    Write-Host "[!] Assessment cancelled." -ForegroundColor Red
    Disconnect-MgGraph | Out-Null
    exit 0
}
Write-Host ""

#endregion

#region ── DATA COLLECTION ────────────────────────────────────────────────────

function Collect([string]$Label, [scriptblock]$Cmd) {
    Write-Host "    $Label..." -NoNewline -ForegroundColor DarkCyan
    try {
        $r = & $Cmd
        $count = if ($r -is [array]) { $r.Count } else { @($r).Count }
        Write-Host " $count records" -ForegroundColor Green
        return $r
    } catch {
        $e = $_.ToString()
        if ($e -like '*not licensed*' -or ($e -like '*403*' -and $e -like '*Forbidden*')) {
            Write-Host " Skipped (tenant not licensed for this feature)" -ForegroundColor Yellow
        } elseif ($e -like '*401*' -or $e -like '*Unauthorized*') {
            Write-Host " Skipped (insufficient permissions)" -ForegroundColor Yellow
        } else {
            Write-Host " ERROR: $e" -ForegroundColor Red
        }
        return @()
    }
}

# ── 1. Entra ID ──
Write-Host "[1/10] Entra ID Configuration" -ForegroundColor Cyan
$org    = Get-MgOrganization | Select-Object -First 1
$domains = Collect "Domains"     { Get-MgDomain -All }
$users   = Collect "Users"       { Get-MgUser -All -Property Id,DisplayName,UserPrincipalName,AccountEnabled,CreatedDateTime,UserType,JobTitle,Department,AssignedLicenses,LastPasswordChangeDateTime,OnPremisesSyncEnabled,LicenseAssignmentStates }
$groups  = Collect "Groups"      { Get-MgGroup -All -Property Id,DisplayName,GroupTypes,MailEnabled,SecurityEnabled,MembershipRule,CreatedDateTime,MembershipRuleProcessingState }
$adminRoles = Collect "Admin Role Assignments" {
    $roles = Get-MgDirectoryRole -All
    $list  = foreach ($role in $roles) {
        $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All
        foreach ($m in $members) {
            [PSCustomObject]@{
                RoleName   = $role.DisplayName
                MemberName = $m.AdditionalProperties['displayName']
                MemberUPN  = $m.AdditionalProperties['userPrincipalName']
                MemberType = ($m.AdditionalProperties['@odata.type'] -replace '#microsoft.graph.','')
            }
        }
    }
    $list
}

# ── 2. Conditional Access ──
Write-Host "[2/10] Conditional Access" -ForegroundColor Cyan
$caPolicies = Collect "CA Policies"     { Get-MgIdentityConditionalAccessPolicy -All }
$namedLocs  = Collect "Named Locations" { Get-MgIdentityConditionalAccessNamedLocation -All }

# ── 3. MFA ──
Write-Host "[3/10] MFA Posture" -ForegroundColor Cyan
$mfaReg = Collect "MFA Registration Details" { Get-MgReportAuthenticationMethodUserRegistrationDetail -All }

# ── 4. Intune Configs ──
$intuneConfigs      = @()
$compliancePolicies = @()
$managedDevices     = @()
$autopilotDevices   = @()
$apps               = @()
$appSummaries       = @{}

if ($script:HasIntuneAccess) {
    Write-Host "[4/10] Intune Configuration Profiles" -ForegroundColor Cyan
    $intuneConfigs = Collect "Device Configurations" { Get-MgDeviceManagementDeviceConfiguration -All }

    # ── 5. Device Compliance ──
    Write-Host "[5/10] Device Compliance" -ForegroundColor Cyan
    $compliancePolicies = Collect "Compliance Policies" { Get-MgDeviceManagementDeviceCompliancePolicy -All }
    $managedDevices     = Collect "Managed Devices"     {
        Get-MgDeviceManagementManagedDevice -All -Property Id,DeviceName,OperatingSystem,OsVersion,ComplianceState,LastSyncDateTime,UserDisplayName,UserPrincipalName,ManagementAgent,JoinType,Manufacturer,Model
    }

    # ── 6. Autopilot ──
    Write-Host "[6/10] Windows Autopilot" -ForegroundColor Cyan
    $autopilotDevices = Collect "Autopilot Devices" { Get-MgDeviceManagementWindowsAutopilotDeviceIdentity -All }

    # ── 7. Applications ──
    Write-Host "[7/10] Application Deployment" -ForegroundColor Cyan
    $apps = Collect "Mobile Apps" {
        Get-MgDeviceAppManagementMobileApp -All -Property Id,DisplayName,Publisher,IsAssigned,CreatedDateTime,LastModifiedDateTime,'@odata.type'
    }

    if (-not $SkipAppSummary -and $apps.Count -gt 0) {
        Write-Host "    App install summaries ($($apps.Count) apps, may take a moment)..." -ForegroundColor DarkCyan
        $i = 0
        foreach ($app in $apps) {
            $i++
            try {
                $s = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/deviceAppManagement/mobileApps/$($app.Id)/installSummary" -ErrorAction SilentlyContinue
                if ($s) { $appSummaries[$app.Id] = $s }
            } catch {}
            if ($i % 20 -eq 0) { Write-Host "      ... $i/$($apps.Count)" -ForegroundColor Gray }
        }
        Write-Host "    Done." -ForegroundColor Green
    }
} else {
    Write-Host "[4-7/10] Skipping Intune sections (DeviceManagement scopes unavailable)" -ForegroundColor Yellow
}

# ── 8. Licensing ──
Write-Host "[8/10] Licensing" -ForegroundColor Cyan
$skus = Collect "Subscribed SKUs" { Get-MgSubscribedSku -All }

# ── 9. Legacy Auth ──
Write-Host "[9/10] Legacy Authentication" -ForegroundColor Cyan
$legacySignIns = @()
if (-not $SkipSignInLogs) {
    $cutoff = (Get-Date).AddDays(-$SignInLogDays).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $legacySignIns = Collect "Legacy Sign-ins (last $SignInLogDays days)" {
        Get-MgAuditLogSignIn -All -Top 1000 -Filter "createdDateTime ge $cutoff and clientAppUsed ne 'Browser' and clientAppUsed ne 'Mobile Apps and Desktop clients'"
    }
} else {
    Write-Host "    Skipped (-SkipSignInLogs)" -ForegroundColor Yellow
}

# ── 10. Emergency Access ──
Write-Host "[10/10] Emergency Access" -ForegroundColor Cyan
$bgPatterns = @('emergency','breakglass','break-glass','breakgl','bga','bgb','bg1','bg2','e911','emerg','bkgls')
$gaUpns = @($adminRoles | Where-Object { $_.RoleName -eq 'Global Administrator' -and $_.MemberUPN } | ForEach-Object { $_.MemberUPN.ToLower() })
$emergencyAccts = @($users | Where-Object {
    $upn  = $_.UserPrincipalName.ToLower()
    $name = $_.DisplayName.ToLower()
    $hit  = $false
    foreach ($p in $bgPatterns) { if ($upn -like "*$p*" -or $name -like "*$p*") { $hit = $true; break } }
    $hit
} | ForEach-Object {
    $isGA = $gaUpns -contains $_.UserPrincipalName.ToLower()
    Add-Member -InputObject $_ -NotePropertyName IsGlobalAdmin -NotePropertyValue $isGA -Force -PassThru
})

$riskyUsers = Collect "Risky Users" { Get-MgRiskyUser -All }

#endregion

#region ── ANALYSIS & FINDINGS ────────────────────────────────────────────────

# ── Entra ID ──
$totalUsers     = $users.Count
$enabledUsers   = @($users | Where-Object AccountEnabled).Count
$disabledUsers  = $totalUsers - $enabledUsers
$guestUsers     = @($users | Where-Object { $_.UserType -eq 'Guest' }).Count
$hybridUsers    = @($users | Where-Object { $_.OnPremisesSyncEnabled }).Count
$federatedDoms  = @($domains | Where-Object { $_.AuthenticationType -eq 'Federated' }).Count

$globalAdmins = @($adminRoles | Where-Object { $_.RoleName -eq 'Global Administrator' })
if ($globalAdmins.Count -gt 5) {
    Add-Finding "Entra ID" "Warning" "$($globalAdmins.Count) Global Administrators found" "Best practice is 2-4 break-glass excluded GA accounts. Review if all are needed."
} elseif ($globalAdmins.Count -eq 0) {
    Add-Finding "Entra ID" "Warning" "No Global Administrator role assignments found" "Could not enumerate GA members — verify permissions."
} else {
    Add-Finding "Entra ID" "Good" "$($globalAdmins.Count) Global Administrator(s)" "GA count is within the recommended 2-4 range."
}

if ($guestUsers -gt 0) {
    Add-Finding "Entra ID" "Info" "$guestUsers guest user(s) in directory" "Review whether all external identities are still required."
}

# ── Conditional Access ──
$enabledPolicies    = @($caPolicies | Where-Object { $_.State -eq 'enabled' }).Count
$reportOnlyPolicies = @($caPolicies | Where-Object { $_.State -eq 'enabledForReportingButNotEnforced' }).Count
$disabledPolicies   = @($caPolicies | Where-Object { $_.State -eq 'disabled' }).Count

$mfaAllUsersPolicy = $caPolicies | Where-Object {
    $_.State -eq 'enabled' -and
    $_.Conditions.Users.IncludeUsers -contains 'All' -and
    $_.GrantControls.BuiltInControls -contains 'mfa'
}
$legacyBlockPolicy = $caPolicies | Where-Object {
    $_.State -eq 'enabled' -and
    $_.Conditions.ClientAppTypes -and
    ($_.Conditions.ClientAppTypes -contains 'exchangeActiveSync' -or $_.Conditions.ClientAppTypes -contains 'other') -and
    $_.GrantControls.BuiltInControls -contains 'block'
}
$signInRiskPolicy = $caPolicies | Where-Object {
    $_.State -eq 'enabled' -and $_.Conditions.SignInRiskLevels.Count -gt 0
}
$userRiskPolicy = $caPolicies | Where-Object {
    $_.State -eq 'enabled' -and $_.Conditions.UserRiskLevels.Count -gt 0
}

if (-not $mfaAllUsersPolicy)  { Add-Finding "Conditional Access" "Critical" "No MFA policy covering All Users"          "No enabled CA policy requires MFA for all users. Users may authenticate without MFA." }
else                           { Add-Finding "Conditional Access" "Good"     "MFA policy for All Users exists"           "An enabled CA policy enforces MFA for all users." }
if (-not $legacyBlockPolicy)   { Add-Finding "Conditional Access" "Critical" "No legacy authentication block policy"     "Legacy auth protocols are not explicitly blocked via Conditional Access." }
else                           { Add-Finding "Conditional Access" "Good"     "Legacy authentication is blocked via CA"   "A CA policy explicitly blocks legacy authentication." }
if (-not $signInRiskPolicy)    { Add-Finding "Conditional Access" "Warning"  "No sign-in risk CA policy"                 "Entra ID Protection sign-in risk signals are not enforced via CA." }
if (-not $userRiskPolicy)      { Add-Finding "Conditional Access" "Warning"  "No user risk CA policy"                    "Entra ID Protection user risk signals are not enforced via CA." }

if ($reportOnlyPolicies -gt 0) {
    Add-Finding "Conditional Access" "Warning" "$reportOnlyPolicies CA policy(ies) in Report-Only mode" "Report-only policies are not enforced. Review and enable when ready."
}

# ── MFA ──
$mfaTotal      = $mfaReg.Count
$mfaRegistered = @($mfaReg | Where-Object { $_.IsMfaRegistered }).Count
$mfaCapable    = @($mfaReg | Where-Object { $_.IsMfaCapable }).Count
$noMfa         = $mfaTotal - $mfaRegistered
$passwordless  = @($mfaReg | Where-Object { $_.IsPasswordlessCapable }).Count
$msAuthApp     = @($mfaReg | Where-Object { $_.MethodsRegistered -contains 'microsoftAuthenticatorPush' }).Count
$oathTotp      = @($mfaReg | Where-Object { $_.MethodsRegistered -contains 'softwareOneTimePasscode' }).Count
$phoneMethod   = @($mfaReg | Where-Object { $_.MethodsRegistered -contains 'mobilePhone' }).Count
$mfaPct        = if ($mfaTotal -gt 0) { [math]::Round($mfaRegistered / $mfaTotal * 100, 1) } else { 0 }

if     ($mfaPct -lt 70) { Add-Finding "MFA Posture" "Critical" "MFA registration is $mfaPct% (below 70%)"  "$noMfa of $mfaTotal users have no MFA registered." }
elseif ($mfaPct -lt 90) { Add-Finding "MFA Posture" "Warning"  "MFA registration is $mfaPct% (below 90%)"  "$noMfa of $mfaTotal users have no MFA registered." }
else                    { Add-Finding "MFA Posture" "Good"     "MFA registration is $mfaPct%"               "$mfaRegistered of $mfaTotal users are MFA registered." }

if ($phoneMethod -gt 0) {
    Add-Finding "MFA Posture" "Warning" "$phoneMethod user(s) using SMS/voice as primary MFA method" "SMS and voice call MFA are vulnerable to SIM-swap and SS7 attacks. Migrate to Authenticator app."
}

# ── Intune ──
$configCount   = $intuneConfigs.Count
$winProfiles   = @($intuneConfigs | Where-Object { $_.'@odata.type' -match 'windows' }).Count
$macProfiles   = @($intuneConfigs | Where-Object { $_.'@odata.type' -match 'mac|osx' }).Count
$iosProfiles   = @($intuneConfigs | Where-Object { $_.'@odata.type' -match 'ios|android' }).Count

if (-not $script:HasIntuneAccess) {
    Add-Finding "Intune Profiles"   "Info" "Intune data not collected" "DeviceManagement scopes were unavailable in this tenant. Sections 4-7 require Intune licensing and admin consent."
    Add-Finding "Device Compliance" "Info" "Intune data not collected" "DeviceManagement scopes were unavailable in this tenant."
    Add-Finding "Autopilot"         "Info" "Intune data not collected" "DeviceManagement scopes were unavailable in this tenant."
    Add-Finding "App Deployment"    "Info" "Intune data not collected" "DeviceManagement scopes were unavailable in this tenant."
} elseif ($configCount -eq 0) {
    Add-Finding "Intune Profiles" "Critical" "No Intune device configuration profiles found" "No device configuration is being pushed via Intune."
} else {
    Add-Finding "Intune Profiles" "Info" "$configCount configuration profile(s) deployed" "$winProfiles Windows, $macProfiles macOS, $iosProfiles iOS/Android."
}

# ── Device Compliance ──
$totalDevices     = $managedDevices.Count
$compliantDev     = @($managedDevices | Where-Object { $_.ComplianceState -eq 'compliant' }).Count
$nonCompliantDev  = @($managedDevices | Where-Object { $_.ComplianceState -eq 'noncompliant' }).Count
$unknownDev       = @($managedDevices | Where-Object { $_.ComplianceState -eq 'unknown' }).Count
$gracePeriodDev   = @($managedDevices | Where-Object { $_.ComplianceState -eq 'inGracePeriod' }).Count
$compliancePct    = if ($totalDevices -gt 0) { [math]::Round($compliantDev / $totalDevices * 100, 1) } else { 0 }

if ($totalDevices -eq 0) {
    Add-Finding "Device Compliance" "Warning" "No managed devices found" "No devices are enrolled in Intune."
} elseif ($compliancePct -lt 70) {
    Add-Finding "Device Compliance" "Critical" "Device compliance is $compliancePct% (below 70%)" "$nonCompliantDev non-compliant, $unknownDev unknown of $totalDevices total devices."
} elseif ($compliancePct -lt 90) {
    Add-Finding "Device Compliance" "Warning"  "Device compliance is $compliancePct% (below 90%)" "$nonCompliantDev non-compliant, $unknownDev unknown of $totalDevices total devices."
} else {
    Add-Finding "Device Compliance" "Good" "Device compliance is $compliancePct%" "$compliantDev of $totalDevices devices are compliant."
}

# ── Autopilot ──
$autopilotCount   = $autopilotDevices.Count
$withGroupTag     = @($autopilotDevices | Where-Object { $_.GroupTag }).Count
$noGroupTag       = $autopilotCount - $withGroupTag

if ($autopilotCount -eq 0) {
    Add-Finding "Autopilot" "Info" "No Autopilot devices registered" "No Windows Autopilot device identities found."
} else {
    Add-Finding "Autopilot" "Info" "$autopilotCount Autopilot device(s) registered" "$withGroupTag have a Group Tag, $noGroupTag do not."
    if ($noGroupTag -gt 0) {
        Add-Finding "Autopilot" "Warning" "$noGroupTag device(s) missing Group Tag" "Group Tags are required for dynamic group assignment and profile targeting."
    }
}

# ── Apps ──
$totalApps      = $apps.Count
$assignedApps   = @($apps | Where-Object { $_.IsAssigned }).Count
$unassignedApps = $totalApps - $assignedApps

if ($unassignedApps -gt 0) {
    Add-Finding "App Deployment" "Warning" "$unassignedApps app(s) have no assignments" "These apps exist in Intune but are not assigned to any users or devices."
}
if ($totalApps -eq 0) {
    Add-Finding "App Deployment" "Info" "No managed apps found" "No apps are deployed through Intune."
} else {
    Add-Finding "App Deployment" "Info" "$totalApps app(s) in Intune" "$assignedApps assigned, $unassignedApps unassigned."
}

# ── Licensing ──
$totalAssigned  = ($skus | Measure-Object -Property ConsumedUnits -Sum).Sum
$totalAvailable = ($skus | ForEach-Object { $_.PrepaidUnits.Enabled } | Measure-Object -Sum).Sum
$unusedSeats    = $totalAvailable - $totalAssigned
$licenseUtil    = if ($totalAvailable -gt 0) { [math]::Round($totalAssigned / $totalAvailable * 100, 1) } else { 0 }

if ($unusedSeats -gt 20) {
    Add-Finding "Licensing" "Warning" "$unusedSeats unused license seats ($licenseUtil% utilization)" "Consider right-sizing subscriptions to reduce cost."
} elseif ($unusedSeats -gt 0) {
    Add-Finding "Licensing" "Info" "$unusedSeats unused license seats" "Minor over-provisioning; monitor during next renewal."
} else {
    Add-Finding "Licensing" "Good" "License utilization is $licenseUtil%" "All available license seats are in use."
}

# ── Legacy Auth ──
$legacyCount    = $legacySignIns.Count
$legacyUniqueU  = if ($legacyCount -gt 0) { @($legacySignIns | Select-Object -ExpandProperty UserPrincipalName -Unique).Count } else { 0 }

if (-not $SkipSignInLogs) {
    if ($legacyCount -gt 0) {
        Add-Finding "Legacy Authentication" "Critical" "$legacyCount legacy auth sign-in(s) in last $SignInLogDays days" "$legacyUniqueU unique user(s) are authenticating with legacy protocols. Block these immediately."
    } else {
        Add-Finding "Legacy Authentication" "Good" "No legacy authentication sign-ins detected" "No legacy auth activity found in the last $SignInLogDays days."
    }
}

# ── Emergency Access ──
$emergencyCount = $emergencyAccts.Count
if ($emergencyCount -eq 0) {
    Add-Finding "Emergency Access" "Warning" "No break-glass accounts identified" "No accounts matching common emergency-access naming patterns were found. Every tenant should have 2 cloud-only break-glass accounts."
} else {
    Add-Finding "Emergency Access" "Info" "$emergencyCount potential break-glass account(s) found" "Verify these are cloud-only, excluded from all CA policies, monitored via alerts, and credentials stored securely offline."
    foreach ($bg in $emergencyAccts) {
        if (-not $bg.IsGlobalAdmin) {
            Add-Finding "Emergency Access" "Warning" "Potential break-glass '$($bg.DisplayName)' does not hold Global Administrator role" "Account name matches break-glass naming patterns but isn't a Global Administrator — may be a false positive or a misconfigured break-glass account."
        }
        # Check if each is excluded from all enabled CA policies
        foreach ($policy in ($caPolicies | Where-Object { $_.State -eq 'enabled' })) {
            if ($policy.Conditions.Users.ExcludeUsers -notcontains $bg.Id) {
                Add-Finding "Emergency Access" "Critical" "Break-glass '$($bg.DisplayName)' not excluded from CA: '$($policy.DisplayName)'" "If this policy locks out all users, break-glass access will fail."
            }
        }
    }
}

#endregion

#region ── HTML HELPERS ───────────────────────────────────────────────────────

function badge([string]$text, [string]$color) { "<span class='badge bg-$color'>$text</span>" }

function sev-badge([string]$sev) {
    switch ($sev) {
        'Critical' { badge 'Critical' 'danger'  }
        'Warning'  { badge 'Warning'  'warning text-dark' }
        'Good'     { badge 'Good'     'success' }
        default    { badge 'Info'     'info text-dark' }
    }
}

function state-badge([string]$state) {
    switch ($state) {
        'enabled'                           { badge 'Enabled'     'success' }
        'disabled'                          { badge 'Disabled'    'secondary' }
        'enabledForReportingButNotEnforced' { badge 'Report Only' 'warning text-dark' }
        default                             { badge $state        'secondary' }
    }
}

function compliance-badge([string]$state) {
    switch ($state) {
        'compliant'     { badge 'Compliant'     'success' }
        'noncompliant'  { badge 'Non-Compliant' 'danger' }
        'inGracePeriod' { badge 'Grace Period'  'warning text-dark' }
        default         { badge $state          'secondary' }
    }
}

function section-status([string]$sec) {
    $f = $script:Findings | Where-Object { $_.Section -eq $sec }
    if ($f | Where-Object { $_.Severity -eq 'Critical' }) { return 'Critical' }
    if ($f | Where-Object { $_.Severity -eq 'Warning'  }) { return 'Warning'  }
    return 'Good'
}

function section-badge([string]$sec) { sev-badge (section-status $sec) }

function findings-list([string]$sec) {
    $f = $script:Findings | Where-Object { $_.Section -eq $sec }
    if (-not $f) { return '<p class="text-muted small mb-0">No findings for this section.</p>' }
    $html = '<ul class="list-group list-group-flush findings-list">'
    foreach ($item in $f) {
        $cls  = switch ($item.Severity) { 'Critical'{'list-group-item-danger'} 'Warning'{'list-group-item-warning'} 'Good'{'list-group-item-success'} default{'list-group-item-light'} }
        $icon = switch ($item.Severity) { 'Critical'{'&#9888;'} 'Warning'{'&#9888;'} 'Good'{'&#10003;'} default{'&#8505;'} }
        $html += "<li class='list-group-item $cls py-2'><strong>$icon $(HE $item.Title)</strong><br><small class='text-muted'>$(HE $item.Detail)</small></li>"
    }
    $html + '</ul>'
}

function stat-box([string]$val, [string]$lbl, [string]$color = 'info') {
    "<div class='stat-box $color'><div class='val'>$val</div><div class='lbl'>$lbl</div></div>"
}

function build-table([array]$Data, [string[]]$Cols, [scriptblock]$Row, [int]$Cap = 250) {
    if (-not $Data -or $Data.Count -eq 0) { return '<p class="text-muted small">No data to display.</p>' }
    $h  = '<div class="table-responsive"><table class="table table-sm table-hover table-striped align-middle mb-0">'
    $h += '<thead class="table-dark sticky-header"><tr>'
    foreach ($c in $Cols) { $h += "<th>$c</th>" }
    $h += '</tr></thead><tbody>'
    $lim = [math]::Min($Data.Count, $Cap)
    for ($i = 0; $i -lt $lim; $i++) {
        $h += "<tr>$($Row.Invoke($Data[$i]))</tr>"
    }
    if ($Data.Count -gt $Cap) {
        $h += "<tr><td colspan='$($Cols.Count)' class='text-center text-muted small'>… $($Data.Count - $Cap) more rows in CSV export</td></tr>"
    }
    $h + '</tbody></table></div>'
}

function section-wrap([string]$id, [string]$num, [string]$icon, [string]$title, [string]$body) {
    $sb = section-badge $title
    @"
<div id="$id" class="section-card">
  <div class="section-header">
    <span class="section-num">$num</span>
    <i class="bi $icon"></i>
    <h2>$title</h2>
    $sb
  </div>
  <div class="section-body">$body</div>
</div>
"@
}

#endregion

#region ── BUILD TABLE DATA ───────────────────────────────────────────────────

# CA Policies table
$caTable = build-table $caPolicies @('Policy Name','State','Include Users','Exclude Users','Include Apps','Grant Controls','Modified') {
    param($p)
    $n   = HE $p.DisplayName
    $st  = state-badge $p.State
    $iu  = HE ($p.Conditions.Users.IncludeUsers -join ', ')
    $eu  = HE ($p.Conditions.Users.ExcludeUsers -join ', ')
    $ia  = HE ($p.Conditions.Applications.IncludeApplications -join ', ')
    $gc  = HE ($p.GrantControls.BuiltInControls -join ', ')
    $mod = if ($p.ModifiedDateTime) { ([datetime]$p.ModifiedDateTime).ToString('yyyy-MM-dd') } else { '-' }
    "<td><strong>$n</strong></td><td>$st</td><td><small>$iu</small></td><td><small>$eu</small></td><td><small>$ia</small></td><td><small>$gc</small></td><td>$mod</td>"
}

# MFA - users without MFA
$noMfaList  = @($mfaReg | Where-Object { -not $_.IsMfaRegistered })
$mfaTable   = build-table $noMfaList @('Display Name','UPN','MFA Capable','SSPR Registered','Methods') {
    param($u)
    $n   = HE $u.UserDisplayName
    $upn = HE $u.UserPrincipalName
    $cap = if ($u.IsMfaCapable)      { badge 'Yes' 'success' } else { badge 'No' 'secondary' }
    $ss  = if ($u.IsSsprRegistered)  { badge 'Yes' 'success' } else { badge 'No' 'secondary' }
    $m   = HE ($u.MethodsRegistered -join ', ')
    "<td>$n</td><td><small>$upn</small></td><td>$cap</td><td>$ss</td><td><small>$m</small></td>"
}

# Intune profiles table
$intuneTable = build-table $intuneConfigs @('Profile Name','Platform/Type','Created','Last Modified') {
    param($c)
    $n   = HE $c.DisplayName
    $t   = HE ($c.'@odata.type' -replace '#microsoft.graph.','')
    $cr  = if ($c.CreatedDateTime)      { ([datetime]$c.CreatedDateTime).ToString('yyyy-MM-dd') } else { '-' }
    $mod = if ($c.LastModifiedDateTime) { ([datetime]$c.LastModifiedDateTime).ToString('yyyy-MM-dd') } else { '-' }
    "<td><strong>$n</strong></td><td><small>$t</small></td><td>$cr</td><td>$mod</td>"
}

# Compliance policies
$compPolicyTable = build-table $compliancePolicies @('Policy Name','Type','Created','Last Modified') {
    param($c)
    $n   = HE $c.DisplayName
    $t   = HE ($c.'@odata.type' -replace '#microsoft.graph.','')
    $cr  = if ($c.CreatedDateTime)      { ([datetime]$c.CreatedDateTime).ToString('yyyy-MM-dd') } else { '-' }
    $mod = if ($c.LastModifiedDateTime) { ([datetime]$c.LastModifiedDateTime).ToString('yyyy-MM-dd') } else { '-' }
    "<td><strong>$n</strong></td><td><small>$t</small></td><td>$cr</td><td>$mod</td>"
}

# Non-compliant devices
$nonCompliantList = @($managedDevices | Where-Object { $_.ComplianceState -ne 'compliant' })
$devTable = build-table $nonCompliantList @('Device','User','OS','Version','Compliance','Last Sync','Join Type') {
    param($d)
    $dn  = HE $d.DeviceName
    $u   = HE $d.UserDisplayName
    $os  = HE $d.OperatingSystem
    $ver = HE $d.OsVersion
    $c   = compliance-badge $d.ComplianceState
    $ls  = if ($d.LastSyncDateTime) { ([datetime]$d.LastSyncDateTime).ToString('yyyy-MM-dd') } else { '-' }
    $jt  = HE $d.JoinType
    "<td><strong>$dn</strong></td><td>$u</td><td>$os</td><td><small>$ver</small></td><td>$c</td><td>$ls</td><td>$jt</td>"
}

# All devices summary
$allDevTable = build-table (@($managedDevices | Select-Object -First 200)) @('Device','User','OS','Compliance','Last Sync') {
    param($d)
    $dn = HE $d.DeviceName
    $u  = HE $d.UserDisplayName
    $os = HE $d.OperatingSystem
    $c  = compliance-badge $d.ComplianceState
    $ls = if ($d.LastSyncDateTime) { ([datetime]$d.LastSyncDateTime).ToString('yyyy-MM-dd') } else { '-' }
    "<td><strong>$dn</strong></td><td>$u</td><td>$os</td><td>$c</td><td>$ls</td>"
}

# Autopilot
$apTable = build-table $autopilotDevices @('Serial Number','Model','Manufacturer','Group Tag','Enrollment State','Last Contacted') {
    param($d)
    $sn  = HE $d.SerialNumber
    $mod = HE $d.Model
    $mfr = HE $d.Manufacturer
    $gt  = if ($d.GroupTag) { HE $d.GroupTag } else { '<span class="text-muted">—</span>' }
    $es  = HE $d.EnrollmentState
    $lc  = if ($d.LastContactedDateTime) { ([datetime]$d.LastContactedDateTime).ToString('yyyy-MM-dd') } else { '-' }
    "<td>$sn</td><td>$mod</td><td>$mfr</td><td>$gt</td><td>$es</td><td>$lc</td>"
}

# Apps
$appsTable = build-table $apps @('App Name','Publisher','Type','Assigned','Last Modified') {
    param($a)
    $n   = HE $a.DisplayName
    $pub = HE $a.Publisher
    $t   = HE ($a.'@odata.type' -replace '#microsoft.graph.','')
    $asgn = if ($a.IsAssigned) { badge 'Assigned' 'success' } else { badge 'Unassigned' 'warning text-dark' }
    $mod = if ($a.LastModifiedDateTime) { ([datetime]$a.LastModifiedDateTime).ToString('yyyy-MM-dd') } else { '-' }

    # Install summary if available
    $instHtml = ''
    if ($appSummaries.ContainsKey($a.Id)) {
        $s = $appSummaries[$a.Id]
        $instHtml = " <small class='text-muted'>(&#10003;$($s.installedDeviceCount) &#10007;$($s.failedDeviceCount))</small>"
    }
    "<td><strong>$n</strong>$instHtml</td><td>$pub</td><td><small>$t</small></td><td>$asgn</td><td>$mod</td>"
}

# Licensing
$skuTable = build-table $skus @('License (SKU Part Number)','Assigned','Available','Unused','Utilization') {
    param($s)
    $n      = HE $s.SkuPartNumber
    $used   = $s.ConsumedUnits
    $avail  = $s.PrepaidUnits.Enabled
    $unused = $avail - $used
    $pct    = if ($avail -gt 0) { [math]::Round($used / $avail * 100, 0) } else { 0 }
    $bc     = if ($pct -gt 95) { 'danger' } elseif ($pct -gt 75) { 'success' } else { 'warning' }
    $bar    = "<div class='progress' style='min-width:90px;height:18px'><div class='progress-bar bg-$bc' style='width:$pct%'>$pct%</div></div>"
    "<td><strong>$n</strong></td><td>$used</td><td>$avail</td><td>$unused</td><td>$bar</td>"
}

# Legacy auth sign-ins
$legacyTable = if ($SkipSignInLogs) {
    '<p class="text-muted small">Skipped. Run without -SkipSignInLogs to collect sign-in data.</p>'
} else {
    build-table $legacySignIns @('User','App','Client App','Date','IP Address','Location','CA Result') {
        param($s)
        $u   = HE $s.UserPrincipalName
        $app = HE $s.AppDisplayName
        $cl  = HE $s.ClientAppUsed
        $dt  = if ($s.CreatedDateTime) { ([datetime]$s.CreatedDateTime).ToString('yyyy-MM-dd HH:mm') } else { '-' }
        $ip  = HE $s.IPAddress
        $loc = HE "$($s.Location.City), $($s.Location.CountryOrRegion)"
        $ca  = HE $s.ConditionalAccessStatus
        "<td><small>$u</small></td><td><small>$app</small></td><td><small>$cl</small></td><td>$dt</td><td>$ip</td><td>$loc</td><td>$ca</td>"
    }
}

# Admin roles
$adminTable = build-table $adminRoles @('Role','Member Name','UPN','Member Type') {
    param($r)
    $role = HE $r.RoleName
    $mem  = HE $r.MemberName
    $upn  = HE $r.MemberUPN
    $mt   = HE $r.MemberType
    "<td><strong>$role</strong></td><td>$mem</td><td><small>$upn</small></td><td>$mt</td>"
}

# Domains
$domTable = build-table $domains @('Domain','Auth Type','Default','Verified','Services') {
    param($d)
    $n   = HE $d.Id
    $at  = HE $d.AuthenticationType
    $def = if ($d.IsDefault)   { badge 'Default'   'primary'  } else { '' }
    $ver = if ($d.IsVerified)  { badge 'Verified'  'success'  } else { badge 'Unverified' 'warning text-dark' }
    $svc = HE ($d.SupportedServices -join ', ')
    "<td><strong>$n</strong></td><td>$at</td><td>$def</td><td>$ver</td><td><small>$svc</small></td>"
}

# Emergency accounts
$bgTable = build-table $emergencyAccts @('Display Name','UPN','Enabled','User Type','Created','Licenses','Global Admin') {
    param($u)
    $n  = HE $u.DisplayName
    $upn = HE $u.UserPrincipalName
    $en = if ($u.AccountEnabled) { badge 'Enabled' 'success' } else { badge 'Disabled' 'danger' }
    $ut = HE $u.UserType
    $cr = if ($u.CreatedDateTime) { ([datetime]$u.CreatedDateTime).ToString('yyyy-MM-dd') } else { '-' }
    $lic = $u.AssignedLicenses.Count
    $ga = if ($u.IsGlobalAdmin) { badge 'Yes' 'success' } else { badge 'No' 'warning' }
    "<td><strong>$n</strong></td><td><small>$upn</small></td><td>$en</td><td>$ut</td><td>$cr</td><td>$lic</td><td>$ga</td>"
}

#endregion

#region ── CHART DATA ─────────────────────────────────────────────────────────

# MFA methods breakdown
$mfaChartLabels = "'Authenticator App','OATH/TOTP','Phone/SMS','No MFA'"
$mfaChartData   = "$msAuthApp,$oathTotp,$phoneMethod,$noMfa"

# Compliance breakdown
$compGroups       = $managedDevices | Group-Object ComplianceState
$compChartLabels  = ($compGroups | ForEach-Object { "'$($_.Name)'" }) -join ','
$compChartData    = ($compGroups | ForEach-Object { $_.Count }) -join ','
$compChartColors  = "'#16a34a','#dc2626','#94a3b8','#d97706','#6366f1'" # compliant/noncompliant/unknown/gracePeriod/other

# OS breakdown
$osGroups       = $managedDevices | Group-Object OperatingSystem | Sort-Object Count -Descending
$osChartLabels  = ($osGroups | ForEach-Object { "'$($_.Name)'" }) -join ','
$osChartData    = ($osGroups | ForEach-Object { $_.Count }) -join ','

# CA policy state breakdown
$caGrouped      = $caPolicies | Group-Object State
$caStateLabels  = ($caGrouped | ForEach-Object { "'$($_.Name)'" }) -join ','
$caStateData    = ($caGrouped | ForEach-Object { $_.Count }) -join ','

#endregion

#region ── HTML REPORT ────────────────────────────────────────────────────────

$reportDate  = Get-Date -Format "MMMM dd, yyyy HH:mm"
$tenantName  = HE $org.DisplayName
$tenantDomain = HE (($domains | Where-Object { $_.IsDefault }).Id | Select-Object -First 1)
$runBy       = HE $ctx.Account
$tenantId    = $ctx.TenantId

$critCount   = @($script:Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
$warnCount   = @($script:Findings | Where-Object { $_.Severity -eq 'Warning'  }).Count
$goodCount   = @($script:Findings | Where-Object { $_.Severity -eq 'Good'     }).Count

$overallSev   = if ($critCount -gt 0) { 'Critical' } elseif ($warnCount -gt 0) { 'Warning' } else { 'Good' }
$overallColor = switch ($overallSev) { 'Critical'{'danger'} 'Warning'{'warning'} default{'success'} }
$overallBadge = sev-badge $overallSev

# All-findings sorted list
$allFindingsHtml = '<ul class="list-group list-group-flush findings-list">'
$sorted = $script:Findings | Sort-Object { switch($_.Severity){'Critical'{0}'Warning'{1}'Good'{2}default{3}} }
foreach ($f in $sorted) {
    $cls  = switch ($f.Severity) { 'Critical'{'list-group-item-danger'} 'Warning'{'list-group-item-warning'} 'Good'{'list-group-item-success'} default{'list-group-item-light'} }
    $icon = switch ($f.Severity) { 'Critical'{'&#9888;'} 'Warning'{'&#9888;'} 'Good'{'&#10003;'} default{'&#8505;'} }
    $allFindingsHtml += "<li class='list-group-item $cls py-2'><small class='text-uppercase fw-bold opacity-75'>$($f.Section)</small><br><strong>$icon $(HE $f.Title)</strong><br><small class='text-muted'>$(HE $f.Detail)</small></li>"
}
$allFindingsHtml += '</ul>'

# ── Intune HTML blocks (sections 4-7, nav links, scorecard rows) ──────────────
# Built outside the main $html here-string to avoid triple-nesting on Linux PS7.
# When -WithIntune was not passed these are all empty strings.
if ($script:HasIntuneAccess) {

    $intuneNavHtml = @"
  <a href="#intune">4. Intune Profiles</a>
  <a href="#compliance">5. Device Compliance</a>
  <a href="#autopilot">6. Autopilot</a>
  <a href="#apps">7. Applications</a>
"@

    $intuneScoreHtml = @"
        <tr><td><a href="#intune">Intune Config Profiles</a></td><td>$(section-badge 'Intune Profiles')</td><td>$configCount profiles: $winProfiles Windows &bull; $macProfiles macOS &bull; $iosProfiles iOS/Android</td></tr>
        <tr><td><a href="#compliance">Device Compliance</a></td><td>$(section-badge 'Device Compliance')</td><td>$compliancePct% compliant ($compliantDev/$totalDevices) &bull; $nonCompliantDev non-compliant &bull; $unknownDev unknown</td></tr>
        <tr><td><a href="#autopilot">Windows Autopilot</a></td><td>$(section-badge 'Autopilot')</td><td>$autopilotCount registered &bull; $withGroupTag with Group Tag &bull; $noGroupTag without Group Tag</td></tr>
        <tr><td><a href="#apps">Application Deployment</a></td><td>$(section-badge 'App Deployment')</td><td>$totalApps apps &bull; $assignedApps assigned &bull; $unassignedApps unassigned</td></tr>
"@

    $s4body = @"
<div class='stat-row'>
  $(stat-box $configCount 'Total Profiles' 'info')
  $(stat-box $winProfiles 'Windows'        'info')
  $(stat-box $macProfiles 'macOS'          'info')
  $(stat-box $iosProfiles 'iOS/Android'    'info')
</div>
<div class='findings-title'>Configuration Profiles</div>
$intuneTable
<div class='findings-title mt-3'>Findings</div>
$(findings-list 'Intune Profiles')
"@

    $s5body = @"
<div class='row g-3'>
  <div class='col-md-8'>
    <div class='stat-row'>
      $(stat-box "$compliancePct%" 'Compliant Rate' $hc_comp_col)
      $(stat-box $compliantDev    'Compliant'      'success')
      $(stat-box $nonCompliantDev 'Non-Compliant'  $hc_noncomp_col)
      $(stat-box $unknownDev      'Unknown'        'secondary')
      $(stat-box $gracePeriodDev  'Grace Period'   'warning')
      $(stat-box $($compliancePolicies.Count) 'Policies' 'info')
    </div>
    <div class='findings-title'>Compliance Policies</div>
    $compPolicyTable
    <div class='findings-title mt-3'>Non-Compliant &amp; Unknown Devices</div>
    $devTable
  </div>
  <div class='col-md-4'>
    <div class='findings-title'>Compliance Breakdown</div>
    <div class='chart-wrap mb-3'><canvas id='complianceChart'></canvas></div>
    <div class='findings-title'>OS Breakdown</div>
    <div class='chart-wrap'><canvas id='osChart'></canvas></div>
  </div>
</div>
<div class='findings-title mt-3'>Findings</div>
$(findings-list 'Device Compliance')
"@

    $s6body = @"
<div class='stat-row'>
  $(stat-box $autopilotCount 'Registered Devices' 'info')
  $(stat-box $withGroupTag   'With Group Tag'      'success')
  $(stat-box $noGroupTag     'Missing Group Tag'   $hc_nogt_col)
</div>
<div class='findings-title'>Autopilot Device Inventory</div>
$apTable
<div class='findings-title mt-3'>Findings</div>
$(findings-list 'Autopilot')
"@

    $s7body = @"
<div class='stat-row'>
  $(stat-box $totalApps      'Total Apps'  'info')
  $(stat-box $assignedApps   'Assigned'    'success')
  $(stat-box $unassignedApps 'Unassigned'  $hc_unasn_col)
</div>
<div class='findings-title'>Application Inventory $hc_appnote</div>
$appsTable
<div class='findings-title mt-3'>Findings</div>
$(findings-list 'App Deployment')
"@

    $intuneHtmlBlock  = (section-wrap 'intune'     '4' 'bi-gear'             'Intune Configuration Profile Review'  $s4body)
    $intuneHtmlBlock += (section-wrap 'compliance' '5' 'bi-clipboard-check'  'Device Compliance Policy Assessment'  $s5body)
    $intuneHtmlBlock += (section-wrap 'autopilot'  '6' 'bi-laptop'           'Windows Autopilot Registration Status' $s6body)
    $intuneHtmlBlock += (section-wrap 'apps'       '7' 'bi-box-seam'         'Application Deployment Review'        $s7body)
    $intuneHtmlBlock += @"
<script>
new Chart(document.getElementById('complianceChart'),{
  type:'doughnut',
  data:{ labels:[$compChartLabels], datasets:[{data:[$compChartData], backgroundColor:palette, borderWidth:2}]},
  options:{plugins:{legend:{position:'bottom',labels:{font:{size:11},padding:8}}}, cutout:'60%'}
});
new Chart(document.getElementById('osChart'),{
  type:'bar',
  data:{ labels:[$osChartLabels], datasets:[{label:'Devices', data:[$osChartData], backgroundColor:'#3b82f6', borderRadius:4}]},
  options:{indexAxis:'y', plugins:{legend:{display:false}}, scales:{x:{grid:{display:false}},y:{grid:{display:false}}}}
});
</script>
"@

} else {
    $intuneNavHtml   = ''
    $intuneScoreHtml = ''
    $intuneHtmlBlock = ''
}

# Pre-compute all conditional values used in stat-box calls.
# 'if' inside (parens) inside a nested here-string fails on Linux PowerShell 7 —
# variables resolve fine; inline if expressions do not.
$hc_mfaAll_val  = if ($mfaAllUsersPolicy) { 'Yes' }     else { 'NO' }
$hc_mfaAll_col  = if ($mfaAllUsersPolicy) { 'success' } else { 'danger' }
$hc_legacy_val  = if ($legacyBlockPolicy) { 'Yes' }     else { 'NO' }
$hc_legacy_col  = if ($legacyBlockPolicy) { 'success' } else { 'danger' }
$hc_srisk_val   = if ($signInRiskPolicy)  { 'Yes' }     else { 'NO' }
$hc_srisk_col   = if ($signInRiskPolicy)  { 'success' } else { 'warning' }
$hc_urisk_val   = if ($userRiskPolicy)    { 'Yes' }     else { 'NO' }
$hc_urisk_col   = if ($userRiskPolicy)    { 'success' } else { 'warning' }

$hc_mfapct_col  = if ($mfaPct -ge 90)  { 'success' } elseif ($mfaPct -ge 70)  { 'warning' } else { 'danger' }
$hc_nomfa_col   = if ($noMfa -eq 0)    { 'success' } else { 'danger' }
$hc_phone_col   = if ($phoneMethod -gt 0) { 'warning' } else { 'success' }
$hc_mfalbl      = if ($noMfaList.Count -gt 50) { "(showing first 50 of $($noMfaList.Count))" } else { '' }

$hc_comp_col    = if ($compliancePct -ge 90) { 'success' } elseif ($compliancePct -ge 70) { 'warning' } else { 'danger' }
$hc_noncomp_col = if ($nonCompliantDev -gt 0) { 'danger' }   else { 'success' }
$hc_nogt_col    = if ($noGroupTag -gt 0)      { 'warning' }  else { 'success' }
$hc_unasn_col   = if ($unassignedApps -gt 0)  { 'warning' }  else { 'success' }
$hc_appnote     = if (-not $SkipAppSummary)   { '(&#10003; installs / &#10007; failures shown inline)' } else { '(run without -SkipAppSummary for install counts)' }

$hc_unused_col  = if ($unusedSeats -gt 20) { 'warning' } elseif ($unusedSeats -gt 0) { 'info' } else { 'success' }
$hc_licutil_col = if ($licenseUtil -ge 80) { 'success' } else { 'warning' }

$hc_lgcnt_val   = if ($SkipSignInLogs) { 'N/A' } else { "$legacyCount" }
$hc_lgcnt_col   = if ($legacyCount   -gt 0) { 'danger' } else { 'success' }
$hc_lguniq_val  = if ($SkipSignInLogs) { 'N/A' } else { "$legacyUniqueU" }
$hc_lguniq_col  = if ($legacyUniqueU  -gt 0) { 'danger' } else { 'success' }
$hc_lgblk_val   = if ($legacyBlockPolicy) { 'Blocked' } else { 'Open' }
$hc_lgblk_col   = if ($legacyBlockPolicy) { 'success' } else { 'danger' }

$hc_emerg_col   = if ($emergencyCount -gt 0) { 'success' } else { 'danger' }

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Azure Tenant Assessment - $tenantName</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.2/dist/chart.umd.min.js"></script>
<style>
  :root { --navy:#0f172a; --slate:#1e293b; --accent:#3b82f6; }
  body  { font-family:'Segoe UI',system-ui,sans-serif; background:#f1f5f9; color:#1e293b; }

  /* Header */
  .rpt-header { background:linear-gradient(135deg,var(--navy),var(--slate)); color:#fff; padding:2rem 2.5rem; }
  .rpt-header h1 { font-size:1.75rem; font-weight:700; margin:0; }
  .rpt-header .meta { opacity:.65; font-size:.82rem; margin-top:.4rem; }
  .rpt-header .meta span { margin-right:1.2rem; }

  /* Sticky nav */
  .rpt-nav { position:sticky; top:0; z-index:200; background:var(--slate);
             padding:.4rem 1.5rem; display:flex; flex-wrap:wrap; gap:.2rem; }
  .rpt-nav a { color:rgba(255,255,255,.6); font-size:.78rem; padding:.25rem .55rem;
               border-radius:4px; text-decoration:none; white-space:nowrap; }
  .rpt-nav a:hover { color:#fff; background:rgba(255,255,255,.1); }

  /* Cards */
  .section-card { background:#fff; border-radius:12px; box-shadow:0 1px 6px rgba(0,0,0,.08);
                  margin-bottom:1.75rem; overflow:hidden; }
  .section-header { background:var(--navy); color:#fff; padding:.9rem 1.5rem;
                    display:flex; align-items:center; gap:.75rem; }
  .section-header h2 { font-size:1rem; font-weight:600; margin:0; flex:1; }
  .section-header i  { font-size:1.1rem; opacity:.8; }
  .section-num { font-size:.7rem; background:rgba(255,255,255,.15);
                 border-radius:50%; width:22px; height:22px; display:flex;
                 align-items:center; justify-content:center; font-weight:700; flex-shrink:0; }
  .section-body { padding:1.25rem 1.5rem; }

  /* Stat boxes */
  .stat-row { display:flex; flex-wrap:wrap; gap:.75rem; margin-bottom:1.25rem; }
  .stat-box { flex:1 1 110px; background:#f8fafc; border:1px solid #e2e8f0;
              border-radius:10px; padding:.9rem .75rem; text-align:center; }
  .stat-box .val { font-size:1.7rem; font-weight:700; line-height:1; }
  .stat-box .lbl { font-size:.68rem; color:#64748b; margin-top:.2rem; text-transform:uppercase; letter-spacing:.03em; }
  .stat-box.danger  .val { color:#dc2626; }
  .stat-box.warning .val { color:#d97706; }
  .stat-box.success .val { color:#16a34a; }
  .stat-box.info    .val { color:#2563eb; }
  .stat-box.secondary .val { color:#64748b; }

  /* Tables */
  .table th { font-size:.78rem; white-space:nowrap; }
  .table td { font-size:.82rem; vertical-align:middle; }
  .table-responsive { border-radius:8px; overflow:hidden; border:1px solid #e2e8f0; }

  /* Findings */
  .findings-list .list-group-item { font-size:.83rem; border-left:none; border-right:none; }
  .findings-title { font-weight:600; font-size:.85rem; color:#374151; margin:1rem 0 .4rem; }

  /* Charts */
  .chart-wrap { max-width:260px; margin:0 auto; }

  /* TOC scorecard */
  .scorecard td, .scorecard th { font-size:.85rem; }

  @media print {
    .rpt-nav { display:none !important; }
    .section-card { page-break-inside:avoid; box-shadow:none; border:1px solid #ddd; }
  }
</style>
</head>
<body>

<div class="rpt-header">
  <h1><i class="bi bi-shield-check me-2"></i>Azure Tenant Security Assessment</h1>
  <div class="meta">
    <span><i class="bi bi-building me-1"></i><strong>$tenantName</strong> ($tenantDomain)</span>
    <span><i class="bi bi-calendar3 me-1"></i>$reportDate</span>
    <span><i class="bi bi-person me-1"></i>$runBy</span>
    <span><i class="bi bi-fingerprint me-1"></i>$tenantId</span>
  </div>
</div>

<nav class="rpt-nav">
  <a href="#exec">&#9733; Summary</a>
  <a href="#entra">1. Entra ID</a>
  <a href="#ca">2. Conditional Access</a>
  <a href="#mfa">3. MFA</a>
$intuneNavHtml
  <a href="#licensing">8. Licensing</a>
  <a href="#legacy">9. Legacy Auth</a>
  <a href="#emergency">10. Emergency Access</a>
</nav>

<div class="container-fluid px-4 py-3" style="max-width:1600px">

<!-- ── EXECUTIVE SUMMARY ── -->
<div id="exec" class="section-card">
  <div class="section-header">
    <i class="bi bi-clipboard-data"></i>
    <h2>Executive Summary</h2>
    $overallBadge
  </div>
  <div class="section-body">
    <div class="row g-3 mb-4">
      <div class="col-6 col-md-3">
        <div class="stat-box $(if($critCount -gt 0){'danger'}else{'success'})">
          <div class="val">$critCount</div><div class="lbl">Critical Findings</div>
        </div>
      </div>
      <div class="col-6 col-md-3">
        <div class="stat-box $(if($warnCount -gt 0){'warning'}else{'success'})">
          <div class="val">$warnCount</div><div class="lbl">Warnings</div>
        </div>
      </div>
      <div class="col-6 col-md-3">
        <div class="stat-box info"><div class="val">$totalUsers</div><div class="lbl">Total Users</div></div>
      </div>
      <div class="col-6 col-md-3">
        <div class="stat-box info"><div class="val">$totalDevices</div><div class="lbl">Managed Devices</div></div>
      </div>
    </div>

    <div class="findings-title">Scorecard</div>
    <div class="table-responsive mb-4">
    <table class="table table-bordered scorecard mb-0">
      <thead class="table-dark"><tr><th>Assessment Area</th><th>Status</th><th>Key Metrics</th></tr></thead>
      <tbody>
        <tr><td><a href="#entra">Entra ID Configuration</a></td><td>$(section-badge 'Entra ID')</td><td>$totalUsers users ($enabledUsers enabled, $guestUsers guests, $hybridUsers hybrid), $federatedDoms federated domain(s)</td></tr>
        <tr><td><a href="#ca">Conditional Access</a></td><td>$(section-badge 'Conditional Access')</td><td>$enabledPolicies enabled &bull; $reportOnlyPolicies report-only &bull; $disabledPolicies disabled | MFA All-Users: $(if($mfaAllUsersPolicy){'Yes'}else{'NO'}) &bull; Legacy Blocked: $(if($legacyBlockPolicy){'Yes'}else{'NO'})</td></tr>
        <tr><td><a href="#mfa">MFA Posture</a></td><td>$(section-badge 'MFA Posture')</td><td>$mfaPct% registered ($mfaRegistered/$mfaTotal) &bull; $msAuthApp Authenticator &bull; $passwordless passwordless capable &bull; $noMfa no MFA</td></tr>
$intuneScoreHtml
        <tr><td><a href="#licensing">M365 Licensing</a></td><td>$(section-badge 'Licensing')</td><td>$licenseUtil% utilization ($totalAssigned/$totalAvailable seats) &bull; $unusedSeats unused seats</td></tr>
        <tr><td><a href="#legacy">Legacy Authentication</a></td><td>$(section-badge 'Legacy Authentication')</td><td>$(if($SkipSignInLogs){'Skipped'}else{"$legacyCount sign-ins ($legacyUniqueU unique users) in last $SignInLogDays days"})</td></tr>
        <tr><td><a href="#emergency">Emergency Access</a></td><td>$(section-badge 'Emergency Access')</td><td>$emergencyCount potential break-glass account(s) identified</td></tr>
      </tbody>
    </table>
    </div>

    <div class="findings-title">All Findings (sorted by severity)</div>
    $allFindingsHtml
  </div>
</div>

<!-- ── 1. ENTRA ID ── -->
$(section-wrap 'entra' '1' 'bi-diagram-3' 'Entra ID Configuration' @"
<div class='stat-row'>
  $(stat-box $totalUsers  'Total Users'    'info')
  $(stat-box $enabledUsers 'Enabled'       'success')
  $(stat-box $disabledUsers 'Disabled'     'secondary')
  $(stat-box $guestUsers  'Guest Users'    'info')
  $(stat-box $hybridUsers 'Hybrid Synced'  'info')
  $(stat-box $($groups.Count) 'Groups'    'info')
  $(stat-box $federatedDoms 'Federated Domains' 'info')
  $(stat-box $($adminRoles.Count) 'Admin Role Assignments' 'info')
</div>
<div class='findings-title'>Domains</div>
$domTable
<div class='findings-title mt-3'>Directory Role Assignments</div>
$adminTable
<div class='findings-title mt-3'>Findings</div>
$(findings-list 'Entra ID')
"@)

<!-- ── 2. CONDITIONAL ACCESS ── -->
$(section-wrap 'ca' '2' 'bi-shield-lock' 'Conditional Access Policy Audit' @"
<div class='stat-row'>
  $(stat-box $enabledPolicies    'Enabled'         'success')
  $(stat-box $reportOnlyPolicies 'Report Only'     'warning')
  $(stat-box $disabledPolicies   'Disabled'        'secondary')
  $(stat-box $hc_mfaAll_val 'MFA All Users'    $hc_mfaAll_col)
  $(stat-box $hc_legacy_val 'Legacy Blocked'   $hc_legacy_col)
  $(stat-box $hc_srisk_val  'Sign-in Risk CA'  $hc_srisk_col)
  $(stat-box $hc_urisk_val  'User Risk CA'     $hc_urisk_col)
</div>
<div class='findings-title'>Policies</div>
$caTable
<div class='findings-title mt-3'>Findings</div>
$(findings-list 'Conditional Access')
"@)

<!-- ── 3. MFA ── -->
$(section-wrap 'mfa' '3' 'bi-phone' 'MFA Posture Assessment' @"
<div class='row g-3'>
  <div class='col-md-8'>
    <div class='stat-row'>
      $(stat-box "$mfaPct%" 'MFA Registered %' $hc_mfapct_col)
      $(stat-box $mfaRegistered 'Registered'       'info')
      $(stat-box $noMfa         'No MFA'           $hc_nomfa_col)
      $(stat-box $msAuthApp     'MS Authenticator' 'info')
      $(stat-box $oathTotp      'OATH/TOTP'        'info')
      $(stat-box $phoneMethod   'SMS/Voice'        $hc_phone_col)
      $(stat-box $passwordless  'Passwordless'     'info')
    </div>
    <div class='findings-title'>Users Without MFA $hc_mfalbl</div>
    $mfaTable
  </div>
  <div class='col-md-4'>
    <div class='findings-title'>Authentication Method Distribution</div>
    <div class='chart-wrap'><canvas id='mfaChart'></canvas></div>
  </div>
</div>
<div class='findings-title mt-3'>Findings</div>
$(findings-list 'MFA Posture')
"@)

$intuneHtmlBlock

<!-- ── 8. LICENSING ── -->
$(section-wrap 'licensing' '8' 'bi-tag' 'Microsoft 365 Licensing Audit' @"
<div class='stat-row'>
  $(stat-box $($skus.Count)  'License SKUs'    'info')
  $(stat-box $totalAssigned  'Assigned Seats'  'info')
  $(stat-box $totalAvailable 'Total Available' 'info')
  $(stat-box $unusedSeats    'Unused Seats'    $hc_unused_col)
  $(stat-box "$licenseUtil%" 'Utilization'     $hc_licutil_col)
</div>
<div class='findings-title'>License SKUs</div>
$skuTable
<div class='findings-title mt-3'>Findings</div>
$(findings-list 'Licensing')
"@)

<!-- ── 9. LEGACY AUTH ── -->
$(section-wrap 'legacy' '9' 'bi-exclamation-triangle' 'Legacy Authentication Analysis' @"
<div class='stat-row'>
  $(stat-box $hc_lgcnt_val  "Sign-ins (${SignInLogDays}d)" $hc_lgcnt_col)
  $(stat-box $hc_lguniq_val 'Unique Users'                $hc_lguniq_col)
  $(stat-box $hc_lgblk_val  'CA Block Policy'             $hc_lgblk_col)
</div>
<div class='findings-title'>Legacy Authentication Sign-ins</div>
$legacyTable
<div class='findings-title mt-3'>Findings</div>
$(findings-list 'Legacy Authentication')
"@)

<!-- ── 10. EMERGENCY ACCESS ── -->
$(section-wrap 'emergency' '10' 'bi-key' 'Emergency Access Account Review' @"
<div class='stat-row'>
  $(stat-box $emergencyCount 'Accounts Found' $hc_emerg_col)
</div>
<div class='alert alert-info py-2 small'>
  <i class='bi bi-info-circle me-1'></i>
  Detection uses naming-pattern matching (emergency, breakglass, bg1, bg2, eam, etc.).
  Accounts should be <strong>cloud-only</strong>, <strong>excluded from all CA policies</strong>,
  have credentials stored offline, and be monitored via sign-in alerts.
</div>
$bgTable
<div class='findings-title mt-3'>Risky Users (Identity Protection)</div>
$(build-table $riskyUsers @('Display Name','UPN','Risk Level','Risk State','Risk Detail','Last Updated') {
    param($u)
    $n   = HE $u.UserDisplayName
    $upn = HE $u.UserPrincipalName
    $rl  = $u.RiskLevel
    $rs  = $u.RiskState
    $rd  = HE $u.RiskDetail
    $lu  = if ($u.RiskLastUpdatedDateTime) { ([datetime]$u.RiskLastUpdatedDateTime).ToString('yyyy-MM-dd') } else { '-' }
    "<td>$n</td><td><small>$upn</small></td><td>$rl</td><td>$rs</td><td><small>$rd</small></td><td>$lu</td>"
})
<div class='findings-title mt-3'>Findings</div>
$(findings-list 'Emergency Access')
"@)

<div class="text-center text-muted small py-4 border-top">
  Azure Tenant Security Assessment &mdash; $reportDate &mdash; Read-only &bull; No changes were made to the tenant.
</div>
</div><!-- /container -->

<script>
const palette = ['#16a34a','#dc2626','#94a3b8','#d97706','#6366f1','#0ea5e9','#ec4899','#f97316'];

new Chart(document.getElementById('mfaChart'),{
  type:'doughnut',
  data:{ labels:[$mfaChartLabels], datasets:[{data:[$mfaChartData], backgroundColor:['#16a34a','#0ea5e9','#f97316','#dc2626'], borderWidth:2}]},
  options:{plugins:{legend:{position:'bottom',labels:{font:{size:11},padding:8}}}, cutout:'60%'}
});

</script>
</body>
</html>
"@

$reportPath = Join-Path $OutputDir "AzureTenantAssessment.html"
$html | Out-File -FilePath $reportPath -Encoding UTF8 -NoNewline

#endregion

#region ── CSV EXPORTS ────────────────────────────────────────────────────────

Write-Host "`n[*] Writing CSV exports..." -ForegroundColor Cyan

function xcsv($data, $name) {
    if ($data -and @($data).Count -gt 0) {
        @($data) | Export-Csv (Join-Path $OutputDir $name) -NoTypeInformation -Encoding UTF8
        Write-Host "    $name" -ForegroundColor Gray
    }
}

xcsv $users                "users.csv"
xcsv $groups               "groups.csv"
xcsv $domains              "domains.csv"
xcsv $adminRoles           "admin_roles.csv"
xcsv $caPolicies           "ca_policies.csv"
xcsv $namedLocs            "named_locations.csv"
xcsv $mfaReg               "mfa_registration.csv"
xcsv $intuneConfigs        "intune_device_configs.csv"
xcsv $compliancePolicies   "compliance_policies.csv"
xcsv $managedDevices       "managed_devices.csv"
xcsv $autopilotDevices     "autopilot_devices.csv"
xcsv $apps                 "apps.csv"
xcsv $skus                 "license_skus.csv"
xcsv $legacySignIns        "legacy_auth_signins.csv"
xcsv $riskyUsers           "risky_users.csv"
xcsv $emergencyAccts       "emergency_access_accounts.csv"
xcsv ($script:Findings)    "findings.csv"

[PSCustomObject]@{
    AssessmentDate   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    TenantName       = $org.DisplayName
    TenantId         = $ctx.TenantId
    RunBy            = $ctx.Account
    TotalUsers       = $totalUsers
    TotalDevices     = $totalDevices
    MfaRegisteredPct = $mfaPct
    DeviceCompliancePct = $compliancePct
    CriticalFindings = $critCount
    Warnings         = $warnCount
    GoodFindings     = $goodCount
    HtmlReport       = $reportPath
} | Export-Csv (Join-Path $OutputDir "00_manifest.csv") -NoTypeInformation

#endregion

#region ── DONE ───────────────────────────────────────────────────────────────

Disconnect-MgGraph | Out-Null

Write-Host "`n╔══════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host   "║              Assessment Complete!                   ║" -ForegroundColor Green
Write-Host   "╚══════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  HTML Report : $reportPath" -ForegroundColor Cyan
Write-Host "  Output Dir  : $OutputDir"  -ForegroundColor Gray
Write-Host "  Critical    : $critCount"  -ForegroundColor $(if ($critCount -gt 0) { 'Red'    } else { 'Green' })
Write-Host "  Warnings    : $warnCount"  -ForegroundColor $(if ($warnCount -gt 0) { 'Yellow' } else { 'Green' })
Write-Host "  Good        : $goodCount"  -ForegroundColor Green
Write-Host ""

if ($script:InCloudShell) {
    Write-Host "  To download the report from Cloud Shell:" -ForegroundColor Yellow
    Write-Host "  1. Click the 'Upload/Download files' button in the Cloud Shell toolbar" -ForegroundColor Gray
    Write-Host "  2. Choose Download and enter: $reportPath" -ForegroundColor Gray
    Write-Host "     -- OR --" -ForegroundColor Gray
    Write-Host "  Open the Azure Storage account backing your Cloud Shell and browse to:" -ForegroundColor Gray
    Write-Host "  fileshare > clouddrive > AzureAssessment > $($reportPath | Split-Path -Leaf)" -ForegroundColor Gray
} else {
    Start-Process $reportPath
}

#endregion
