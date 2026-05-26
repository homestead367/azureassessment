# Azure Tenant Full Assessment

PowerShell script that connects to Microsoft Graph and exports a full snapshot of your Azure/Entra/Intune tenant to CSV files for review, auditing, or security assessments.

## What it collects

| File | Description |
|---|---|
| `users.csv` | All users with account status, license, department |
| `guest_users.csv` | External/guest identities |
| `groups.csv` | All groups (security, M365, dynamic) |
| `admin_roles.csv` | All directory role assignments with member UPNs |
| `ca_policies.csv` | Conditional Access policies with conditions + grant controls |
| `named_locations.csv` | Named/trusted IP locations used in CA |
| `mfa_registration.csv` | Per-user MFA/SSPR/passwordless registration state |
| `intune_device_configs.csv` | Intune device configuration profiles |
| `compliance_policies.csv` | Intune compliance policies |
| `autopilot_devices.csv` | Windows Autopilot enrolled devices |
| `managed_apps.csv` | Intune-managed mobile/desktop apps |
| `user_licensing.csv` | Per-user license SKUs + group-based assignment |
| `legacy_auth_signins.csv` | Non-browser sign-ins from the last 30 days |
| `risky_users.csv` | Identity Protection risky user list |
| `00_manifest.csv` | Run metadata (tenant, date, account) |

## Prerequisites

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -Force
```

## Usage

```powershell
# Run with default output folder (.\AssessmentOutput\<timestamp>)
.\Invoke-AzureTenantAssessment.ps1

# Specify output folder
.\Invoke-AzureTenantAssessment.ps1 -OutputDir "C:\Reports\Contoso-2026-05"
```

The script will prompt for interactive browser sign-in on first run. The account must have sufficient read permissions (Global Reader covers most of it; some Intune scopes may require Intune Administrator).

## Required Graph Scopes

| Scope | Used for |
|---|---|
| `Directory.Read.All` | Users, groups, roles |
| `Policy.Read.All` | Conditional Access |
| `UserAuthenticationMethod.Read.All` | MFA registration |
| `DeviceManagementConfiguration.Read.All` | Intune configs |
| `DeviceManagementCompliance.Read.All` | Compliance policies |
| `DeviceManagementApps.Read.All` | Managed apps |
| `DeviceManagementServiceConfig.Read.All` | Autopilot |
| `AuditLog.Read.All` | Sign-in logs |
| `Reports.Read.All` | Auth method reports |
| `IdentityRiskyUser.Read.All` | Risky users |
| `RoleManagement.Read.Directory` | Admin role assignments |

## Notes

- Legacy auth filter targets non-browser/non-modern-auth clients from the **last 30 days** (sign-in logs have a 30-day retention window).
- Requires an Entra ID P1 or P2 license for Conditional Access and Identity Protection data.
- All output is read-only — no changes are made to the tenant.
