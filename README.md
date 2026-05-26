# Azure Tenant Security Assessment

PowerShell script that connects to Microsoft Graph and runs a full security assessment across 10 domains, producing a **self-contained HTML report** plus raw CSV exports.

## Report sections

| # | Area | What it covers |
|---|------|----------------|
| 1 | **Entra ID Configuration** | Directory structure, user/group counts, domain federation status, hybrid sync, admin role assignments |
| 2 | **Conditional Access Policy Audit** | All CA policies with state, coverage gaps (MFA for all users, legacy auth block, risk policies), named locations |
| 3 | **MFA Posture Assessment** | Per-user registration state, Microsoft Authenticator vs OATH/TOTP vs SMS/voice breakdown, passwordless readiness, users with no MFA |
| 4 | **Intune Configuration Profile Review** | All device config profiles by platform (Windows/macOS/iOS/Android) |
| 5 | **Device Compliance Policy Assessment** | Compliance policies, per-device compliance state, non-compliant device list |
| 6 | **Windows Autopilot Registration Status** | Device inventory, serial numbers, group tag coverage, enrollment state |
| 7 | **Application Deployment Review** | Full app catalog, assigned vs unassigned apps, optional install success/failure counts |
| 8 | **Microsoft 365 Licensing Audit** | All SKUs, assigned vs available seats, utilization rate, unused seat count |
| 9 | **Legacy Authentication Analysis** | Sign-in logs filtered to legacy protocols, unique users, CA block policy check |
| 10 | **Emergency Access Account Review** | Break-glass account detection by naming pattern, CA policy exclusion verification, risky users |

The report also includes an **Executive Summary scorecard** with all findings sorted by severity (Critical → Warning → Good).

## Prerequisites

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser -Force
```

## Usage

The script always prompts for the **target tenant domain or ID** before connecting.
This prevents accidentally running the assessment against a tenant you already manage.

```powershell
# Prompts interactively for tenant domain, then opens browser sign-in
.\Invoke-AzureTenantAssessment.ps1

# Pass the tenant up front (skips the prompt)
.\Invoke-AzureTenantAssessment.ps1 -TenantDomain contoso.onmicrosoft.com

# Full example with options
.\Invoke-AzureTenantAssessment.ps1 -TenantDomain contoso.onmicrosoft.com `
    -OutputDir "C:\Reports\Contoso" `
    -SignInLogDays 14

# Skip sign-in logs (faster on large tenants)
.\Invoke-AzureTenantAssessment.ps1 -TenantDomain contoso.onmicrosoft.com -SkipSignInLogs

# Skip per-app install summaries (faster for large app catalogs)
.\Invoke-AzureTenantAssessment.ps1 -TenantDomain contoso.onmicrosoft.com -SkipAppSummary
```

After authenticating, the script confirms the connected tenant ID and asks you to confirm before proceeding — a second safety check before any data is pulled.

Output lands in `.\AssessmentOutput\<timestamp>\`:
- `AzureTenantAssessment.html` — self-contained HTML report (open in any browser)
- `findings.csv` — all scored findings
- `users.csv`, `groups.csv`, `ca_policies.csv`, … — raw data per domain
- `00_manifest.csv` — run metadata

## Required Graph scopes

| Scope | Used for |
|---|---|
| `Directory.Read.All` | Users, groups, roles, domains |
| `Policy.Read.All` | Conditional Access policies |
| `UserAuthenticationMethod.Read.All` | MFA registration details |
| `DeviceManagementConfiguration.Read.All` | Intune config profiles |
| `DeviceManagementCompliance.Read.All` | Compliance policies |
| `DeviceManagementApps.Read.All` | App catalog |
| `DeviceManagementServiceConfig.Read.All` | Autopilot |
| `DeviceManagementManagedDevices.Read.All` | Enrolled device list |
| `AuditLog.Read.All` | Sign-in logs |
| `Reports.Read.All` | MFA registration report |
| `IdentityRiskyUser.Read.All` | Identity Protection risky users |
| `RoleManagement.Read.Directory` | Admin role assignments |
| `Organization.Read.All` | Tenant info |

**Minimum role:** Global Reader (covers most data). Some Intune data may require Intune Administrator.

## Notes

- Sign-in log retention is 30 days max in Entra ID (P1/P2 required for full history).
- Conditional Access and Identity Protection data requires Entra ID P1 or P2.
- No changes are made to the tenant — all calls are read-only.
- Break-glass detection is pattern-based. Verify identified accounts manually.
