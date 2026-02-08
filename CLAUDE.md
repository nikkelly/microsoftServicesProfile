# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

M365Connect - A PowerShell module that simplifies connections to Microsoft 365 services. Provides unified authentication, credential management, app registration (service principal) support, and connection tracking for multiple Microsoft cloud services.

**Version 3.0** - Now a proper PowerShell module with PS 5.1 and PS 7+ support.

## Commands

**Installation:**
```powershell
# Import for current session
Import-Module .\M365Connect.psd1

# Install to PowerShell modules directory
Copy-Item -Recurse .\M365Connect $env:PSModulePath.Split(';')[0]
Import-Module M365Connect
```

**Testing:**
```powershell
# Run Pester tests
Invoke-Pester -Path .\Tests\M365Connect.Tests.ps1

# Run PSScriptAnalyzer (uses project settings file)
Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
```

## Architecture

### Module Structure
```
M365Connect/
├── M365Connect.psd1                   # Module manifest
├── M365Connect.psm1                   # Module loader
├── PSScriptAnalyzerSettings.psd1      # Analyzer rule exclusions
├── Public/                            # Exported functions
│   ├── Connect-MS*.ps1               # Service connection functions
│   ├── Add-MS*.ps1                   # Account/config management
│   ├── Remove-MS*.ps1                # Cleanup functions
│   ├── Get-MSConnectionStatus.ps1    # Status reporting
│   └── Show-MSCommands.ps1           # Help display
├── Private/                           # Internal helper functions
│   ├── Write-ColorOutput.ps1
│   ├── Test-ModuleAvailable.ps1
│   ├── Get-MSCredential.ps1
│   ├── Export-MSCredential.ps1
│   ├── Export-MSAppRegistration.ps1
│   ├── Import-MSCredential.ps1
│   ├── Update-ConnectedServices.ps1
│   ├── Test-AlreadyConnected.ps1
│   └── Initialize-ModuleState.ps1
└── Tests/
    └── M365Connect.Tests.ps1
```

### Module State
All state managed via `$script:MSProfileState` hashtable:
- `ConnectedServices` - ArrayList tracking active connections
- `Credential` - PSCredential object
- `MicrosoftUser` - Stored admin username
- `Domain` - Extracted from email
- `MFAEnabled` - Boolean for MFA mode
- `AuthMethod` - 'Interactive', 'Credential', or 'ServicePrincipal'
- `AppRegistration` - Hashtable with AppId, TenantId, CertificateThumbprint, ClientSecret
- `PSVersionInfo` - PowerShell version and platform info

### Supported Services
| Function | Alias | Service | PS 5.1 Module | PS 7+ Module |
|----------|-------|---------|---------------|--------------|
| `Connect-MSTeams` | `Teams` | Microsoft Teams | MicrosoftTeams | MicrosoftTeams |
| `Connect-MSExchange` | `Exchange` | Exchange Online | ExchangeOnlineManagement | ExchangeOnlineManagement |
| `Connect-MSAzureAD` | `AzureAD` | Azure AD | AzureAD | → Connect-MSGraph |
| `Connect-MSGraph` | `MSOnline` | Microsoft Graph | Microsoft.Graph.Authentication | Microsoft.Graph.Authentication |
| `Connect-MSSharePoint` | `SharePoint` | SharePoint Online | Microsoft.Online.SharePoint.PowerShell | Microsoft.Online.SharePoint.PowerShell |
| `Connect-MSSecurityCompliance` | `Security_Compliance` | Security & Compliance | ExchangeOnlineManagement | ExchangeOnlineManagement |
| `Connect-MSIntune` | `Intune` | Intune | Microsoft.Graph.Intune | Microsoft.Graph.DeviceManagement |
| `Connect-MSExchangeServer` | `ExchangeServer` | Exchange On-Prem | PSSession (Kerberos) | PSSession (Kerberos) |

### Authentication Methods
1. **Interactive** - Browser-based auth, supports MFA
2. **Credential** - Username/password stored in environment variables
3. **ServicePrincipal** - App registration with certificate or client secret

### Key Functions

**Connection:**
- `Connect-MS*` - Individual service connections
- `Connect-AllMSServices` - Connect to all services
- `Disconnect-AllMSServices` - Disconnect from all services

**Account Management:**
- `Add-MSAccount` - Configure and save credentials
- `Remove-MSAccount` - Remove saved credentials
- `Add-MSMFA` / `Remove-MSMFA` - Enable/disable MFA mode

**App Registration:**
- `Add-MSAppRegistration` - Configure service principal auth
- `Remove-MSAppRegistration` - Clear service principal config

**Status:**
- `Get-MSConnectionStatus` - View current connection state
- `Show-MSCommands` - Display available commands

### Environment Variables
| Variable | Purpose |
|----------|---------|
| `microsoftConnectionUser` | Encrypted username |
| `microsoftConnectionPass` | Encrypted password |
| `microsoftConnectionMFA` | MFA enabled flag |
| `microsoftConnectionAuthMethod` | Auth method preference |
| `microsoftConnectionAppId` | App registration client ID |
| `microsoftConnectionTenantId` | Azure AD tenant ID |
| `microsoftConnectionCertThumbprint` | Certificate thumbprint |
| `microsoftConnectionClientSecret` | Encrypted client secret |

## Development Notes

- **PS Version Handling**: Module auto-detects PS version and adjusts available features
- **PS 7+**: AzureAD/MSOnline aliases redirect to Connect-MSGraph
- **Deprecated Modules**: AzureAD, MSOnline, Microsoft.Graph.Intune show deprecation warnings
- **Admin Rights**: Module installation requires admin; connections don't
- **Non-Windows**: Limited encryption support; warns users to use certificate auth
- **ShouldProcess**: `Remove-*` and `Update-*` functions support `-WhatIf` / `-Confirm`
- **PSScriptAnalyzer**: `PSAvoidUsingWriteHost` is suppressed in settings file (Write-Host is intentional for interactive UI); plural noun warnings are suppressed per-function via `SuppressMessageAttribute`

## Branch Strategy
- `main` - Production releases
- Feature branches: `nikkelly/issue##` format
