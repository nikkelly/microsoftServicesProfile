# Microsoft Services PowerShell Profile

Connect to Microsoft 365 services with a single command

![IMAGE](https://i.imgur.com/868HdVi.png)

## Installation

### PowerShell 

`Install-Module -Name MicrosoftServicesProfile -AllowClobber -Force`

Force and AllowClobber aren't really necessary but they do skip errors in case some appear

## Updates
`Update-Module -Name MicrosoftServicesProfile`

Alternatively, rerunning `Install-Module` with `-Force` will trigger reinstallation or update
`Install-Module -Name MicrosoftServicesProfile -AllowClobber -Force`

**NOTE:** The module will automatically check GitHub for the latest published version on startup. This can be disabled with `Disable-CheckProfileUpdate`

## Usage

| Service Command       | Module Documentation                                                                                                                                      |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Teams`               | [Microsoft Teams](https://docs.microsoft.com/en-us/MicrosoftTeams/teams-powershell-overview)                                                              |
| `Exchange`            | [Microsoft Exchange Online](https://docs.microsoft.com/en-us/powershell/exchange/exchange-online-powershell?view=exchange-ps)                             |
| `AzureAD`             | [Azure Active Directory (AAD V2 PowerShell)](https://docs.microsoft.com/en-us/powershell/module/azuread/?view=azureadps-2.0)                              |
| `MSOnline`            | [MSOnline (AAD V1 Powershell)](https://docs.microsoft.com/en-us/powershell/azure/active-directory/overview?view=azureadps-1.0)                            |
| `SharePoint`          | [SharePoint](https://docs.microsoft.com/en-us/powershell/sharepoint/sharepoint-online/introduction-sharepoint-online-management-shell?view=sharepoint-ps) |
| `Security_Compliance` | [Security and Compliance Center](https://docs.microsoft.com/en-us/powershell/exchange/connect-to-scc-powershell?view=exchange-ps)                         |


`Add-Account` Save your account credentials for future sessions without needing to re-enter

`Remove-Account` Remove saved account

`Disconnect` close all active connections

`connectAll` connect to all services at once

`Add-MFA` Add MFA to saved account credentials

`Remove-MFA` Remove MFA from saved account credentials

`$microsoftUser` Full user name of the admin user: **admin@contoso.onmicrosoft.com**

`$domain` Full domain name of the admin user: **contoso.onmicrosoft.com**

## Removal
If you decide that MicrosoftServicesProfile is not for you, it can easily be removed. 

### Option 1
1. Find where modules are stored `(Get-Module -ListAvailable MicrosoftServicesProfile).ModuleBase`
2. Manually Delete all MicrosoftServicesProfile folders
3. Remove `Import-Module MicrosoftServicesProfile -Force` or from `$profile`
  
### Option 2

`Uninstall-Module MicrosoftServicesProfile`

### Option 3

1. Remove `Import-Module <Download_Dicretory>\MicrosoftServicesProfile.ps1 -Force` from `$profile`

## Notes

- Automatically checks github for the latest version
- Supports accounts with MFA enabled
- Username and Password are saved to environment variables as encrypted standard strings
- Automatic prompt for install if module is not already installed
- All of the listed service commands (Teams/SharePoint/etc.) will perform these checks:
  - Is the user an admin?
  - Is the necessary module installed? If not already installed, prompt the user for install