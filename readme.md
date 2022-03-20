# Microsoft Services PowerShell Profile

Connect to Microsoft 365 services with a single command

![IMAGE](https://i.imgur.com/868HdVi.png)

## Installation

### PowerShell 

`git clone https://github.com/nikkelly/microsoftServicesProfile.git` 

`.<download directory>\servicesProfilev2.ps1 -install`


## First Time Setup
`<download directory>\servicesProfilev2.ps1 -install`
![Image](https://i.imgur.com/JpBt21j.png)


`<download directory>\servicesProfilev2.ps1 -uninstall`
![IMAGE](https://imgur.com/tJOjrl9.png)


`add-account`
![IMAGE](https://imgur.com/ASchEPT.png)

`remove-account`
![IMAGE](https://i.imgur.com/zYnFRA6.png)

## Usage

| Service Command               | Module Documentation                                                                                                                                               |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `Teams`               | [Microsoft Teams](https://docs.microsoft.com/en-us/MicrosoftTeams/teams-powershell-overview)                                                                       |
| `Exchange`            | [Microsoft Exchange Online](https://docs.microsoft.com/en-us/powershell/exchange/exchange-online-powershell?view=exchange-ps)                                      |
| `AzureAD`             | [Azure Active Directory (AAD V2 PowerShell)](https://docs.microsoft.com/en-us/powershell/module/azuread/?view=azureadps-2.0)                                       |
| `MSOnline`            | [MSOnline (AAD V1 Powershell)](https://docs.microsoft.com/en-us/powershell/azure/active-directory/overview?view=azureadps-1.0)                                     |
| `SharePoint`          | [SharePoint](https://docs.microsoft.com/en-us/powershell/sharepoint/sharepoint-online/introduction-sharepoint-online-management-shell?view=sharepoint-ps)          |
| `Security_Compliance` | [Security and Compliance Center](https://docs.microsoft.com/en-us/powershell/exchange/connect-to-scc-powershell?view=exchange-ps)                                  |


`Disconnect` close all active connections

`connectAll` connect to all services at once

`Remove-Account` Remove saved Account

`Add-MFA` Add MFA to saved account credentials

`Remove-MFA` Remove MFA from saved account credentials

`$microsoftUser` Full user name of the admin user: **admin@contoso.onmicrosoft.com**

`$domain` Full domain name of the admin user: **contoso.onmicrosoft.com**


## Notes

- Supports accounts with MFA enabled
- Username and Password are saved to environment variables as encrypted standard strings
- Will prompt for install if module is not already installed
- All of the listed service commands (Teams/SharePoint/etc.) will perform these checks:
  - Is the user an admin?
  - Is the necessary module installed? If not already installed, prompt the user for install


### Changelog for v2.0
- Refactored the entire project to be more dynamic
- No more auto-prompt for credentials
- Now allows for blank passwords
- Fixed an issue with SharePoint 