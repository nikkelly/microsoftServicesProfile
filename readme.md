# Microsoft Services PowerShell Profile
Connect to M365 services with a single command.
## Installation
`git clone https://github.com/nikkelly/microsoftServicesProfile.git`

Use `notepad $profile` to add this to your PowerShell profile
```
Import-module '<path to file>/microsoftServicesProfile.ps1' -Force
```
## Usage
Command | Module
--- | ---
`Teams`|[Microsoft Teams](https://docs.microsoft.com/en-us/MicrosoftTeams/teams-powershell-overview)
`Skype`|[Skype for Business](https://docs.microsoft.com/en-us/microsoft-365/enterprise/manage-skype-for-business-online-with-microsoft-365-powershell?view=o365-worldwide)
`Exchange` |[Microsoft Exchange Online](https://docs.microsoft.com/en-us/powershell/exchange/exchange-online-powershell?view=exchange-ps)
`AzureAD`|[Azure Active Directory (AAD V2 PowerShell)](https://docs.microsoft.com/en-us/powershell/module/azuread/?view=azureadps-2.0)
`MSOnline`|[MSOnline (AAD V1 Powershell)](https://docs.microsoft.com/en-us/powershell/azure/active-directory/overview?view=azureadps-1.0)
`SharePoint`|[SharePoint](https://docs.microsoft.com/en-us/powershell/sharepoint/sharepoint-online/introduction-sharepoint-online-management-shell?view=sharepoint-ps)
`Security_Compliance`|[Security and Compliance Center](https://docs.microsoft.com/en-us/powershell/exchange/connect-to-scc-powershell?view=exchange-ps)

Use `Disconnect` to close all active connections

## Notes
Passwords are stored in the local user environment variable `$env:microsoftConnectionPass` as plain text. 

Accounts with MFA not currently supported
