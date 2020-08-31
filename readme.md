# Microsoft Services PowerShell Profile

Connect to Microsoft 365 services with a single command.

![Screenshot](https://i.imgur.com/sayOzoX.png)

## Installation

### PowerShell

`git clone https://github.com/nikkelly/microsoftServicesProfile.git`

Use `notepad $profile` to open your PowerShell profile

Add `Import-module '<PATH TO FILE>/microsoftServicesProfile.ps1' -Force` to the file and save.

### Windows Terminal

`git clone https://github.com/nikkelly/microsoftServicesProfile.git`

Generate a new GUID in PowerShell with `New-Guid`

Add new profile in Windows Terminal settings:

```JSON
{
    "guid": "<GUID FROM POWERSHELL>",
    "name": "M365 Admin Console",
    "commandline": "powershell.exe -noprofile -noexit -command \"invoke-expression '. ''<PATH TO FILE>/microsoftServicesProfile.ps1''' \"",
    "icon": "<PATH TO LOGO>/m365logo.png",
    "hidden": false,
    "colorScheme": "Tomorrow Night Eighties"
}
```

## Usage

| Command               | Module Documentation                                                                                                                                               |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `Teams`               | [Microsoft Teams](https://docs.microsoft.com/en-us/MicrosoftTeams/teams-powershell-overview)                                                                       |
| `Skype`               | [Skype for Business](https://docs.microsoft.com/en-us/microsoft-365/enterprise/manage-skype-for-business-online-with-microsoft-365-powershell?view=o365-worldwide) |
| `Exchange`            | [Microsoft Exchange Online](https://docs.microsoft.com/en-us/powershell/exchange/exchange-online-powershell?view=exchange-ps)                                      |
| `AzureAD`             | [Azure Active Directory (AAD V2 PowerShell)](https://docs.microsoft.com/en-us/powershell/module/azuread/?view=azureadps-2.0)                                       |
| `MSOnline`            | [MSOnline (AAD V1 Powershell)](https://docs.microsoft.com/en-us/powershell/azure/active-directory/overview?view=azureadps-1.0)                                     |
| `SharePoint`          | [SharePoint](https://docs.microsoft.com/en-us/powershell/sharepoint/sharepoint-online/introduction-sharepoint-online-management-shell?view=sharepoint-ps)          |
| `Security_Compliance` | [Security and Compliance Center](https://docs.microsoft.com/en-us/powershell/exchange/connect-to-scc-powershell?view=exchange-ps)                                  |

`Disconnect` close all active connections

`connectAll` connect to all services at once

## Notes

- Supports accounts with MFA enabled
- Username and Password are saved to environment variables as encrypted standard strings
- Will prompt for install if module is not already installed
  
