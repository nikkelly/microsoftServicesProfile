# Microsoft Services PowerShell Profile

## Allows for connection to these M365 Services
- [Microsoft Teams](https://docs.microsoft.com/en-us/MicrosoftTeams/teams-powershell-overview)
- [Skype for Business](https://docs.microsoft.com/en-us/microsoft-365/enterprise/manage-skype-for-business-online-with-microsoft-365-powershell?view=o365-worldwide)
- [Microsoft Exchange Online](https://docs.microsoft.com/en-us/powershell/exchange/exchange-online-powershell?view=exchange-ps)
- [Azure Active Directory (AAD V2 PowerShell)](https://docs.microsoft.com/en-us/powershell/module/azuread/?view=azureadps-2.0)
- [MSOnline (AAD V1 Powershell)](https://docs.microsoft.com/en-us/powershell/azure/active-directory/overview?view=azureadps-1.0)
- [SharePoint](https://docs.microsoft.com/en-us/powershell/sharepoint/sharepoint-online/introduction-sharepoint-online-management-shell?view=sharepoint-ps)
- [Security and Compliance Center](https://docs.microsoft.com/en-us/powershell/exchange/connect-to-scc-powershell?view=exchange-ps)

## Windows Terminal Profile
This was created to be used as a Windows Terminal profile and you can view my sample profile below:
```
{
  "guid": "{db7918ba-865e-456a-8adb-c3fc5a059a4a}",
  "name": "M365 Admin Console",
  "commandline": "powershell.exe -noprofile -noexit -command \"invoke-expression '. ''<path_to_file>/microsoftServicesProfile.ps1''' \"",
  "icon": "<path_to_icon>/m365logo.png",
  "hidden": false,
  "colorScheme": "Tomorrow Night Eighties"
}
```
- [M365 Profile Icon](https://upload.wikimedia.org/wikipedia/commons/thumb/4/44/Microsoft_logo.svg/1200px-Microsoft_logo.svg.png)
- Terminal colorScheme is [Tomorrow Night Eighties](https://github.com/mbadolato/iTerm2-Color-Schemes/blob/master/windowsterminal/Tomorrow%20Night%20Eighties.json)

## Links and Resources
- [Generate a new guid with PowerShell](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/new-guid?view=powershell-7)
